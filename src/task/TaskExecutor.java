package task;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import util.Utils;

public class TaskExecutor {

	/*
	 *  TODO:
	 *  	verbose output (result, flags, etc.)
	 *  	add timeout (kinda done)
	 *  	add multi-threading ? (probably not, as there is not too much use to it I think, if it is needed it can easily be done within the task)
	 *  	synchronize output (only if multi-threading :D)
	 */
	
	private static Map<Class<?>, Map<String, Object>> defaultVariables;
	private static Map<Class<?>, Function<Object, Result>> defaultReturnFunctions;
	
	private Map<Class<?>, Map<String, Object>> variables;
	private Map<Class<?>, Function<Object, Result>> returnFunctions;
	
	private PrintStream flagStream;
	private ByteArrayOutputStream flagOut;
	
	private Pattern flagPattern;
	private Collection<String> collectedFlags;
	private String taskName;
	
	private long timeout = -1;
	
	static {
		defaultReturnFunctions = new HashMap<>();
		defaultVariables = new HashMap<>();
		addDefaultReturnFunction(Boolean.class, b -> b ? Result.SUCCESS : Result.FAIL);
		addDefaultReturnFunction(Result.class, r -> r);
		addDefaultReturnFunction(Boolean.TYPE, b -> b ? Result.SUCCESS : Result.FAIL);
	}
	
	public TaskExecutor() {
		
		variables = new HashMap<>();
		returnFunctions = new HashMap<>();
		
		variables.putAll(defaultVariables);
		returnFunctions.putAll(defaultReturnFunctions);

		addReturnFunction(Void.TYPE, b -> collectedFlags.isEmpty() ? Result.UNKNOWN : Result.SUCCESS);
		flagOut = new ByteArrayOutputStream();		
		flagStream = new PrintStream(flagOut);
		addVariable(PrintStream.class, "flags", flagStream);	
		
		PrintStream out = new PrintStream(System.out) {
			
			@Override
			public void println(String s) {
				super.println(String.format("[%s]: %s", taskName, s));
			}
			
			@Override
			public void println(Object s) {
				super.println(String.format("[%s]: %s", taskName, s));
			}
			
			@Override
			public void println(boolean s) {
				super.println(String.format("[%s]: %b", taskName, s));
			}
			
			@Override
			public void println(char s) {
				super.println(String.format("[%s]: %c", taskName, s));
			}
			
		};
		addVariable(PrintStream.class, "out", out);
		
	}
	
	public Map<String, ExecutionResult<?>> wholeClass(Class<?> clzz){
		Map<String, ExecutionResult<?>> ret = new HashMap<>();
		
		for(Method m : clzz.getMethods()) {
			if(!m.isAnnotationPresent(Task.class))
				continue;
			
			Task t = m.getAnnotation(Task.class);
			
			ret.put(t.value(), execute(m));
		}
		
		return ret;
	}
	
	@SuppressWarnings("unchecked")
	public <T> void addReturnFunction(Class<T> type, Function<T, Result> function) {
		returnFunctions.put(type, x -> function.apply((T)x));
	}
	
	@SuppressWarnings("unchecked")
	public static <T> void addDefaultReturnFunction(Class<T> type, Function<T, Result> function) {
		defaultReturnFunctions.put(type, x -> function.apply((T)x));
	}
	
	public void setTimeout(long millis) {
		timeout = millis;
	}
	
	public void addVariable(String name, Object value) {
		if(variables.containsKey(value.getClass())) {
			variables.get(value.getClass()).put(name, value);
		} else {
			Map<String, Object> map = new HashMap<>();
			map.put(name, value);
			variables.put(value.getClass(), map);
		}
	}
	
	public  <T> void addVariable(Class<T> type, String name, T value) {
		if(variables.containsKey(type)) {
			variables.get(type).put(name, value);
		} else {
			Map<String, Object> map = new HashMap<>();
			map.put(name, value);
			variables.put(type, map);
		}
	}
	
	public int findFlags(String s) {
		Matcher m = flagPattern.matcher(s);
		
		int amount = 0;
		
		while(m.find()) {
			amount ++;
			String flag = s.substring(m.start(), m.end());
			collectedFlags.add(flag);
		}
		
		return amount;
	}
	
	public void newFlags() {
		collectedFlags = new HashSet<String>();
	}
	
	public void prepare() {
		
	}
	
	public <T> ExecutionResult<T> execute(Class<?> clazz, String name){
		try {
			for(Method m : clazz.getMethods()) {
				if(m.isAnnotationPresent(Task.class)) {
					if(m.getDeclaredAnnotation(Task.class).value().equals(name)) {
						return execute(m);
					}
				}
			}
			throw new IllegalArgumentException(String.format("Task '%s' was not found in class '%s'", name, clazz.getName()));
		} catch (SecurityException e) {
			throw new IllegalArgumentException(String.format("Cannot execute task '%s' (class: %s)", name, clazz.getName()));
		}
	}
	
	@SuppressWarnings("unchecked")
	public <T> ExecutionResult<T> execute(Method m) {
		
		
		if(!m.isAnnotationPresent(Task.class))
			throw new IllegalArgumentException(String.format("Method '%s' is not a Task!", m.getName()));
		
		Task t = m.getAnnotation(Task.class);
		
		flagPattern = Pattern.compile(t.flagPattern());
		taskName = t.value();
		
		Object[] args = constructArgs(m);
		
		newFlags();
		
		try {
			Optional<Object> returnValue = Utils.withTimeout(() -> {
				try {
					return m.invoke(null, args);
				} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
					throw new RuntimeException("Cannot invoke method", e);
				}
			}, timeout);
			
			findFlags(new String(flagOut.toByteArray(), t.encoding()));
			Collection<String> collectedFlags = this.collectedFlags;
			flagOut.reset();
			
			Result result;
			if(returnValue == null) {
				result = returnFunctions.get(m.getReturnType()).apply(null);
			} else if(returnValue.isEmpty()) {
				result = Result.TIMEOUT;
			} else if(returnFunctions.containsKey(m.getReturnType())) {
				result = returnFunctions.get(m.getReturnType()).apply(returnValue.get());
			} else {
				result = Result.UNKNOWN;
			}
			return ExecutionResult.create(collectedFlags, null, result, returnValue == null ? null : returnValue.isEmpty() ? null : (T)returnValue.get());
			
		} catch(RuntimeException ex) {
			return ExecutionResult.create(Result.NO_EXEC, ex);
		} catch(Exception e) {
			return ExecutionResult.create(Result.EXCEPTION, e);
		}
		
	}
	
	public Object[] constructArgs(Method m){
		Parameter[] params = m.getParameters();
		
		Object[] result = new Object[params.length];
		
		for(int i = 0; i < params.length; i++) {
			
			String name;
			
			if(params[i].isAnnotationPresent(Name.class)) {
				name = params[i].getAnnotation(Name.class).value();
			} else {
				name = params[i].getName();
			}
			
			result[i] = constructArg(name, params[i].getType());
		}
		
		return result;
	}
	
	@SuppressWarnings("unchecked")
	public <T> T constructArg(String name, Class<T> type) {
		Map<String, Object> options = variables.get(type);
		if(options == null) {
			throw new IllegalArgumentException(String.format("Cannot construct argument for Parameter '%s' with type %s", name, type.getName()));
		}
		
		T choice;
		
		if(options.containsKey(name)) {
			choice = (T)options.get(name);
		} else {
			choice = (T)options.values().iterator().next();
		}
		
		return choice;
	}
	
}
