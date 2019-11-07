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
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TaskExecutor {

	private Map<Class<?>, Map<String, Object>> variables;
	private Map<Class<?>, Function<Object, Result>> returnFunctions;
	
	private PrintStream flagStream;
	private ByteArrayOutputStream flagOut;
	
	private Pattern flagPattern;
	private Collection<String> collectedFlags;
	private String taskName;
	
	public TaskExecutor() {
		
		variables = new HashMap<>();
		returnFunctions = new HashMap<>();
		
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
		
		addReturnFunction(Boolean.class, b -> b ? Result.SUCCESS : Result.FAIL);
		addReturnFunction(Result.class, r -> r);
	}
	
	public Map<String, ExecutionResult<?>> wholeClass(Class<?> clzz){
		Map<String, ExecutionResult<?>> ret = new HashMap<>();
		
		for(Method m : clzz.getMethods()) {
			if(!m.isAnnotationPresent(Task.class))
				continue;
			
			Task t = m.getAnnotation(Task.class);
			
			ret.put(t.name(), execute(m, m.getReturnType()));
		}
		
		return ret;
	}
	
	@SuppressWarnings("unchecked")
	public <T> void addReturnFunction(Class<T> type, Function<T, Result> function) {
		returnFunctions.put(type, x -> function.apply((T)x));
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
			String flag = s.substring(m.start(), m.end()+1);
			collectedFlags.add(flag);
		}
		
		return amount;
	}
	
	public void newFlags() {
		collectedFlags = new HashSet<String>();
	}
	
	public void prepare() {
		
	}
	
	@SuppressWarnings("unchecked")
	public <T> ExecutionResult<T> execute(Method m, T returnType) {
		
		
		if(!m.isAnnotationPresent(Task.class))
			throw new IllegalArgumentException(String.format("Method '%s' is not a Task!", m.getName()));
		
		Task t = m.getAnnotation(Task.class);
		
		flagPattern = Pattern.compile(t.flagPattern());
		taskName = t.name();
		
		Object[] args = constructArgs(m);
		
		newFlags();
		
		try {
			Object returnValue = m.invoke(null, args);
			
			findFlags(new String(flagOut.toByteArray(), t.encoding()));
			Collection<String> collectedFlags = this.collectedFlags;
			flagOut.reset();
			
			Result result;
			if(returnFunctions.containsKey(m.getReturnType())) {
				result = returnFunctions.get(m.getReturnType()).apply(returnValue);
			} else {
				result = Result.UNKNOWN;
			}
			return ExecutionResult.create(collectedFlags, null, result, (T)returnValue);
			
			
		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			return ExecutionResult.create(Result.NO_EXEC, e);
		} catch(Exception e) {
			return ExecutionResult.create(Result.EXCEPTION, e);
		}
		
	}
	
	public Object[] constructArgs(Method m){
		Parameter[] params = m.getParameters();
		
		Object[] result = new Object[params.length];
		
		for(int i = 0; i < params.length; i++) {
			result[i] = constructArg(params[i].getName(), params[i].getType());
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
