package task;

import java.util.Collection;
import java.util.LinkedList;
import java.util.Optional;

public class ExecutionResult<T> {

	public final Collection<String> flags;
	public final Exception exception;
	public final Result result;
	public final T returnValue;
	
	public ExecutionResult(Collection<String> flags, Exception exception, Result result, T returnValue) {
		this.flags = flags;
		this.exception = exception;
		this.result = result;
		this.returnValue = returnValue;
	}

	public Optional<T> returnValue(){
		if(hasReturn())
			return Optional.of(returnValue);
		return Optional.empty();
	}
	
	public boolean timedOut() {
		return result == Result.TIMEOUT;
	}
	
	public boolean wasExecuted() {
		return result != Result.NO_EXEC;
	}
	
	public boolean hasReturn() {
		return returnValue != null;
	}
	
	public boolean wasSuccess() {
		return result == Result.SUCCESS;
	}
	
	public boolean wasException() {
		return exception != null;
	}
	
	public boolean hasFlag() {
		return !flags.isEmpty();
	}


	public static <T> ExecutionResult<T> create(Collection<String> flags, Exception exception, Result result, T returnValue){
		return new ExecutionResult<T>(flags, exception, result, returnValue);
	}
	
	public static <T> ExecutionResult<T> create(Collection<String> flags, Exception exception){
		return new ExecutionResult<T>(flags, exception, Result.EXCEPTION, null);
	}
	
	public static <T> ExecutionResult<T> create(Collection<String> flags){
		return new ExecutionResult<T>(flags, null, flags.size() > 0 ? Result.SUCCESS : Result.FAIL, null);
	}
	
	public static <T> ExecutionResult<T> create(Collection<String> flags, Result result){
		return new ExecutionResult<T>(flags, null, result, null);
	}
	
	public static <T> ExecutionResult<T> create(Result result){
		return new ExecutionResult<T>(new LinkedList<>(), null, result, null);
	}
	
	public static <T> ExecutionResult<T> create(Result result, Exception exception){
		return new ExecutionResult<T>(new LinkedList<>(), exception, result, null);
	}

	public String getFlag() {
		return flags.iterator().next();
	}
	
}
