package util;

import java.math.BigInteger;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

public class Utils {

	public static ExecutorService executor = new ThreadPoolExecutor(0, 12, 2, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
	
	public static byte[] XOR(BigInteger a, BigInteger b) {
		return XOR(a.toByteArray(), b.toByteArray());
	}
	
	public static byte[] XOR(byte[] a, byte[] b) {
		byte[] result = new byte[Integer.max(a.length, b.length)];
		
		for(int i = 0; i < result.length; i++)
			result[i] = (byte) ( a[i % a.length] ^ b[i % b.length]);
		
		return result;
	}
	
	public static <T> Optional<T> withTimeout(Supplier<T> function, long timeout){
		
		if(timeout == -1)
			return Optional.of(function.get());
		
		Callable<T> task = new Callable<T>() {

			@Override
			public T call() throws Exception {
				return function.get();
			}

		};
		Future<T> future = executor.submit(task);
		try {
			T result = future.get(timeout, TimeUnit.MILLISECONDS);
			if(result == null) {
				return null;
			}
			return Optional.of(result);
		} catch (InterruptedException | ExecutionException | TimeoutException e) {
			future.cancel(true);
			return Optional.empty();
		}
	}
	
}
