package util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
import java.util.zip.CRC32;

public class Utils {

	public static ExecutorService executor = new ThreadPoolExecutor(0, 12, 2, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
	
	public static final String hexChars = "0123456789abcdef";
	
	public static byte[] md5(byte[] input) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("MD5");
		    return md.digest(input);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("I guess MD5 is not a thing?", e);
		}
	}
	
	public static String shift(String input, int amount, int mod, int offset) {
		char[] chars = input.toCharArray();
		StringBuilder builder = new StringBuilder();
		
		for(int i = 0; i < chars.length; i++) {
			int result = chars[i] + amount;
			if(result > mod) {
				result -= mod - offset;
			}
			if(result < 0) {
				result += mod;
			}
			builder.append((char)result);
		}
		
		return builder.toString();
	}
	
	public static byte[] hash(String algo, byte[] input) {
		if(algo.toLowerCase().equals("crc32")) {
			CRC32 c = new CRC32();
			c.update(input);
			return ByteBuffer.allocate(8).putLong(c.getValue()).array();
		}
		MessageDigest md;
		try {
			md = MessageDigest.getInstance(algo);
		    return md.digest(input);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("I guess " + algo + " is not a thing?", e);
		}
	}
	
	public static byte[] sha1(byte[] input) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-1");
		    return md.digest(input);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("I guess SHA-1 is not a thing?", e);
		}
	}
	
	public static long address64(long value) {
		return new BigInteger(p64(value)).longValue();
	}
	
	public static byte[] fromHex(String hex) {
		
		char[] chars = hex.toLowerCase().toCharArray();
		byte[] ret = new byte[chars.length / 2];
		
		for(int i = 0; i < ret.length; i ++ ) {
			ret[i] = (byte) (((hexChars.indexOf(chars[2 * i])) << 4) + (hexChars.indexOf(chars[2 * i + 1])));
		}
		
		return ret;
	}
	
	public static String hex(byte[] data) {
		StringBuilder builder = new StringBuilder();
		
		int tmp;
		for(byte b : data) {
			tmp = b & 0xFF;
			builder.append(hexChars.charAt(tmp >> 4)).append(hexChars.charAt(tmp % 16));
		}
		
		return builder.toString();
	}

	public static long address64(String address) {
		return new BigInteger(address + "", 16).longValue();
	}
	
	public static byte[] p64(long address) {
		byte[] addr = new BigInteger(address +"").toByteArray();
		byte[] ret = new byte[8];
		
		for(int i = 0; i < addr.length;i++) {
			ret[i] = addr[addr.length-i-1];
		}
		return ret;
	}
	
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
