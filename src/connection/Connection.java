package connection;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.ProcessBuilder.Redirect;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Pattern;


public abstract class Connection {

	public static Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
	
	public Charset charset = DEFAULT_CHARSET;
	
	private boolean inputDead;
	private boolean outputDead;
	private boolean verbose;
	
	public static InputStreamOutputStreamConnection remote(String host, int port) {
		try {
			// TODO close socket somehow xD
			@SuppressWarnings("resource")
			Socket socket = new Socket(host, port);
			
			return new InputStreamOutputStreamConnection(socket.getInputStream(), socket.getOutputStream());
		} catch(IOException e) {
			throw new IllegalStateException("IOException while creating remote", e);
		}
	}
	
	public static InputStreamOutputStreamConnection process(String... command) {
		
		// TODO this will redirect error stream to STDERR which is kinda not really what we want :D
		
		ProcessBuilder builder = new ProcessBuilder(command);
		
		Process p;
		try {
			p = builder.redirectError(Redirect.INHERIT).start();
		} catch (IOException e) {
			e.printStackTrace();
			throw new IllegalStateException("IOException while starting process!");
		}
		
		return new InputStreamOutputStreamConnection(p.getInputStream(), p.getOutputStream());
		
	}
	
	public abstract void write(byte b) throws IOException;
	
	public abstract void flush() throws IOException;
	
	public abstract int read() throws IOException;

	public abstract int available() throws IOException;
	
	public void verbose() {
		verbose = true;
	}
	
	public void inputDied() {
		inputDead = true;
	}
	
	public void outputDied() {
		outputDead = true;
	}
	
	public void read(byte[] to, int offset, int amount) throws IOException {
		for(int i = offset; i < offset + amount; i++) {
			int result = read();
			if(result == -1) {
				inputDead = true;
				throw new IOException("End of input reached!");
			}
			to[i] = (byte)result;
		}
	}
	
	public  void closeOut() throws IOException {
		outputDead = true;
	}
	
	public  void closeIn() throws IOException {
		inputDead = true;
	}
	
	public boolean inputAlive() {
		return !inputDead;
	}
	
	public boolean outputAlive() {
		return !outputDead;
	}
	
	public boolean alive() {
		return !inputDead && !outputDead;
	}
	
	public void close() {
		try {
			closeOut();
		} catch(IOException e) {
			
		}
		try {
			closeIn();
		} catch(IOException e) {
			
		}
	}
	
	public byte[] read(int amount) {
		try {
			byte[] result = new byte[amount];
			read(result, 0, amount);
			return result;
		} catch(IOException e) {
			inputDead = true;
			throw new IllegalStateException("IOException while reading", e);
		}
	}
	
	public void write(byte[] bytes) throws IOException{
		for(byte b : bytes)
			write(b);
	}
	
	public Optional<Byte> tryRead(){
		try {
			int value = read();
			if(value == -1) {
				inputDead = true;
				return Optional.empty();
			}
			return Optional.of((byte)read());
		} catch(IOException e) {
			inputDead = true;
			return Optional.empty();
		}
	}
	
	public byte readByte() {
		try {
			int value = read();
			if(value == -1) {
				inputDead = true;
				throw new IllegalStateException("Input closed");
			}
			return (byte)value;
		} catch(IOException e) {
			inputDead = true;
			throw new IllegalStateException("IOException while reading bytes", e);
		}
	}
	
	public char readChar() {
		char c = (char)readByte();
		if(verbose) {
			System.out.print(c);
		}
		return c;
	}
	
	public String readln() {
		return readUntil("\n");
	}
	
	public String readFull() {
		return new String(readAll(),charset);
	}
	
	public byte[] readAll() {
		try {
			int available;
			byte[] lastBuffer = new byte[] {};
			byte[] buffer = new byte[] {};
			while((available = available()) > 0) {
				buffer = new byte[lastBuffer.length + available];
				System.arraycopy(lastBuffer, 0, buffer, 0, lastBuffer.length);
				read(buffer, lastBuffer.length, available);
				lastBuffer = buffer;
			}
			close();
			return buffer;
		} catch (IOException e) {
			throw new IllegalStateException("IOException while reading", e);
		}
	}
	
	public int readInt() {
		return Integer.parseInt(readNumber());
	}
	
	public double readDouble() {
		return Double.parseDouble(readNumber() + "." + readNumber());
	}
	
	public String readNumber() {
		char first = readChar();
		if(!"-0123456789".contains(first + ""))
			return "";
		return first + readUntil(c -> !"0123456789".contains(c + ""));
	}
	
	public long readAddr() {
		String s = readUntil("(nil|0x)");
		
		if(s.endsWith("nil"))
			return 0;
		
		return readHexNum().longValue();
	}
	
	public String readHex() {
		return readUntil(c -> !"0123456789abcdefABCDEF".contains(c + ""));
	}
	
	public BigInteger readHexNum() {
		return new BigInteger(readHex(), 16);
	}
	
	public String readUntil(Function<Character, Boolean> end) {
		String result = "";
		Character cur;
		while(!end.apply(cur = readChar()))
			result += cur;
		
		return result;
	}
	
	public String readUntilP(String text) {
		return readUntil(Pattern.quote(text));
	}
	
	public String readUntil(String regex) {
		Pattern pattern = Pattern.compile(regex);
		String read = "";
		
		while(!pattern.matcher(read).find()) {
			read += readChar();
		}
		
		return read;
	}
	
	public void send(byte[] bytes) {
		try {
			write(bytes);
			flush();
		} catch(IOException e) {
			outputDead = true;
			throw new IllegalStateException("IOException while sending bytes", e);
		}
	}
	
	public void send(ByteBuffer buffer) {
		send(buffer.array());
	}
	
	public void send(Object o) {
		send(o.toString());
	}
	
	public void sendln(Object o) {
		sendln(o.toString());
	}
	
	public void sendln(ByteBuffer buffer) {
		sendln(buffer.array());
	}
	
	public void send(String text) {
		send(text.getBytes(charset));
	}
	
	public void sendln(byte[] bytes) {
		try {
			write(bytes);
			write((byte)'\n');
			flush();
		} catch(IOException e) {
			outputDead = true;
			throw new IllegalStateException("IOException while sending bytes", e);
		}
	}
	
	public void sendln(String line) {
		send ((line + '\n').getBytes());
	}
	
	public void interactive() {
		Thread output = new Thread(
				() -> {
					while(!inputDead) {
						try {
							System.out.print(readChar());
						} catch(Exception e) {
							System.err.println("Input from interactive died");
							inputDead = true;
						}
					}
				}
		);
		output.setName("INTERACTIVE");
		output.start();
		
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		
		String line;
		
		try {
			while(!outputDead && (line = reader.readLine()) != null) {
				sendln(line);
			}
		} catch (Exception e) {
			System.err.println("Output to interactive died");
		}

		
	}
	
}
