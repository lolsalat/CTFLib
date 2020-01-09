package connection;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class InputStreamOutputStreamConnection extends Connection{

	public final InputStream in;
	public final OutputStream out;
	
	public InputStreamOutputStreamConnection(InputStream in, OutputStream out) {
		this.in = in;
		this.out = out;
	}
	
	@Override
	public void write(byte b) throws IOException {
		out.write(b);
	}
	
	@Override
	public void write(byte[] bytes) throws IOException{
		out.write(bytes);
	}

	@Override
	public void flush() throws IOException {
		out.flush();
	}

	@Override
	public int read() throws IOException {
		return in.read();
	}

	@Override
	public void read(byte[] to, int offset, int amount) throws IOException {
		in.read(to, offset, amount);
	}
	
	@Override
	public int available() throws IOException {
		return in.available();
	}

}
