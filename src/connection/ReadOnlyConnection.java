package connection;

import java.io.IOException;
import java.io.InputStream;

public class ReadOnlyConnection extends Connection{

	private InputStream in;
	
	public ReadOnlyConnection(InputStream in) {
		this.in = in;
	}
	
	@Override
	public void write(byte b) throws IOException {
		
	}

	@Override
	public void flush() throws IOException {
		
	}

	@Override
	public int read() throws IOException {
		return in.read();
	}

	@Override
	public int available() throws IOException {
		return in.available();
	}

}
