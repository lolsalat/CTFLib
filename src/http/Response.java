package http;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collection;

public class Response {

	public static Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
	
	public final Parameters header;
	public final int statusCode;
	public final byte[] data;
	public final Parameters setCookie;
	
	public Response(Parameters header, Parameters setCookie, int statusCode, byte[] data) {
		this.header = header;
		this.statusCode = statusCode;
		this.data = data;
		this.setCookie = setCookie;
	}
	
	public boolean hasData() {
		return data != null;
	}
	
	public String headerField(String key) {
		return header.getAny(key);
	}
	
	public Collection<String> header(String key) {
		return header.get(key);
	}
	
	public String cookie(String name) {
		return setCookie.getAny(name);
	}
	
	public boolean success() {
		return statusCode == 200;
	}
	
	public String text(Charset charset) {
		return new String(data, charset);
	}
	
	public String text() {
		return text(DEFAULT_CHARSET);
	}
	
}
