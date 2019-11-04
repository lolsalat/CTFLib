package http;

import java.util.Collection;

import org.apache.http.NameValuePair;

public class HttpSession {

	public Parameters cookies;
	
	public HttpSession() {
		cookies = new Parameters(ParameterType.COOKIE);
	}
	
	private Parameters[] buildParams(Parameters[] parameters) {
		Parameters[] newParams = new Parameters[parameters.length + 1];
		
		newParams[0] = cookies;
		
		System.arraycopy(parameters, 0, newParams, 1, parameters.length);
		
		return newParams;
	}
	
	public Response get(String url, Parameters... parameters) {
		Response response = Requests.get(url, buildParams(parameters));
		
		addCookies(response.setCookie.params);
		
		return response;
	}
	
	public Response post(String url, Parameters... parameters) {
		Response response = Requests.post(url, buildParams(parameters));
		
		addCookies(response.setCookie.params);
		
		return response;
	}
	
	public Response post(String url, byte[] data, Parameters... parameters) {
		Response response = Requests.post(url, data, buildParams(parameters));
		
		addCookies(response.setCookie.params);
		
		return response;
	}
	
	public void addCookies(Collection<NameValuePair> cookies) {
		cookies.forEach(x -> this.cookies.addOrUpdate(x));
	}
	
}
