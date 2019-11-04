package examples;

import java.nio.charset.StandardCharsets;
import java.util.Collection;

import http.Parameters;
import http.Requests;
import http.Response;

public class Responses {

	public static void barbarfoo() {
		/*
		 * Send any request to get a response
		 */
		Response r = Requests.get("https://www.google.com");
		
		/*
		 * status code
		 */
		int status = r.statusCode;
		
		/*
		 * check if response has data
		 */
		if(r.hasData()) {
			
			/*
			 * data as byte[]
			 */
			byte[] responseBytes = r.data;
			
			/*
			 * data as String
			 */
			String responseText = r.text();
			
			/*
			 * ... with different charset
			 */
			String responseASCII = r.text(StandardCharsets.US_ASCII);
			
		}
		
		/*
		 * Response Set-cookie
		 */
		Parameters cookies = r.setCookie;
		
		/*
		 * Response headers
		 */
		Parameters headers = r.header;
		
		/*
		 * Directly grab specific cookie value
		 */
		String cookie = r.cookie("cookieA");
		
		/*
		 * Directly grab header field
		 * (if there are multiple fields with the same name, this will return any of them)
		 */
		String header = r.headerField("headerField");
		
		/*
		 * grab all header fields with specific name
		 */
		Collection<String> headerFields = r.header("headerFields");
	}
	
}
