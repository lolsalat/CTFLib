package examples;


import http.Parameters;
import http.Requests;
import http.Response;

public class HttpRequests {

	public static void foo() {
		
		/*
		 * Basic get request
		 */
		Response getResponse = Requests.get("https://www.google.com");
		
		/*
		 * Basic post request
		 */
		Response postResponse = Requests.post("https://www.google.com");
		
		/*
		 * for simplicity only example code for POST requests will be given from here on
		 * GET requests work exactly the same (well they can't do some stuff)
		 */
		
		/*
		 * Request with GET parameters
		 * (will be urlencoded into URL e.g. https://google.com?q=Hello&a=World)
		 */
		postResponse = Requests.post("https://www.google.com", Parameters.GET("q", "Hello", "a", "World"));
		
		/*
		 * Request with body (POST only)
		 */
		postResponse = Requests.post("https://www.google.com", new byte[] {1, 2, 3, 4});
		
		/*
		 * Request with custom headers:
		 *  User-Agent: Internet Explorer
		 *  Why: Not
		 */
		postResponse = Requests.post("https://www.google.com", Parameters.HEADER("User-Agent", "Internet Explorer", "Why", "Not"));
		
		/*
		 * Request with Form parameters (URLEncoded, POST only)
		 */
		postResponse = Requests.post("https://www.google.com", Parameters.POST("q", "Hello", "a", "World"));
		
		/*
		 * Request with Custom cookies
		 */
		postResponse = Requests.post("https://www.google.com", Parameters.COOKIE("cookieA", "valueA", "cookieB", "valueB"));
		
		/*
		 * of course, you can do multiple parameters at once:
		 */
		postResponse = Requests.post("https://www.google.com", new byte[] {1, 2, 3, 4}, Parameters.GET("q", "Hello", "a", "World"), Parameters.COOKIE("cookieA", "valueA", "cookieB", "valueB"), Parameters.HEADER("User-Agent", "Internet Explorer", "Why", "Not"));
	}
	
}
