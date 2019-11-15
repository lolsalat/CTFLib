# CTFLib
This requires ApacheHTTPClient library as well as the Google GSON library (cause Steam login gives me JSON responses)

Works with Java11 idk about lower versions (Should not require any major changes if you really need that though)

I will add JavaDoc and more examples at some point. (As well as more content)

### Code snippets

#### Http GET and POST requests
Sending GET and POST requests is easy (finally yey).

```java
/*
 * imports
 */
import http.Parameters;
import http.Requests;
import http.Response;

//...

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
 * (will be urlencoded into URL e.g. https://www.google.com?q=Hello&a=World)
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
```

#### Responses
Every successful request yields a response.
They can do quite some stuff

```java
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
```

#### Sessions
When you need to do multiple requests, a Session will handle cookies for you (kinda)

```java
/*
 * imports
 */
import http.HttpSession;
import static http.Parameters.GET;
import static http.Requests.session;

// ...

/*
 * create a Session
 * Sessions will handle cookies for you 
 * (but path and expiry date are ignored as well as httponly ... All cookies are sent always xD)
 */
HttpSession session = session();

/*
 * Sessions can do post and get requests just like the static methods of Requests
 */
 session.get("https://www.google.com", GET("q","Hello Goolge"));

```
