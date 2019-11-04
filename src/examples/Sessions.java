package examples;

/*
 * imports
 */
import http.HttpSession;
import static http.Parameters.GET;
import static http.Requests.session;

public class Sessions {

	public static void bar() {
		/*
		 * create a Session
		 * Sessions will handle cookies for you 
		 * (but path and expiry date are ignored as well as httponly ... All cookies are sent always xD)
		 */
		HttpSession session = session();

		/*
		 * Sessions can do post and get requests just like the static methods of Requests
		 */
		session.get("https://google.com", GET("q","Hello Goolge"));
	}
	
}
