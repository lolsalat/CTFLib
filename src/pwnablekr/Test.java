package pwnablekr;

import connection.Connection;
import http.Parameters;
import http.Requests;

public class Test {

	public static void main(String[] args) {
		var sess = Requests.session();
		var resp = sess.post("https://www.google.de", Parameters.POST("what","ever"), Parameters.GET("deine","Mudda","ist","toll"));
		System.out.println(resp.text());
		
		var proc = Connection.remote("towel.blinkenlights.nl", 23);
		proc.interactive();
	}
	
}
