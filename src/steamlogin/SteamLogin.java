package steamlogin;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import http.HttpSession;
import http.Parameters;
import http.Requests;

public class SteamLogin {

	
	private final LoginHandler handler;
	private final List<LoginObserver> observer;
	
	public SteamLogin(LoginHandler handler) {
		this.handler = handler;
		observer = new ArrayList<>();
	}
	
	public void addObserver(LoginObserver observer) {
		this.observer.add(observer);
	}
	
	public HttpSession dologin(String targetUrl, String redirect) {
		
		HttpSession session = Requests.session();
		
		Parameters openidParams = Parameters.GET(
				"openid.ns", "http://specs.openid.net/auth/2.0",
				"openid.mode", "checkid_setup",
				"openid.return_to", redirect,
				"openid.realm", targetUrl,
				"openid.ns.sreg", "http://openid.net/extensions/sreg/1.1",
				"openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select",
				"openid.identity", "http://specs.openid.net/auth/2.0/identifier_select"
			);
		
		long time = System.currentTimeMillis();
		
		session.get("https://steamcommunity.com/openid/login/", openidParams);
		
		String rsa = session.post("https://steamcommunity.com/login/getrsakey/", 
				openidParams,
				Parameters.POST("donotcache", "" + time, "username", handler.getUsername())
		).text();
		
		JsonObject json = new JsonParser().parse(rsa).getAsJsonObject();
	
		BigInteger N = new BigInteger(json.get("publickey_mod").getAsString(), 16);
		BigInteger e = new BigInteger(json.get("publickey_exp").getAsString(), 16);
		String timestamp = json.get("timestamp").getAsString();
		
		
		Cipher cipher;
		String result;
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(N, e)));
			result = new String(Base64.getEncoder().encode(cipher.doFinal(handler.getPassword().getBytes())));
		} catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e1) {
			throw new IllegalStateException("Exception doing RSA stuff", e1);
		} 
		
		String login = session.post("https://steamcommunity.com/login/dologin/", 
				openidParams,
				Parameters.POST(
						"captcha_text", "",
						"captchagid", "-1",
						"emailauth", "",
						"emailsteamid", "",
						"loginfriendlyname", "",
						"password", result,
						"remember_login", "false",
						"rsatimestamp", timestamp + "",
						"twofactorcode", "",
						"username", handler.getUsername()
				)
		).text();
		
		JsonObject login_json = new JsonParser().parse(login).getAsJsonObject();
		
		if(login_json.has("requires_twofactor") && login_json.get("requires_twofactor").getAsBoolean()) {
			observer.forEach(x -> x.onSecondFactorRequired());
			
			login = session.post("https://steamcommunity.com/login/dologin/", 
					openidParams,
					Parameters.POST(
							"captcha_text", "",
							"captchagid", "-1",
							"emailauth", "",
							"emailsteamid", "",
							"loginfriendlyname", "",
							"password", result,
							"remember_login", "false",
							"rsatimestamp", timestamp + "",
							"twofactorcode", handler.getSecondFactor(),
							"username", handler.getUsername()
					)
			).text();
			
			login_json = new JsonParser().parse(login).getAsJsonObject();
		}
		
		if(login_json.get("success").getAsBoolean()) {
			observer.forEach(x -> x.onLoginDone());
		} else {
			String message = login_json.get("message").getAsString();
			observer.forEach(x -> x.onError(message));
		}
		
		return session;
	}
	
}
