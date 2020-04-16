package utils;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;

import org.bouncycastle.jcajce.util.AlgorithmParametersUtils;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import com.google.gson.JsonArray;

import http.Parameters;
import http.Requests;

public class Crypto {

	public static ArrayList<BigInteger> factors(BigInteger number){
		JsonArray resp = Requests.get("http://www.factordb.com/api", Parameters.GET("query", number.toString())).jsonObject().get("factors").getAsJsonArray();
		ArrayList<BigInteger> factors = new ArrayList<BigInteger>();
		resp.forEach(x -> {
			for(int i = 0; i < x.getAsJsonArray().get(1).getAsLong(); i++) {
				factors.add(x.getAsJsonArray().get(0).getAsBigInteger());
			}
		});
		factors.sort((a,b) -> b.compareTo(a));
		return factors;
	}
	
	public static boolean coPrime(BigInteger a, BigInteger b) {
		return a.gcd(b).equals(BigInteger.ONE);
	}
	
	public static String createPrivPem(BigInteger p, BigInteger q, BigInteger d, BigInteger e, BigInteger N) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			PemWriter w = new PemWriter(new OutputStreamWriter(out));
			RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(N, e, d, p, q, d.mod(p.subtract(BigInteger.ONE)), d.mod(q.subtract(BigInteger.ONE)), q.subtract(BigInteger.ONE).mod(p));
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey generatedPublic = kf.generatePrivate(spec);
			w.writeObject(new JcaMiscPEMGenerator( generatedPublic));
			w.flush();
			return out.toString();
			} catch(Exception ex) {
				ex.printStackTrace();
				return "ERROR";
			}
	}
	
	public static String createPubPem(BigInteger e, BigInteger N) {
		try {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		PemWriter w = new PemWriter(new OutputStreamWriter(out));
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(N, e);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey generatedPublic = kf.generatePublic(keySpec);
		w.writeObject(new JcaMiscPEMGenerator( generatedPublic));
		w.flush();
		return out.toString();
		} catch(Exception ex) {
			ex.printStackTrace();
			return "ERROR";
		}
	}
}
