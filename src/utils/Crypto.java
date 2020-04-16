package utils;

import java.math.BigInteger;
import java.util.ArrayList;

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

}
