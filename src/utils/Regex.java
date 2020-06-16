package utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Regex {

	public static String find(String regex, String input) {
		Matcher m = Pattern.compile(regex).matcher(input);
		m.find();
		return m.group();
	}
	
}
