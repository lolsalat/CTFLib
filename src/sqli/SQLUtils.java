package sqli;

import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

public class SQLUtils {

	public static Optional<String> SQLLeak(Function<String, Boolean> prepare, Function<String, Boolean> verify, Consumer<String> onCorrect, String charset) {
		String guess = "";
		outer:
		while(prepare.apply(guess)) {
			for(char c : charset.toCharArray()) {
				if(verify.apply(guess + c)) {
					guess += c;
					onCorrect.accept(guess);
					continue outer;
				}
			}
			return Optional.empty();
		}
		return Optional.of(guess);
	}
	
}
