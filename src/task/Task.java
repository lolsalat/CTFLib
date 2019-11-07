package task;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface Task {

	public String name() default "Unknown Task";
	
	public String flagPattern() default "{..*}";
	
	public String encoding() default "UTF-8";
	
}
