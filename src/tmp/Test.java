package tmp;

import java.io.PrintStream;
import java.util.Map.Entry;

import task.ExecutionResult;
import task.Task;
import task.TaskExecutor;

public class Test {

	public static void main(String[] args) {
		TaskExecutor exec = new TaskExecutor();
		
		for(Entry<String, ExecutionResult<?>> result : exec.wholeClass(Test.class).entrySet()) {
			System.out.println(String.format("%s: %s", result.getKey(), result.getValue().result));
			result.getValue().flags.forEach(System.out::println);
		}
		
	}
	
	@Task(name = "TestTask", flagPattern = "FLAG\\{..*\\}", params = {"flags", "out"})
	public static boolean testTask(PrintStream flags, PrintStream out) {
		
		flags.println("asdsafagagasgsFLAG{asdaAGHASga}Sdnasfha");
		
		flags.print("ASDasddasdFLAG{ASd");
		flags.print("asdsd}");
		
		out.print("I'm done :)");
		
		return true;
	}
	
}
