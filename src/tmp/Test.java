package tmp;

import java.io.PrintStream;
import java.math.BigInteger;

import task.Name;
import task.Result;
import task.Task;
import task.TaskExecutor;
import util.Utils;

public class Test {

	public static void main(String[] args) {
		TaskExecutor exec = new TaskExecutor();
		
		exec.addReturnFunction(BigInteger.class, x -> Result.SUCCESS);
		
		exec.addVariable("encrypted", new BigInteger("9410050859967524542558366524072642723170135883653722943708972721157838964323549022451814786885420637567248064850924356489250353697507925072405571897285468927531295740367800688980104132812749540088700490654590765754908742364164645997129114401775680063828587650921732388950713014817427194272781929518317349629"));
		exec.addVariable("A", new BigInteger("23187236114044737980202301010377981957567834826097002259329732215832029164590548427993813872022269906985621659321099027486723905974929455935991355762087044060029595324765770506591481384894816231783432348105429644301363629158842814317415281139353649806479664213472400388579627465889915195938912323761394901854"));
		exec.addVariable("B", new BigInteger("430023359390034222082732011948356798311147247214997695270038813781532497547421283"));
		exec.addVariable("g", new BigInteger("3"));
		exec.addVariable("p", new BigInteger("90305169335730485950598415101217893402303737362315135278730261409445294704031509167637512660107955559185918986090983396652562770019199845552383394105389567680479440949527585226547133634308236806601707583400796205442270978108989952437585118186046289928998856968685505809825714658244999497754030142252225690743"));
		
		exec.setTimeout(2500);
		
		exec.wholeClass(Test.class).forEach(
			(x,y) -> y.flags.forEach(f -> System.out.printf("[%s]: %s", x, f))
		);
		
	}
	
	@Task(value="Bruteforce Diffie Hellman", flagPattern = "FLAG\\{..*\\}")
	public static void bruteforceDH(@Name("g") BigInteger g, @Name("p") BigInteger p, @Name("B") BigInteger B, @Name("A") BigInteger A, @Name("encrypted") BigInteger encrypted, @Name("flags") PrintStream flags) {
		BigInteger counter = BigInteger.ONE;
		BigInteger guess = g;
		
		while(!guess.equals(B) && !Thread.interrupted()) {
			guess = guess.multiply(g).mod(p);
			counter = counter.add(BigInteger.ONE);
		}
		
		BigInteger key = A.modPow(counter, p);
		
		String decrypted = new String(Utils.XOR(key, encrypted));

		flags.print(decrypted);
	}
	
}
