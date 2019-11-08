package tmp;

import java.io.PrintStream;
import java.math.BigInteger;
import task.ExecutionResult;
import task.Name;
import task.Result;
import task.Task;
import task.TaskExecutor;
import util.Utils;

public class Test {

	public static void main(String[] args) {
		TaskExecutor exec = new TaskExecutor();
		
		exec.addReturnFunction(BigInteger.class, x -> Result.SUCCESS);
		
		exec.addVariable("encrypted", new BigInteger("53476643231071734807158736665463603110827647847089693357167693375268948774718459249615352604115615837790749555521469634492613601981886345547793309426251548519172160717480784679750109328962595978245114914998362562232523624981641941143476211828179736533597527896624568401371575936393130259220286931741596498941"));
		exec.addVariable("A", new BigInteger("23187236114044737980202301010377981957567834826097002259329732215832029164590548427993813872022269906985621659321099027486723905974929455935991355762087044060029595324765770506591481384894816231783432348105429644301363629158842814317415281139353649806479664213472400388579627465889915195938912323761394901854"));
		exec.addVariable("B", new BigInteger("430023359390034222082732011948356798311147247214997695270038813781532497547421283"));
		exec.addVariable("g", new BigInteger("3"));
		exec.addVariable("p", new BigInteger("90305169335730485950598415101217893402303737362315135278730261409445294704031509167637512660107955559185918986090983396652562770019199845552383394105389567680479440949527585226547133634308236806601707583400796205442270978108989952437585118186046289928998856968685505809825714658244999497754030142252225690743"));
		
		exec.setTimeout(2500);
		
		ExecutionResult<?> bruteForceResult = exec.execute(Test.class, "Bruteforce Diffie Hellman");
		
		if(bruteForceResult.hasFlag()) {
			System.out.printf("Flag: %s\n", bruteForceResult.getFlag());
		} else {
			System.out.printf("No flag found, result: %s\n", bruteForceResult.result);
			if(bruteForceResult.wasException()) {
				bruteForceResult.exception.printStackTrace();
			}
		}
	}
	
	@Task("Bruteforce Diffie Hellman")
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
