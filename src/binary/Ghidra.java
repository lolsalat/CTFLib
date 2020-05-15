package binary;

import java.io.OutputStream;
import java.io.PrintStream;
import java.util.List;

import ghidra.GhidraJarApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

public class Ghidra {

	public static PrintStream dummyOut = new PrintStream(new OutputStream() {
	    @Override public void write(int b) {}
	});
	
	public static PrintStream out = System.out;
	public static PrintStream err = System.err;
	
	public static long address(Program program, String symbol) {
		return program.getSymbolTable().getSymbol(symbol).getAddress().getOffset();
	}
	
	public static long address(Program program, String symbol, long base) {
		return program.getSymbolTable().getSymbol(symbol).getAddress().getOffset() + base;
	}
	
	public static Function function(Program program, String name) {
		List<Symbol> symbols = program.getSymbolTable().getGlobalSymbols(name);
		
		for(Symbol s : symbols) {
			if(s.getSymbolType() == SymbolType.FUNCTION) {
				return program.getFunctionManager().getFunctionAt(s.getAddress());
			}
		}
		
		throw new IllegalArgumentException("No function named '" + name + "' found");
	}

	public static int stackOffset(StackFrame stackFrame, String variableName) {
		if(variableName.equals("RETURN"))
			return stackFrame.getReturnAddressOffset();
		for(Variable v : stackFrame.getStackVariables()) {
			if(v.getName().equals(variableName))
				return v.getStackOffset();
		}
		throw new IllegalArgumentException("No stack variable named '" + variableName + "' found");
	}
	
	
	public static Project openProject(String path, String name, boolean silent) {
		try {
			// Define Ghidra components
			GhidraProject ghidraProject;
			
			if(silent) {
				System.setOut(dummyOut);
				System.setErr(dummyOut);
			}
			
			// Initialize application
			if (!Application.isInitialized()) {
				ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
				configuration.setInitializeLogging(false);
				Application.initializeApplication(new GhidraJarApplicationLayout(), configuration);
			}

			ghidraProject = GhidraProject.openProject(path, name);

			if(silent) {
				System.setOut(out);
				System.setErr(err);
			}
			
			return new Project(ghidraProject);

		} catch (Exception e) {
			if(silent) {
				System.setOut(out);
				System.setErr(err);
			}
			throw new RuntimeException(e);
		}
	}
	
	public static Program[] openPrograms(String project, String name, boolean silent, String... programs) {
		try {
			// Define Ghidra components
			GhidraProject ghidraProject;
			
			if(silent) {
				System.setOut(dummyOut);
				System.setErr(dummyOut);
			}
			
			// Initialize application
			if (!Application.isInitialized()) {
				ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
				configuration.setInitializeLogging(false);
				Application.initializeApplication(new GhidraJarApplicationLayout(), configuration);
			}

			ghidraProject = GhidraProject.openProject(project, name);

			if(silent) {
				System.setOut(out);
				System.setErr(err);
			}
			
			Program[] progs = new Program[programs.length];
			
			for(int i = 0; i < programs.length; i++) {
				progs[i] = ghidraProject.openProgram("/", programs[i], false);
			}
			
			return progs;

		} catch (Exception e) {
			if(silent) {
				System.setOut(out);
				System.setErr(err);
			}
			throw new RuntimeException(e);
		}
	}
	
	public static Program openProgram(String project, String name, String program, boolean silent) {
		try {
			// Define Ghidra components
			GhidraProject ghidraProject;
			
			if(silent) {
				System.setOut(dummyOut);
				System.setErr(dummyOut);
			}
			
			// Initialize application
			if (!Application.isInitialized()) {
				ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
				configuration.setInitializeLogging(false);
				Application.initializeApplication(new GhidraJarApplicationLayout(), configuration);
			}

			ghidraProject = GhidraProject.openProject(project, name);

			if(silent) {
				System.setOut(out);
				System.setErr(err);
			}
			return ghidraProject.openProgram("/", program, false);

		} catch (Exception e) {
			if(silent) {
				System.setOut(out);
				System.setErr(err);
			}
			throw new RuntimeException(e);
		}
	}

	public static Program openProgram(String project, String name, String program) {
		return openProgram(project, name, program, true);
	}
	
}
