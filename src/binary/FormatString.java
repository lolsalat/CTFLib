package binary;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;

public class FormatString {

	public StackFrame stackFrame;
	public int frameSize;
	public Function function;
	public Program program;
	
	public FormatString(Program p, String function) {
		this.function = Ghidra.function(p, function);
		this.stackFrame = this.function.getStackFrame();
		this.frameSize = stackFrame.getFrameSize();
		this.program = p;
	}
	
	public String address(String name) {
		int offset = frameSize + Ghidra.stackOffset(stackFrame, name);
		int stackO = program.getDefaultPointerSize() == 8 ? 5 : 0;
		return "%" + (offset / program.getDefaultPointerSize() + stackO) + "$p"; 
	}
	
	public String addressS(String name) {
		return address(name) + " ";
	}
}
