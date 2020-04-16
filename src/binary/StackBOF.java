package binary;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import utils.PayloadBuffer;

public class StackBOF {

	public StackFrame stackFrame;
	public int startOffset;
	public PayloadBuffer payload;
	public Function function;
	public Charset charset = StandardCharsets.UTF_8;
	
	public StackBOF(Program program, String function, int offset, int max) {
		payload = new PayloadBuffer(program, 0, max, (byte)'A');
		this.function = Ghidra.function(program, function);
		startOffset = offset;
		this.stackFrame = this.function.getStackFrame();
	}
	

	public StackBOF(Program program, String function, int offset) {
		this(program, function, offset, Integer.MAX_VALUE);
	}
	
	public StackBOF(Program program, String function, String buffer, int max) {
		payload = new PayloadBuffer(program, 0, max, (byte)'A');
		this.function = Ghidra.function(program, function);
		this.stackFrame = this.function.getStackFrame();
		startOffset = Ghidra.stackOffset(stackFrame, buffer);
	}

	public StackBOF(Program program, String function, String buffer) {
		this(program, function, buffer, Integer.MAX_VALUE);
	}
	
	
	public StackBOF O(String name, long address) {
		int offset = Ghidra.stackOffset(stackFrame, name);
		if(offset < startOffset)
			throw new IllegalStateException("Cannot overwrite variable below buffer");
		payload.put(offset - startOffset, address);
		return this;
	}
	
	public StackBOF O(String name, byte[] data) {
		int offset = Ghidra.stackOffset(stackFrame, name);
		if(offset < startOffset)
			throw new IllegalStateException("Cannot overwrite variable below buffer");
		payload.put(offset - startOffset, data);
		return this;
	}

	public StackBOF O(String name, String data) {
		int offset = Ghidra.stackOffset(stackFrame, name);
		if(offset < startOffset)
			throw new IllegalStateException("Cannot overwrite variable below buffer");
		payload.put(offset - startOffset, data.getBytes(charset));
		return this;
	}
	
	public StackBOF OS(String name, String symbol, long base) {
		int offset = Ghidra.stackOffset(stackFrame, name);
		if(offset < startOffset)
			throw new IllegalStateException("Cannot overwrite variable below buffer");
		long addr = Ghidra.address(payload.program, symbol, base);
		payload.put(offset - startOffset, addr);
		return this;
	}
	
	public StackBOF O0(String name, String data) {
		return O(name, data + (char)0);
	}
	
	public StackBOF ROP(long ... addresses) {
		int offset = -startOffset;
		for(long l : addresses) {
			payload.put(offset, l);
			offset += payload.program.getDefaultPointerSize();
		}
		return this;
	}
	
	public byte[] payload() {
		return payload.data;
	}

}