package utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import ghidra.program.model.listing.Program;

public class PayloadBuffer {

	public Program program;
	public byte[] data;
	public ByteBuffer buf;
	public int maxSize;
	public byte padding;
	
	public PayloadBuffer(Program program, int initialSize, int maxSize, byte padding) {
		if(initialSize > maxSize)
			throw new IllegalArgumentException(String.format("Initial size %d is bigger than maximum size %d", initialSize, maxSize));
		
		this.program = program;
		this.maxSize = maxSize;
		data = new byte[initialSize];
		buf = ByteBuffer.wrap(data);
		if(program.getLanguage().isBigEndian()) {
			buf.order(ByteOrder.BIG_ENDIAN);
		} else {
			buf.order(ByteOrder.LITTLE_ENDIAN);
		}
	}
	
	public PayloadBuffer(Program program, byte padding) {
		this(program, 0, Integer.MAX_VALUE, padding);
	}
	
	public PayloadBuffer(Program program) {
		this(program, 0, Integer.MAX_VALUE, (byte)0);
	}
	
	public void setPadding(byte padding) {
		this.padding = padding;
	}
	
	public void extend(int offset, int length) {
		int newSize;
		if(offset < 0) {
			newSize = Math.max(length + offset, this.data.length) - offset;
		} else {
			if(offset + length > this.data.length) {
				newSize = offset + length;
			} else {
				return;
			}
		}
		if(newSize > maxSize)
			throw new IllegalStateException("Buffer overflow!");
		byte[] tmp = new byte[newSize];
		if(padding != 0) {
			Arrays.fill(tmp, padding);
		}
		ByteBuffer tmp_buf = ByteBuffer.wrap(tmp);
		tmp_buf.order(buf.order());
		tmp_buf.put(this.data, offset < 0 ? -offset : 0, this.data.length);
		this.data = tmp;
		this.buf = tmp_buf;
	}
	
	public byte[] address(long address) {
		byte[] ret = new byte[program.getDefaultPointerSize()];
		
		ByteBuffer tmp = ByteBuffer.wrap(ret);
		tmp.order(buf.order());
		
		switch(ret.length) {
		case 1:
			tmp.put((byte)address);
			break;
		
		case 2:
			tmp.putShort((short)address);
			break;
			
		case 4:
			tmp.putInt((int)address);
			break;
			
		case 8:
			tmp.putLong(address);
			break;
		
			default:
				throw new IllegalStateException("Address size of " + ret.length + " bytes is not supported ...\nSorry :(");
		}
		return ret;
	}
	
	public PayloadBuffer put(int offset, long address) {
		byte[] addr = address(address);
		return put(offset, addr);
	}
	
	public PayloadBuffer put(int offset, byte[] data) {
		extend(offset, data.length);
		if(offset > 0) {
			buf.position(offset);
		}
		buf.put(data);
		return this;
	}
}
