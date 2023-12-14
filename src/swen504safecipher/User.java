package swen504safecipher;

import java.security.MessageDigest;

public class User {
	
	private String username;
	private String password;
	
	
	public User(String username, String password) {
		this.username = username;
		this.password = hashPassword(password);
	}

	public static String hashPassword(String password) {
		try {
			MessageDigest mdDigest = MessageDigest.getInstance("SHA-256");
			byte[] hashedPassword = mdDigest.digest(password.getBytes());
			StringBuilder hexPassword = new StringBuilder();
			for(byte b : hashedPassword) {
				hexPassword.append(String.format("%02x", b));
			}
		    return hexPassword.toString();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public String getUsername() {
		return username;
	}


	public String getPassword() {
		return password;
	}
	

	

}
