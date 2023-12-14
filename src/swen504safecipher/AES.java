package swen504safecipher;

	import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
	import java.util.Base64;

	public class AES {

	    private SecretKey secretKey;

	    public AES() throws NoSuchAlgorithmException {
	        generateKey();
	    }

	    // 生成一个AES密钥
	    public void generateKey() throws NoSuchAlgorithmException {
	        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
	        keyGen.init(256); // 可以是128, 192或256位
	        this.secretKey = keyGen.generateKey();
	    }

	    // 使用AES密钥加密文本
	    public String encrypt(String strDataToEncrypt) throws Exception {
	        Cipher cipher = Cipher.getInstance("AES");
	        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	        byte[] byteDataToEncrypt = strDataToEncrypt.getBytes();
	        byte[] byteCipherText = cipher.doFinal(byteDataToEncrypt);
	        return Base64.getEncoder().encodeToString(byteCipherText);
	    }

	    // 使用AES密钥解密文本
	    public String decrypt(String strCipherText) throws Exception {
	        Cipher cipher = Cipher.getInstance("AES");
	        cipher.init(Cipher.DECRYPT_MODE, secretKey);
	        byte[] byteCipherText = Base64.getDecoder().decode(strCipherText);
	        byte[] byteDecryptedText = cipher.doFinal(byteCipherText);
	        return new String(byteDecryptedText);
	    }
	    
	    public String decrypt(String strCipherText, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
            Cipher desCipher = Cipher.getInstance("AES");
            desCipher.init(Cipher.DECRYPT_MODE, key);
            byte[] byteCipherText = Base64.getDecoder().decode(strCipherText);
            byte[] byteDecryptedText = desCipher.doFinal(byteCipherText);
            return new String(byteDecryptedText);
       }

	    // 获取当前的密钥
	    public SecretKey getSecretKey() {
	        return secretKey;
	    }

	    // 设置一个新的密钥
	    public void setSecretKey(SecretKey secretKey) {
	        this.secretKey = secretKey;
	    }
	}

