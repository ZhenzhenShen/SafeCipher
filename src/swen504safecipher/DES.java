package swen504safecipher;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.util.Base64;

public class DES {

    private Key secretKey;

    public DES() throws NoSuchAlgorithmException {
        generateKey();
    }

    /**
     * Step 1. Generate a DES key using KeyGenerator
     */
    public void generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        this.setSecretKey(keyGen.generateKey());
    }

    public String encrypt(String strDataToEncrypt) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher desCipher = Cipher.getInstance("DES");
        desCipher.init(Cipher.ENCRYPT_MODE, this.getSecretKey());
        byte[] byteDataToEncrypt = strDataToEncrypt.getBytes();
        byte[] byteCipherText = desCipher.doFinal(byteDataToEncrypt);
        return Base64.getEncoder().encodeToString(byteCipherText);
    }
    
    public String encrypt(String strDataToEncrypt, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher desCipher = Cipher.getInstance("DES");
        desCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] byteDataToEncrypt = strDataToEncrypt.getBytes();
        byte[] byteCipherText = desCipher.doFinal(byteDataToEncrypt);
        return Base64.getEncoder().encodeToString(byteCipherText);
}

    public String decrypt(String strCipherText) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher desCipher = Cipher.getInstance("DES");
        desCipher.init(Cipher.DECRYPT_MODE, this.getSecretKey());
        byte[] byteCipherText = Base64.getDecoder().decode(strCipherText);
        byte[] byteDecryptedText = desCipher.doFinal(byteCipherText);
        return new String(byteDecryptedText);
    }
    
    public String decrypt(String strCipherText, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException,
             InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher desCipher = Cipher.getInstance("DES");
        desCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] byteCipherText = Base64.getDecoder().decode(strCipherText);
        byte[] byteDecryptedText = desCipher.doFinal(byteCipherText);
        return new String(byteDecryptedText);
}

    /**
     * @return the secretKey
     */
    public Key getSecretKey() {
        return secretKey;
    }

    /**
     * @param secretKey the secretKey to set
     */
    public void setSecretKey(Key secretKey) {
        this.secretKey = secretKey;
    }
}


