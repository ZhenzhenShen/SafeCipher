package swen504safecipher;

public class CaesarCipher {
    
    private String alphabet;
    private int key;

    public CaesarCipher(int key) {
        this.alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        this.key = key;
    }

    public String encrypt(String text) {
        StringBuilder cipherText = new StringBuilder();
        text = text.toUpperCase();

        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            int idx = alphabet.indexOf(ch);

            if (idx != -1) { // Check if the character is in the alphabet
                int newPosition = (idx + key) % alphabet.length();
                char cipherChar = alphabet.charAt(newPosition);
                cipherText.append(cipherChar);
            } else {
                cipherText.append(ch); // Non-alphabetical characters are unchanged
            }
        }

        return cipherText.toString();
    }

    public String decrypt(String cipherText) {
        StringBuilder plainText = new StringBuilder();

        for (int i = 0; i < cipherText.length(); i++) {
            char ch = cipherText.charAt(i);
            int idx = alphabet.indexOf(ch);

            if (idx != -1) {
                int newPosition = (idx - key) % alphabet.length();
                if (newPosition < 0) {
                    newPosition += alphabet.length();
                }
                char plainChar = alphabet.charAt(newPosition);
                plainText.append(plainChar);
            } else {
                plainText.append(ch);
            }
        }

        return plainText.toString();
    }

    public static void main(String[] args) {
        CaesarCipher cipher = new CaesarCipher(3); // Example key is 3
        String originalText = "Hello World!";
        String encrypted = cipher.encrypt(originalText);
        String decrypted = cipher.decrypt(encrypted);

        System.out.println("Original Text: " + originalText);
        System.out.println("Encrypted Text: " + encrypted);
        System.out.println("Decrypted Text: " + decrypted);
    }
}

