package com.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.security.SecureRandom;

public class AesEncryptionExample {
    private static final String ALGORITHM = "AES";
    private static final String CIPHER_INSTANCE = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256); // Per AES-256
        SecretKey key = keyGen.generateKey();

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        String originalText = "Testo da cifrare";
        String encrypted = encrypt(originalText, key, ivSpec);
        String decrypted = decrypt(encrypted, key, ivSpec);

        System.out.println("Originale: " + originalText);
        System.out.println("Cifrato: " + encrypted);
        System.out.println("Decifrato: " + decrypted);
    }

    public static String encrypt(String input, SecretKey key, IvParameterSpec ivSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encrypted, SecretKey key, IvParameterSpec ivSpec) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        return new String(original);
    }
}
