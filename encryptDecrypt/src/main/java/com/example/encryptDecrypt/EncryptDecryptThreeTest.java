package com.example.encryptDecrypt;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class EncryptDecryptThreeTest {//https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;

    public static String encrypt(String strToEncrypt, String secretKey, String salt) {
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
            SecretKey secret = secretKeyFactory.generateSecret(keySpec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC//PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] cipherText = cipher.doFinal(strToEncrypt.getBytes("UTF-8"));
            byte[] encryptedData = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(cipherText, 0, encryptedData, iv.length, cipherText.length);
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {// handle exception
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt(String strToDecrypt, String secretKey, String salt) {

        try {

            byte[] encryptedData = Base64.getDecoder().decode(strToDecrypt);
            byte[] iv = new byte[16];
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC//PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);

            byte[] cipherText = new byte[encryptedData.length - 16];
            System.arraycopy(encryptedData, 16, cipherText, 0, cipherText.length);

            byte[] decryptedText = cipher.doFinal(cipherText);
            return new String(decryptedText, "UTF-8");
        } catch (Exception e) {
            // Handle the exception properly
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {

        // Define your secret key and salt (keep these secure and don't hardcode in production)
        String secretKey = "dpBank.Cam";
        String salt = "dpBank.Cam";

        // String to be encrypted
        String originalString = "FATCA en/de report test";

        // Encrypt the string
        String encryptedString = encrypt(originalString, secretKey, salt);
        if (encryptedString != null) {
            System.out.println("Encrypted: " + encryptedString);
        } else {
            System.err.println("Encryption failed.");
            return;
        }

        // Decrypt the string
        String decryptedString = decrypt(encryptedString, secretKey, salt);
        if (decryptedString != null) {
            System.out.println("Decrypted: " + decryptedString);
        } else {
            System.err.println("Decryption failed.");
        }
    }
}
