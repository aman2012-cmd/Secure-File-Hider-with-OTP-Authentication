package com.security.filehider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {

    // --- Public Constants for external access ---
    public static final String ALGORITHM = "AES";
    public static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    public static final String SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int ITERATION_COUNT = 65536; // Number of iterations for PBKDF2
    public static final int KEY_LENGTH = 256; // AES key length in bits (256 bits = 32 bytes)
    public static final int SALT_LENGTH = 16; // 16 bytes = 128 bits for salt
    public static final int IV_LENGTH = 16;   // 16 bytes = 128 bits for IV

    /**
     * Generates a cryptographically strong random salt.
     * @return A byte array representing the salt.
     */
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Generates a cryptographically strong random Initialization Vector (IV).
     * @return A byte array representing the IV.
     */
    public static byte[] generateIv() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Derives a secret key from a passphrase and salt using PBKDF2WithHmacSHA256.
     * @param passphrase The user's passphrase.
     * @param salt The salt generated for PBKDF2.
     * @return A SecretKey object.
     * @throws Exception if key derivation fails.
     */
    public static SecretKey deriveKey(String passphrase, byte[] salt) throws Exception {
        // Ensure salt is not null, as PBEKeySpec would throw NullPointerException
        if (salt == null) {
            throw new IllegalArgumentException("Salt parameter must be non-null for key derivation.");
        }
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_ALGORITHM);
        SecretKey secretKey = factory.generateSecret(spec);
        return new SecretKeySpec(secretKey.getEncoded(), ALGORITHM);
    }

    /**
     * Encrypts a file using AES/CBC/PKCS5Padding with a derived key and IV.
     * Writes the salt and IV as a header to the output file.
     * @param inputFile The path to the file to encrypt.
     * @param outputFile The path where the encrypted file will be saved.
     * @param secretKey The AES secret key.
     * @param salt The salt used for key derivation (to be written to header).
     * @param iv The Initialization Vector (to be written to header).
     * @throws Exception if encryption or file operations fail.
     */
    public static void encryptFile(String inputFile, String outputFile, SecretKey secretKey, byte[] salt, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            
            // Write salt and IV as a header to the output file
            fos.write(salt);
            fos.write(iv);

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    fos.write(output);
                }
            }
            byte[] output = cipher.doFinal(); // Handle remaining bytes
            if (output != null) {
                fos.write(output);
            }
        }
        System.out.println("File encrypted successfully: " + inputFile + " -> " + outputFile);
    }

    /**
     * Decrypts a file using AES/CBC/PKCS5Padding with a master passphrase.
     * Reads the file-specific salt and IV from the beginning of the input file
     * and derives the decryption key internally.
     * @param inputFile The path to the file to decrypt.
     * @param outputFile The path where the decrypted file will be saved.
     * @param masterPassphrase The master passphrase used for key derivation.
     * @throws Exception if decryption or file operations fail.
     */
    public static void decryptFile(String inputFile, String outputFile, String masterPassphrase) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            // Read salt and IV from the beginning of the encrypted file
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            if (fis.read(salt) != SALT_LENGTH || fis.read(iv) != IV_LENGTH) {
                throw new IOException("Could not read full salt or IV from encrypted file header. File may be corrupted or not properly encrypted.");
            }

            // Derive the decryption key using the master passphrase AND the file-specific salt
            SecretKey secretKey = deriveKey(masterPassphrase, salt);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    fos.write(output);
                }
            }
            byte[] output = cipher.doFinal(); // Handle remaining bytes
            if (output != null) {
                fos.write(output);
            }
        }
        System.out.println("File decrypted successfully: " + inputFile + " -> " + outputFile);
    }

    /**
     * Converts a byte array to a Base64 encoded string. Useful for storing/transmitting salts and IVs.
     * @param bytes The byte array to convert.
     * @return Base64 encoded string.
     */
    public static String bytesToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Converts a Base64 encoded string back to a byte array.
     * @param base64String The Base64 string.
     * @return The decoded byte array.
     */
    public static byte[] base64ToBytes(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }
}