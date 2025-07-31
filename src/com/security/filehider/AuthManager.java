package com.security.filehider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64; // Used for potential future array comparisons, or just for clarity

public class AuthManager {

    private static final String HASH_ALGORITHM = "SHA-256"; // Algorithm for master password hashing
    private static final int SALT_LENGTH = 16; // 16 bytes = 128 bits for salt
    private static final int OTP_LENGTH = 6; // Desired length for the OTP (e.g., 6 digits)

    /**
     * Generates a cryptographically strong random salt for password hashing.
     * @return A byte array representing the salt.
     */
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt); // Fill the salt array with random bytes
        return salt;
    }

    /**
     * Hashes a password using SHA-256 with a given salt.
     * This method combines the salt and password before hashing to prevent rainbow table attacks.
     * @param password The user's master password (plain text).
     * @param salt The salt (byte array) generated for hashing.
     * @return The hashed password as a Base64 encoded string.
     * @throws NoSuchAlgorithmException if the specified hashing algorithm is not available.
     */
    public static String hashPassword(String password, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        digest.reset(); // Reset digest for new hashing operation
        digest.update(salt); // Add salt before hashing password
        byte[] hashedBytes = digest.digest(password.getBytes()); // Hash the password bytes
        return Base64.getEncoder().encodeToString(hashedBytes); // Encode hash to Base64 string
    }

    /**
     * Verifies an entered password against a stored hashed password and its corresponding salt.
     * @param enteredPassword The password entered by the user (plain text).
     * @param storedHashedPassword The stored hashed password (Base64 encoded string).
     * @param storedSalt The stored salt (byte array).
     * @return true if the entered password, when hashed with the stored salt, matches the stored hashed password; false otherwise.
     * @throws NoSuchAlgorithmException if the specified hashing algorithm is not available.
     */
    public static boolean verifyPassword(String enteredPassword, String storedHashedPassword, byte[] storedSalt) throws NoSuchAlgorithmException {
        String hashedEnteredPassword = hashPassword(enteredPassword, storedSalt); // Hash the entered password with the stored salt
        return hashedEnteredPassword.equals(storedHashedPassword); // Compare the resulting hash with the stored hash
    }

    /**
     * Generates a random 6-digit OTP.
     * Uses SecureRandom for cryptographically strong randomness.
     * @return The generated OTP as a String.
     */
    public static String generateOtp() {
        SecureRandom random = new SecureRandom();
        // Generates a random number between 100,000 (inclusive) and 999,999 (inclusive)
        int otp = 100000 + random.nextInt(900000); 
        return String.valueOf(otp);
    }

    // Utility methods for byte[] <-> Base64String conversion (also in CryptoUtils for self-contained use)
    /**
     * Converts a byte array to a Base64 encoded string.
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