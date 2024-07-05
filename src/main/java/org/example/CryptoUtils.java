package org.example;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.logging.Logger;

public class CryptoUtils {
    private static final Logger logger = Logger.getLogger(CryptoUtils.class.getName());
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final String AES_ALGO = "AES";

    public static SecretKey deriveKey(String baseKey, long timestamp) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(HMAC_ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(baseKey.getBytes(StandardCharsets.UTF_8), HMAC_ALGO);
        mac.init(keySpec);
        byte[] rawHmac = mac.doFinal(String.valueOf(timestamp).getBytes(StandardCharsets.UTF_8));

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        rawHmac = sha.digest(rawHmac);
        byte[] keyBytes = new byte[16];
        System.arraycopy(rawHmac, 0, keyBytes, 0, keyBytes.length);
        return new SecretKeySpec(keyBytes, AES_ALGO);
    }

    public static String encrypt(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public static long getNTPTime() {
        return System.currentTimeMillis();
    }
}
