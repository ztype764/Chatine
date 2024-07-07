package org.example;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.logging.Logger;

public class CryptoUtils {
    private static final Logger logger = Logger.getLogger(CryptoUtils.class.getName());
    private static final String HMAC_ALGO = "HmacSHA256";
    private static final String AES_ALGO = "AES";
    private static final String KEYSTORE_TYPE = "JCEKS";
    private static final String KEYSTORE_FILE = "mykeystore.jks";
    private static final String KEYSTORE_PASSWORD = "faster";
    private static final String KEY_ALIAS = "mykey";
    private static final String ENTRY_PASSWORD = "faster";

    private static SecretKey loadKeyFromKeystore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(KEYSTORE_FILE)) {
            keystore.load(fis, KEYSTORE_PASSWORD.toCharArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        Key key = keystore.getKey(KEY_ALIAS, ENTRY_PASSWORD.toCharArray());
        if (key instanceof SecretKey) {
            return (SecretKey) key;
        } else {
            throw new IllegalArgumentException("Not a secret key");
        }
    }

    public static SecretKey deriveKey(long timestamp) throws Exception {
        SecretKey originalKey = loadKeyFromKeystore();
        Mac mac = Mac.getInstance(HMAC_ALGO);
        mac.init(originalKey);
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
        LocalDateTime now = LocalDateTime.now(ZoneId.of("UTC")); // Use UTC timezone
        now = now.withSecond(0).withNano(0); // Set seconds and nanoseconds to zero
        return now.atZone(ZoneId.of("UTC")).toEpochSecond(); // Convert to epoch seconds
    }
}
