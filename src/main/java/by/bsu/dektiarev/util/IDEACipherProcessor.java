package by.bsu.dektiarev.util;

import by.bsu.dektiarev.exception.EncryptionException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * Created by USER on 05.10.2016.
 */
public final class IDEACipherProcessor {

    private static final String ALGORITHM_NAME = "IDEA";
    private static final String ALGORITHM_REGIME_NAME = "IDEA/CFB/NoPadding";
    private static final String INIT_VECTOR = "InVector";

    public static byte[] encrypt(byte[] input, Key key) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_REGIME_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(INIT_VECTOR.getBytes()));
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException ex) {
            throw new EncryptionException(ex);
        }
    }

    public static byte[] decrypt(byte[] input, Key key) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_REGIME_NAME);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(INIT_VECTOR.getBytes()));
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException ex) {
            throw new EncryptionException(ex);
        }
    }

    public static Key generateKey() throws EncryptionException {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM_NAME);
            generator.init(new SecureRandom());
            return generator.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            throw new EncryptionException(ex);
        }
    }

    public static Key restoreKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, ALGORITHM_NAME);
    }

    private IDEACipherProcessor() {
    }
}
