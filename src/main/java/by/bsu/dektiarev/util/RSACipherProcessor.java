package by.bsu.dektiarev.util;

import by.bsu.dektiarev.client.ClientConfig;
import by.bsu.dektiarev.exception.EncryptionException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.*;

/**
 * Created by USER on 05.10.2016.
 */
public final class RSACipherProcessor {

    private static final String ALGORITHM_NAME = "RSA";
    private static final BigInteger RSA_PUBLIC_EXPONENT = new BigInteger("10001", 16);
    private static final int RSA_KEY_STRENGTH = 1024;
    private static final int RSA_KEY_CERTAINTY = 80;

    public static KeyPair generateKeyPair() throws EncryptionException {
        try {
            RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
            KeyGenerationParameters keyGenerationParameters =
                    new RSAKeyGenerationParameters(RSA_PUBLIC_EXPONENT,
                            new SecureRandom(),
                            RSA_KEY_STRENGTH,
                            RSA_KEY_CERTAINTY);
            generator.init(keyGenerationParameters);

            AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
            RSAKeyParameters privateKeyParams = (RSAKeyParameters) keyPair.getPrivate();
            RSAKeyParameters publicKeyParams = (RSAKeyParameters) keyPair.getPublic();

            KeySpec spec = new RSAPrivateKeySpec(privateKeyParams.getModulus(), privateKeyParams.getExponent());
            PrivateKey privateKey = KeyFactory.getInstance(ALGORITHM_NAME).generatePrivate(spec);

            spec = new RSAPublicKeySpec(publicKeyParams.getModulus(), publicKeyParams.getExponent());
            PublicKey publicKey = KeyFactory.getInstance(ALGORITHM_NAME).generatePublic(spec);

            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new EncryptionException(ex);
        }
    }

    public static KeyPair getKeyPairsFromFiles() throws EncryptionException {
        Path publicKeyFilePath = Paths.get(ClientConfig.RSA_PUBLIC_KEY_FILENAME);
        Path privateKeyFilePath = Paths.get(ClientConfig.RSA_PRIVATE_KEY_FILENAME);
        try {
            byte[] publicBytes = Files.readAllBytes(publicKeyFilePath);
            byte[] privateBytes = Files.readAllBytes(privateKeyFilePath);

            PublicKey publicKey =
                    KeyFactory.getInstance(ALGORITHM_NAME).generatePublic(new X509EncodedKeySpec(publicBytes));
            PrivateKey privateKey =
                    KeyFactory.getInstance(ALGORITHM_NAME).generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
            return new KeyPair(publicKey, privateKey);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new EncryptionException(ex);
        }
    }

    public static PublicKey getPublicKeyFromBytes(byte[] encodedBytes) throws EncryptionException {
        try {
            return KeyFactory.getInstance(ALGORITHM_NAME).generatePublic(new X509EncodedKeySpec(encodedBytes));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new EncryptionException(ex);
        }
    }

    public static void writeKeyPairsToFiles(KeyPair rsaKeyPair) throws EncryptionException {
        Path publicKeyFilePath = Paths.get(ClientConfig.RSA_PUBLIC_KEY_FILENAME);
        Path privateKeyFilePath = Paths.get(ClientConfig.RSA_PRIVATE_KEY_FILENAME);

        try {
            Files.write(privateKeyFilePath, rsaKeyPair.getPrivate().getEncoded(),
                    StandardOpenOption.CREATE);
            Files.write(publicKeyFilePath, rsaKeyPair.getPublic().getEncoded(),
                    StandardOpenOption.CREATE);
        } catch (IOException ex) {
            throw new EncryptionException(ex);
        }
    }

    public static byte[] encrypt(byte[] input, PublicKey key) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | BadPaddingException | IllegalBlockSizeException | InvalidKeyException ex) {
            throw new EncryptionException(ex);
        }
    }

    public static byte[] decrypt(byte[] input, PrivateKey key) throws EncryptionException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_NAME);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | BadPaddingException | IllegalBlockSizeException | InvalidKeyException ex) {
            throw new EncryptionException(ex);
        }
    }

    private RSACipherProcessor() {
    }
}
