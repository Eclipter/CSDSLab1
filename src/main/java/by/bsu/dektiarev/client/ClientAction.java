package by.bsu.dektiarev.client;

import by.bsu.dektiarev.exception.EncryptionException;
import by.bsu.dektiarev.util.IDEACipherProcessor;
import by.bsu.dektiarev.util.RSACipherProcessor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.Security;
import java.util.Scanner;

/**
 * Created by USER on 04.10.2016.
 */
public class ClientAction {

    private static final Logger logger = LogManager.getLogger();

    private static final String FILE_REQUEST = "FILE";
    private static final String EXIT_REQUEST = "EXIT";
    private static final String OK_ANSWER = "OK";
    private static final String NO_FILE_ANSWER = "NO_FILE";
    private static final String CONFIRM_REQUEST = "1";

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        try (Socket socket = new Socket(ClientConfig.SERVER_ADDRESS, ClientConfig.PORT_NUMBER)) {

            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

            int length;
            byte[] message;

            Scanner fin = new Scanner(System.in);

            while (!socket.isClosed()) {
                System.out.println("Print 1 in order to request new file");
                String answer = fin.nextLine();
                if (!CONFIRM_REQUEST.equals(answer)) {
                    dataOutputStream.writeInt(EXIT_REQUEST.getBytes().length);
                    dataOutputStream.write(EXIT_REQUEST.getBytes());
                    break;
                } else {
                    dataOutputStream.writeInt(FILE_REQUEST.getBytes().length);
                    dataOutputStream.write(FILE_REQUEST.getBytes());
                }
                System.out.println("Generate RSA keys or use existent? (0 | 1)");
                answer = fin.nextLine();
                boolean useExistent = false;
                try {
                    useExistent = Boolean.parseBoolean(answer);
                } catch (NumberFormatException ex) {
                    ex.printStackTrace();
                }

                KeyPair rsaKeyPair;
                if (useExistent) {
                    try {
                        rsaKeyPair = RSACipherProcessor.getKeyPairsFromFiles();
                    } catch (EncryptionException ex) {
                        logger.warn("Failed to retrieve keys from files: " + ex.getMessage());
                        logger.warn("Trying to generate new keys");
                        rsaKeyPair = RSACipherProcessor.generateKeyPair();
                        RSACipherProcessor.writeKeyPairsToFiles(rsaKeyPair);
                    }
                } else {
                    rsaKeyPair = RSACipherProcessor.generateKeyPair();
                    RSACipherProcessor.writeKeyPairsToFiles(rsaKeyPair);
                }

                String fileName;
                System.out.println("Enter filename to receive from server: ");
                fileName = fin.nextLine();

                dataOutputStream.writeInt(rsaKeyPair.getPublic().getEncoded().length);
                dataOutputStream.write(rsaKeyPair.getPublic().getEncoded());

                dataOutputStream.writeInt(fileName.getBytes().length);
                dataOutputStream.write(fileName.getBytes());
                length = dataInputStream.readInt();
                message = new byte[length];
                dataInputStream.read(message, 0, length);
                answer = new String(message);

                if (NO_FILE_ANSWER.equals(answer)) {
                    logger.info("No such file " + fileName);
                    continue;
                } else if(!OK_ANSWER.equals(answer)) {
                    throw new EncryptionException("Wrong answer from server");
                }

                logger.info("File exists.");
                int keyLength = dataInputStream.readInt();
                byte[] encryptedIDEAKeyBytes = new byte[keyLength];
                dataInputStream.read(encryptedIDEAKeyBytes, 0, keyLength);
                logger.info("Received encrypted IDEA key");

                byte[] decryptedIDEAKeyBytes =
                        RSACipherProcessor.decrypt(encryptedIDEAKeyBytes, rsaKeyPair.getPrivate());
                logger.info("Decrypted IDEA key");

                length = dataInputStream.readInt();
                byte[] encryptedTextBytes = new byte[length];
                dataInputStream.read(encryptedTextBytes, 0, length);
                logger.info("Received encrypted text");

                Key ideaKey = IDEACipherProcessor.restoreKey(decryptedIDEAKeyBytes);
                byte[] decryptedText = IDEACipherProcessor.decrypt(encryptedTextBytes, ideaKey);
                System.out.println("File " + fileName + " content: ");
                System.out.println(new String(decryptedText));
            }

            if (!socket.isClosed()) {
                dataInputStream.close();
                dataOutputStream.close();
                socket.close();
            }
        } catch (EncryptionException | IOException e) {
            logger.error(e);
        }
    }
}
