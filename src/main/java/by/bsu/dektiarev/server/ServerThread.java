package by.bsu.dektiarev.server;

import by.bsu.dektiarev.exception.EncryptionException;
import by.bsu.dektiarev.util.IDEACipherProcessor;
import by.bsu.dektiarev.util.RSACipherProcessor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.security.Key;
import java.security.PublicKey;

/**
 * Created by USER on 05.10.2016.
 */
public class ServerThread extends Thread {

    private static final Logger logger = LogManager.getLogger();

    private static final String OK_ANSWER = "OK";
    private static final String FILE_REQUEST = "FILE";
    private static final String NO_FILE_ANSWER = "NO_FILE";

    private Socket clientSocket;

    public ServerThread(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        try {
            DataInputStream dataInputStream = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());

            int length;
            byte[] message;
            while (!clientSocket.isClosed()) {
                logger.info("Waiting for a new file request from " + clientSocket.getInetAddress().getHostName());

                length = dataInputStream.readInt();
                message = new byte[length];
                dataInputStream.read(message, 0, length);
                String command = new String(message);
                if (!command.equals(FILE_REQUEST)) {
                    logger.info("Exit request");
                    break;
                }

                PublicKey rsaPublicKey;
                logger.info("Waiting for public key");
                length = dataInputStream.readInt();
                byte[] keyBytes = new byte[length];
                dataInputStream.read(keyBytes, 0, length);
                rsaPublicKey = RSACipherProcessor.getPublicKeyFromBytes(keyBytes);

                logger.info("Public key accepted");
                logger.info("Waiting for filename");
                length = dataInputStream.readInt();
                message = new byte[length];
                dataInputStream.read(message, 0, length);
                String filename = new String(message);

                if (!Files.exists(Paths.get(ServerConfig.PATH_TO_FILES + filename), LinkOption.NOFOLLOW_LINKS)) {
                    logger.info("No such file: " + filename);
                    dataOutputStream.writeInt(NO_FILE_ANSWER.getBytes().length);
                    dataOutputStream.write(NO_FILE_ANSWER.getBytes());
                    continue;
                }
                dataOutputStream.writeInt(OK_ANSWER.getBytes().length);
                dataOutputStream.write(OK_ANSWER.getBytes());

                logger.info("Reading file...");
                byte[] fileBytes = Files.readAllBytes(Paths.get(ServerConfig.PATH_TO_FILES + filename));

                Key ideaKey;

                if (!ServerService.getInstance().getSessionKeyMap().containsKey(clientSocket)) {
                    logger.info("Generating IDEA key");
                    ideaKey = IDEACipherProcessor.generateKey();
                    ServerService.getInstance().getSessionKeyMap().put(clientSocket, ideaKey);
                    logger.info("IDEA key generated");
                } else {
                    logger.info("Retrieving session key from map");
                    ideaKey = ServerService.getInstance().getSessionKeyMap().get(clientSocket);
                }

                byte[] encryptedKey = RSACipherProcessor.encrypt(ideaKey.getEncoded(), rsaPublicKey);
                byte[] encryptedFile = IDEACipherProcessor.encrypt(fileBytes, ideaKey);

                dataOutputStream.writeInt(encryptedKey.length);
                dataOutputStream.write(encryptedKey);
                logger.info("Sent encrypted key");

                dataOutputStream.writeInt(encryptedFile.length);
                dataOutputStream.write(encryptedFile);
                logger.info("Sent encrypted text");
            }

            ServerService.getInstance().getSessionKeyMap().remove(clientSocket);
            if (!clientSocket.isClosed()) {
                dataInputStream.close();
                dataOutputStream.close();
                clientSocket.close();
            }

        } catch (IOException | EncryptionException ex) {
            logger.error(ex);
        }

    }
}
