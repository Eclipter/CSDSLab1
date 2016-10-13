package by.bsu.dektiarev.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Created by USER on 04.10.2016.
 */
public class ServerAction {

    private static final Logger logger = LogManager.getLogger();

    private static final String EXIT_COMMAND = "exit";
    private static final AtomicBoolean EXIT = new AtomicBoolean();

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        try (ServerSocket serverSocket = new ServerSocket(ServerConfig.PORT_NUMBER)) {

            new Thread(() -> {
                Scanner in = new Scanner(System.in);
                while(in.hasNextLine() && !EXIT.get()) {
                    String command = in.nextLine();
                    if(EXIT_COMMAND.equals(command)) {
                        EXIT.compareAndSet(false, true);
                        try {
                            ServerService.getInstance().getSessionKeyMap().keySet().forEach(socket -> {
                                try {
                                    socket.close();
                                } catch (IOException ex) {
                                    ex.printStackTrace();
                                }
                            });
                            serverSocket.close();
                            System.exit(0);
                        } catch (IOException ex) {
                            logger.info("Sockets closed");
                        }
                    }
                }
            }).start();

            while(!EXIT.get()) {
                logger.info("Waiting for connection");
                Socket clientSocket = serverSocket.accept();
                logger.info("New client connected: " + clientSocket.getInetAddress().getHostName());

                new ServerThread(clientSocket).start();
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}
