package by.bsu.dektiarev.server;

import java.net.Socket;
import java.security.Key;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by USER on 05.10.2016.
 */
public class ServerService {

    private static final ServerService INSTANCE = new ServerService();

    private Map<Socket, Key> sessionKeyMap = new ConcurrentHashMap<>();

    public static ServerService getInstance() {
        return INSTANCE;
    }

    public Map<Socket, Key> getSessionKeyMap() {
        return sessionKeyMap;
    }

    private ServerService() {
    }
}
