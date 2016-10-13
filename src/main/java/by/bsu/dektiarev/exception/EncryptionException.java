package by.bsu.dektiarev.exception;

/**
 * Created by USER on 05.10.2016.
 */
public class EncryptionException extends Exception {

    private static final long serialVersionUID = 8222761199329819073L;

    public EncryptionException() {
    }

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    public EncryptionException(Throwable cause) {
        super(cause);
    }
}
