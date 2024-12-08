import java.io.*;
import java.net.Socket;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Collectors;

public class SHPClient {
    private String serverAddress;
    private int port;
    private String clientKeyPairFile;
    private String userId;

    public SHPClient(String serverAddress, int port, String clientKeyPairFile, String userId) {
        this.serverAddress = serverAddress;
        this.port = port;
        this.clientKeyPairFile = clientKeyPairFile;
        this.userId = userId;
    }

    public void connect() throws Exception {
        try (Socket socket = new Socket(serverAddress, port)) {
            System.out.println("Connected to server.");

            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(output);
            // Phase 1 Message 1: Send userID
            Message1 message = new Message1((byte) 1, (byte) 1); // Example: Protocol version 1, release 0
            message.setUserId(userId);

            objectOutputStream.writeObject(message);
            objectOutputStream.flush();
            System.out.println("Sent userID: " + userId);

            ObjectInputStream objectInputStream = new ObjectInputStream(input);

            // Read the object (Message2) sent via ObjectOutputStream
            Message2 receivedMessage = (Message2) objectInputStream.readObject();

            byte[] nonce1 = receivedMessage.getNonce1();
            byte[] nonce2 = receivedMessage.getNonce2();
            byte[] nonce3 = receivedMessage.getNonce3();
            System.out.println("Received Nonces: " + Arrays.asList(nonce1, nonce2, nonce3).stream().map(Base64.getEncoder()::encodeToString).collect(Collectors.joining(", ")));

            // Further message exchanges would go here (Messages 3, 4, 5)
        }
    }
}
