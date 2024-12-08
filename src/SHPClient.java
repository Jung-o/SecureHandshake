import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
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

            // Phase 1 Message 1: Send userID
            output.write((userId + "\n").getBytes());
            output.flush();
            System.out.println("Sent userID: " + userId);

            // Receive Nonces (Message 2)
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));
            byte[] nonce1 = Base64.getDecoder().decode(reader.readLine());
            byte[] nonce2 = Base64.getDecoder().decode(reader.readLine());
            byte[] nonce3 = Base64.getDecoder().decode(reader.readLine());
            //System.out.println("Received Nonces.");
            System.out.println("Received Nonces: " + Arrays.asList(nonce1, nonce2, nonce3).stream().map(Base64.getEncoder()::encodeToString).collect(Collectors.joining(", ")));

            // Further message exchanges would go here (Messages 3, 4, 5)
        }
    }
}
