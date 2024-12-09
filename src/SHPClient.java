import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Collectors;

public class SHPClient {
    private String serverAddress;
    private int port;
    private String clientKeyPairFile;
    private String userId;

    // Client's known protocol version and release
    private final byte knownProtocolVersion = 0x1;
    private final byte knownRelease = 0x1;

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

            // Send MessageType1 (UserID)
            SHPMessageType1 msg1 = new SHPMessageType1(userId);
            byte[] m1Data = msg1.toBytes(knownProtocolVersion, knownRelease);
            sendMessage(output, m1Data);
            System.out.println("Sent userID: " + userId);

            // Receive MessageType2 (nonces)
            byte[] m2Data = receiveMessage(input);
            SHPMessageType2 msg2 = new SHPMessageType2();
            msg2.fromBytes(m2Data);

            // Verify protocolVersion and release
            if (msg2.getProtocolVersion() != knownProtocolVersion || msg2.getRelease() != knownRelease) {
                System.out.println("Protocol version or release mismatch on received message 2!");
                return;
            }

            byte[] nonce1 = msg2.getNonce1();
            byte[] nonce2 = msg2.getNonce2();
            byte[] nonce3 = msg2.getNonce3();

            System.out.println("Received Nonces: " + Arrays.asList(nonce1, nonce2, nonce3).stream()
                    .map(Base64.getEncoder()::encodeToString)
                    .collect(Collectors.joining(", ")));


            byte[] nonce4 = generateNonce();
            int counter=2048;
            ECCKeyInfo eccKeyInfo= ECCKeyInfo.readKeyFromFile(clientKeyPairFile);

            //data to send (later probably from program args)
            String hashedPassword="XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=";
            byte[] salt=Base64.getDecoder().decode("KgplqWYHvK/7ebSKnG2FWg==");
            String request = "movie";
            int udpPort=1234;

            SHPMessageType3 msg3 = new SHPMessageType3(userId, request, nonce3, nonce4, udpPort, salt, counter, hashedPassword, eccKeyInfo);
            byte[] m3Data = msg3.toBytes(knownProtocolVersion, knownRelease);
            sendMessage(output, m3Data);
            System.out.println("Sent msg3:" + msg3);

            Thread.sleep(4000); //placeholder before implementing msg4 (wait 4s until server finish execution for msg3)

            // Additional message exchanges...
        }
    }

    public static void sendMessage(OutputStream out, byte[] data) throws IOException {
        out.write((data.length >>> 24) & 0xFF);
        out.write((data.length >>> 16) & 0xFF);
        out.write((data.length >>> 8) & 0xFF);
        out.write(data.length & 0xFF);
        out.write(data);
        out.flush();
    }

    public static byte[] receiveMessage(InputStream in) throws Exception {
        byte[] lengthBytes = new byte[4];
        if (in.read(lengthBytes) < 4) {
            throw new Exception("Failed to read message length");
        }
        int length = ((lengthBytes[0] & 0xFF) << 24) |
                ((lengthBytes[1] & 0xFF) << 16) |
                ((lengthBytes[2] & 0xFF) << 8) |
                (lengthBytes[3] & 0xFF);

        byte[] data = new byte[length];
        int offset = 0;
        while (offset < length) {
            int r = in.read(data, offset, length - offset);
            if (r < 0) throw new Exception("EOF while reading message");
            offset += r;
        }
        return data;
    }

    private byte[] generateNonce() {
        byte[] nonce = new byte[16]; // 128-bit nonce
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }
}
