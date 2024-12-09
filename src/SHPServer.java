import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SHPServer {
    private int port;
    private String userDbFile;
    private String eccKeyPairFile;
    private Map<String, UserRecord> userDatabase;

    // Server's known (or chosen) protocol version and release
    private final byte knownProtocolVersion = 0x1;
    private final byte knownRelease = 0x1;

    public SHPServer(int port, String userDbFile, String eccKeyPairFile) throws Exception {
        this.port = port;
        this.userDbFile = userDbFile;
        this.eccKeyPairFile = eccKeyPairFile;
        this.userDatabase = loadUserDatabase(userDbFile);
    }

    public void start() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started on port " + port);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected.");
                new Thread(() -> {
                    try {
                        handleClient(clientSocket);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }).start();
            }
        }
    }

    private void handleClient(Socket socket) throws Exception {
        InputStream input = socket.getInputStream();
        OutputStream output = socket.getOutputStream();

        // Receive MessageType1 (UserID)
        byte[] msgData = receiveMessage(input);

        SHPMessageType1 msg1 = new SHPMessageType1();
        msg1.fromBytes(msgData);

        // Verify protocolVersion and release
        if (msg1.getProtocolVersion() != knownProtocolVersion || msg1.getRelease() != knownRelease) {
            System.out.println("Protocol version or release mismatch on received message 1!");
            socket.close();
            return;
        }

        String userId = msg1.getUserID();
        System.out.println("Received userID: " + userId);

        if (!userDatabase.containsKey(userId)) {
            System.out.println("User not found.");
            socket.close();
            return;
        }

        // Send MessageType2 (nonces)
        byte[] nonce1 = generateNonce();
        byte[] nonce2 = generateNonce();
        byte[] nonce3 = generateNonce();

        SHPMessageType2 msg2 = new SHPMessageType2(nonce1, nonce2, nonce3);
        sendMessage(output, msg2.toBytes(knownProtocolVersion, knownRelease));

        System.out.println("Sent Nonces: " + Stream.of(nonce1, nonce2, nonce3)
                .map(Base64.getEncoder()::encodeToString)
                .collect(Collectors.joining(", ")));

        Thread.sleep(500);

        byte[] msgData3 = receiveMessage(input);
        UserRecord userData = userDatabase.get(userId);
        int counter=2048;
        byte[] userPublicKey = userDatabase.get(userId).getClientPublicKeyBytes();
        ECCKeyInfo eccKeyInfo= new ECCKeyInfo(userPublicKey);

        SHPMessageType3 msg3 = new SHPMessageType3(userData.getPasswordHash(), userData.getSalt(), counter, eccKeyInfo);
        msg3.fromBytes(msgData3);
        if (msg3.getProtocolVersion() != knownProtocolVersion || msg3.getRelease() != knownRelease) {
            System.out.println("Protocol version or release mismatch on received message 1!");
            socket.close();
            return;
        }
        if (!msg3.verifyMessage()){
            System.out.println("Failed to verify message HMAC or Signature, discarding message!");
            socket.close();
            return;
        }
        msg3.parseDecryptedData();

        System.out.println("Received msg3: " + msg3);

        // Additional message exchanges...
        System.out.println("Session complete.");
        socket.close();
    }

    private Map<String, UserRecord> loadUserDatabase(String fileName) throws Exception {
        Map<String, UserRecord> userDatabase = new HashMap<>();
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.trim().isEmpty()) continue;
            // Expected format:
            // Userid : H(password) : salt : KpubClient
            // All except Userid are Base64-encoded
            String[] parts = line.split(" : ");
            if (parts.length != 4) {
                System.err.println("Invalid user database line format: " + line);
                continue;
            }
            
            String userId = parts[0].trim();
            String passwordHash = parts[1].trim();
            byte[] salt = Base64.getDecoder().decode(parts[2].trim());
            byte[] kpubClient = Base64.getDecoder().decode(parts[3].trim());

            UserRecord rec = new UserRecord();
            rec.userId = userId;
            rec.passwordHash = passwordHash; // store the hashed password (SHA-256)
            rec.salt = salt;
            rec.clientPublicKeyBytes = kpubClient; // Store as byte[], can later construct a PublicKey

            userDatabase.put(userId, rec);
        }
        reader.close();
        return userDatabase;
    }

    private static class UserRecord {
        String userId;
        String passwordHash;       // H(password) as a byte array
        byte[] salt;               // salt as a byte array
        byte[] clientPublicKeyBytes; // client's ECC public key as byte array

        public byte[] getClientPublicKeyBytes() {
            return clientPublicKeyBytes;
        }

        public String getUserId() {
            return userId;
        }

        public String getPasswordHash() {
            return passwordHash;
        }

        public byte[] getSalt() {
            return salt;
        }
    }

    private byte[] generateNonce() {
        byte[] nonce = new byte[16]; // 128-bit nonce
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static void sendMessage(OutputStream out, byte[] data) throws IOException {
        out.write((data.length >>> 24) & 0xFF);
        out.write((data.length >>> 16) & 0xFF);
        out.write((data.length >>> 8) & 0xFF);
        out.write(data.length & 0xFF);
        out.write(data);
        out.flush();
    }

    public static byte[] receiveMessage(InputStream in) throws IOException {
        byte[] lengthBytes = new byte[4];
        int read = in.read(lengthBytes);
        if (read < 4) {
            throw new IOException("Failed to read message length");
        }
        int length = ((lengthBytes[0] & 0xFF) << 24) |
                ((lengthBytes[1] & 0xFF) << 16) |
                ((lengthBytes[2] & 0xFF) << 8) |
                (lengthBytes[3] & 0xFF);

        byte[] data = new byte[length];
        int offset = 0;
        while (offset < length) {
            int r = in.read(data, offset, length - offset);
            if (r < 0) throw new IOException("EOF while reading message");
            offset += r;
        }
        return data;
    }
}