import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;

public class SHPServer {
    private int port;
    private String userDbFile;
    private String eccKeyPairFile;
    private Map<String, UserRecord> userDatabase;
    private String cryptoConfigFilename;

    // Server's known (or chosen) protocol version and release
    private final byte knownProtocolVersion = 0x1;
    private final byte knownRelease = 0x1;
    public String request;
    private final String hostname;

    public SHPServer(String hostname, int port, String userDbFile, String eccKeyPairFile, String cryptoConfigFilename) throws Exception {
        this.port = port;
        this.userDbFile = userDbFile;
        this.eccKeyPairFile = eccKeyPairFile;
        this.userDatabase = loadUserDatabase(userDbFile);
        this.cryptoConfigFilename = cryptoConfigFilename;
        this.hostname = hostname;
    }

    public void server_shp_phase1() throws Exception {
        InetAddress addr = new InetSocketAddress(hostname, port).getAddress();
        try (ServerSocket serverSocket = new ServerSocket(port, 10, addr)) {
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
        System.out.println("Received Message 1 with User ID : " + userId);

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

        System.out.println("Sent Message 2 with nonce1, nonce2, nonce3");

        Thread.sleep(500);

        byte[] msgData3 = receiveMessage(input);
        UserRecord userData = userDatabase.get(userId);
        int counter=2048;
        byte[] userPublicKey = userDatabase.get(userId).getClientPublicKeyBytes();
        ECCKeyInfo eccClientKeyInfo= new ECCKeyInfo(userPublicKey);

        SHPMessageType3 msg3 = new SHPMessageType3(userData.getPasswordHash(), userData.getSalt(), counter, eccClientKeyInfo, nonce3);
        msg3.fromBytes(msgData3);
        if (msg3.getProtocolVersion() != knownProtocolVersion || msg3.getRelease() != knownRelease) {
            System.out.println("Protocol version or release mismatch on received message 3!");
            socket.close();
            return;
        }
        if (!msg3.verifyMessage()){
            System.out.println("Failed to verify message HMAC or Signature, discarding message!");
            socket.close();
            return;
        }
        msg3.parseDecryptedData();
        if (!msg3.verifyNonce3()){
            System.out.println("Nonce 3 has been tampered with between messages 2 and 3!");
            socket.close();
            return;
        }

        request = msg3.getRequestField();
        int udpPort = msg3.getUdpPort();
        System.out.println("Received Message 3 with request: " + request + " on UDP port: " + udpPort + ", nonce3 and nonce4");

        byte[] nonce5= generateNonce();
        ECCKeyInfo eccServerKeyInfo = ECCKeyInfo.readKeyFromFile(eccKeyPairFile);
        SHPMessageType4 msg4 = new SHPMessageType4(userData.getPasswordHash(), msg3.getUserID(), request, msg3.getNonce4(), nonce5, cryptoConfigFilename, eccServerKeyInfo, eccClientKeyInfo);

        sendMessage(output, msg4.toBytes(knownProtocolVersion, knownRelease));
        System.out.println("Sent Message 4 with request " + request + " confirmation, crypto config file: " + cryptoConfigFilename + ", nonce4 and nonce5.");


        byte[] m5Data = receiveMessage(input);
        SHPMessageType5 msg5 = new SHPMessageType5(nonce5, cryptoConfigFilename);
        msg5.fromBytes(m5Data);
        if (msg5.getProtocolVersion() != knownProtocolVersion || msg5.getRelease() != knownRelease) {
            System.out.println("Protocol version or release mismatch on received message 5!");
            socket.close();
            return;
        }
        if (!msg5.verifyAndDecrypt()){
            System.out.println("Failed to verify message HMAC or Signature, discarding message!");
            socket.close();
            return;
        }

        if (!msg5.verifyNonce5()){
            System.out.println("Nonce 5 has been tampered with between messages 4 and 5!");
            socket.close();
            return;
        }
        System.out.println("Received Message 5 nonce5, using previously transferred crypto config");


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
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(data.length);
        byte[] lengthBytes = buffer.array();
        out.write(lengthBytes);
        out.write(data);
        out.flush();
    }

    public static byte[] receiveMessage(InputStream in) throws IOException {
        byte[] lengthBytes = new byte[4];
        if (in.read(lengthBytes) < 4) {
            throw new IOException("Failed to read message length");
        }
        ByteBuffer buffer = ByteBuffer.wrap(lengthBytes);
        int length = buffer.getInt();

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