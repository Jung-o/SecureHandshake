import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Collectors;

public class SHPClient {
    private String serverAddress;
    private int tcpPort;
    private String clientKeyPairFile;
    private String userId;
    private String plaintextPwd;
    private int udpPort;
    private String request;
    private String cryptoConfigFilename;
    private byte[] salt;

    // Client's known protocol version and release
    private final byte knownProtocolVersion = 0x1;
    private final byte knownRelease = 0x1;

    public SHPClient(String serverAddress, int tcpPort, String clientKeyPairFile, String userId, String plaintextPwd, String base64Salt, int udpPort, String request, String cryptoConfigFilename) {
        this.serverAddress = serverAddress;
        this.tcpPort = tcpPort;
        this.clientKeyPairFile = clientKeyPairFile;
        this.userId = userId;
        this.plaintextPwd = plaintextPwd;
        this.udpPort = udpPort;
        this.request = request;
        this.cryptoConfigFilename = cryptoConfigFilename;
        this.salt = Base64.getDecoder().decode(base64Salt);;
    }

    public void client_shp_phase1() throws Exception {
        try (Socket socket = new Socket(serverAddress, tcpPort)) {
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
            ECCKeyInfo eccClientKeyInfo= ECCKeyInfo.readKeyFromFile(clientKeyPairFile);

            //data to send (later probably from program args)
            String hashedPassword=hashAndEncode(plaintextPwd);

            SHPMessageType3 msg3 = new SHPMessageType3(userId, request, nonce3, nonce4, udpPort, salt, counter, hashedPassword, eccClientKeyInfo);
            byte[] m3Data = msg3.toBytes(knownProtocolVersion, knownRelease);
            sendMessage(output, m3Data);
            System.out.println("Sent msg3:" + msg3);

            PublicKey serverPublicKey= ECCKeyInfo.readKeyFromFile("ServerECCKeyPair.sec").getPublicKey();
            byte[] m4Data = receiveMessage(input);
            SHPMessageType4 msg4 = new SHPMessageType4(hashedPassword, eccClientKeyInfo, serverPublicKey, nonce4, cryptoConfigFilename);
            msg4.fromBytes(m4Data);
            if (msg4.getProtocolVersion() != knownProtocolVersion || msg4.getRelease() != knownRelease) {
                System.out.println("Protocol version or release mismatch on received message 4!");
                socket.close();
                return;
            }
            if (!msg4.verifyMessage()){
                System.out.println("Failed to verify message HMAC or Signature, discarding message!");
                socket.close();
                return;
            }
            msg4.parseDecryptedData();
            if (!msg4.verifyNonce4()){
                System.out.println("Nonce 4 has been tampered with between messages 3 and 4!");
                socket.close();
                return;
            }

            System.out.println("Received msg4: " + msg4);
            byte[] nonce5 = msg4.getNonce5();
            SHPMessageType5 msg5 = new SHPMessageType5(nonce5, cryptoConfigFilename);
            byte[] m5Data = msg5.toBytes(knownProtocolVersion, knownRelease);
            sendMessage(output, m5Data);
            System.out.println("Sent msg5: " + msg5);

            // Additional message exchanges...
        }
    }

    public static void sendMessage(OutputStream out, byte[] data) throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(data.length);
        byte[] lengthBytes = buffer.array();
        out.write(lengthBytes);
        out.write(data);
        out.flush();
    }

    public static byte[] receiveMessage(InputStream in) throws Exception {
        byte[] lengthBytes = new byte[4];
        if (in.read(lengthBytes) < 4) {
            throw new Exception("Failed to read message length");
        }
        ByteBuffer buffer = ByteBuffer.wrap(lengthBytes);
        int length = buffer.getInt();

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

    public static String hashAndEncode(String plaintext) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }
}
