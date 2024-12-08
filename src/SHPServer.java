import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;


public class SHPServer {
    private int port;
    private String userDbFile;
    private String eccKeyPairFile;
    private Map<String, String> userDatabase;
    private KeyPair serverKeyPair;

    public SHPServer(int port, String userDbFile, String eccKeyPairFile) throws Exception {
        this.port = port;
        this.userDbFile = userDbFile;
        this.eccKeyPairFile = eccKeyPairFile;
        this.userDatabase = loadUserDatabase(userDbFile);
        //this.serverKeyPair = loadECCKeyPair(eccKeyPairFile);
    }

    public void start() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started on port " + port);

            while (true) {
                try (Socket clientSocket = serverSocket.accept()) {
                    System.out.println("Client connected.");
                    handleClient(clientSocket);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void handleClient(Socket socket) throws Exception {
        InputStream input = socket.getInputStream();
        OutputStream output = socket.getOutputStream();

        BufferedReader reader = new BufferedReader(new InputStreamReader(input));

        // Phase 1 Message 1: Receive userID
        String userId = reader.readLine();
        System.out.println("Received userID: " + userId);

        if (!userDatabase.containsKey(userId)) {
            System.out.println("User not found.");
            return;
        }

        // Send Nonces (Message 2)
        byte[] nonce1 = generateNonce();
        byte[] nonce2 = generateNonce();
        byte[] nonce3 = generateNonce();

        System.out.println("Sent Nonces: " + Arrays.asList(nonce1, nonce2, nonce3).stream().map(Base64.getEncoder()::encodeToString).collect(Collectors.joining(", ")));

        output.write((Base64.getEncoder().encodeToString(nonce1) + "\n").getBytes());
        output.write((Base64.getEncoder().encodeToString(nonce2) + "\n").getBytes());
        output.write((Base64.getEncoder().encodeToString(nonce3) + "\n").getBytes());
        output.flush();

        // Further message exchanges would go here (Messages 3, 4, 5)
        System.out.println("Session complete.");
    }

    private KeyPair loadECCKeyPair(String fileName) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String curveName = reader.readLine().split(":")[1].trim();
        String privateKeyHex = reader.readLine().split(":")[1].trim();
        String publicKeyHex = reader.readLine().split(":")[1].trim();

        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(privateKeyHex, 16), ecSpec);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(new BigInteger(publicKeyHex, 16).toByteArray()), ecSpec);

        return new KeyPair(keyFactory.generatePublic(publicKeySpec), keyFactory.generatePrivate(privateKeySpec));
    }

    private Map<String, String> loadUserDatabase(String fileName) throws Exception {
        Map<String, String> userDatabase = new HashMap<>();
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String line;
        while ((line = reader.readLine()) != null) {
            String[] parts = line.split(" : ");
            userDatabase.put(parts[0], parts[1]);
        }
        return userDatabase;
    }

    private byte[] generateNonce() {
        byte[] nonce = new byte[16]; // 128-bit nonce
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }
}
