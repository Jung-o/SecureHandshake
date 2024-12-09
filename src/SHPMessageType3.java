import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Signature;
import java.util.Arrays;

public class SHPMessageType3 extends SHPMessage {
    private String hashedPassword;
    private ECCKeyInfo eccKeyInfo;
    private String request;
    private String userId;
    private byte[] incrementedNonce3;
    private byte[] nonce4;
    private int udpPort;
    private byte[] salt;
    private int counter;

    private byte[] encryptedData;
    private byte[] signature;
    private byte[] hmac;

    private byte[] decryptedData;


    public SHPMessageType3() {
        this.messageType = 0x03; // Type 3
    }


    // Client side constructor
    public SHPMessageType3(String userID, String request, byte[] nonce3, byte[] nonce4, int udpPort, byte[] salt, int counter, String hashedPassword, ECCKeyInfo eccKeyInfo) throws Exception {
        this();
        this.userId = userID;
        this.request = request;
        this.incrementedNonce3 = incrementNonce(nonce3);
        this.nonce4 = nonce4;
        this.udpPort = udpPort;
        this.salt = salt;
        this.counter = counter;
        this.hashedPassword = hashedPassword;
        this.eccKeyInfo = eccKeyInfo;

        byte[] plaintext = serializePlaintext();
        this.encryptedData = passwordBasedEncryption(plaintext);
        this.signature = generateDataSignature(plaintext);
        byte[] contentToHMAC = buildHmacInput();
        this.hmac = computeHMAC(contentToHMAC);

    }

    // Server side constructor
    public SHPMessageType3(String hashedPassword, byte[] salt, int counter, ECCKeyInfo eccKeyInfo){
        this();
        this.hashedPassword = hashedPassword;
        this.salt = salt;
        this.counter = counter;
        this.eccKeyInfo = eccKeyInfo;
    }

    private byte[] serializePlaintext() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // request (length-prefixed string)
        byte[] reqBytes = request.getBytes(StandardCharsets.UTF_8);
        baos.write((reqBytes.length >>> 8) & 0xFF);
        baos.write(reqBytes.length & 0xFF);
        baos.write(reqBytes);

        // userID (length-prefixed string)
        byte[] userBytes = userId.getBytes(StandardCharsets.UTF_8);
        baos.write((userBytes.length >>> 8) & 0xFF);
        baos.write(userBytes.length & 0xFF);
        baos.write(userBytes);

        // nonce3+1 (16 bytes)
        baos.write(incrementedNonce3);

        // nonce4 (16 bytes)
        baos.write(nonce4);

        // udp_port (4 bytes)
        baos.write((udpPort >>> 24) & 0xFF);
        baos.write((udpPort >>> 16) & 0xFF);
        baos.write((udpPort >>> 8) & 0xFF);
        baos.write(udpPort & 0xFF);

        return baos.toByteArray();
    }

    private byte[] incrementNonce(byte[] nonce3) {
        ByteBuffer buffer = ByteBuffer.wrap(nonce3);
        buffer.position(nonce3.length - 4);
        int lastPart = buffer.getInt();
        lastPart += 1;
        buffer.position(nonce3.length - 4);
        buffer.putInt(lastPart);
        return buffer.array();
    }

    public byte[] passwordBasedEncryption(byte[] input) throws Exception {
        return doPBRoutine(Cipher.ENCRYPT_MODE, input);
    }

    public byte[] passwordBasedDecryption(byte[] encryptedData) throws Exception {
        return doPBRoutine(Cipher.DECRYPT_MODE, encryptedData);
    }

    public byte[] doPBRoutine(int opmode, byte[] data) throws Exception{
        char[] password = hashedPassword.toCharArray();
        PBEKeySpec pbeSpec = new PBEKeySpec(password);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC", "BC");
        Key sKey = keyFact.generateSecret(pbeSpec);

        Cipher cDec = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC", "BC");
        cDec.init(opmode, sKey, new PBEParameterSpec(salt, counter));
        return cDec.doFinal(data);

    }

    public byte[] generateDataSignature(byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
        signature.initSign(eccKeyInfo.getPrivateKey());
        signature.update(data);
        return signature.sign();
    }

    private byte[] buildHmacInput() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // encryptedData length + encryptedData
        baos.write((encryptedData.length >>> 8) & 0xFF);
        baos.write(encryptedData.length & 0xFF);
        baos.write(encryptedData);

        // signature length + signature
        baos.write((signature.length >>> 8) & 0xFF);
        baos.write(signature.length & 0xFF);
        baos.write(signature);

        return baos.toByteArray();
    }

    private byte[] computeHMAC(byte[] data) throws Exception {
        byte[] key = hashedPassword.getBytes();
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    public byte[] toBytes(byte protocolVersion, byte release) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(createHeader(protocolVersion, release, messageType));

        // Write encryptedData
        baos.write((encryptedData.length >>> 8) & 0xFF);
        baos.write(encryptedData.length & 0xFF);
        baos.write(encryptedData);

        // Write signature
        baos.write((signature.length >>> 8) & 0xFF);
        baos.write(signature.length & 0xFF);
        baos.write(signature);

        // Write HMAC (assume 32 bytes for HMAC-SHA256)
        baos.write(hmac);

        return baos.toByteArray();
    }

    @Override
    public void fromBytes(byte[] data) {
        int offset = parseHeader(data);

        // Read encryptedData
        int encLen = ((data[offset] & 0xFF) << 8) | (data[offset+1] & 0xFF);
        offset += 2;
        encryptedData = Arrays.copyOfRange(data, offset, offset+encLen);
        offset += encLen;

        // Read signature
        int sigLen = ((data[offset] & 0xFF) << 8) | (data[offset+1] & 0xFF);
        offset += 2;
        signature = Arrays.copyOfRange(data, offset, offset+sigLen);
        offset += sigLen;

        // Read HMAC (assuming fixed length, e.g., 32 bytes)
        hmac = Arrays.copyOfRange(data, offset, offset+32);
        offset += 32;
    }

    public boolean verifyMessage() throws Exception {
        boolean hmacVerified = verifyHMAC();
        if (!hmacVerified){
            return false;
        }

        this.decryptedData = passwordBasedDecryption(encryptedData);
        boolean signatureVerified = verifySignature();

        if (!signatureVerified){
            return false;
        }
        return true;
    }

    private boolean verifyHMAC() throws Exception {
        byte[] contentToHMAC = buildHmacInput();
        byte[] computedHmac = computeHMAC(contentToHMAC);
        return Arrays.equals(computedHmac, hmac);
    }

    private boolean verifySignature() throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(eccKeyInfo.getPublicKey());
        verifier.update(decryptedData);
        return verifier.verify(signature);
    }

    public void parseDecryptedData() {
        int offset = 0;

        // 1. request
        int reqLen = ((decryptedData[offset] & 0xFF) << 8) | (decryptedData[offset+1] & 0xFF);
        offset += 2;
        byte[] reqBytes = Arrays.copyOfRange(decryptedData, offset, offset + reqLen);
        offset += reqLen;
        this.request = new String(reqBytes, StandardCharsets.UTF_8);

        // 2. userID
        int userLen = ((decryptedData[offset] & 0xFF) << 8) | (decryptedData[offset+1] & 0xFF);
        offset += 2;
        byte[] userBytes = Arrays.copyOfRange(decryptedData, offset, offset + userLen);
        offset += userLen;
        this.userId = new String(userBytes, StandardCharsets.UTF_8);

        // 3. nonce3+1 (16 bytes)
        this.incrementedNonce3 = Arrays.copyOfRange(decryptedData, offset, offset + 16);
        offset += 16;

        // 4. nonce4 (16 bytes)
        this.nonce4 = Arrays.copyOfRange(decryptedData, offset, offset + 16);
        offset += 16;

        // 5. udpPort (4 bytes)
        this.udpPort = ((decryptedData[offset] & 0xFF) << 24) |
                ((decryptedData[offset+1] & 0xFF) << 16) |
                ((decryptedData[offset+2] & 0xFF) << 8) |
                (decryptedData[offset+3] & 0xFF);
        offset += 4;
    }

    @Override
    public String toString() {
        return "SHPMessageType3 {" +
                "hashedPassword='" + hashedPassword + '\'' +
                ", request='" + request + '\'' +
                ", userID='" + userId + '\'' +
                ", udpPort=" + udpPort +
                '}';
    }

    public String getUserID() { return userId; }
    public String getRequestField() { return request; }
    public byte[] getIncrementedNonce3() { return incrementedNonce3; }
    public byte[] getNonce4() { return nonce4; }
    public int getUdpPort() { return udpPort; }

    public byte[] getEncryptedData() { return encryptedData; }
    public byte[] getSignature() { return signature; }
    public byte[] getHmac() { return hmac; }
    public byte[] getSalt() { return salt; }
    public int getCounter() { return counter; }
}
