import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

public class SHPMessageType4 extends SHPMessage {
    private String hashedPassword;
    private ECCKeyInfo eccClientKeyInfo;
    private ECCKeyInfo eccServerKeyInfo;
    private String request;
    private String userId;
    private byte[] nonce4;
    private byte[] incrementedNonce4;
    private byte[] nonce5;
    private String dstpConfigFileName;

    private byte[] encryptedData;
    private byte[] signature;
    private byte[] hmac;

    private byte[] decryptedData;

    public SHPMessageType4() {
        this.messageType = 0x04; // Type 4
    }


    // Server side constructor
    public SHPMessageType4(String hashedPassword, String userID, String request, byte[] nonce4, byte[] nonce5, String dstpConfigFilename, ECCKeyInfo eccServerKeyInfo, ECCKeyInfo eccClientKeyInfo) throws Exception {
        this();
        this.hashedPassword = hashedPassword;
        this.userId = userID;
        this.request = request;
        this.nonce4 = nonce4;
        this.nonce5 = nonce5;
        this.dstpConfigFileName = dstpConfigFilename;
        this.eccClientKeyInfo = eccClientKeyInfo;
        this.eccServerKeyInfo = eccServerKeyInfo;

        byte[] plaintext = serializePlaintext();
        this.encryptedData = publicKeyEncryption(plaintext);
        this.signature = generateDataSignature(plaintext);
        byte[] contentToHMAC = buildHmacInput();
        this.hmac = computeHMAC(contentToHMAC);

    }

    // Client side constructor
    public SHPMessageType4(String hashedPassword, ECCKeyInfo eccClientKeyInfo, PublicKey serverPublicKey, byte[] nonce4, String dstpConfigFileName) {
        this();
        this.hashedPassword = hashedPassword;
        this.eccClientKeyInfo = eccClientKeyInfo;
        this.eccServerKeyInfo = new ECCKeyInfo();
        this.eccServerKeyInfo.setPublicKey(serverPublicKey);
        this.nonce4 = nonce4;
        this.dstpConfigFileName = dstpConfigFileName;
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

        // nonce4+1 (16 bytes)
        incrementedNonce4 = incrementNonce(nonce4);
        baos.write(incrementedNonce4);

        // nonce5 (16 bytes)
        baos.write(nonce5);

        byte[] configBytes = serializeConfigFile();
        baos.write((configBytes.length >>> 8) & 0xFF);
        baos.write(configBytes.length & 0xFF);
        baos.write(configBytes);

        return baos.toByteArray();
    }

    private byte[] serializeConfigFile() throws IOException {
        String fileContent = new String(Files.readAllBytes(Paths.get(dstpConfigFileName)));
        return fileContent.getBytes(StandardCharsets.UTF_8);
    }

    private byte[] incrementNonce(byte[] nonce4) {
        ByteBuffer buffer = ByteBuffer.wrap(nonce4);
        buffer.position(nonce4.length - 4);
        int lastPart = buffer.getInt();
        lastPart += 1;
        buffer.position(nonce4.length - 4);
        buffer.putInt(lastPart);
        return buffer.array();
    }

    public byte[] publicKeyEncryption(byte[] input) throws Exception {
        return doPublicKeyRoutine(Cipher.ENCRYPT_MODE, input);
    }

    public byte[] privateKeyDecryption(byte[] encryptedData) throws Exception {
        return doPublicKeyRoutine(Cipher.DECRYPT_MODE, encryptedData);
    }

    public byte[] doPublicKeyRoutine(int opmode, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        if (opmode == Cipher.ENCRYPT_MODE) {
            cipher.init(opmode, eccClientKeyInfo.getPublicKey());
        } else {
            cipher.init(opmode, eccClientKeyInfo.getPrivateKey());
        }

        return cipher.doFinal(data);

    }

    public byte[] generateDataSignature(byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
        signature.initSign(eccServerKeyInfo.getPrivateKey());
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
        int encLen = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        offset += 2;
        encryptedData = Arrays.copyOfRange(data, offset, offset + encLen);
        offset += encLen;

        // Read signature
        int sigLen = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        offset += 2;
        signature = Arrays.copyOfRange(data, offset, offset + sigLen);
        offset += sigLen;

        // Read HMAC (assuming fixed length, e.g., 32 bytes)
        hmac = Arrays.copyOfRange(data, offset, offset + 32);
        offset += 32;
    }

    public boolean verifyMessage() throws Exception {
        boolean hmacVerified = verifyHMAC();
        if (!hmacVerified) {
            return false;
        }

        this.decryptedData = privateKeyDecryption(encryptedData);
        boolean signatureVerified = verifySignature();
        if (!signatureVerified) {
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
        verifier.initVerify(eccServerKeyInfo.getPublicKey());
        verifier.update(decryptedData);
        return verifier.verify(signature);
    }

    public boolean verifyNonce4() {
        byte[] incrementedOriginalNonce4 = incrementNonce(nonce4);
        return Arrays.equals(incrementedOriginalNonce4, incrementedNonce4);
    }


    public void parseDecryptedData() throws IOException {
        int offset = 0;

        // 1. request
        int reqLen = ((decryptedData[offset] & 0xFF) << 8) | (decryptedData[offset + 1] & 0xFF);
        offset += 2;
        byte[] reqBytes = Arrays.copyOfRange(decryptedData, offset, offset + reqLen);
        offset += reqLen;
        this.request = new String(reqBytes, StandardCharsets.UTF_8);

        // 2. userID
        int userLen = ((decryptedData[offset] & 0xFF) << 8) | (decryptedData[offset + 1] & 0xFF);
        offset += 2;
        byte[] userBytes = Arrays.copyOfRange(decryptedData, offset, offset + userLen);
        offset += userLen;
        this.userId = new String(userBytes, StandardCharsets.UTF_8);

        // 3. nonce4+1 (16 bytes)
        this.incrementedNonce4 = Arrays.copyOfRange(decryptedData, offset, offset + 16);
        offset += 16;

        // 4. nonce5 (16 bytes)
        this.nonce5 = Arrays.copyOfRange(decryptedData, offset, offset + 16);
        offset += 16;

        // 5. configFile
        int configLen = ((decryptedData[offset] & 0xFF) << 8) | (decryptedData[offset + 1] & 0xFF);
        offset += 2;
        byte[] configBytes = Arrays.copyOfRange(decryptedData, offset, offset + configLen);
        offset += configLen;

        Files.write(Paths.get(dstpConfigFileName), configBytes);
    }

    @Override
    public String toString() {
        return "SHPMessageType4 {" +
                " request='" + request + '\'' +
                ", userID='" + userId + '\'' +
                '}';
    }

    public String getUserID() {
        return userId;
    }

    public String getRequestField() {
        return request;
    }

    public byte[] getNonce4() {
        return nonce4;
    }

    public byte[] getDecryptedData() {
        return decryptedData;
    }

    public byte[] getIncrementedNonce4() {
        return incrementedNonce4;
    }

    public byte[] getNonce5() {
        return nonce5;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getHmac() {
        return hmac;
    }
}
