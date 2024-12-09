import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SHPMessageType3 extends SHPMessage {
    private String hashedPassword;
    private byte[] salt;
    private int counter;
    private String request;
    private String userID;
    private byte[] nonce3;
    private byte[] nonce4;
    private int udpPort;
    private ECCKeyInfo eccKeyInfo;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public SHPMessageType3() {
        this.messageType = 0x03; // Type 3
    }

    public SHPMessageType3(String hashedPassword, byte[] salt, int counter, String request, String userID, byte[] nonce3, byte[] nonce4, int udpPort, ECCKeyInfo eccKeyInfo) {
        this();
        this.hashedPassword = hashedPassword;
        this.salt = salt;
        this.counter = counter;
        this.request = request;
        this.userID = userID;
        this.nonce3 = nonce3;
        this.nonce4 = nonce4;
        this.udpPort = udpPort;
        this.eccKeyInfo = eccKeyInfo;
    }

    public SHPMessageType3(String hashedPassword, byte[] salt, int counter, ECCKeyInfo eccKeyInfo) {
        this();
        this.hashedPassword = hashedPassword;
        this.salt = salt;
        this.counter = counter;
        this.eccKeyInfo = eccKeyInfo;
    }

    public byte[] toBytes(byte protocolVersion, byte release) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(createHeader(protocolVersion, release, messageType));

        byte[] messageInBytes = creteBytesMessageData();
        byte[] pbePayload = passwordBasedEncryption(messageInBytes);
        baos.write(intToBytes(pbePayload.length));
        baos.write(pbePayload);

        byte[] sign = generateDataSignature(messageInBytes);
        baos.write(intToBytes(sign.length));
        baos.write(sign);

        byte[] messageSoFar = baos.toByteArray();
        byte[] hmac = computeHMAC(messageSoFar);
        baos.write(intToBytes(hmac.length));
        baos.write(hmac);

        return baos.toByteArray();
    }

    @Override
    public void fromBytes(byte[] data) {
        try {
            int offset = parseHeader(data);

            int encryptedDataLength = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset + 4)).getInt();
            offset += 4;

            byte[] encryptedData = Arrays.copyOfRange(data, offset, offset + encryptedDataLength);
            offset += encryptedDataLength;

            int signatureLength = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset + 4)).getInt();
            offset += 4;

            byte[] signature = Arrays.copyOfRange(data, offset, offset + signatureLength);
            offset += signatureLength;

            int hmacLength = ByteBuffer.wrap(Arrays.copyOfRange(data, offset, offset + 4)).getInt();
            offset += 4;
            byte[] receivedHMAC = Arrays.copyOfRange(data, offset, offset + hmacLength);
            byte[] messageForHMAC = Arrays.copyOfRange(data, 0, data.length - hmacLength - 4);
            if (!verifyHMAC(messageForHMAC, receivedHMAC)) {
                throw new RuntimeException("HMAC verification failed.");
            }

            byte[] decryptedData = passwordBasedDecryption(encryptedData);
            if (!verifySignature(decryptedData, signature, eccKeyInfo.getPublicKey())) {
                throw new RuntimeException("Signature verification failed.");
            }
            mapDecryptedDataToClassFields(decryptedData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private boolean verifyHMAC(byte[] message, byte[] receivedHMAC) throws Exception {
        byte[] computedHMAC = computeHMAC(message);
        return Arrays.equals(computedHMAC, receivedHMAC);
    }

    private byte[] computeHMAC(byte[] data) throws Exception {
        byte[] key = hashedPassword.getBytes();
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    private boolean verifySignature(byte[] message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(eccKeyInfo.getPublicKey());
        verifier.update(message);
        if (verifier.verify(signature)) {
            System.out.println("Signature verification succeeded.");
            return true;
        } else {
            System.out.println("Signature verification failed.");
            return false;
        }
    }

    public byte[] passwordBasedEncryption(byte[] input) throws Exception {
        char[] password = hashedPassword.toCharArray();
        PBEKeySpec pbeSpec = new PBEKeySpec(password);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
        Key sKey= keyFact.generateSecret(pbeSpec);
        Cipher cEnc = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");
        cEnc.init(Cipher.ENCRYPT_MODE, sKey, new PBEParameterSpec(salt, counter));
        return cEnc.doFinal(input);
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

    public byte[] creteBytesMessageData() throws UnsupportedEncodingException {
        byte[] nonce3Incremented = incrementNonce(nonce3);

        byte requestByte;
        if ("files".equalsIgnoreCase(request)) {
            requestByte = 1;
        } else if ("movie".equalsIgnoreCase(request)) {
            requestByte = 2;
        } else {
            throw new IllegalArgumentException("Invalid request type: " + request);
        }
        byte[] userIDBytes = userID.getBytes("UTF-8");
        userIDBytes = Arrays.copyOf(userIDBytes, 320);
        ByteBuffer udpPortBuffer = ByteBuffer.allocate(4).putInt(udpPort);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(requestByte);
            baos.write(userIDBytes);
            baos.write(nonce3Incremented);
            baos.write(nonce4);
            baos.write(udpPortBuffer.array());
        } catch (IOException e) {
            throw new RuntimeException("Error constructing input data", e);
        }

        return baos.toByteArray();
    }

    public byte[] passwordBasedDecryption(byte[] encryptedData) throws Exception {
        char[] password = hashedPassword.toCharArray();
        PBEKeySpec pbeSpec = new PBEKeySpec(password);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC", "BC");
        Key sKey = keyFact.generateSecret(pbeSpec);

        Cipher cDec = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC", "BC");
        cDec.init(Cipher.DECRYPT_MODE, sKey, new PBEParameterSpec(salt, counter));
        return cDec.doFinal(encryptedData);
    }

    public byte[] generateDataSignature(byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
        signature.initSign(eccKeyInfo.getPrivateKey());
        signature.update(data);
        return signature.sign();
    }

    private void mapDecryptedDataToClassFields(byte[] decryptedData) throws UnsupportedEncodingException {
        ByteBuffer buffer = ByteBuffer.wrap(decryptedData);
        byte requestByte = buffer.get();
        switch (requestByte) {
            case 1:
                this.request = "files";
                break;
            case 2:
                this.request = "movie";
                break;
            default:
                throw new IllegalArgumentException("Invalid request byte: " + requestByte);
        }

        byte[] userIDBytes = new byte[320];
        buffer.get(userIDBytes);
        this.userID = new String(userIDBytes, "UTF-8").trim();

        this.nonce3 = new byte[16];
        buffer.get(this.nonce3);

        this.nonce4 = new byte[16];
        buffer.get(this.nonce4);

        this.udpPort = buffer.getInt();
    }

    @Override
    public String toString() {
        return "SHPMessageType3 {" +
                "hashedPassword='" + hashedPassword + '\'' +
                ", salt='" + new String(salt) + '\'' +
                ", counter=" + counter +
                ", request='" + request + '\'' +
                ", userID='" + userID + '\'' +
                ", nonce3='" + Arrays.toString(nonce3) + '\'' +
                ", nonce4='" + Arrays.toString(nonce4) + '\'' +
                ", udpPort=" + udpPort +
                '}';
    }

    private byte[] intToBytes(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }
}
