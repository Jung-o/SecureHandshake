import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class SHPMessageType5 extends SHPMessage {
    private String goString = "GO";
    private byte[] nonce5;       // Provided from previous message
    private byte[] incrementedNonce5;

    // Fields parsed from the config
    private String cipherTransformation; // e.g. "AES/CBC/PKCS5Padding"
    private byte[] symmetricKey;
    private byte[] iv;
    private byte[] macKey;

    private byte[] encryptedData;
    private byte[] hmac;

    public SHPMessageType5(byte[] nonce5, String configFilePath) throws Exception {
        this.messageType = 0x05; // Type 5
        this.nonce5 = nonce5;
        parseConfigFile(configFilePath);
    }

    private void parseConfigFile(String configFilePath) throws IOException {
        Map<String, String> configMap = new HashMap<>();
        try (BufferedReader br = new BufferedReader(new FileReader(configFilePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    configMap.put(parts[0].trim(), parts[1].trim());
                }
            }
        }

        // Example fields:
        // CONFIDENTIALITY: AES/CBC/PKCS5Padding
        this.cipherTransformation = configMap.get("CONFIDENTIALITY");
        // SYMMETRIC_KEY: hex string
        this.symmetricKey = hexStringToByteArray(configMap.get("SYMMETRIC_KEY"));
        // IV: hex string
        this.iv = hexStringToByteArray(configMap.get("IV"));

        // MACKEY: hex string
        String integrity = configMap.get("INTEGRITY");
        if ("HMAC".equalsIgnoreCase(integrity)) {
            this.macKey = hexStringToByteArray(configMap.get("MACKEY"));
        } else {
            throw new IOException("Only HMAC integrity supported for now.");
        }
    }

    private static byte[] hexStringToByteArray(String s) {
        s = s.replaceAll("\\s", "");
        int len = s.length();
        byte[] data = new byte[len/2];
        for (int i = 0; i < len; i+=2) {
            data[i/2] = (byte) ((Character.digit(s.charAt(i),16) <<4)
                    + Character.digit(s.charAt(i+1),16));
        }
        return data;
    }

    private byte[] serializePlaintext() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // increment nonce5
        incrementedNonce5 = incrementNonce(nonce5);

        // "GO" length-prefixed
        byte[] goBytes = goString.getBytes(StandardCharsets.UTF_8);
        baos.write((goBytes.length >>> 8) & 0xFF);
        baos.write(goBytes.length & 0xFF);
        baos.write(goBytes);

        // nonce5+1 (16 bytes)
        baos.write(incrementedNonce5);

        return baos.toByteArray();
    }

    private byte[] incrementNonce(byte[] nonce) {
        byte[] copy = Arrays.copyOf(nonce, nonce.length);
        ByteBuffer bb = ByteBuffer.wrap(copy);
        bb.position(copy.length - 4);
        int val = bb.getInt();
        val += 1;
        bb.position(copy.length - 4);
        bb.putInt(val);
        return copy;
    }

    private byte[] encrypt(byte[] plaintext) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(cipherTransformation);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(plaintext);
    }

    private byte[] decrypt(byte[] ciphertext) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(cipherTransformation);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(ciphertext);
    }

    private byte[] computeHMAC(byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
        return mac.doFinal(data);
    }

    public byte[] toBytes(byte protocolVersion, byte release) throws Exception {
        byte[] plaintext = serializePlaintext();

        // Encrypt plaintext with AES/CBC/PKCS5Padding using symmetricKey and iv
        encryptedData = encrypt(plaintext);

        // Compute HMAC over encryptedData
        hmac = computeHMAC(encryptedData);

        // Construct final message
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(createHeader(protocolVersion, release, messageType));

        // Write encryptedData length + data
        baos.write((encryptedData.length >>> 8) & 0xFF);
        baos.write(encryptedData.length & 0xFF);
        baos.write(encryptedData);

        // Write HMAC (32 bytes)
        baos.write(hmac);

        return baos.toByteArray();
    }

    @Override
    public void fromBytes(byte[] data) {
        int offset = parseHeader(data);

        // Read encryptedData
        int encLen = ((data[offset] & 0xFF) << 8) | (data[offset+1] & 0xFF);
        offset += 2;
        encryptedData = Arrays.copyOfRange(data, offset, offset + encLen);
        offset += encLen;

        // Read HMAC (32 bytes)
        hmac = Arrays.copyOfRange(data, offset, offset + 32);
        offset += 32;
    }

    public boolean verifyNonce5() {
        byte[] incrementedOriginalNonce3 = incrementNonce(nonce5);
        return Arrays.equals(incrementedOriginalNonce3, incrementedNonce5);
    }

    public boolean verifyAndDecrypt() throws Exception {
        // Verify HMAC
        byte[] computedHmac = computeHMAC(encryptedData);
        if (!Arrays.equals(computedHmac, hmac)) {
            return false;
        }

        // Decrypt
        byte[] plaintext = decrypt(encryptedData);
        parsePlaintext(plaintext);
        if (!Objects.equals(goString, "GO")){
            return false;
        }
        return verifyNonce5();
    }

    private void parsePlaintext(byte[] plaintext) {
        int offset = 0;

        // GO
        int goLen = ((plaintext[offset] & 0xFF) << 8) | (plaintext[offset+1] & 0xFF);
        offset += 2;
        byte[] goBytes = Arrays.copyOfRange(plaintext, offset, offset + goLen);
        offset += goLen;
        this.goString = new String(goBytes, StandardCharsets.UTF_8);

        // nonce5+1 (16 bytes)
        this.incrementedNonce5 = Arrays.copyOfRange(plaintext, offset, offset+16);
        offset += 16;
    }

    public String getGoString() {
        return goString;
    }

    public byte[] getIncrementedNonce5() {
        return incrementedNonce5;
    }

    @Override
    public String toString() {
        return "SHPMessageType5 {" +
                " nonce5='" + Base64.getEncoder().encodeToString(nonce5) + '\'' +
                ", incrementedNonce5='" + Base64.getEncoder().encodeToString(incrementedNonce5) + '\'' +
                '}';
    }
}
