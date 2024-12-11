import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;

public class DSTPPacket {
    private final byte[] payload;

    public DSTPPacket(byte[] data, int sequenceNumber, DSTPConfig config) throws Exception {
        Key encryptionKey = config.getEncryptionKey();
        Key macKey = config.getMacKey();
        Cipher cipher = Cipher.getInstance(config.getCipher());
        Mac mac = config.getMac();
        MessageDigest messageDigest = config.getMessageDigest();
        boolean useHMAC = config.doesUseHMAC();

        // Convert sequence number to byte array
        byte[] sequenceNumberBytes = ByteBuffer.allocate(2).putShort((short) sequenceNumber).array();

        // Concatenate sequence number with data
        byte[] dataWithSequence = concatenate(sequenceNumberBytes, data);
        // Generate HMAC or Hash for integrity
        byte[] integrityCheck;
        if (useHMAC) {
            mac.init(macKey);
            integrityCheck = mac.doFinal(dataWithSequence);
        } else {
            integrityCheck = messageDigest.digest(dataWithSequence);
        }

        // Concatenate data with integrity check
        byte[] dataWithIntegrity = concatenate(dataWithSequence, integrityCheck);

        // Initialize cipher
        if (config.doesUseIV()) {
            byte[] ivBytes = config.getIv();
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        }

        // Encrypt concatenated data
        byte[] encryptedData = cipher.doFinal(dataWithIntegrity);

        // Add version number, release number, and size of encrypted payload
        byte[] versionNumber = ByteBuffer.allocate(2).putShort((short) config.getVersion()).array();
        byte[] releaseNumber = ByteBuffer.allocate(1).put((byte) config.getRelease()).array();
        byte[] payloadSize = ByteBuffer.allocate(2).putShort((short) encryptedData.length).array();

        // Concatenate version number, release number, payload size, and encrypted data
        this.payload = concatenate(versionNumber, releaseNumber, payloadSize, encryptedData);
    }

    // Combine IV and encrypted payload into a single byte array
    public byte[] getPayload() {
        return payload;
    }

    // Parse a received packet to extract the encrypted payload and IV
    public static byte[] decryptPacket(byte[] encryptedPayload, DSTPConfig config) throws Exception {
        Key encryptionKey = config.getEncryptionKey();
        Cipher cipher = Cipher.getInstance(config.getCipher());
        Mac mac = config.getMac();
        MessageDigest messageDigest = config.getMessageDigest();
        boolean useHMAC = config.doesUseHMAC();

        // Decrypt the payload
        if (config.doesUseIV()) {
            byte[] ivBytes = config.getIv();
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
        }
        byte[] decryptedDataWithIntegrity = cipher.doFinal(encryptedPayload);

        // Separate data and integrity check
        int integrityLength = useHMAC ? mac.getMacLength() : messageDigest.getDigestLength();
        byte[] dataWithSequence = Arrays.copyOfRange(decryptedDataWithIntegrity, 0, decryptedDataWithIntegrity.length - integrityLength);
        byte[] receivedIntegrityCheck = Arrays.copyOfRange(decryptedDataWithIntegrity, decryptedDataWithIntegrity.length - integrityLength, decryptedDataWithIntegrity.length);

        // Verify integrity
        byte[] calculatedIntegrity;
        if (useHMAC) {
            mac.init(config.getMacKey());
            calculatedIntegrity = mac.doFinal(dataWithSequence);
        } else {
            calculatedIntegrity = messageDigest.digest(dataWithSequence);
        }
        if (!Arrays.equals(receivedIntegrityCheck, calculatedIntegrity)) {
            throw new SecurityException("Packet integrity check failed");
        }

        // Return data and sequence number
        return dataWithSequence;
    }

    private static byte[] concatenate(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            if (array != null) {
                totalLength += array.length;
            }
        }
        byte[] result = new byte[totalLength];
        int currentIndex = 0;
        for (byte[] array : arrays) {
            if (array != null) {
                System.arraycopy(array, 0, result, currentIndex, array.length);
                currentIndex += array.length;
            }
        }
        return result;
    }
}