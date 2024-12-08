import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class SHPMessageType1 extends SHPMessage {
    private String userID;

    public SHPMessageType1() {
        this.messageType = 0x01; // Type 1
    }

    public SHPMessageType1(String userID) {
        this();
        this.userID = userID;
    }

    public byte[] toBytes(byte protocolVersion, byte release) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(createHeader(protocolVersion, release, messageType));
        byte[] userBytes = userID.getBytes(StandardCharsets.UTF_8);
        baos.write((userBytes.length >>> 8) & 0xFF);
        baos.write((userBytes.length) & 0xFF);
        baos.write(userBytes);
        return baos.toByteArray();
    }

    @Override
    public void fromBytes(byte[] data) {
        int offset = parseHeader(data);
        int length = ((data[offset] & 0xFF) << 8) | (data[offset+1] & 0xFF);
        offset += 2;
        byte[] userBytes = new byte[length];
        System.arraycopy(data, offset, userBytes, 0, length);
        userID = new String(userBytes, StandardCharsets.UTF_8);
    }

    public String getUserID() {
        return userID;
    }
}
