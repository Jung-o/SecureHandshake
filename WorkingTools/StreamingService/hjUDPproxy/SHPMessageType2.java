import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class SHPMessageType2 extends SHPMessage {
    private byte[] nonce1;
    private byte[] nonce2;
    private byte[] nonce3;

    public SHPMessageType2() {
        this.messageType = 0x02; // Type 2
    }

    public SHPMessageType2(byte[] nonce1, byte[] nonce2, byte[] nonce3) {
        this();
        this.nonce1 = nonce1;
        this.nonce2 = nonce2;
        this.nonce3 = nonce3;
    }

    public byte[] toBytes(byte protocolVersion, byte release) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(createHeader(protocolVersion, release, messageType));
        baos.write(nonce1);
        baos.write(nonce2);
        baos.write(nonce3);
        return baos.toByteArray();
    }

    @Override
    public void fromBytes(byte[] data) {
        int offset = parseHeader(data);
        nonce1 = Arrays.copyOfRange(data, offset, offset+16);
        offset += 16;
        nonce2 = Arrays.copyOfRange(data, offset, offset+16);
        offset += 16;
        nonce3 = Arrays.copyOfRange(data, offset, offset+16);
    }

    public byte[] getNonce1() { return nonce1; }
    public byte[] getNonce2() { return nonce2; }
    public byte[] getNonce3() { return nonce3; }
}
