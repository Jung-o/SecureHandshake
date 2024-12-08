import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Arrays;

public class Message2 extends Message {
    private static final long serialVersionUID = 1L;

    // Store the 3 nonces (each 16 bytes)
    private byte[] nonce1;
    private byte[] nonce2;
    private byte[] nonce3;

    public Message2(byte protocolVersion, byte protocolRelease, byte[] nonce1, byte[] nonce2, byte[] nonce3) {
        super(protocolVersion, protocolRelease, MessageType.MSG2.getTypeCode());

        this.nonce1 = nonce1;
        this.nonce2 = nonce2;
        this.nonce3 = nonce3;

    }

    public byte[] getNonce1() {
        return nonce1;
    }

    public byte[] getNonce2() {
        return nonce2;
    }

    public byte[] getNonce3() {
        return nonce3;
    }


    // For debugging purposes: print nonces in a readable format
    @Override
    public String toString() {
        return "Message2{" +
                "nonce1=" + Arrays.toString(nonce1) +
                ", nonce2=" + Arrays.toString(nonce2) +
                ", nonce3=" + Arrays.toString(nonce3) +
                '}';
    }
}