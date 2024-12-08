import java.io.Serializable;

public class Message implements Serializable {
    private static final long serialVersionUID = 1L; // Ensure compatibility during serialization

    private final byte protocolVersionAndRelease;
    private final byte messageTypeCode;

    public Message(byte protocolVersion, byte protocolRelease, byte messageTypeCode) {
        this.protocolVersionAndRelease = combineProtocolVersionAndReleaseUsingBits(protocolVersion, protocolRelease);
        this.messageTypeCode = messageTypeCode;
    }

    public static byte combineProtocolVersionAndReleaseUsingBits(byte protocolVersion, byte protocolRelease) {
        return (byte) ((protocolVersion << 4) | (protocolRelease & 0x0F));
    }

    public static byte extractProtocolVersion(byte combined) {
        return (byte) (combined >> 4);
    }

    public static byte extractProtocolRelease(byte combined) {
        return (byte) (combined & 0x0F);
    }

    public byte getprotocolVersionAndRelease() {
        return protocolVersionAndRelease;
    }


    public byte getMessageTypeCode() {
        return messageTypeCode;
    }
}
