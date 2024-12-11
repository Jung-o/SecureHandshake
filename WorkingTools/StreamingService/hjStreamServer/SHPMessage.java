import java.io.IOException;

public abstract class SHPMessage {
    private byte receivedVersion;
    private byte receivedRelease;
    protected byte messageType;

    public abstract void fromBytes(byte[] data) throws IOException;

    protected byte[] createHeader(byte protocolVersion, byte release, byte messageType) {
        byte headerFirstByte = (byte)((protocolVersion << 4) | (release & 0x0F));
        return new byte[]{headerFirstByte, messageType};
    }

    protected int parseHeader(byte[] data) {
        byte first = data[0];
        receivedVersion = (byte)((first & 0xF0) >> 4);
        receivedRelease = (byte)(first & 0x0F);
        messageType = data[1];
        return 2; // We consumed 2 bytes for the header
    }

    public byte getProtocolVersion() {
        return receivedVersion;
    }

    public byte getRelease() {
        return receivedRelease;
    }

    public byte getMessageType() {
        return messageType;
    }
}
