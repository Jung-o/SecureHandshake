public class Message1 extends Message {
    private static final long serialVersionUID = 1L;
    private String userId;

    public Message1(byte protocolVersion, byte protocolRelease) {
        super(protocolVersion, protocolRelease, MessageType.MSG1.getTypeCode()); // Message type 1
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}