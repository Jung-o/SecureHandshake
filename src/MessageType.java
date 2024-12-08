public enum MessageType {
    MSG1((byte) 1),  // Message Type 1: from client (userId)
    MSG2((byte) 2),  // Message Type 2: from server (Nonces)
    MSG3((byte) 3),  // Message Type 3: from client (PBE, DigitalSig, HMAC)
    MSG4((byte) 4),  // Message Type 4: from server (Encryption, DigitalSig, HMAC)
    MSG5((byte) 5);  // Message Type 5: from client (data encrypted using crypto config)

    private final byte typeCode;

    MessageType(byte typeCode) {
        this.typeCode = typeCode;
    }

    public byte getTypeCode() {
        return typeCode;
    }

    // Get MessageType by its typeCode
    public static MessageType fromTypeCode(byte typeCode) {
        for (MessageType type : MessageType.values()) {
            if (type.getTypeCode() == typeCode) {
                return type;
            }
        }
        throw new IllegalArgumentException("Invalid type code: " + typeCode);
    }
}
