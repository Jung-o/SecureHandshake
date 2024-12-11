import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class DSTPSocket {
    private final DatagramSocket socket;
    private final DSTPConfig config;
    private int sequenceNumber;
    private final Set<Integer> receivedSequenceNumbers;

    public DSTPSocket(int port, DSTPConfig config) throws Exception {
        this.socket = new DatagramSocket(port);
        this.config = config;
        this.sequenceNumber = 0;
        this.receivedSequenceNumbers = new HashSet<>();
    }

    public DSTPSocket(DatagramSocket socket, DSTPConfig config) {
        this.socket = socket;
        this.config = config;
        this.sequenceNumber = 0;
        this.receivedSequenceNumbers = new HashSet<>();
    }

    // Send encrypted packet
    public void send(byte[] data, InetAddress address, int port) throws Exception {
        DSTPPacket packet = new DSTPPacket(data, sequenceNumber++, config); // increments sequenceNumber after sending
        byte[] securePayload = packet.getPayload();

        // Create a DatagramPacket and send
        DatagramPacket datagramPacket = new DatagramPacket(securePayload, securePayload.length, address, port);
        socket.send(datagramPacket);
    }

    // Receive and decrypt packet, discarding invalid packets
    public byte[] receive(DatagramPacket packet) {
        while (true) {
            try {
                packet.setData(new byte[65536], 0, 65536);
                socket.receive(packet);

                byte[] receivedData = Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
                // Extract version number, release number, and payload size
                int versionNumber = ByteBuffer.wrap(Arrays.copyOfRange(receivedData, 0, 2)).getShort();
                int releaseNumber = ByteBuffer.wrap(Arrays.copyOfRange(receivedData, 2, 3)).get();
                int payloadSize = ByteBuffer.wrap(Arrays.copyOfRange(receivedData, 3, 5)).getShort();

                // Check if version number and release number match the config
                if (versionNumber != config.getVersion() || releaseNumber != config.getRelease()) {
                    throw new SecurityException("Version or release number mismatch");
                }

                // Check if the payload size matches the actual size of the encrypted payload
                byte[] encryptedPayload = Arrays.copyOfRange(receivedData, 5, receivedData.length);
                if (payloadSize != encryptedPayload.length) {
                    throw new SecurityException("Payload size mismatch");
                }

                byte[] decryptedDataWithSequence = DSTPPacket.decryptPacket(encryptedPayload, config);

                // Extract sequence number
                int sequenceNumber = ByteBuffer.wrap(Arrays.copyOfRange(decryptedDataWithSequence, 0, 2)).getShort();
                // Check for duplicate sequence number
                if (receivedSequenceNumbers.contains(sequenceNumber)) {
                    throw new SecurityException("Duplicate sequence number received: " + sequenceNumber);
                }

                // Store the received sequence number
                receivedSequenceNumbers.add(sequenceNumber);

                byte[] decryptedValidData = Arrays.copyOfRange(decryptedDataWithSequence, 2, decryptedDataWithSequence.length);
                packet.setData(decryptedValidData);

                return decryptedValidData;
            } catch (Exception e) {
                System.err.println("Discarding invalid packet: " + e.getMessage());
            }
        }
    }

    public byte[] receive(){
        DatagramPacket packet = new DatagramPacket(new byte[65536], 65536);
        return receive(packet);
    }

    // Close the socket
    public void close() {
        socket.close();
    }

    public DatagramPacket sendableDatagramPacket(byte[] data, InetAddress address, int port){
        try {
            DSTPPacket packet = new DSTPPacket(data, sequenceNumber++, config);
            byte[] securePayload = packet.getPayload();

            // Create a DatagramPacket and send
            return new DatagramPacket(securePayload, securePayload.length, address, port);
        }
        catch (Exception _) { }
        return null;
    }
}