/* hjUDPproxy, for use in 2024
 */

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.MulticastSocket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

class hjUDPproxy {
    public static void main(String[] args) throws Exception {
        if (args.length != 7)
        {
            System.out.println("Use: hjUDPproxy <username> <password> <server> <tcpPort> <movie> <udpPort> <endpoint2>");
            System.out.println("<username>: username for SHP exchange");
            System.out.println("<password>: password for SHP exchange");
            System.out.println("<server>: hostname of media player");
            System.out.println("<tcpPort>: TCP port for SHP exchange");
            System.out.println("<movie>: the movie requested");
            System.out.println("<udpPort>: port for DSTP exchange");
            System.out.println("<endpoint2>: endpoint of media player");

            System.out.println("Ex: hjUDPproxy alice@gmail.com password 224.2.2.2 1337 movies/cars.dat 9000 127.0.0.1:8888");
            System.out.println("Ex: hjUDPproxy alice@gmail.com password 127.0.0.1 1337 movies/cars.dat 10000 127.0.0.1:8888");
            System.exit(0);
        }

        String shpUsername = args[0];
        String shpPwd = args[1];
        String salt = "KgplqWYHvK/7ebSKnG2FWg=="; // assumed it is known by user because not in the message flow specifications
        String shpHostname = args[2];
        int shpPort = Integer.parseInt(args[3]);
        String request = args[4];
        int udpPort = Integer.parseInt(args[5]);
        String destinations=args[6]; //resend mediastream to this destination endpoint

        InetSocketAddress inSocketAddress = new InetSocketAddress(shpHostname, udpPort);
        String cryptoConfigName = "configuration.txt";
        SHPClient shpClient = new SHPClient(shpHostname, shpPort, "ClientECCKeyPair.sec", "ServerECCPubKey.sec", shpUsername, shpPwd, salt, udpPort, request, cryptoConfigName);
        shpClient.client_shp_phase1();

        DSTPConfig config = new DSTPConfig(cryptoConfigName);

        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

        DSTPSocket dstpSocket = null;

        if(inSocketAddress.getAddress().isMulticastAddress()){
            MulticastSocket ms = new MulticastSocket(inSocketAddress.getPort());
            ms.joinGroup(InetAddress.getByName(inSocketAddress.getHostName()));
            dstpSocket = new DSTPSocket(ms, config);
        }
        else{
            DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
            dstpSocket = new DSTPSocket(inSocket, config);
        }
        int countframes=0;
        DatagramSocket outSocket = new DatagramSocket();

        byte[] buffer = new byte[4 * 1024];
        System.out.println("Sending frames...");
        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            byte[] decryptedData = dstpSocket.receive(inPacket);

            for (SocketAddress outSocketAddress : outSocketAddressSet)
            {
                outSocket.send(new DatagramPacket(decryptedData, inPacket.getLength(), outSocketAddress));
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress)
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
