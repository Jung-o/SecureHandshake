import java.net.*;
import java.io.*;
import java.util.*;

public class TFTPServer {

	public static void main(String argv[]) {
		try {
			if (argv.length == 0){
				System.out.println("Use: TFTPServer <tcpPort>");
				System.out.println("Ex: TFTPServer 1337");
				System.exit(0);
			}
			String serverHost = "127.0.0.1";
			int tcpPort = Integer.parseInt(argv[0]);
			String cryptoConfigFilename = "configuration.txt";
			String userDbFile = "userdatabase.txt";
			String keyPairFile = "ServerECCKeyPair.sec";

			SHPServer shpServer = new SHPServer(serverHost, tcpPort, userDbFile, keyPairFile, cryptoConfigFilename);
			//use port 6973
			DatagramSocket sock = new DatagramSocket(6973);

			System.out.println("Server Ready.  Port:  " + sock.getLocalPort());

			// Listen for requests
			while (true) {
				shpServer.server_shp_phase1();
				DSTPConfig config = new DSTPConfig(cryptoConfigFilename);
				DSTPSocket safeSocket = new DSTPSocket(sock, config);
				TFTPpacket in = TFTPpacket.receive(safeSocket);
				// receive read request
				if (in instanceof TFTPread) {
					System.out.println("Read Request from " + in.getAddress());
					TFTPserverRRQ r = new TFTPserverRRQ((TFTPread) in);
				}
				// receive write request
				else if (in instanceof TFTPwrite) {
					System.out.println("Write Request from " + in.getAddress());
					TFTPserverWRQ w = new TFTPserverWRQ((TFTPwrite) in);
				}
			}
		} catch (SocketException e) {
			System.out.println("Server terminated(SocketException) " + e.getMessage());
		} catch (TftpException e) {
			System.out.println("Server terminated(TftpException)" + e.getMessage());
		} catch (IOException e) {
			System.out.println("Server terminated(IOException)" + e.getMessage());
		} catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}