/*
* hjStreamServer.java 
* Streaming server: emitter of video streams (movies)
* Can send in unicast or multicast IP for client listeners
* that can play in real time the transmitted movies
*/

import java.io.*;
import java.net.*;

class hjStreamServer {

	static public void main( String []args ) throws Exception {

		String serverHost = "127.0.0.1";
		int tcpPort = 1337;
		String cryptoConfigFilename = "configuration.txt";
		String userDbFile = "userdatabase.txt";
		String keyPairFile = "ServerECCKeyPair.sec";

		SHPServer shpServer = new SHPServer(serverHost, tcpPort, userDbFile, keyPairFile, cryptoConfigFilename);
		shpServer.server_shp_phase1();


		DSTPConfig config= new DSTPConfig(cryptoConfigFilename);

		int size;
		int count = 0;
 		long time;
		DataInputStream g = new DataInputStream( new FileInputStream(shpServer.request) );
		InetSocketAddress addr =
		    new InetSocketAddress(serverHost,shpServer.udpPort);

		DSTPSocket dstpSocket = null;
		if(addr.getAddress().isMulticastAddress()){
			MulticastSocket ms = new MulticastSocket();
			dstpSocket = new DSTPSocket(ms, config);
		}
		else{
			DatagramSocket s = new DatagramSocket();
			dstpSocket = new DSTPSocket(s, config);
		}

		long t0 = System.nanoTime(); // tempo de referencia
		long q0 = 0;

		while ( g.available() > 0 ) {
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time; // tempo de referencia no stream
			count += 1;
			byte[] buff = new byte[size];
			g.readFully(buff,0,size);
			dstpSocket.send(buff, addr.getAddress(), addr.getPort());
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );

			System.out.print( "." );
		}

		System.out.println("\nEND ! packets with frames sent: "+count);
	}

}
