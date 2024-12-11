

import java.net.InetAddress;
import java.net.UnknownHostException;
class UseException extends Exception {
	public UseException() {
		super();
	}

	public UseException(String s) {
		super(s);
	}
}

public class TFTPClient {
	public static void main(String argv[]) throws TftpException, UseException {
		String host = "";
		String fileName = "";
		String mode="octet"; //default mode
		String type="";

		String shpUsername = "";
		String shpPwd = "";
		String salt = "KgplqWYHvK/7ebSKnG2FWg=="; // assumed it is known by user because not in the message flow specifications
		int shpPort = 0;
		try {
			// Process command line
			if (argv.length < 6)
				throw new UseException("--Usage-- \nocter mode:  TFTPClient [shpUsername] [shpPassword] [host] [shpTcpPort] [Type(R/W?)] [filename] \nother mode:  TFTPClient [shpUsername] [shpPassword] [host] [shpTcpPort] [Type(R/W?)] [filename] [mode]" );
			//use default mode(octet)
			if(argv.length == 6){
				shpUsername = argv[0];
				shpPwd = argv[1];
				host =argv[2];
				shpPort = Integer.parseInt(argv[3]);
			    type = argv[argv.length - 2];
			    fileName = argv[argv.length - 1];}
			//use other modes
			else if(argv.length == 7){
				shpUsername = argv[0];
				shpPwd = argv[1];
				host =argv[2];
				shpPort = Integer.parseInt(argv[3]);
				mode =argv[argv.length-1];
				type = argv[argv.length - 3];
				fileName = argv[argv.length - 2];
			}
			else throw new UseException("wrong command. \n--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]");
			
			
			InetAddress server = InetAddress.getByName(host);
			
			//process read request
			if(type.matches("R")){
				TFTPclientRRQ r = new TFTPclientRRQ(server, fileName, mode, shpUsername, shpPwd, salt, shpPort);}
			//process write request
			else if(type.matches("W")){
				TFTPclientWRQ w = new TFTPclientWRQ(server, fileName, mode, shpUsername, shpPwd, salt, shpPort);
			}
			else{throw new UseException("wrong command. \n--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]");}
			
		} catch (UnknownHostException e) {
			System.out.println("Unknown host " + host);
		} catch (UseException e) {
			System.out.println(e.getMessage());
		}
	}
}