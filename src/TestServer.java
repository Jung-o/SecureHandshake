public class TestServer {
    public static void main(String[] args) throws Exception {
        String hostname = "127.0.0.1";
        SHPServer server = new SHPServer(hostname, 12345, "userdatabase.txt", "ServerECCKeyPair.sec", "configuration-block.txt");
        server.server_shp_phase1();
    }
}