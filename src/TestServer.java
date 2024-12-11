public class TestServer {
    public static void main(String[] args) throws Exception {
        SHPServer server = new SHPServer(12345, "userdatabase.txt", "ServerECCKeyPair.sec");
        server.server_shp_phase1();
    }
}