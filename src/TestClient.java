public class TestClient {
    public static void main(String[] args) throws Exception {
        String userId = "alice@gmail.com";
        String pwd = "password";
        String salt = "KgplqWYHvK/7ebSKnG2FWg==";
        String request = "block";
        String cryptoConfig = "configuration-client-" + request + ".txt";
        SHPClient client = new SHPClient("localhost", 12345, "ClientECCKeyPair.sec",
                userId, pwd, salt, 1234, request, cryptoConfig);
        client.client_shp_phase1();
    }
}