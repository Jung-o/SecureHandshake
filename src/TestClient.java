public class TestClient {
    public static void main(String[] args) throws Exception {
        SHPClient client = new SHPClient("localhost", 12345, "ClientECCKeyPair.sec",
                "alice@gmail.com");
        client.connect();
    }
}