import java.io.BufferedReader;
import java.io.FileReader;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECCKeyInfo {
    private String curve;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public ECCKeyInfo() {
    }

    public ECCKeyInfo(byte[] publicKeyBytes) {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory ;
        try{
            keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            this.publicKey =  keyFactory.generatePublic(keySpec);
        }catch (Exception e) {}
    }

    public String getCurve() {
        return curve;
    }

    public void setCurve(String curve) {
        this.curve = curve;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public static ECCKeyInfo readKeyFromFile(String filePath) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(filePath));
        ECCKeyInfo keyInfo = new ECCKeyInfo();
        String line;

        while ((line = reader.readLine()) != null) {
            if (line.startsWith("Curve:")) {
                keyInfo.setCurve(line.split(":")[1].trim());
            } else if (line.startsWith("PrivateKey:")) {
                String privateKeyBase64 = line.split(":")[1].trim();
                if (privateKeyBase64.equals("null")) {continue;}
                PrivateKey privateKey = loadPrivateKeyFromString(privateKeyBase64);
                keyInfo.setPrivateKey(privateKey);
            } else if (line.startsWith("PublicKey:")) {
                String publicKeyBase64 = line.split(":")[1].trim();
                PublicKey publicKey = loadPublicKeyFromString(publicKeyBase64);
                keyInfo.setPublicKey(publicKey);
            }
        }

        reader.close();
        return keyInfo;
    }

    public static PrivateKey loadPrivateKeyFromString(String base64PrivateKey) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(base64PrivateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        return keyFactory.generatePrivate(keySpec);
    }

    private static PublicKey loadPublicKeyFromString(String base64PublicKey) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        return keyFactory.generatePublic(keySpec);
    }

}