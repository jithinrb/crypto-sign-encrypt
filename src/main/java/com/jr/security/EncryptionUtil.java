import static java.lang.String.format;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class EncryptionUtil {
    
    /**
     * Read public key file from a path
     * @param sPath
     * @return
     * @throws Exception
     */
    public PublicKey loadPublicKey(String sPath) throws Exception {
        byte[] publicKeyBytes = getClass().getResourceAsStream(sPath).readAllBytes();

        KeyFactory publicKeyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = publicKeyFactory.generatePublic(publicKeySpec);
        return publicKey;
    }

    /**
     * Encrypt payload  with given public key
     * @param payload
     * @param publicKey
     * @return : Encrypted payload in Base64 encoded format
     * @throws Exception
     */
    public String encryptPayload(byte[] payload,PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytes = cipher.doFinal(payload);
        return new String(Base64.getEncoder().encode(bytes));
    }

    /**
     * Load Private key form a path
     * @param sPath
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public PrivateKey loadPrivateKey(String sPath) throws Exception {
        // reading from resource folder
        byte[] privateKeyBytes = getClass().getResourceAsStream(sPath).readAllBytes();

        KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = privateKeyFactory.generatePrivate(privateKeySpec);
        return privateKey;
    }
    
    /**
     * Decrypt a payload using private key
     * @param payload
     * @param privateKey
     * @return
     * @throws Exception
     */
    public String decryptPayload(byte[] payload,PrivateKey privateKey) throws Exception {    
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
    
        byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(payload));
        return new String(bytes);
    
    }

    /**
     * Main to unit test the class
     * @param args
     * @throws Exception
     */
    public static void main(String args[]) throws Exception{
        //Payload
        String message = "Lorem ipsum dolor sit amet, ";
        
        // Test instance for EncryptionUtil        
        EncryptionUtil eUtil = new EncryptionUtil();

        // Test Loading public Key
        PublicKey pubKey = eUtil.loadPublicKey("/keystore/public_key.der");
        System.out.println(format("Public Key with format '%s' Loaded Successfully.....",pubKey.getFormat()));
        
        // Test encryption using public key
        String sEncrypted = eUtil.encryptPayload(message.getBytes(StandardCharsets.UTF_8), pubKey);
        System.out.println(format("Encrypted payload - \n%s",sEncrypted));

        // Test Loading Private Key
        PrivateKey privKey = eUtil.loadPrivateKey("/keystore/private_key.der");
        System.out.println(format("Private Key with format '%s' Loaded Successfully.....",privKey.getFormat()));

        String sDecrypted = eUtil.decryptPayload(sEncrypted.getBytes(), privKey);
        System.out.println(format("Decrypted Payload - %s\nOriginal Payload - %s",sDecrypted,message));
       

    }
}
