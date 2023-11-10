import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import static java.lang.String.format;

import java.nio.charset.StandardCharsets;
public class DigitalSignUtil extends EncryptionUtil{


    /**
     * Sign a payload with a given private key
     * @param payload
     * @param privKey
     * @return
     * @throws Exception
     */
    public String generateSignature(byte[] payload,PrivateKey privKey,String signAlgo) throws Exception{
        //Creating a Signature object
        Signature sign = Signature.getInstance(signAlgo);
        
        //Initialize the signature & add data
        sign.initSign(privKey);
        sign.update(payload);

        // Issue signature 
        return Base64.getEncoder().encodeToString(sign.sign());
    }


    /**
     * Validate a signature using public key of the signer
     * @param signToVrify
     * @param pubKey
     * @param signAlgo
     * @return
     */
    public boolean verifySignature(byte[] payload, String signToVrify, PublicKey pubKey,String signAlgo)throws Exception{  
        //Creating a Signature object
        Signature sign = Signature.getInstance(signAlgo);

        //Initializing the signature with original data
        sign.initVerify(pubKey);
        sign.update(payload);

        //Verifying the signature
        return sign.verify(Base64.getDecoder().decode(signToVrify));
    }

    public static void main(String args[]) throws Exception{
        //Payload
       String message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Sed viverra tellus in hac habitasse platea dictumst vestibulum. Cursus mattis molestie a iaculis at. Id volutpat lacus laoreet non curabitur. Rhoncus est pellentesque elit ullamcorper dignissim. Ut ornare lectus sit amet est placerat in. Quisque egestas diam in arcu cursus euismod quis. Congue mauris rhoncus aenean vel elit scelerisque mauris pellentesque. Felis bibendum ut tristique et egestas quis ipsum suspendisse. Ornare suspendisse sed nisi lacus sed viverra tellus. Phasellus vestibulum lorem sed risus ultricies tristique nulla aliquet. Urna nunc id cursus metus aliquam eleifend mi.Leo in vitae turpis massa sed elementum tempus egestas. Tortor id aliquet lectus proin. Non blandit massa enim nec dui nunc mattis. Interdum consectetur libero id faucibus. Neque gravida in fermentum et. Volutpat maecenas volutpat blandit aliquam etiam. Massa placerat duis ultricies lacus sed turpis tincidunt id aliquet. Molestie a iaculis at erat. Tincidunt id aliquet risus feugiat. Leo a diam sollicitudin tempor id eu nisl. Bibendum neque egestas congue quisque.Sit amet cursus sit amet dictum sit amet justo. Rutrum quisque non tellus orci ac auctor augue. Est lorem ipsum dolor sit amet consectetur adipiscing. Ullamcorper a lacus vestibulum sed arcu non odio euismod lacinia. Nisl nisi scelerisque eu ultrices vitae auctor eu augue ut. Felis donec et odio pellentesque diam volutpat. Lectus magna fringilla urna porttitor rhoncus dolor purus. Consectetur purus ut faucibus pulvinar elementum integer. Est sit amet facilisis magna etiam tempor orci. Quis auctor elit sed vulputate mi sit amet mauris. Turpis tincidunt id aliquet risus feugiat in. Egestas diam in arcu cursus euismod. Nullam ac tortor vitae purus faucibus. Auctor elit sed vulputate mi. Neque convallis a cras semper auctor neque vitae tempus quam. Sagittis eu volutpat odio facilisis. Turpis egestas integer eget aliquet. Congue mauris rhoncus aenean vel elit.Amet dictum sit amet justo. Aliquam id diam maecenas ultricies mi eget mauris. In ante metus dictum at tempor commodo ullamcorper. Faucibus et molestie ac feugiat. Elementum integer enim neque volutpat. Viverra accumsan in nisl nisi scelerisque. Rutrum tellus pellentesque eu tincidunt tortor aliquam nulla facilisi cras. Amet volutpat consequat mauris nunc. Ultrices mi tempus imperdiet nulla malesuada. Aliquam nulla facilisi cras fermentum odio eu feugiat pretium. Dui vivamus arcu felis bibendum ut tristique et egestas quis. Id donec ultrices tincidunt arcu non sodales. Risus viverra adipiscing at in. Amet tellus cras adipiscing enim eu turpis. Amet commodo nulla facilisi nullam vehicula ipsum. Mi proin sed libero enim sed. Sit amet tellus cras adipiscing enim.Consectetur a erat nam at. Sollicitudin ac orci phasellus egestas. Lectus arcu bibendum at varius vel pharetra vel turpis. Nunc mi ipsum faucibus vitae aliquet. Neque convallis a cras semper auctor neque vitae. Suscipit adipiscing bibendum est ultricies integer quis. Sed arcu non odio euismod lacinia at quis. Adipiscing elit pellentesque habitant morbi. Id venenatis a condimentum vitae sapien pellentesque habitant morbi. Sit amet purus gravida quis blandit turpis cursus in. Odio euismod lacinia at quis risus sed vulputate odio. Vulputate dignissim suspendisse in est. Egestas congue quisque egestas diam in arcu cursus. Sed nisi lacus sed viverra tellus in hac habitasse. Laoreet sit amet cursus sit amet dictum sit. Non blandit massa enim nec dui nunc mattis enim ut. Ac orci phasellus egestas tellus rutrum.Scelerisque felis imperdiet proin fermentum leo vel orci porta non. Quam pellentesque nec nam aliquam sem et. Tristique nulla aliquet enim tortor at auctor urna nunc. Sed tempus urna et pharetra pharetra massa massa. Volutpat blandit aliquam etiam erat. Turpis tincidunt id aliquet risus feugiat. Lectus proin nibh nisl condimentum. Turpis egestas sed tempus urna et. Mi eget mauris pharetra et ultrices neque ornare. Pellentesque diam volutpat commodo sed egestas egestas fringilla phasellus. Tortor id aliquet lectus proin nibh nisl. Ac odio tempor orci dapibus ultrices in iaculis nunc sed. Etiam non quam lacus suspendisse faucibus interdum posuere. Ornare lectus sit amet est. In dictum non consectetur a erat nam at lectus. Diam vel quam elementum pulvinar etiam non quam lacus suspendisse.Morbi tempus iaculis urna id volutpat lacus laoreet non curabitur. Eget lorem dolor sed viverra ipsum nunc aliquet bibendum. Orci dapibus ultrices in iaculis nunc sed. Sit amet porttitor eget dolor morbi non. Mollis nunc sed id semper risus in hendrerit gravida rutrum. Nunc sed velit dignissim sodales ut eu sem. Tristique senectus et netus et. Sapien nec sagittis aliquam malesuada bibendum arcu. Et netus et malesuada fames ac turpis egestas maecenas. Semper risus in hendrerit gravida. Sit amet tellus cras adipiscing enim eu. Adipiscing tristique risus nec feugiat in. Velit ut tortor pretium viverra.Nunc vel risus commodo viverra maecenas accumsan lacus vel. Scelerisque viverra mauris in aliquam sem fringilla. Sit amet nisl suscipit adipiscing bibendum est ultricies. Sed lectus vestibulum mattis ullamcorper velit. Porttitor leo a diam sollicitudin. Sagittis nisl rhoncus mattis rhoncus urna. Euismod nisi porta lorem mollis aliquam ut porttitor. Pretium viverra suspendisse potenti nullam. Eu nisl nunc mi ipsum faucibus. Id volutpat lacus laoreet non. Bibendum at varius vel pharetra. Congue mauris rhoncus aenean vel elit scelerisque mauris pellentesque. Quam adipiscing vitae proin sagittis nisl. In dictum non consectetur a erat nam at lectus.Aliquet sagittis id consectetur purus. Magnis dis parturient montes nascetur ridiculus mus. Egestas dui id ornare arcu odio. Congue mauris rhoncus aenean vel elit scelerisque. Morbi blandit cursus risus at ultrices. In hac habitasse platea dictumst vestibulum rhoncus est pellentesque elit. Fusce id velit ut tortor pretium viverra. Dolor sed viverra ipsum nunc aliquet bibendum enim facilisis. Nec sagittis aliquam malesuada bibendum arcu vitae elementum curabitur. Nibh nisl condimentum id venenatis a condimentum vitae sapien. Viverra tellus in hac habitasse platea dictumst. Tellus in hac habitasse platea dictumst. Vulputate mi sit amet mauris commodo. Adipiscing commodo elit at imperdiet dui accumsan sit amet.Quis enim lobortis scelerisque fermentum dui faucibus in. Vel orci porta non pulvinar. Eu tincidunt tortor aliquam nulla facilisi cras. Et egestas quis ipsum suspendisse ultrices gravida dictum. Risus nullam eget felis eget nunc lobortis mattis aliquam faucibus. Sem nulla pharetra diam sit amet nisl. Aenean euismod elementum nisi quis eleifend quam adipiscing vitae proin. Orci phasellus egestas tellus rutrum. Ac felis donec et odio. Vel risus commodo viverra maecenas accumsan lacus vel facilisis. Id volutpat lacus laoreet non. Nibh tortor id aliquet lectus proin nibh nisl condimentum. Porttitor rhoncus dolor purus non enim praesent elementum. Vel pharetra vel turpis nunc eget lorem dolor. Ac tincidunt vitae semper quis. Porttitor rhoncus dolor purus non enim praesent elementum.";

       // Test instance for DigitalSignUtil        
       DigitalSignUtil signUtil = new DigitalSignUtil();

       // Test Loading Private Key
       PrivateKey privKey = signUtil.loadPrivateKey("/keystore/private_key.der");
       System.out.println(format("Private Key with format '%s' Loaded Successfully.....",privKey.getFormat()));

       // Test Generating Signature
       String digiSign = signUtil.generateSignature(message.getBytes(StandardCharsets.UTF_8), privKey,"SHA3-512withRSA");
       System.out.println(format("Digital signature issued successfully - '%s' .........",digiSign));

       // Test Loading public Key
       PublicKey pubKey = signUtil.loadPublicKey("/keystore/public_key.der");
       System.out.println(format("Public Key with format '%s' Loaded Successfully.....",pubKey.getFormat()));       
       
       // Test  Signature Verification - Valid scenario
       boolean isValid = signUtil.verifySignature(message.getBytes(StandardCharsets.UTF_8), digiSign, pubKey, "SHA3-512withRSA");
       System.out.println(format("Signature status - %s",(isValid?"Valid":"Invalid")));   

       // Test  Signature Verification - Tampered scenario (Payload is different)
       isValid = signUtil.verifySignature(message.concat("Modified").getBytes(StandardCharsets.UTF_8), digiSign, pubKey, "SHA3-512withRSA");
       System.out.println(format("Signature status - %s",(isValid?"Valid":"Invalid"))); 

       // Test  Signature Verification - Valid scenario (With Message Digest)
       MessageDigestUtil mdUtil = new MessageDigestUtil();
       byte[] mdBytes = mdUtil.digestPayload(message, "SHA-256");
       System.out.println(format("Digest value generated for payload '%s'",Base64.getEncoder().encodeToString(mdBytes)));
       digiSign = signUtil.generateSignature(mdBytes, privKey,"SHA3-512withRSA");
       System.out.println(format("Digital signature issued successfully for digest- '%s' .........",digiSign));


     
    }
    
}
