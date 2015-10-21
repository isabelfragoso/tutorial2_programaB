package rc4;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class RC4 {
    private final byte[] S = new byte[256];
    private final byte[] T = new byte[256];
    private final int keylen;

    public RC4(final byte[] key) {
        if (key.length < 1 || key.length > 256) {
            throw new IllegalArgumentException(
                    "key must be between 1 and 256 bytes");
        } else {
            keylen = key.length;
            for (int i = 0; i < 256; i++) {
                S[i] = (byte) i;
                T[i] = key[i % keylen];
            }
            int j = 0;
            byte tmp;
            for (int i = 0; i < 256; i++) {
                j = (j + S[i] + T[i]) & 0xFF;
                tmp = S[j];
                S[j] = S[i];
                S[i] = tmp;
            }
        }
    }

   

    public byte[] encrypt(final byte[] plaintext) {
        
        final byte[] ciphertext = new byte[plaintext.length];
        int i = 0, j = 0, k, t;
        byte tmp;
        for (int counter = 0; counter < plaintext.length; counter++) {
            i = (i + 1) & 0xFF;
            j = (j + S[i]) & 0xFF;
            tmp = S[j];
            S[j] = S[i];
            S[i] = tmp;
            t = (S[i] + S[j]) & 0xFF;
            k = S[t];
            ciphertext[counter] = (byte) (plaintext[counter] ^ k);
        }
        return ciphertext;
    }

    public byte[] decrypt(final byte[] ciphertext) {
        System.out.println("\nDecrypting File");
        return encrypt(ciphertext);
       
    }
    
    public static void genkey(String keyfilepath) throws IOException{
		try{
		System.out.println("\nGenerating 128 bit key...");
		Path kfp = Paths.get(keyfilepath);
		KeyGenerator gerador = KeyGenerator.getInstance("RC4");
		gerador.init(128); //e' dito que a chave devera' ter 128-bits
                SecretKey key = gerador.generateKey();
		System.out.println("\nKey generated, look at "+keyfilepath+"");
		Files.write(kfp,key.getEncoded());
                
	}
	catch ( NoSuchAlgorithmException | IOException e){
		System.err.println("Erro!"+ e);
	}

	}
    
    public static void main(String[] args) throws UnsupportedEncodingException, IOException
    {
        
         Boolean fail=false;
        
        if(args.length==0)
        {
            fail=true;
        }else
        {
            switch (args[0]){
                case "-genkey":
                    if(args.length==2)
                    {
                       genkey(""+args[1]);
                    }
                else{
                            fail=true;
                            System.err.println("\n Error, missing argument!");
                        }   break;
                case "-enc":
                        if(args.length==4)
                        {
                            System.out.println("\nEncrypting File");
                            Path kfp=Paths.get(args[1]);
                            Path ifp=Paths.get(args[2]);
                            Path ofp=Paths.get(args[3]);
                            final byte[] keyByte= Files.readAllBytes(kfp);
                            RC4 rc4 = new RC4(keyByte);
                            final byte[] plainByte= Files.readAllBytes(ifp);
                            final byte[] ciphertext = rc4.encrypt(plainByte);
                            Files.write(ofp,ciphertext);
                            System.out.println("\nFile Encrypted");
                        }
                        else{
                            fail=true;
                            System.err.println("\n Error, missing argument!");
                            
                        }break;
                case "-dec":
                        if(args.length==4)
                        {
                            Path kfp=Paths.get(args[1]);
                            Path efp=Paths.get(args[2]); //ficheiro encriptado
                            Path dfp=Paths.get(args[3]); // ficheiro de saída
                            final byte[] keyByte= Files.readAllBytes(kfp);
                            RC4 rc4 = new RC4(keyByte);
                            final byte[] ciphertext = Files.readAllBytes(efp);
                            final byte[] plaintext = rc4.decrypt(ciphertext); 
                            Files.write(dfp,plaintext);   
                            System.out.println("\nFile Decrypted");
                            
                        }
                else
                        {
                            fail=true;
                            System.err.println("\n Error, missing argument!");
                        }break;
 
            }
        }
    }
}

