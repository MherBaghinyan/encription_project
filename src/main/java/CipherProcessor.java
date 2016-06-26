import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;

public class CipherProcessor {


    protected CipherProcessor() {

    }

    public static void main(String[] args) {
        System.out.println(asciiToHex("16symbolpassword"));
    }


    public static String asciiToHex(String ascii) {
        return String.format("%x", new BigInteger(1, ascii.getBytes())).toUpperCase();
    }

    public static String processSalt(String salt, int length) {
        int difference = length - salt.length(); //how much times we need to add FF
        StringBuilder processedSalt = new StringBuilder(asciiToHex(salt));
        if (difference > 0) {
            for (int i = 0; i < difference; i++) {
                processedSalt.append("FF");
            }
        }
        return processedSalt.toString();
    }
    
    
    public static String ASCII2HEX(String in) {        
        StringBuilder out = new StringBuilder(asciiToHex(in));
        
        return out.toString().toUpperCase();
    }
    

    /**
     * @param key  - ASCII, must be 16-length
     * @param text - ASCII
     * @param iv   - HEX, must be 16-length
     */

    public static String AES256(String key, String text, String iv) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Hex.decodeHex(iv.toCharArray()));
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));
            return Hex.encodeHexString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * @param text - must be HEX
     * @param salt - must be HEX
     */
    public static String hmacSHA256(String text, String salt, int iterations) {
        try {
            String processedText = text.replace(" ", "");
            String processedSalt = salt.replace(" ", "");
            Security.addProvider(new BouncyCastleProvider());
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(processedSalt.getBytes("UTF-8"), "HmacSHA256");  //substring(12) for DGI0701
            sha256_HMAC.init(secret_key);
            byte[] result = sha256_HMAC.doFinal(processedText.getBytes("UTF-8"));
//            String result = Hex.encodeHexString(sha256_HMAC.doFinal(text.getBytes("UTF-8"),iterations)).toUpperCase(); //first iteration
            for (int i = 1; i < iterations; i++) {
                result = sha256_HMAC.doFinal(result);
            }
            return Hex.encodeHexString(result);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
    
    public static void TestSHA256(){
    	
    	String [] textf = {"1","123456789012,123456789012345678","4","abc","abcdefghijkl"}; //%s FORMAT_ID (1) 1; ABA_NUMBER (6) 123456789012; BANK_ACCOUNT_NUMBER (9) 123456789012345678; BANK_ACCOUNT_TYPE (1) 4; ISSUING_DEVICE (3) abc; RFU (12)  
    	//String text = "11234567890121234567890123456781abcabcdefghijkl"; 
    	String text = Arrays.toString(textf);
    	text = text.replace("[", "").replace("]", "").replace(",", "").replace(" ", "");
    	String salt = "sha256geheim";

		String h_text = ASCII2HEX(text);
		System.out.println("Text[ASCII]: ");                        
		System.out.println(text);  		
		System.out.println("Text[HEX]: ");                        
		System.out.println(h_text);  		
		
		System.out.println("Salt[ASCII]: ");                        
		System.out.println(salt);  		
		String h_salt = processSalt(salt, 16);
		System.out.println("Salt[HEX]: ");                        
		System.out.println(h_salt);
		
		int iter = 10000;
		System.out.println("Iterations[%d]: ");                        
		System.out.println(iter);		
		
		String result = hmacSHA256(h_text, h_salt, iter).toUpperCase();
		System.out.println("SHA256: ");                        
		System.out.println(result);    	    	    	
    }        
    

}
