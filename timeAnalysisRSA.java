import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;

public class timeAnalysisRSA {
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static List<Long> keyGenTimes = new ArrayList<Long>();
    private static List<Long> encrTimes = new ArrayList<Long>();
    private static List<Long> decrTimes = new ArrayList<Long>();
    public static byte[] encrptedMessage;

    public static byte[] encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] data)  throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    public static void main(String[] args) {
        calculateTime(1024*1, 117);

        for (int i=1; i<=5; i++) {
            calculateTime(1024*i, ((1024*i)/8)-11 );
        }
        keyGenTimes.remove(0);
        encrTimes.remove(0);
        decrTimes.remove(0);
        System.out.println("Key Generation times: "+ keyGenTimes);
        System.out.println("Encryption Times: "+encrTimes);
        System.out.println("Decryption Times: "+decrTimes);
    }

    public static void calculateTime(int keyInBits, int randomDataSize) {

        try{
            long time_k=0, time_e=0, time_d=0, timeElapsed;
            Instant start, end;
            System.out.println("###################################");
            System.out.println("Key Length : "+keyInBits + " bits/" + (keyInBits / 8) + " bytes, Plain Data Length :"+randomDataSize);
            String data = getRandomString(randomDataSize);

            for (int i=0; i<10; i++) {

                start = Instant.now();
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(keyInBits);
                KeyPair pair = keyGen.generateKeyPair();
                privateKey = pair.getPrivate();
                publicKey = pair.getPublic();
                end = Instant.now();
                timeElapsed = Duration.between(start, end).toNanos();
                timeElapsed = TimeUnit.MICROSECONDS.convert(timeElapsed, TimeUnit.NANOSECONDS);
                time_k += timeElapsed;

                start = Instant.now();
                encrptedMessage = encrypt(data);
                end = Instant.now();
                timeElapsed = Duration.between(start, end).toNanos();
                timeElapsed = TimeUnit.MICROSECONDS.convert(timeElapsed, TimeUnit.NANOSECONDS);
                time_e += timeElapsed;

                start = Instant.now();
                String decryptedString = decrypt(encrptedMessage);
                if(!data.equals(decryptedString)) {
                    System.out.println("Error!!!");
                }
                end = Instant.now();
                timeElapsed = Duration.between(start, end).toNanos();
                timeElapsed = TimeUnit.MICROSECONDS.convert(timeElapsed, TimeUnit.NANOSECONDS);
                time_d += timeElapsed;
            }

            System.out.println("Key Generation Time Taken in MicroSec: " + (time_k/10));
            System.out.println("Encryption Time Taken in MicroSec: " + (time_e/10));
            System.out.println("Decryption Time Taken in MicroSec: " + (time_d/10));
            keyGenTimes.add(time_k/10);
            encrTimes.add(time_e/10);
            decrTimes.add(time_d/10);
        }
        catch (Exception e) {
            System.err.println(e.getMessage());
        }

    }


    // function to generate a random string of length n
    static String getRandomString(int n) {
        // chose a Character random from this String
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz";
        // create StringBuffer size of AlphaNumericString
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            // generate a random number between 0 to AlphaNumericString variable length
            int index = (int) (AlphaNumericString.length() * Math.random());
            // add Character one by one in end of sb
            sb.append(AlphaNumericString.charAt(index));
        }
        return sb.toString();
    }
}

