import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class ElGamalEncryption {
    public static void main(String[] args) {
        BigInteger p = ElGamalSignature.generatePrime(5, 15);
        BigInteger g = ElGamalSignature.generatePrimitiveRoot(p);
        BigInteger a = ElGamalSignature.generatePrivateKey(p);
        BigInteger b = g.modPow(a, p);
        String message = "Hello, world! This is a test message.";

        List<BigInteger[]> encryptedBlocks = encryptMessage(message, p, g, b);
        String decryptedMessage = decryptMessage(encryptedBlocks, p, a);
        System.out.println("Decrypted message: " + decryptedMessage);
    }

    private static List<BigInteger[]> encryptMessage(String message, BigInteger p, BigInteger g, BigInteger b) {
        List<BigInteger[]> encryptedBlocks = new ArrayList<>();
        byte[] bytes = message.getBytes();

        for (byte bVal : bytes) {
            BigInteger m = BigInteger.valueOf((long) bVal & 0xff); // Convert byte to positive integer
            Random random = new Random();
            BigInteger k = new BigInteger(p.bitLength() - 1, random);
            BigInteger x = g.modPow(k, p);
            BigInteger y = b.modPow(k, p).multiply(m).mod(p);

            BigInteger[] encryptedBlock = {x, y};
            encryptedBlocks.add(encryptedBlock);
        }
        return encryptedBlocks;
    }

    private static String decryptMessage(List<BigInteger[]> encryptedBlocks, BigInteger p, BigInteger a) {
        StringBuilder decryptedMessage = new StringBuilder();
        for (BigInteger[] block : encryptedBlocks) {
            BigInteger x = block[0];
            BigInteger y = block[1];
            BigInteger s = x.modPow(a, p);
            BigInteger m = y.multiply(s.modInverse(p)).mod(p);
            decryptedMessage.append((char) m.intValue());
        }
        return decryptedMessage.toString();
    }
}
