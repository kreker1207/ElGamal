import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class Main {
    public static void main(String[] args) {
        BigInteger p = generatePrime(10, 20);
        System.out.println("p: "+p);
        BigInteger g = generatePrimitiveRoot(p);
        System.out.println("g: "+g);
        BigInteger a = generatePrivateKey(p);
        System.out.println("a: "+a);
        BigInteger b = g.modPow(a, p);
        System.out.println("b: "+b);
        String message = "Hello, world!";
        BigInteger[] signature = sign(message, p, g, a);
        boolean verified = verify(message, signature, p, g, b);
        System.out.println("Signature verified: " + verified);
    }

    private static BigInteger generatePrime(int lowerBound, int upperBound) {
        Random random = new Random();
        int bitLength = random.nextInt(upperBound - lowerBound) + lowerBound;
        return BigInteger.probablePrime(bitLength, random);
    }

    private static BigInteger generatePrimitiveRoot(BigInteger p) {
        BigInteger TWO = BigInteger.valueOf(2);
        BigInteger phi = p.subtract(BigInteger.ONE);
        for (BigInteger i = TWO; i.compareTo(p) < 0; i = i.add(BigInteger.ONE)) {
            if (phi.gcd(i).equals(BigInteger.ONE)) {
                boolean isPrimitiveRoot = true;
                for (BigInteger j = TWO; j.compareTo(phi) < 0; j = j.add(BigInteger.ONE)) {
                    if (i.modPow(j, p).equals(BigInteger.ONE)) {
                        isPrimitiveRoot = false;
                        break;
                    }
                }
                if (isPrimitiveRoot) {
                    return i;
                }
            }
        }

        return BigInteger.ZERO;
    }


    private static BigInteger generatePrivateKey(BigInteger p) {
        Random random = new Random();
        return new BigInteger(p.bitLength() - 1, random);
    }

    private static BigInteger[] sign(String message, BigInteger p, BigInteger g, BigInteger a) {
        BigInteger[] signature = new BigInteger[2];
        BigInteger hashedMessage = hashMessage(message);
        Random random = new Random();
        BigInteger k;
        BigInteger inverseK;

        do {
            k = new BigInteger(p.bitLength() - 1, random);

            // Check if k and p-1 are coprime
            if (!k.gcd(p.subtract(BigInteger.ONE)).equals(BigInteger.ONE)) {
                continue; // Regenerate k if they share a common factor
            }

            BigInteger r = g.modPow(k, p);
            inverseK = k.modInverse(p.subtract(BigInteger.ONE));

            BigInteger s = hashedMessage.subtract(a.multiply(r)).multiply(inverseK).mod(p.subtract(BigInteger.ONE));

            signature[0] = r;
            signature[1] = s;
            return signature;

        } while (true);
    }

    private static boolean verify(String message, BigInteger[] signature, BigInteger p, BigInteger g, BigInteger b) {
        BigInteger r = signature[0];
        BigInteger s = signature[1];
        BigInteger hashedMessage = hashMessage(message);

        BigInteger y = b.modPow(BigInteger.ONE.negate(), p);

        // Check if s has a modular inverse
        if (s.gcd(p.subtract(BigInteger.ONE)).equals(BigInteger.ONE)) {
            BigInteger u1 = hashedMessage.multiply(s.modInverse(p.subtract(BigInteger.ONE))).mod(p.subtract(BigInteger.ONE));
            BigInteger u2 = r.multiply(s.modInverse(p.subtract(BigInteger.ONE))).mod(p.subtract(BigInteger.ONE));
            BigInteger v = g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p);

            return v.equals(r);
        } else {
            // Handle the case where s doesn't have a modular inverse
            System.out.println("s does not have a modular inverse");
            return false;
        }
    }

    private static BigInteger hashMessage(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(message.getBytes());
            return new BigInteger(1, hashBytes);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
        }
        return BigInteger.ZERO;
    }
}