package signature;

import sha1simplified.SimplifiedSHA1;
import util.Validation;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Demonstrates RSA signing with Simplified SHA-1 and a short RSA encryption/decryption round trip.
 */
public final class SignatureDemo {

    private SignatureDemo() {
    }

    public static void run() {
        SimplifiedSHA1 sha1 = new SimplifiedSHA1(false);
        RSASignatureService.RsaKeyMaterial bob = RSASignatureService.generateKeyPair();

        String x = "Signed and encrypted demo message!";
        Validation.requireNonEmpty(x, "plaintext x");

        String zHex = sha1.hash(x);
        BigInteger z = RSASignatureService.digestStringToInteger(sha1, x);
        BigInteger signature = RSASignatureService.sign(z, bob);

        BigInteger v = RSASignatureService.recoverDigest(signature, bob);

        System.out.println("--- RSA digital signature (Simplified SHA-1) ---");
        System.out.println("Bob's modulus n (bit length): " + bob.n().bitLength());
        System.out.println("Public exponent e: " + bob.e());
        System.out.println("Plaintext x: " + x);
        System.out.println("z = H(x) digest (hex): " + zHex);
        System.out.println("z as BigInteger: " + z);
        System.out.println("Signature (z^d mod n): " + signature);
        System.out.println("v = recovered digest (signature^e mod n): " + v);
        System.out.println("z == v: " + z.equals(v));
        System.out.println("Verify via helper: "
                + RSASignatureService.verifyMessage(x, signature, bob, sha1));
        System.out.println();

        // Encryption demo: pack short UTF-8 plaintext into integer < n (fixed-width padding)
        String plainShort = "Hello from Alice!";
        byte[] msgBytes = plainShort.getBytes(StandardCharsets.UTF_8);
        byte[] padded = new byte[32];
        System.arraycopy(msgBytes, 0, padded, 0, Math.min(msgBytes.length, padded.length));
        BigInteger mInt = RSASignatureService.bytesToPositiveBigEndian(padded);
        if (mInt.compareTo(bob.n()) >= 0) {
            throw new IllegalStateException("Demo message too large for this modulus.");
        }

        BigInteger c = RSASignatureService.rsaEncrypt(mInt, bob);
        BigInteger mDec = RSASignatureService.rsaDecrypt(c, bob);
        String recovered = RSASignatureService.utf8FromPaddedBytes(RSASignatureService.bigIntegerToUnsignedBytes(mDec, 32));

        System.out.println("--- RSA encryption demo (same key pair) ---");
        System.out.println("Original: " + plainShort);
        System.out.println("Ciphertext (integer): " + c);
        System.out.println("Decrypted text: " + recovered);
        System.out.println("Round-trip OK: " + plainShort.equals(recovered));
    }
}
