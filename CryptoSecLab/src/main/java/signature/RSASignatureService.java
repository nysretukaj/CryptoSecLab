package signature;

import sha1simplified.SimplifiedSHA1;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

/**
 * RSA key generation, signing and verifying digests produced by Simplified SHA-1.
 * The 32-bit hash is encoded as a {@link BigInteger} from its 8-hex-digit representation.
 */
public class RSASignatureService {

    private static final int DEFAULT_PRIME_BIT_LENGTH = 512;
    private static final SecureRandom RNG = new SecureRandom();

    /**
     * RSA public / private material for simplified demos (n is large; digest is only 32 bits).
     */
    public record RsaKeyMaterial(BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q) {
    }

    /**
     * Generate a random RSA key pair with {@code e = 65537} when gcd(phi, e) == 1.
     * Default prime size is 512 bits: good for 32-bit hash residues with quick key generation.
     */
    public static RsaKeyMaterial generateKeyPair() {
        return generateKeyPair(DEFAULT_PRIME_BIT_LENGTH);
    }

    /**
     * @param primeBitLength bit length for each prime {@code p}, {@code q}
     */
    public static RsaKeyMaterial generateKeyPair(int primeBitLength) {
        if (primeBitLength < 32) {
            throw new IllegalArgumentException("primeBitLength too small for safe RSA demos.");
        }
        BigInteger e = BigInteger.valueOf(65537);
        while (true) {
            BigInteger p = BigInteger.probablePrime(primeBitLength, RNG);
            BigInteger q = BigInteger.probablePrime(primeBitLength, RNG);
            if (p.equals(q)) {
                continue;
            }
            BigInteger n = p.multiply(q);
            BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
            if (phi.gcd(e).equals(BigInteger.ONE)) {
                BigInteger d = e.modInverse(phi);
                return new RsaKeyMaterial(n, e, d, p, q);
            }
        }
    }

    public static BigInteger digestStringToInteger(SimplifiedSHA1 sha1, String plaintext) {
        Objects.requireNonNull(plaintext, "plaintext");
        String hex = sha1.hash(plaintext);
        validateHashHex(hex);
        return new BigInteger(hex, 16);
    }

    public static BigInteger digestBytesToInteger(SimplifiedSHA1 sha1, byte[] data) {
        String hex = sha1.hashBytes(data);
        validateHashHex(hex);
        return new BigInteger(hex, 16);
    }

    static void validateHashHex(String hex) {
        String h = hex.trim().toUpperCase(Locale.ROOT);
        if (h.length() != 8 || !h.matches("[0-9A-F]{8}")) {
            throw new IllegalArgumentException("Expected 8-hex simplified digest, got: " + hex);
        }
    }

    /**
     * RSA signature: {@code signature = z^d mod n}.
     */
    public static BigInteger sign(BigInteger digestInt, RsaKeyMaterial keys) {
        if (digestInt.signum() < 0) {
            throw new IllegalArgumentException("digest must be non-negative.");
        }
        if (digestInt.compareTo(keys.n()) >= 0) {
            throw new IllegalArgumentException("Digest integer must be smaller than modulus n.");
        }
        return digestInt.modPow(keys.d(), keys.n());
    }

    /**
     * RSA verification: {@code v = sig^e mod n}.
     */
    public static BigInteger recoverDigest(BigInteger signature, RsaKeyMaterial keys) {
        return signature.modPow(keys.e(), keys.n());
    }

    public static BigInteger signMessage(String plaintext, RsaKeyMaterial keys, SimplifiedSHA1 sha1) {
        BigInteger z = digestStringToInteger(sha1, plaintext);
        return sign(z, keys);
    }

    public static boolean verifyMessage(String plaintext, BigInteger signature, RsaKeyMaterial keys,
                                       SimplifiedSHA1 sha1) {
        BigInteger z = digestStringToInteger(sha1, plaintext);
        BigInteger v = recoverDigest(signature, keys);
        return z.equals(v);
    }

    public static BigInteger rsaEncrypt(BigInteger messageInt, RsaKeyMaterial keys) {
        if (messageInt.signum() < 0 || messageInt.compareTo(keys.n()) >= 0) {
            throw new IllegalArgumentException("message integer must be in [0, n).");
        }
        return messageInt.modPow(keys.e(), keys.n());
    }

    public static BigInteger rsaDecrypt(BigInteger ciphertext, RsaKeyMaterial keys) {
        return ciphertext.modPow(keys.d(), keys.n());
    }

    /**
     * Big-endian unsigned interpretation of bytes (prepends a leading zero for {@link BigInteger}).
     */
    public static BigInteger bytesToPositiveBigEndian(byte[] data) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("data must be non-empty.");
        }
        byte[] unsigned = new byte[data.length + 1];
        System.arraycopy(data, 0, unsigned, 1, data.length);
        return new BigInteger(unsigned);
    }

    /**
     * Converts a non-negative {@link BigInteger} to a fixed-width big-endian byte array.
     */
    public static byte[] bigIntegerToUnsignedBytes(BigInteger value, int byteLength) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("value must be non-negative.");
        }
        byte[] raw = value.toByteArray();
        int start = 0;
        if (raw.length > 0 && raw[0] == 0) {
            start = 1;
        }
        int significant = raw.length - start;
        if (significant > byteLength) {
            throw new IllegalArgumentException("Value does not fit in " + byteLength + " bytes.");
        }
        byte[] out = new byte[byteLength];
        System.arraycopy(raw, start, out, byteLength - significant, significant);
        return out;
    }

    /**
     * Returns a trimmed string from decrypted bytes (strips trailing zero padding used for alignment).
     */
    public static String utf8FromPaddedBytes(byte[] data) {
        int end = data.length;
        while (end > 0 && data[end - 1] == 0) {
            end--;
        }
        return new String(Arrays.copyOf(data, end), java.nio.charset.StandardCharsets.UTF_8);
    }
}
