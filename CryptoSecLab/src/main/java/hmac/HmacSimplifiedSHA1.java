package hmac;

import sha1simplified.SimplifiedSHA1;
import util.HexUtil;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * HMAC using Simplified SHA-1, following the assignment formula (note the ipad/opad nesting is
 * exactly as specified — it differs from RFC 2104’s outer/inner pattern):
 *
 * <pre>
 *   HMAC(K, m) = H( (K' XOR ipad) || H( (K' XOR opad) || m ) )
 * </pre>
 *
 * <p><b>Block size B:</b> the simplified hash pads and processes the message in 32-bit (4-byte)
 * units; the HMAC block size is therefore 4 bytes ({@link #BLOCK_BYTES}) — see README.</p>
 */
public class HmacSimplifiedSHA1 {

    /**
     * Block size in bytes: one simplified-SHA word block = 32 bits.
     */
    public static final int BLOCK_BYTES = 4;

    public static final byte IPAD_BYTE = 0x36;
    public static final byte OPAD_BYTE = 0x5C;

    private final SimplifiedSHA1 sha1;
    private final boolean debug;

    public HmacSimplifiedSHA1() {
        this(false);
    }

    public HmacSimplifiedSHA1(boolean debug) {
        this.sha1 = new SimplifiedSHA1(false);
        this.debug = debug;
    }

    /**
     * Computes HMAC for UTF-8 key and message.
     */
    public String compute(String key, String message) {
        if (key == null || message == null) {
            throw new IllegalArgumentException("key and message must not be null.");
        }
        return computeBytes(key.getBytes(StandardCharsets.UTF_8), message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Core HMAC on raw bytes.
     */
    public String computeBytes(byte[] key, byte[] message) {
        byte[] kPrime = deriveKPrime(key);
        byte[] ipad = repeatByte(IPAD_BYTE, BLOCK_BYTES);
        byte[] opad = repeatByte(OPAD_BYTE, BLOCK_BYTES);
        byte[] kXorIpad = xor(kPrime, ipad);
        byte[] kXorOpad = xor(kPrime, opad);

        byte[] innerMsg = concat(kXorOpad, message);
        String innerHashHex = sha1.hashBytes(innerMsg);
        byte[] innerDigest = HexUtil.hashHex32ToBytes(innerHashHex);

        byte[] outerMsg = concat(kXorIpad, innerDigest);
        String result = sha1.hashBytes(outerMsg);

        if (debug) {
            System.out.println("--- HMAC (Simplified SHA-1) debug ---");
            System.out.println("B (block bytes) = " + BLOCK_BYTES);
            System.out.println("K' (hex) = " + HexUtil.bytesToHexUpper(kPrime));
            System.out.println("K' XOR ipad (hex) = " + HexUtil.bytesToHexUpper(kXorIpad));
            System.out.println("K' XOR opad (hex) = " + HexUtil.bytesToHexUpper(kXorOpad));
            System.out.println("Inner H((K' XOR opad) || m) = " + innerHashHex);
            System.out.println("Final HMAC = " + result);
            System.out.println("--- end HMAC debug ---");
        }
        return result;
    }

    /**
     * K' = H(K) when len(K) &gt; B, else K zero-padded/truncated? Truncation only if longer — handled
     * by hashing per assignment.
     */
    static byte[] deriveKPrime(byte[] key) {
        if (key.length > BLOCK_BYTES) {
            String h = new SimplifiedSHA1(false).hashBytes(key);
            return HexUtil.hashHex32ToBytes(h);
        }
        if (key.length == BLOCK_BYTES) {
            return Arrays.copyOf(key, BLOCK_BYTES);
        }
        byte[] out = new byte[BLOCK_BYTES];
        System.arraycopy(key, 0, out, 0, key.length);
        return out;
    }

    static byte[] repeatByte(byte v, int len) {
        byte[] a = new byte[len];
        Arrays.fill(a, v);
        return a;
    }

    static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException("xor length mismatch");
        }
        byte[] o = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            o[i] = (byte) (a[i] ^ b[i]);
        }
        return o;
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
