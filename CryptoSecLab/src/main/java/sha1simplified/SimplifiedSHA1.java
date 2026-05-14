package sha1simplified;

import java.nio.charset.StandardCharsets;
import java.util.BitSet;
import java.util.Locale;

import util.HexUtil;

/**
 * Simplified SHA-1 hash per assignment specification:
 * <ul>
 *   <li>32-bit blocks, 8-bit registers and word schedule</li>
 *   <li>Padding: message || 1 || k zeros || L (16 bits); {@code N*32 = L + k + 1 + 16}</li>
 *   <li>Chaining: after each block, {@code H_i = (H_i + register_i) mod 256}</li>
 * </ul>
 */
public class SimplifiedSHA1 {

    /** Initial / IV bytes H0..H3 */
    public static final int H0_IV = 0x45;
    public static final int H1_IV = 0xAF;
    public static final int H2_IV = 0xAC;
    public static final int H3_IV = 0xFE;

    private final boolean debug;

    public SimplifiedSHA1() {
        this(false);
    }

    public SimplifiedSHA1(boolean debug) {
        this.debug = debug;
    }

    public boolean isDebug() {
        return debug;
    }

    /**
     * Hash a text message using UTF-8 bytes.
     */
    public String hash(String message) {
        if (message == null) {
            throw new IllegalArgumentException("message must not be null");
        }
        return hashBytes(message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Returns the 32-bit digest as an {@code int} (big-endian: H0||H1||H2||H3).
     */
    public int hashToInt32(byte[] data) {
        byte[] padded = padMessageBits(data);
        int[] h = new int[] { H0_IV, H1_IV, H2_IV, H3_IV };
        int numBlocks = padded.length / 4;
        for (int bi = 0; bi < numBlocks; bi++) {
            int off = bi * 4;
            int x0 = padded[off] & 0xFF;
            int x1 = padded[off + 1] & 0xFF;
            int x2 = padded[off + 2] & 0xFF;
            int x3 = padded[off + 3] & 0xFF;
            h = compressBlock(h, new int[] { x0, x1, x2, x3 }, bi);
        }
        return ((h[0] & 0xFF) << 24) | ((h[1] & 0xFF) << 16) | ((h[2] & 0xFF) << 8) | (h[3] & 0xFF);
    }

    public String hashBytes(byte[] data) {
        if (!debug) {
            return String.format(Locale.ROOT, "%08X", hashToInt32(data));
        }
        byte[] padded = padMessageBits(data);
        System.out.println("--- Simplified SHA-1 debug ---");
        System.out.println("Padded message (bits length): " + padded.length * 8);
        System.out.println("Padded bytes (hex, uppercase): " + HexUtil.bytesToHexUpper(padded));

        int[] h = new int[] { H0_IV, H1_IV, H2_IV, H3_IV };
        int numBlocks = padded.length / 4;
        for (int bi = 0; bi < numBlocks; bi++) {
            int off = bi * 4;
            int x0 = padded[off] & 0xFF;
            int x1 = padded[off + 1] & 0xFF;
            int x2 = padded[off + 2] & 0xFF;
            int x3 = padded[off + 3] & 0xFF;
            System.out.println("Block " + bi + " bytes x_i^0..x_i^3: "
                    + String.format(Locale.ROOT, "%02X %02X %02X %02X", x0, x1, x2, x3));
            h = compressBlock(h, new int[] { x0, x1, x2, x3 }, bi);
        }
        String out = String.format(Locale.ROOT, "%02X%02X%02X%02X", h[0], h[1], h[2], h[3]);
        System.out.println("Final hash: " + out);
        System.out.println("--- end Simplified SHA-1 debug ---");
        return out;
    }

    /**
     * Padding: L = bit-length of message; total bits T is smallest multiple of 32 with T &gt;= L + 17,
     * with k = T - L - 17 &gt;= 0 zero bits after the single 1-bit.
     */
    static byte[] padMessageBits(byte[] messageBytes) {
        if (messageBytes == null) {
            throw new IllegalArgumentException("messageBytes must not be null");
        }
        int L = messageBytes.length * 8;
        int T = ((L + 17 + 31) / 32) * 32;
        int k = T - L - 17;
        if (k < 0) {
            throw new IllegalStateException("Invalid padding: k=" + k);
        }

        BitSet bits = new BitSet(T);
        int pos = 0;
        for (byte b : messageBytes) {
            int v = b & 0xFF;
            for (int bit = 7; bit >= 0; bit--) {
                bits.set(pos++, ((v >> bit) & 1) != 0);
            }
        }
        bits.set(pos++, true); // append 1
        // k zeros: BitSet defaults to false
        pos += k;
        // Length L in last 16 bits (big-endian)
        int lengthStart = T - 16;
        for (int i = 0; i < 16; i++) {
            int bitIndex = 15 - i;
            boolean bit = ((L >> bitIndex) & 1) != 0;
            bits.set(lengthStart + i, bit);
        }

        byte[] out = new byte[T / 8];
        for (int i = 0; i < T; i++) {
            if (bits.get(i)) {
                int byteIndex = i / 8;
                int bitInByte = 7 - (i % 8);
                out[byteIndex] |= (byte) (1 << bitInByte);
            }
        }
        return out;
    }

    /**
     * Left-rotate an 8-bit value (input masked to 8 bits).
     */
    public static int rotateLeft8(int value, int bits) {
        int v = value & 0xFF;
        int n = ((bits % 8) + 8) % 8;
        return ((v << n) | (v >>> (8 - n))) & 0xFF;
    }

    int[] compressBlock(int[] hIn, int[] xiParts, int blockIndex) {
        int A = hIn[0] & 0xFF;
        int B = hIn[1] & 0xFF;
        int C = hIn[2] & 0xFF;
        int D = hIn[3] & 0xFF;

        int[] W = new int[16];
        for (int j = 0; j <= 3; j++) {
            W[j] = xiParts[j] & 0xFF;
        }
        for (int j = 4; j <= 15; j++) {
            W[j] = rotateLeft8((W[j - 4] ^ W[j - 2]) & 0xFF, 2);
        }

        if (debug) {
            System.out.println("Word schedule W0..W15:");
            for (int j = 0; j < 16; j++) {
                System.out.printf(Locale.ROOT, "  W%2d = %02X%n", j, W[j]);
            }
        }

        for (int round = 0; round < 16; round++) {
            int roundConstantK;
            int roundFunctionBc;
            if (round <= 3) {
                roundConstantK = 0x5A;
                roundFunctionBc = f1(B, C);
            } else if (round <= 7) {
                roundConstantK = 0xE7;
                roundFunctionBc = f2(B, C);
            } else if (round <= 11) {
                roundConstantK = 0x8C;
                roundFunctionBc = f3(B, C);
            } else {
                roundConstantK = 0xBD;
                roundFunctionBc = f4(B, C);
            }

            int sum = (D & 0xFF) + (roundFunctionBc & 0xFF) + rotateLeft8(A, 3) + (W[round] & 0xFF) + roundConstantK;
            int temp = Math.floorMod(sum, 256);
            int prevA = A;
            int prevB = B;
            int prevC = C;

            A = temp & 0xFF;
            B = prevA & 0xFF;
            C = rotateLeft8(prevB, 7);
            D = prevC & 0xFF;

            if (debug) {
                System.out.printf(Locale.ROOT,
                        "Block %d round %2d | K=%02X f=%02X W=%02X | A=%02X B=%02X C=%02X D=%02X%n",
                        blockIndex, round, roundConstantK, roundFunctionBc & 0xFF, W[round] & 0xFF, A, B, C, D);
            }
        }

        final int registerA = A;
        final int registerB = B;
        final int registerC = C;
        final int registerD = D;
        return new int[] {
                Math.floorMod(hIn[0] + registerA, 256),
                Math.floorMod(hIn[1] + registerB, 256),
                Math.floorMod(hIn[2] + registerC, 256),
                Math.floorMod(hIn[3] + registerD, 256)
        };
    }

    static int f1(int B, int C) {
        return (B & C) & 0xFF;
    }

    static int f2(int B, int C) {
        return (B ^ C) & 0xFF;
    }

    static int f3(int B, int C) {
        return (B ^ ((~C) & 0xFF)) & 0xFF;
    }

    static int f4(int B, int C) {
        return (B ^ C) & 0xFF;
    }
}
