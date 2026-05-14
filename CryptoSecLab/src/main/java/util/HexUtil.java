package util;

import java.util.Locale;

/**
 * Hex encoding/decoding for byte arrays and 8-bit values.
 */
public final class HexUtil {

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private HexUtil() {
    }

    /**
     * Converts bytes to uppercase hex (no separator).
     */
    public static String bytesToHexUpper(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    /**
     * Parses exactly 8 hex characters (32-bit hash) to 4 bytes, big-endian.
     */
    public static byte[] hashHex32ToBytes(String hex) {
        if (hex == null || hex.length() != 8) {
            throw new IllegalArgumentException("Expected 8 hex characters for 32-bit hash.");
        }
        String h = hex.trim().toUpperCase(Locale.ROOT);
        if (!h.matches("[0-9A-F]{8}")) {
            throw new IllegalArgumentException("Invalid hex string: " + hex);
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /**
     * Parses a hex string to bytes (even length, upper/lower allowed).
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("Hex string is null.");
        }
        String h = hex.trim();
        if (h.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string length must be even.");
        }
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
