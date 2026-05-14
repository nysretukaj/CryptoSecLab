package sha1simplified;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SimplifiedSHA1Test {

    @Test
    void rotateLeft8_examples() {
        assertEquals(0x01, SimplifiedSHA1.rotateLeft8(0x80, 1));
        assertEquals(0x02, SimplifiedSHA1.rotateLeft8(0x80, 2));
        assertEquals(0xFF, SimplifiedSHA1.rotateLeft8(0xFF, 3));
        assertEquals(0x0F, SimplifiedSHA1.rotateLeft8(0xF0, 4));
    }

    @Test
    void hashBytes_matches_known_vectors() {
        SimplifiedSHA1 sha = new SimplifiedSHA1(false);
        assertEquals("C9093000", sha.hash(""));
        assertEquals("14E74F40", sha.hash("a"));
        assertEquals("61F23F18", sha.hash("hello"));
    }

    @Test
    void hashToInt32_matchesFormattedHash() {
        SimplifiedSHA1 sha = new SimplifiedSHA1(false);
        byte[] data = "probe".getBytes(StandardCharsets.UTF_8);
        String hex = sha.hashBytes(data);
        int fromInt = sha.hashToInt32(data);
        assertEquals(Integer.parseUnsignedInt(hex, 16), fromInt);
    }
}
