package hmac;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HmacSimplifiedSHA1Test {

    @Test
    void mac_forShortKey_matches_fixture() {
        HmacSimplifiedSHA1 h = new HmacSimplifiedSHA1(false);
        assertEquals("D74B768B", h.compute("k", "m"));
    }

    @Test
    void longKey_is_hashed_down_to_block_size() {
        HmacSimplifiedSHA1 h = new HmacSimplifiedSHA1(false);
        String key = "ABCDEFGH"; // 8 bytes > B=4 -> K' = H(K)
        assertEquals(HmacSimplifiedSHA1.BLOCK_BYTES, 4);
        String tag = h.compute(key, "msg");
        assertEquals(8, tag.length());
        assertEquals(tag, h.computeBytes(key.getBytes(), "msg".getBytes()));
    }

    @Test
    void nullArgumentsRejected() {
        assertThrows(IllegalArgumentException.class, () -> new HmacSimplifiedSHA1(false).compute(null, "x"));
        assertThrows(IllegalArgumentException.class, () -> new HmacSimplifiedSHA1(false).compute("x", null));
    }
}
