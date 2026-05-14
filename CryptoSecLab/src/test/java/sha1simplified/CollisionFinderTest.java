package sha1simplified;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class CollisionFinderTest {

    @Test
    void invalid_target_hex_rejected() {
        assertThrows(IllegalArgumentException.class, () -> CollisionFinder.findForTargetHash("BAD"));
    }
}
