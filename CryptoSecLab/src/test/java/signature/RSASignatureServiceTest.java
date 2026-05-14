package signature;

import org.junit.jupiter.api.Test;
import sha1simplified.SimplifiedSHA1;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RSASignatureServiceTest {

    @Test
    void sign_then_verify_recover_equal_digest() {
        RSASignatureService.RsaKeyMaterial keys = RSASignatureService.generateKeyPair(128);
        SimplifiedSHA1 sha = new SimplifiedSHA1(false);
        String message = "Integrity check payload.";
        BigInteger z = RSASignatureService.digestStringToInteger(sha, message);
        BigInteger signature = RSASignatureService.sign(z, keys);
        BigInteger v = RSASignatureService.recoverDigest(signature, keys);
        assertEquals(z, v);
        assertTrue(RSASignatureService.verifyMessage(message, signature, keys, sha));
    }
}
