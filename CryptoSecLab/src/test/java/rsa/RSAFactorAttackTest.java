package rsa;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RSAFactorAttackTest {

    @Test
    void assignment_n_factors_and_multiply_back() {
        BigInteger[] pq = RSAFactorAttack.factorNearSqrt(RSAFactorAttack.N);
        BigInteger p = pq[0];
        BigInteger q = pq[1];
        assertEquals(RSAFactorAttack.N, p.multiply(q));
        assertTrue(p.compareTo(BigInteger.ONE) > 0);
        assertTrue(q.compareTo(BigInteger.ONE) > 0);
    }
}
