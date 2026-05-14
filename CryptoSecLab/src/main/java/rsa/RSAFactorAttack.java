package rsa;

import java.math.BigInteger;

/**
 * Task 2: factor the assignment modulus {@code n} using {@link BigInteger#sqrtAndRemainder()} and
 * an “around {@code sqrt(n)}” strategy (Fermat for balanced primes, then a tight trial ring,
 * then Pollard’s rho as a probabilistic fallback).
 */
public final class RSAFactorAttack {

    /**
     * Exact modulus from the assignment (RSA-1024 style size).
     */
    public static final BigInteger N = new BigInteger(
            "15000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018518518350617283945");

    /**
     * Maximum Fermat iterations starting at {@code ceil(sqrt(n))}.
     */
    public static final long MAX_FERMAT_STEPS = 5_000_000L;

    /**
     * Trial divisors {@code floor(sqrt(n)) ± delta} for {@code delta in [0, MAX_TRIAL_DELTA]}.
     */
    public static final long MAX_TRIAL_DELTA = 250_000L;

    private RSAFactorAttack() {
    }

    /**
     * Factors {@code n} when primes are close to {@code sqrt(n)} (assignment case).
     *
     * @return array {@code [p, q]} with {@code p.multiply(q).equals(n)}
     */
    public static BigInteger[] factorNearSqrt(BigInteger n) {
        if (n == null || n.signum() <= 0) {
            throw new IllegalArgumentException("n must be positive.");
        }
        BigInteger[] sr = n.sqrtAndRemainder();
        BigInteger s = sr[0];
        BigInteger r = sr[1];

        if (r.signum() == 0) {
            return new BigInteger[] { s, s };
        }

        BigInteger p = searchFromSqrt(n, s);
        BigInteger q = n.divide(p);
        return new BigInteger[] { p, q };
    }

    /**
     * 1) Fermat (uses {@code sqrtAndRemainder} to detect perfect squares).
     * 2) small neighborhood trial on {@code floor(sqrt(n))}.
     * 3) Pollard rho.
     */
    static BigInteger searchFromSqrt(BigInteger n, BigInteger floorSqrt) {
        BigInteger small = trialSmallFactors(n, 200_000L);
        if (small != null) {
            return small;
        }
        BigInteger f = fermatFactor(n);
        if (f != null) {
            return f;
        }
        BigInteger two = BigInteger.valueOf(2);
        for (long delta = 0; delta <= MAX_TRIAL_DELTA; delta++) {
            BigInteger candPlus = floorSqrt.add(BigInteger.valueOf(delta));
            if (candPlus.compareTo(two) > 0 && !candPlus.equals(n) && n.mod(candPlus).signum() == 0) {
                return candPlus;
            }
            if (delta > 0) {
                BigInteger candMinus = floorSqrt.subtract(BigInteger.valueOf(delta));
                if (candMinus.compareTo(two) > 0 && !candMinus.equals(n) && n.mod(candMinus).signum() == 0) {
                    return candMinus;
                }
            }
        }
        return pollardRhoFactor(n);
    }

    /**
     * Cheap trial division for small factors (handles cases like factor {@code 3} instantly).
     */
    static BigInteger trialSmallFactors(BigInteger n, long limitInclusive) {
        if (n.remainder(BigInteger.TWO).signum() == 0) {
            return BigInteger.TWO;
        }
        for (long d = 3; d <= limitInclusive; d += 2) {
            BigInteger bd = BigInteger.valueOf(d);
            if (bd.multiply(bd).compareTo(n) > 0) {
                break;
            }
            if (n.mod(bd).signum() == 0) {
                return bd;
            }
        }
        return null;
    }

    /**
     * Fermat: find {@code a} such that {@code a^2 - n} is a perfect square {@code b^2};
     * then {@code n = (a-b)(a+b)}.
     */
    static BigInteger fermatFactor(BigInteger n) {
        BigInteger[] sr = n.sqrtAndRemainder();
        BigInteger a = sr[1].signum() == 0 ? sr[0] : sr[0].add(BigInteger.ONE);
        for (long i = 0; i < MAX_FERMAT_STEPS; i++) {
            BigInteger b2 = a.multiply(a).subtract(n);
            if (b2.signum() >= 0) {
                BigInteger[] br = b2.sqrtAndRemainder();
                if (br[1].signum() == 0) {
                    BigInteger b = br[0];
                    BigInteger p = a.subtract(b);
                    BigInteger q = a.add(b);
                    if (p.compareTo(BigInteger.ONE) > 0 && q.compareTo(BigInteger.ONE) > 0
                            && p.multiply(q).equals(n)) {
                        return p.min(q);
                    }
                }
            }
            a = a.add(BigInteger.ONE);
        }
        return null;
    }

    static BigInteger pollardRhoFactor(BigInteger n) {
        if (n.remainder(BigInteger.TWO).signum() == 0) {
            return BigInteger.TWO;
        }
        final int maxRetries = 100;
        for (int retry = 0; retry < maxRetries; retry++) {
            BigInteger c = BigInteger.valueOf(1 + retry);
            BigInteger x = BigInteger.TWO;
            BigInteger y = BigInteger.TWO;
            BigInteger d = BigInteger.ONE;
            int inner = 0;
            while (d.equals(BigInteger.ONE) && inner < 2_000_000) {
                inner++;
                x = x.multiply(x).mod(n).add(c).mod(n);
                y = y.multiply(y).mod(n).add(c).mod(n);
                y = y.multiply(y).mod(n).add(c).mod(n);
                d = x.subtract(y).gcd(n);
                if (d.equals(n)) {
                    d = BigInteger.ONE;
                }
            }
            if (d.compareTo(BigInteger.ONE) > 0 && d.compareTo(n) < 0) {
                return d;
            }
        }
        throw new IllegalStateException("Pollard rho failed to split n.");
    }

    /**
     * Runs the attack on {@link #N}, prints verification {@code p * q == n}.
     */
    public static FactorResult runAssignmentAttack() {
        BigInteger[] pq = factorNearSqrt(N);
        BigInteger p = pq[0];
        BigInteger q = pq[1];
        BigInteger prod = p.multiply(q);
        boolean ok = prod.equals(N);
        System.out.println("RSA factorization (assignment n):");
        System.out.println("p = " + p);
        System.out.println("q = " + q);
        System.out.println("Verification p * q == n: " + ok);
        if (!ok) {
            throw new IllegalStateException("Factorization failed verification.");
        }
        return new FactorResult(p, q);
    }

    public record FactorResult(BigInteger p, BigInteger q) {
    }
}
