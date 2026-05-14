package sha1simplified;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

/**
 * preimage and second-preimage helpers for simplified SHA-1 (32-bit digest / eight hex chars).
 */
public final class CollisionFinder {

    private static final SecureRandom RNG = new SecureRandom();

    /** Wall-clock ceiling for bounded interactive preimage / collision searches (menus 3 and 4). */
    public static final long BOUNDED_SEARCH_MAX_DURATION_MS = 15_000L;

    /** Probe budget counted per hash evaluation in bounded scans. */
    public static final int BOUNDED_SEARCH_MAX_ATTEMPTS = 500_000;

    public static final int BOUNDED_SEARCH_PROGRESS_INTERVAL = 50_000;

    @Deprecated(since = "1.1", forRemoval = false)
    public static final long SECOND_PREIMAGE_MAX_TIME_MS = BOUNDED_SEARCH_MAX_DURATION_MS;

    @Deprecated(since = "1.1", forRemoval = false)
    public static final int SECOND_PREIMAGE_MAX_ATTEMPTS = BOUNDED_SEARCH_MAX_ATTEMPTS;

    @Deprecated(since = "1.1", forRemoval = false)
    public static final int SECOND_PREIMAGE_PROGRESS_EVERY = BOUNDED_SEARCH_PROGRESS_INTERVAL;

    private CollisionFinder() {
    }

    /**
     * Full preimage finder (heavy: lowercase sweep + parallel four-byte traversal + megasamples). Intended for
     * offline research, not interactive menus.
     */
    public static CollisionResult findForTargetHash(String targetHex8) {
        Objects.requireNonNull(targetHex8, "targetHex8");
        String target = normalizeHash8(targetHex8);
        SimplifiedSHA1 hasher = new SimplifiedSHA1(false);

        for (int length = 1; length <= 3; length++) {
            Optional<CollisionResult> match = scanFixedLengthPrintableAscii(hasher, target, length, null,
                    Integer.MAX_VALUE, candidate -> true);
            if (match.isPresent()) {
                return match.get();
            }
        }

        byte[] lowercase = new byte[26];
        for (int i = 0; i < 26; i++) {
            lowercase[i] = (byte) ('a' + i);
        }
        String fromLowerFive = depthFirstAlphabetSearch(hasher, target, new int[5], 0, lowercase);
        if (fromLowerFive != null) {
            return verifyAndBuild(hasher, target, fromLowerFive.getBytes(StandardCharsets.US_ASCII));
        }

        int digestWord = (int) Long.parseLong(target, 16);
        byte[] fourByteHit = parallelScanAllFourByteMessages(digestWord);
        if (fourByteHit != null) {
            return verifyAndBuild(hasher, target, fourByteHit);
        }

        for (int trial = 0; trial < 50_000_000; trial++) {
            byte[] noise = new byte[1 + RNG.nextInt(64)];
            RNG.nextBytes(noise);
            if (digestWord == hasher.hashToInt32(noise)) {
                return verifyAndBuild(hasher, target, noise);
            }
        }

        throw new IllegalStateException("No preimage found in the attempted search space.");
    }

    /**
     * Menu option 3 — bounded preimage for a fixed digest; never launches the parallel 2³² scan.
     */
    public static Optional<CollisionResult> findForTargetHashBounded(String targetHex8) {
        Objects.requireNonNull(targetHex8, "targetHex8");
        String target = normalizeHash8(targetHex8);
        SimplifiedSHA1 hasher = new SimplifiedSHA1(false);
        int digestWord = (int) Long.parseLong(target, 16);
        long started = System.currentTimeMillis();
        long deadline = started + BOUNDED_SEARCH_MAX_DURATION_MS;
        Budget budget = new Budget(deadline, started);

        for (int length = 1; length <= 3; length++) {
            Optional<CollisionResult> match = scanFixedLengthPrintableAscii(hasher, target, length, budget,
                    BOUNDED_SEARCH_MAX_ATTEMPTS, candidate -> true);
            if (match.isPresent()) {
                return match;
            }
            if (budget.exhausted(BOUNDED_SEARCH_MAX_ATTEMPTS)) {
                printStop("Option 3", budget, deadline);
                return Optional.empty();
            }
        }

        while (!budget.exhausted(BOUNDED_SEARCH_MAX_ATTEMPTS)) {
            budget.recordProbe();
            if (budget.probes % BOUNDED_SEARCH_PROGRESS_INTERVAL == 0) {
                logProgress("Option 3", budget.probes, started);
            }
            byte[] noise = new byte[1 + RNG.nextInt(64)];
            RNG.nextBytes(noise);
            if (digestWord == hasher.hashToInt32(noise)) {
                return Optional.of(verifyAndBuild(hasher, target, noise));
            }
        }

        printStop("Option 3", budget, deadline);
        return Optional.empty();
    }

    static byte[] parallelScanAllFourByteMessages(int digestAsInt32) {
        int workers = Math.max(2, Runtime.getRuntime().availableProcessors());
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        AtomicReference<byte[]> winner = new AtomicReference<>();
        long span = 1L << 32;
        long slice = (span + workers - 1) / workers;
        for (int worker = 0; worker < workers; worker++) {
            final long begin = worker * slice;
            final long end = (worker == workers - 1) ? span : Math.min(span, begin + slice);
            pool.submit(() -> {
                SimplifiedSHA1 local = new SimplifiedSHA1(false);
                byte[] word = new byte[4];
                for (long cursor = begin; cursor < end && winner.get() == null; cursor++) {
                    word[0] = (byte) (cursor >>> 24);
                    word[1] = (byte) (cursor >>> 16);
                    word[2] = (byte) (cursor >>> 8);
                    word[3] = (byte) cursor;
                    if (local.hashToInt32(word) == digestAsInt32) {
                        winner.compareAndSet(null, word.clone());
                        return;
                    }
                }
            });
        }
        pool.shutdown();
        try {
            if (!pool.awaitTermination(4, TimeUnit.HOURS)) {
                pool.shutdownNow();
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            pool.shutdownNow();
        }
        return winner.get();
    }

    /**
     * Menu option 4 — bounded second-preimage.
     */
    public static Optional<SecondPreimageResult> findDifferentMessageSameHashBounded(String messageUtf8) {
        if (messageUtf8 == null) {
            throw new IllegalArgumentException("messageUtf8 must not be null.");
        }
        SimplifiedSHA1 hasher = new SimplifiedSHA1(false);
        byte[] originalBytes = messageUtf8.getBytes(StandardCharsets.UTF_8);
        String digestHex = hasher.hashBytes(originalBytes);
        int digestWord = Integer.parseUnsignedInt(digestHex, 16);
        long started = System.currentTimeMillis();
        long deadline = started + BOUNDED_SEARCH_MAX_DURATION_MS;
        Budget budget = new Budget(deadline, started);
        Predicate<byte[]> notOriginal = candidate -> !Arrays.equals(candidate, originalBytes)
                && !new String(candidate, StandardCharsets.US_ASCII).equals(messageUtf8);

        for (int length = 1; length <= 3; length++) {
            Optional<CollisionResult> match = scanFixedLengthPrintableAscii(hasher, digestHex, length, budget,
                    BOUNDED_SEARCH_MAX_ATTEMPTS, notOriginal);
            if (match.isPresent()) {
                byte[] payload = match.get().messageBytes();
                return Optional.of(new SecondPreimageResult(messageUtf8, digestHex,
                        new String(payload, StandardCharsets.US_ASCII), digestHex));
            }
            if (budget.exhausted(BOUNDED_SEARCH_MAX_ATTEMPTS)) {
                printStop("Option 4", budget, deadline);
                return Optional.empty();
            }
        }

        while (!budget.exhausted(BOUNDED_SEARCH_MAX_ATTEMPTS)) {
            budget.recordProbe();
            if (budget.probes % BOUNDED_SEARCH_PROGRESS_INTERVAL == 0) {
                logProgress("Option 4", budget.probes, started);
            }
            byte[] noise = new byte[1 + RNG.nextInt(24)];
            RNG.nextBytes(noise);
            if (Arrays.equals(noise, originalBytes)) {
                continue;
            }
            if (digestWord == hasher.hashToInt32(noise)) {
                return Optional.of(new SecondPreimageResult(messageUtf8, digestHex,
                        new String(noise, StandardCharsets.UTF_8), digestHex));
            }
        }

        printStop("Option 4", budget, deadline);
        return Optional.empty();
    }

    /**
     * Enumerates ASCII [32..126] strings of fixed length. Counts probes against {@link Budget}. When budget is {@code
     * null}, no limits apply.
     */
    private static Optional<CollisionResult> scanFixedLengthPrintableAscii(SimplifiedSHA1 hasher, String hexTarget,
            int length, Budget budgetOrNull, int attemptCeilingInclusive, Predicate<byte[]> acceptCandidateBeforeHash) {

        byte[] candidate = new byte[length];
        if (length == 1) {
            for (int value = 32; value <= 126; value++) {
                if (budgetOrNull != null && budgetOrNull.exhausted(attemptCeilingInclusive)) {
                    return Optional.empty();
                }
                candidate[0] = (byte) value;
                if (!acceptCandidateBeforeHash.test(candidate)) {
                    continue;
                }
                countProbeTowardsBudget(budgetOrNull);
                if (budgetOrNull != null && budgetOrNull.probes % BOUNDED_SEARCH_PROGRESS_INTERVAL == 0
                        && budgetOrNull.probes > 0) {
                    logProgress("", budgetOrNull.probes, budgetOrNull.phaseStartWallClockMs);
                }
                if (hexTarget.equals(hasher.hashBytes(candidate))) {
                    return Optional.of(verifyAndBuild(hasher, hexTarget, Arrays.copyOf(candidate, 1)));
                }
            }
            return Optional.empty();
        }

        if (length == 2) {
            for (int hi = 32; hi <= 126; hi++) {
                for (int lo = 32; lo <= 126; lo++) {
                    if (budgetOrNull != null && budgetOrNull.exhausted(attemptCeilingInclusive)) {
                        return Optional.empty();
                    }
                    candidate[0] = (byte) hi;
                    candidate[1] = (byte) lo;
                    if (!acceptCandidateBeforeHash.test(candidate)) {
                        continue;
                    }
                    countProbeTowardsBudget(budgetOrNull);
                    if (budgetOrNull != null && budgetOrNull.probes % BOUNDED_SEARCH_PROGRESS_INTERVAL == 0
                            && budgetOrNull.probes > 0) {
                        logProgress("", budgetOrNull.probes, budgetOrNull.phaseStartWallClockMs);
                    }
                    if (hexTarget.equals(hasher.hashBytes(candidate))) {
                        return Optional.of(verifyAndBuild(hasher, hexTarget, Arrays.copyOf(candidate, 2)));
                    }
                }
            }
            return Optional.empty();
        }

        for (int a = 32; a <= 126; a++) {
            for (int b = 32; b <= 126; b++) {
                for (int c = 32; c <= 126; c++) {
                    if (budgetOrNull != null && budgetOrNull.exhausted(attemptCeilingInclusive)) {
                        return Optional.empty();
                    }
                    candidate[0] = (byte) a;
                    candidate[1] = (byte) b;
                    candidate[2] = (byte) c;
                    if (!acceptCandidateBeforeHash.test(candidate)) {
                        continue;
                    }
                    countProbeTowardsBudget(budgetOrNull);
                    if (budgetOrNull != null && budgetOrNull.probes % BOUNDED_SEARCH_PROGRESS_INTERVAL == 0
                            && budgetOrNull.probes > 0) {
                        logProgress("", budgetOrNull.probes, budgetOrNull.phaseStartWallClockMs);
                    }
                    if (hexTarget.equals(hasher.hashBytes(candidate))) {
                        return Optional.of(verifyAndBuild(hasher, hexTarget, Arrays.copyOf(candidate, 3)));
                    }
                }
            }
        }
        return Optional.empty();
    }

    private static void countProbeTowardsBudget(Budget budgetOrNull) {
        if (budgetOrNull != null) {
            budgetOrNull.recordProbe();
        }
    }

    private static void logProgress(String menuLabel, int probes, long phaseStartMs) {
        String label = menuLabel == null || menuLabel.isEmpty() ? "Bounded search" : menuLabel;
        System.out.printf("%s progress: %d probes, %d ms elapsed%n", label, probes,
                System.currentTimeMillis() - phaseStartMs);
    }

    private static void printStop(String menuLabel, Budget budget, long deadlineMs) {
        boolean timeHit = System.currentTimeMillis() >= deadlineMs;
        boolean attemptsHit = budget.probes >= BOUNDED_SEARCH_MAX_ATTEMPTS;
        System.out.printf("%s: stopped without success under bounded limits.%n", menuLabel);
        System.out.printf("  Probes=%d, time limit reached=%s, attempt limit reached=%s.%n", budget.probes, timeHit,
                attemptsHit);
        System.out.println("  Adjust CollisionFinder.BOUNDED_SEARCH_MAX_DURATION_MS or "
                + "CollisionFinder.BOUNDED_SEARCH_MAX_ATTEMPTS for longer offline attempts.");
    }

    private static final class Budget {
        final long deadlineWallClockMs;
        final long phaseStartWallClockMs;
        int probes;

        Budget(long deadlineWallClockMs, long phaseStartWallClockMs) {
            this.deadlineWallClockMs = deadlineWallClockMs;
            this.phaseStartWallClockMs = phaseStartWallClockMs;
        }

        void recordProbe() {
            probes++;
        }

        boolean exhausted(int attemptCeilingInclusive) {
            if (probes >= attemptCeilingInclusive) {
                return true;
            }
            return System.currentTimeMillis() >= deadlineWallClockMs;
        }
    }

    private static String depthFirstAlphabetSearch(SimplifiedSHA1 hasher, String targetHex, int[] stack, int depth,
            byte[] alphabet) {
        if (depth == stack.length) {
            byte[] assembled = new byte[stack.length];
            for (int i = 0; i < stack.length; i++) {
                assembled[i] = (byte) stack[i];
            }
            if (targetHex.equals(hasher.hashBytes(assembled))) {
                return new String(assembled, StandardCharsets.US_ASCII);
            }
            return null;
        }
        for (byte choice : alphabet) {
            stack[depth] = choice & 0xFF;
            String hit = depthFirstAlphabetSearch(hasher, targetHex, stack, depth + 1, alphabet);
            if (hit != null) {
                return hit;
            }
        }
        return null;
    }

    private static CollisionResult verifyAndBuild(SimplifiedSHA1 hasher, String normalizedHex, byte[] preimage) {
        String recomputed = hasher.hashBytes(preimage);
        if (!normalizedHex.equals(recomputed)) {
            throw new IllegalStateException("Internal error: digest mismatch after locating candidate.");
        }
        return new CollisionResult(normalizedHex, preimage, recomputed);
    }

    private static String normalizeHash8(String raw) {
        String normalized = raw.trim().toUpperCase(Locale.ROOT);
        if (normalized.length() != 8 || !normalized.matches("[0-9A-F]{8}")) {
            throw new IllegalArgumentException("Expected exactly eight hex digits: " + raw);
        }
        return normalized;
    }

    public record CollisionResult(String targetHash, byte[] messageBytes, String computedHash) {
    }

    public record SecondPreimageResult(String originalMessage, String hashDigestHex, String collidingMessage,
                                       String collidingDigestHex) {
    }
}
