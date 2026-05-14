package util;

/**
 * Simple input validation helpers for the console application.
 */
public final class Validation {

    private Validation() {
    }

    public static String requireNonEmpty(String s, String fieldName) {
        if (s == null || s.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must be non-empty.");
        }
        return s;
    }
}
