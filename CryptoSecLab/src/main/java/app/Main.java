package app;

import hmac.HmacSimplifiedSHA1;
import rsa.RSAFactorAttack;
import sha1simplified.CollisionFinder;
import sha1simplified.SimplifiedSHA1;
import signature.SignatureDemo;
import util.Validation;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Scanner;

/**
 * Console menu for the simplified crypto lab (Java 17).
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        Locale.setDefault(Locale.ROOT);
        try (Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8)) {
            while (true) {
                printMenu();
                String line = scanner.nextLine().trim();
                int choice;
                try {
                    choice = Integer.parseInt(line);
                } catch (NumberFormatException e) {
                    System.out.println("Please enter a number 1-7.");
                    continue;
                }
                try {
                    switch (choice) {
                        case 1 -> runRsaFactor();
                        case 2 -> runShaMenu(scanner);
                        case 3 -> runFixedDigestPreimage();
                        case 4 -> runUserCollision(scanner);
                        case 5 -> runHmac(scanner);
                        case 6 -> SignatureDemo.run();
                        case 7 -> {
                            System.out.println("Goodbye.");
                            return;
                        }
                        default -> System.out.println("Unknown option. Choose 1-7.");
                    }
                } catch (Exception ex) {
                    System.out.println("Error: " + ex.getMessage());
                }
                System.out.println();
            }
        }
    }

    private static void printMenu() {
        System.out.println("====================================================");
        System.out.println(" Simplified Crypto Lab - main menu");
        System.out.println("====================================================");
        System.out.println(" 1. RSA task 2: factor n and find p, q");
        System.out.println(" 2. Simplified SHA-1 hash a message");
        System.out.println(" 3. Find preimage for fixed digest 4BAFE69C (bounded search)");
        System.out.println(" 4. Second preimage: M' != M with H(M')=H(M) (bounded)");
        System.out.println(" 5. HMAC_Simplified_SHA1");
        System.out.println(" 6. RSA digital signature + verification using Simplified SHA-1");
        System.out.println(" 7. Exit");
        System.out.print("Choose an option: ");
    }

    private static void runRsaFactor() {
        RSAFactorAttack.runAssignmentAttack();
    }

    private static void runShaMenu(Scanner scanner) {
        System.out.print("Enter message to hash: ");
        String msg = scanner.nextLine();
        System.out.print("Verbose debug? (y/N): ");
        String d = scanner.nextLine().trim().toLowerCase(Locale.ROOT);
        boolean verbose = d.equals("y") || d.equals("yes");
        SimplifiedSHA1 sha = new SimplifiedSHA1(verbose);
        String h = sha.hash(msg);
        if (!verbose) {
            System.out.println("H(message) = " + h);
        }
    }

    private static void runFixedDigestPreimage() {
        final String target = "4BAFE69C";
        System.out.println("(Bounded search: max " + CollisionFinder.BOUNDED_SEARCH_MAX_ATTEMPTS + " hash probes, "
                + CollisionFinder.BOUNDED_SEARCH_MAX_DURATION_MS + " ms wall time; no parallel 2^32 scan.)");
        System.out.println("Searching for M' with H(M') = " + target + " ...");
        CollisionFinder.findForTargetHashBounded(target).ifPresentOrElse(r -> {
            System.out.println("Found M' = " + new String(r.messageBytes(), StandardCharsets.ISO_8859_1));
            System.out.println("H(M') = " + r.computedHash());
            System.out.println("Target  = " + r.targetHash());
            System.out.println("Match: " + r.targetHash().equals(r.computedHash()));
        }, () -> System.out.println("No preimage found under bounded limits (see stop message above if printed)."));
    }

    private static void runUserCollision(Scanner scanner) {
        System.out.print("Enter message M: ");
        String m = scanner.nextLine();
        Validation.requireNonEmpty(m, "M");
        System.out.println("(Bounded search: max " + CollisionFinder.BOUNDED_SEARCH_MAX_ATTEMPTS + " hash probes, "
                + CollisionFinder.BOUNDED_SEARCH_MAX_DURATION_MS + " ms wall time.)");

        CollisionFinder.findDifferentMessageSameHashBounded(m).ifPresentOrElse(r -> {
            System.out.println("M   = " + r.originalMessage());
            System.out.println("H(M)= " + r.hashDigestHex());
            System.out.println("M'  = " + r.collidingMessage());
            System.out.println("H(M')=" + r.collidingDigestHex());
            System.out.println("M != M': " + !r.originalMessage().equals(r.collidingMessage()));
            System.out.println("Hashes equal: " + r.hashDigestHex().equals(r.collidingDigestHex()));
        }, () -> {
            System.out.println("No second preimage printed (see collision stop message above).");
        });
    }

    private static void runHmac(Scanner scanner) {
        System.out.print("Key K: ");
        String key = scanner.nextLine();
        System.out.print("Message m: ");
        String msg = scanner.nextLine();
        Validation.requireNonEmpty(key, "K");
        Validation.requireNonEmpty(msg, "m");
        System.out.print("Verbose HMAC debug? (y/N): ");
        String d = scanner.nextLine().trim().toLowerCase(Locale.ROOT);
        boolean verbose = d.equals("y") || d.equals("yes");
        HmacSimplifiedSHA1 hmac = new HmacSimplifiedSHA1(verbose);
        String tag = hmac.compute(key, msg);
        if (!verbose) {
            System.out.println("HMAC-Simplified-SHA1(K, m) = " + tag);
        }
    }
}
