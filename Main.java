import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

public class Main {
    /**
     * A cryptographically secure random number generator.
     */
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * 
     */
    private static void genkey(String publicKeyPath, String passphrase) {

    }

    /**
     */
    private static void ecencrypt(String inputPath, String outputPath,
            String publicKeyPath) {

        // reads the raw bytes directly, preserving the exact data without any text
        // interpretation.
        try (FileInputStream fileInput = new FileInputStream(inputPath);
                FileOutputStream fileOutput = new FileOutputStream(outputPath)) {

        } catch (IOException e) {
            System.out.println("Encryption failed: " + e);
        }
    }

    /**
     * Decrypt the input ciphertext using XOR with a key derived from the
     * passphrase.
     * 
     * @throws IOException
     */
    private static void ecdecrypt(String inputPath, String outputPath,
            String passphrase) {

        try (FileInputStream fileInput = new FileInputStream(inputPath);
                FileOutputStream fileOutput = new FileOutputStream(outputPath)) {

        } catch (IOException e) {
            System.out.println("Decryption failed: " + e);
        }
    }

    private static void sign() {

    }

    private static void verify() {

    }

    public static void main(String[] args) throws IOException {
        String service = args[0];

        if (!isValidService(service)) {
            System.out.println("Invalid service: \"" + service +
                    "\". Must be one of hash, mac, encrypt, or decrypt.");
            return;
        }

        if (args.length < 3) {
            System.out.println("Insufficient arguments provided.");
            return;
        }

        String inPath = args[1];
        String outPath = args[2];

        try {
            if (service.equals("genkey")) {
                if (args.length != 4) {
                    System.out.println("Usage: java Main.java hash <input_file> <output_file> <security_level>");
                    return;
                }
                int securityLevel = Integer.parseInt(args[3]);
                if (!isValidSecurityLevel(securityLevel)) {
                    System.out.println("Invalid security level: \"" + securityLevel
                            + "\". Must be one of one of 224, 256, 384, or 512.");
                    return;
                }
                computeHash(inPath, outPath, securityLevel);
            } else if (service.equals("ecencrypt")) {
                if (args.length != 6) {
                    System.out.println(
                            "Usage: java Main.java mac <input_file> <output_file> <passphrase> <security_level> <mac_length> <mac_length>");
                    return;
                }
                int securityLevel = Integer.parseInt(args[4]);
                if (!isValidSecurityLevel(securityLevel)) {
                    System.out.println("Invalid security level: \"" + securityLevel
                            + "\". Must be one of one of 224, 256, 384, or 512.");
                    return;
                }

                int macLength = Integer.parseInt(args[5]);
                if (macLength <= 0) {
                    System.out.println("MAC length must be greater than zero.");
                    return;
                }

                computeMAC(inPath, outPath, securityLevel, args[3], macLength);
            } else if (service.equals("ecdecrypt")) {
                if (args.length != 4) {
                    System.out.println("Usage: java Main.java encrypt <input_file> <output_file> <passphrase>");
                    return;
                }
                ecencrypt(inPath, outPath, args[3]);
            } else if (service.equals("ecdecrypt")) {
                if (args.length != 4) {
                    System.out.println("Usage: java Main.java decrypt <input_file> <output_file> <passphrase>");
                    return;
                }
                ecdecrypt(inPath, outPath, args[3]);
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid number format: " + e.getMessage());
        }
    }

    private static boolean isValidService(String service) {
        return (service.equals("hash") || service.equals("mac") ||
                service.equals("encrypt") || service.equals("decrypt"));
    }

    private static boolean isValidSecurityLevel(int securityLevel) {
        return (securityLevel == 224) || (securityLevel == 256) ||
                (securityLevel == 384) || (securityLevel == 512);
    }
}