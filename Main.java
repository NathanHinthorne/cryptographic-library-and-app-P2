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
     * Generates a private/public key pair based on a provided passphrase, returns
     * the private key, and optionally writes the public key (which is a point on 
     * an elliptic curve) to a file.
     * 
     * @param publicKeyPath file path to write the public key to, or null if the 
     * public key should not be written to a file
     * @param passphrase the passphrase from which to generate the key pair
     * @return the private key
     */
    private static BigInteger genkey(String publicKeyPath, String passphrase) {
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(passphrase.getBytes());
        BigInteger s = new BigInteger(sponge.squeeze(256)).mod(Edwards.r);
        
        Edwards curve = new Edwards();
        Edwards.Point v = curve.gen().mul(s);

        if (v.x.testBit(0)) {
            s = Edwards.r.subtract(s);
            v = v.negate();
        }

        if (publicKeyPath != null) {
            try (FileOutputStream fileOutput = new FileOutputStream(publicKeyPath)) {
                fileOutput.write(v.x.toByteArray());
                fileOutput.write(v.y.toByteArray());
            } catch (IOException e) {
                System.out.println("Failed to write public key to requested file: " + e);
            }
        }

        return s;
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
                    "\". Must be one of \"genkey\", \"ecencrypt\", \"ecdecrypt\", \"sign\", or \"verify\".");
            return;
        }

        try {
            if (service.equals("genkey")) {
                if (args.length != 2) {
                    System.out.println("Usage: java Main genkey <public_key_file> <passphrase> [options]");
                    return;
                }

                // genkey();
            } else if (service.equals("ecencrypt")) {
                if (args.length != 3) {
                    System.out.println(
                            "Usage: java Main ecencrypt <input_file> <output_file> <public_key_file> [options]");
                    return;
                }

                // ecencrypt();
            } else if (service.equals("ecdecrypt")) {
                if (args.length != 3) {
                    System.out.println("Usage: java Main ecdecrypt <input_file> <output_file> <passphrase> [options]");
                    return;
                }

                // ecdecrypt();
            } else if (service.equals("sign")) {
                if (args.length != 3) {
                    System.out.println("Usage: java Main sign <signature_file> <input_file> <passphrase> [options]");
                    return;
                }

                // sign();
            } else if (service.equals("verify")) {
                if (args.length != 3) {
                    System.out.println(
                            "Usage: java Main verify <input_file> <signature_file> <public_key_file> [options]");
                    return;
                }

                // verify();
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid number format: " + e.getMessage());
        }
    }

    private static boolean isValidService(String service) {
        return (service.equals("genkey") || service.equals("ecencrypt") ||
                service.equals("ecdecrypt") || service.equals("sign") ||
                service.equals("verify"));
    }
}