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
     * Compute the hash of the input data using SHA-3.
     */
    private static void computeHash(String inputPath, String outPath, int securityLevel) {
        try (FileInputStream fileInput = new FileInputStream(inputPath);
        FileOutputStream fileOutput = new FileOutputStream(outPath)) {

            byte[] data = fileInput.readAllBytes();

            byte[] hash = SHA3SHAKE.SHA3(securityLevel, data, null);

            fileOutput.write(hash);
        } catch (IOException e) {
            System.out.println("Hashing failed: " + e);
        }
    }

    /**
     * Compute the MAC of the input data using SHA-3.
     */
    private static void computeMAC(String inputPath, String outPath, int securityLevel,
            String passphrase, int macLength) {
        try (FileInputStream fileInput = new FileInputStream(inputPath);
            FileOutputStream fileOutput = new FileOutputStream(outPath)) {

            byte[] passphraseBytes = passphrase.getBytes();
            byte[] data = fileInput.readAllBytes();

            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(securityLevel);
            sponge.absorb(passphraseBytes);
            sponge.absorb(data);
            sponge.absorb("T".getBytes());
            byte[] result = sponge.squeeze(macLength);

            fileOutput.write(result);
        } catch (IOException e) {
            System.out.println("Failed to compute MAC: " + e);
        }
    }

    /**
     * Encrypt the input data using XOR with a key derived from the passphrase.
     * 
     * @throws IOException if an I/O error occurs
     */
    private static void encrypt(String inputPath, String outPath,
            String passphrase) {

        // reads the raw bytes directly, preserving the exact data without any text
        // interpretation.
        try (FileInputStream fileInput = new FileInputStream(inputPath);
                FileOutputStream fileOutput = new FileOutputStream(outPath)) {

            byte[] passphraseBytes = passphrase.getBytes();
            byte[] data = fileInput.readAllBytes();

            byte[] key = SHA3SHAKE.SHAKE(128, passphraseBytes, 128, null);
            byte[] nonce = new byte[16];
            RANDOM.nextBytes(nonce);

            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(128);
            sponge.absorb(nonce);
            sponge.absorb(key);

            byte[] mask = sponge.squeeze(data.length);
            for (int i = 0; i < data.length; i++) {
                data[i] ^= mask[i];
            }

            fileOutput.write(nonce);
            fileOutput.write(data);
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
    private static void decrypt(String inputPath, String outPath,
            String passphrase) {

        try (FileInputStream fileInput = new FileInputStream(inputPath);
                FileOutputStream fileOutput = new FileOutputStream(outPath)) {

            byte[] passphaseBytes = passphrase.getBytes();
            byte[] nonce = fileInput.readNBytes(16);
            byte[] ciphertext = fileInput.readAllBytes();

            byte[] key = SHA3SHAKE.SHAKE(128, passphaseBytes, 128, null);

            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(128);
            sponge.absorb(nonce);
            sponge.absorb(key);

            byte[] mask = sponge.squeeze(ciphertext.length);
            for (int i = 0; i < ciphertext.length; i++) {
                ciphertext[i] ^= mask[i];
            }

            fileOutput.write(ciphertext);
        } catch (IOException e) {
            System.out.println("Decryption failed: " + e);
        }
    }

    public static void main(String[] args) throws IOException {
        String service = args[0];

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--help":
                    switch (service) {
                        case "hash":
                            System.out.println(
                                "Usage: \n\t java Main.java hash <input_file> <output_file> <security_level> [options]\n\n"
                                + "Description: \n"
                                + "\tHash the provided message.\n"
                                + "\nArguments: \n"
                                + "\tinput_file: Path to the input file.\n"
                                + "\toutput_file: Path to the output file.\n"
                                + "\tsecurity_level: One of 224, 256, 384, or 512. \n"
                                + "\nOptions: \n"
                                + "\t--help: Show help.\n"
                            );
                            return;
                        case "mac":
                            System.out.println(
                                "Usage: \n\t java Main.java mac <input_file> <output_file> <passphrase> <security_level> <mac_length> [options]\n\n"
                                + "Description: \n"
                                + "\tCompute a MAC for the provided message.\n"
                                + "\nArguments: \n"
                                + "\tinput_file: Path to the input file.\n"
                                + "\toutput_file: Path to the output file. \n"
                                + "\tpassphrase: Passphrase to compute the MAC with. \n"
                                + "\tsecurity_level: One of 224, 256, 384, or 512. \n"
                                + "\tmac_length: Length of computed MAC; must be > 0.\n"
                                + "\nOptions: \n"
                                + "\t--help: Show help.\n"
                            );
                            return;
                        case "encrypt":
                            System.out.println(
                                "Usage: \n\t java Main.java encrypt <input_file> <output_file> <passphrase> [options]\n\n"
                                + "Description: \n"
                                + "\tEncrypt the provided message.\n"
                                + "\nArguments: \n"
                                + "\tinput_file: Path to the input file.\n"
                                + "\toutput_file: Path to the output file. \n"
                                + "\tpassphrase: Passphrase to encrypt with. \n"
                                + "\nOptions: \n"
                                + "\t--help: Show help.\n"
                            );
                            return;
                        case "decrypt":
                            System.out.println(
                                "Usage: \n\t java Main.java decrypt <input_file> <output_file> <passphrase> [options]\n\n"
                                + "Description: \n"
                                + "\tDecrypt the provided cryptogram.\n"
                                + "\nArguments: \n"
                                + "\tinput_file: Path to the input file/cryptogram.\n"
                                + "\toutput_file: Path to the output file. \n"
                                + "\tpassphrase: Passphrase to decrypt with. \n"
                                + "\nOptions: \n"
                                + "\t--help: Show help.\n"
                            );
                            return;
                        default: 
                            System.out.println(
                                "Usage: \n\t java Main.java <command> [options]\n\n"
                                + "Commands: \n"
                                + "\thash: Compute the hash of a message.\n"
                                + "\tmac: Compute the MAC for a message.\n"
                                + "\tencrypt: Encrypt a message under a passphrase.\n"
                                + "\tdecrypt: Decrypt a message under a passphrase.\n"
                                + "\nGeneral Options: \n"
                                + "\t--help: Show help.\n"
                            );
                            return;
                    }   
            }
        }

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
            if (service.equals("hash")) {
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
            } else if (service.equals("mac")) {
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
            } else if (service.equals("encrypt")) {
                if (args.length != 4) {
                    System.out.println("Usage: java Main.java encrypt <input_file> <output_file> <passphrase>");
                    return;
                }
                encrypt(inPath, outPath, args[3]);
            } else if (service.equals("decrypt")) {
                if (args.length != 4) {
                    System.out.println("Usage: java Main.java decrypt <input_file> <output_file> <passphrase>");
                    return;
                }
                decrypt(inPath, outPath, args[3]);
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