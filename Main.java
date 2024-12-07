import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * This program offers several cryptographic services based on elliptic curve 
 * cryptography.
 * 
 * @author Nathan Hinthorne
 * @author Trae Claar
 */
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
     * Note for reading a public key file: the first byte of the public key output
     * file corresponds to least significant byte of the x-coordinate of the key,
     * and the remaining bytes contain the bytes of the y-coordinate.
     * 
     * @param publicKeyPath file path to write the public key to, or null if the
     *                      public key should not be written to a file
     * @param passphrase    the passphrase from which to generate the key pair
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

        byte[] x = v.x.toByteArray();

        if (publicKeyPath != null) {
            try (FileOutputStream fileOutput = new FileOutputStream(publicKeyPath)) {
                fileOutput.write(x[x.length - 1]);
                fileOutput.write(v.y.toByteArray());
            } catch (IOException e) {
                System.out.println("Failed to write public key to requested file: " + e);
            }
        }

        return s;
    }

    /**
     * Encrypts a message using the provided public key and passphrase.
     * 
     * @param inputPath     file path to the message to encrypt
     * @param outputPath    file path to write the encrypted message to
     * @param publicKeyPath file path to the public key to use for encryption
     * 
     * @throws IOException
     */
    private static void ecencrypt(String inputPath, String outputPath, String publicKeyPath) {

        // reads the raw bytes directly, preserving the exact data without any text
        // interpretation.
        try (FileInputStream messageFile = new FileInputStream(inputPath)) {
            writeCryptogram(messageFile.readAllBytes(), outputPath, publicKeyPath);
        } catch (IOException e) {
            System.out.println("Failed to read input file: " + e);
        }
    }

    /**
     * Decrypt the input ciphertext with a private key derived from the passphrase.
     * 
     * @param inputPath  file path to the encrypted message to decrypt
     * @param outputPath file path to write the decrypted message to
     * @param passphrase the passphrase used to decrypt the message
     * 
     * @throws IOException
     */
    private static void ecdecrypt(String inputPath, String outputPath, String passphrase) {

        try (FileInputStream fileInput = new FileInputStream(inputPath);
                FileOutputStream fileOutput = new FileOutputStream(outputPath)) {

            Edwards curve = new Edwards();

            // 1. Reconstruct the point Z from the input file
            byte zXLsb = fileInput.readNBytes(1)[0];
            byte[] zYBytes = fileInput.readNBytes(33);

            BigInteger zY = new BigInteger(zYBytes);
            boolean lsbIsOne = (zXLsb & 1) == 1;
            Edwards.Point z = curve.getPoint(zY, lsbIsOne);

            // 2. Read the ciphertext and tag
            byte[] c = fileInput.readNBytes(fileInput.available() - 32); // remaining bytes minus tag
            byte[] t = fileInput.readNBytes(32); // last 32 bytes are the tag

            // 3. Recompute private key from passphrase
            BigInteger s = genkey(null, passphrase);

            // 4. Compute W = s*Z
            Edwards.Point w = z.mul(s);

            // 5. Derive keys ka and ke
            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(256);
            sponge.absorb(w.y.toByteArray());
            byte[] derivedKey = sponge.squeeze(64); // 512 bits total

            // Split the derived key into ka and ke (each 256 bits)
            byte[] ka = new byte[32];
            byte[] ke = new byte[32];
            System.arraycopy(derivedKey, 0, ka, 0, 32);
            System.arraycopy(derivedKey, 32, ke, 0, 32);

            // 6. Verify authentication tag
            sponge.init(256);
            sponge.absorb(ka);
            sponge.absorb(c);
            byte[] tPrime = sponge.digest();

            // Compare tags
            if (!java.util.Arrays.equals(t, tPrime)) {
                throw new IOException("Authentication failed: Invalid tag");
            }

            // 7. Decrypt the message
            sponge.init(128);
            sponge.absorb(ke);
            byte[] oneTimePad = sponge.squeeze(c.length);

            // XOR with ciphertext to get plaintext
            byte[] message = new byte[c.length]; // plaintext
            for (int i = 0; i < c.length; i++) {
                message[i] = (byte) (c[i] ^ oneTimePad[i]);
            }

            // 8. Write decrypted message to output file
            fileOutput.write(message);

        } catch (IOException e) {
            System.out.println("Decryption failed: " + e);
        }
    }

    /**
     * Compute the signature of a file under a specified passphrase and
     * write it to a file.
     * 
     * @param inputPath  file path to the file to sign
     * @param outputPath fle path to the file to write the signature to
     * @param passphrase the passphrase used to generate the private key
     */
    private static void sign(String inputPath, String outputPath, String passphrase) {
        try (FileInputStream inputFile = new FileInputStream(inputPath);
                FileOutputStream outputFile = new FileOutputStream(outputPath)) {

            byte[] m = inputFile.readAllBytes();
            outputFile.write(genSignature(passphrase, m));
        } catch (IOException e) {
            System.out.println("Signing failed: " + e);
        }
    }

    /**
     * Verify that a provided signature file corresponds to a given file
     * under a certain public key. Outputs a message indicating whether
     * the signature matches.
     * 
     * @param dataPath      file path to the plaintext document that was signed
     * @param sigPath       file path to the signature file
     * @param publicKeyPath file path to the public key file
     */
    private static void verify(String dataPath, String sigPath, String publicKeyPath) {
        try (FileInputStream dataFile = new FileInputStream(dataPath);
                FileInputStream sigFile = new FileInputStream(sigPath);
                FileInputStream keyFile = new FileInputStream(publicKeyPath)) {

            byte[] m = dataFile.readAllBytes();
            BigInteger h = new BigInteger(sigFile.readNBytes(modRMaxBytes()));
            BigInteger z = new BigInteger(sigFile.readAllBytes());

            Edwards curve = new Edwards();
            boolean xLsb = keyFile.readNBytes(1)[0] % 2 == 1;
            Edwards.Point v = curve.getPoint(new BigInteger(keyFile.readAllBytes()), xLsb);

            Edwards.Point uPrime = curve.gen().mul(z).add(v.mul(h));

            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(256);
            sponge.absorb(uPrime.y.toByteArray());
            sponge.absorb(m);
            BigInteger hPrime = (new BigInteger(sponge.digest())).mod(Edwards.r);

            if (h.equals(hPrime)) {
                System.out.println("Signature verified: document is authentic.");
            } else {
                System.out.println("Could not verify signature: document may not be authentic.");
            }
        } catch (IOException e) {
            System.out.println("Verification failed: " + e);
        }
    }

    /**
     * Compute the signature of the provided input file under a specified passphrase, 
     * then generate a cryptogram containing the signature and message under the 
     * provided public key. 
     * 
     * Note for reading the decrypted result: the first 62 bytes will contain the
     * signature, and the remaining bytes will contain the message.
     * 
     * @param inputPath the path to the file to sign/encrypt
     * @param outputPath the path to write the cryptogram to
     * @param passphrase the passphrase with which to sign the message
     * @param publicKeyPath the path to the public key file to be used in encryption
     */
    private static void signencrypt(String inputPath, String outputPath, String passphrase, 
            String publicKeyPath) {

        try (FileInputStream inputFile = new FileInputStream(inputPath)) {
            byte[] m = inputFile.readAllBytes();

            byte[] sig = genSignature(passphrase, m);
            byte[] plaintext = new byte[m.length + sig.length];
            System.arraycopy(sig, 0, plaintext, 0, sig.length);
            System.arraycopy(m, 0, plaintext, sig.length, m.length);

            writeCryptogram(m, outputPath, publicKeyPath);
        } catch (IOException e) {
            System.out.println("Failed to read input file: " + e);
        }
    }

    /**
     * Encrypt the provided message under the public key and write it to a file.
     * 
     * @param message the message to encrypt
     * @param outputPath the path to write the cryptogram
     * @param publicKeyPath path to the public key file
     */
    private static void writeCryptogram(byte[] message, String outputPath, String publicKeyPath) {

        // reads the raw bytes directly, preserving the exact data without any text
        // interpretation.
        try (FileInputStream publicKeyFile = new FileInputStream(publicKeyPath);
                FileOutputStream fileOutput = new FileOutputStream(outputPath)) {

            Edwards curve = new Edwards();

            // 1. Reconstruct the public key from the file
            byte vXLsb = publicKeyFile.readNBytes(1)[0];
            byte[] vYBytes = publicKeyFile.readAllBytes();
            BigInteger vY = new BigInteger(vYBytes);

            boolean lsbIsOne = (vXLsb & 1) == 1;
            Edwards.Point v = curve.getPoint(vY, lsbIsOne);

            // 2. Generate random nonce k
            BigInteger k = genNonce();

            // 3. Compute key exchange points (W <- k*V, Z <- k*G)
            Edwards.Point w = v.mul(k); // W = k*V
            Edwards.Point z = curve.gen().mul(k); // Z = k*G

            // 4. Key derivation
            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(256);
            sponge.absorb(w.y.toByteArray());
            byte[] derivedKey = sponge.squeeze(64); // 512 bits total

            // Split the derived key into ka and ke (each 256 bits)
            byte[] ka = new byte[32];
            byte[] ke = new byte[32];
            System.arraycopy(derivedKey, 0, ka, 0, 32);
            System.arraycopy(derivedKey, 32, ke, 0, 32);

            // 5. Symmetric encryption
            sponge.init(128);
            sponge.absorb(ke);

            // squeeze as many bytes as the message length
            byte[] oneTimePad = sponge.squeeze(message.length);

            // XOR with message
            byte[] c = new byte[message.length]; // ciphertext
            for (int i = 0; i < message.length; i++) {
                c[i] = (byte) (message[i] ^ oneTimePad[i]);
            }

            // 6. Authentication tag generation
            sponge.init(256);
            sponge.absorb(ka);
            sponge.absorb(c);
            byte[] t = sponge.digest();

            // 7. Write full cryptogram to output
            // Cryptogram is (Z, ciphertext, tag)
            byte[] zXBytes = z.x.toByteArray();
            fileOutput.write(zXBytes[zXBytes.length - 1]);

            byte[] zY = z.y.toByteArray();
            byte[] paddedZY = new byte[33];
            int offset = 33 - zY.length;
            System.arraycopy(zY, 0, paddedZY, offset, zY.length);
            fileOutput.write(paddedZY);

            fileOutput.write(c);
            fileOutput.write(t);

        } catch (IOException e) {
            System.out.println("Failed to write cryptogram to requested file: " + e);
        }
    }

    /**
     * Generate a signature of a message with a private key based on a provided 
     * passphrase.
     * 
     * @param passphrase the passphrase to use for signing
     * @param message the message to sign
     * @return the signature of the message
     */
    private static byte[] genSignature(String passphrase, byte[] message) {
        BigInteger s = genkey(null, passphrase);
        BigInteger k = genNonce();

        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(s.toByteArray());
        sponge.absorb(message);
        sponge.absorb(k.toByteArray());
        byte[] kBytes = sponge.squeeze(512);
        k = (new BigInteger(kBytes)).mod(Edwards.r);

        Edwards curve = new Edwards();
        Edwards.Point u = curve.gen().mul(k);

        sponge.init(256);
        sponge.absorb(u.y.toByteArray());
        sponge.absorb(message);
        BigInteger h = (new BigInteger(sponge.digest())).mod(Edwards.r);
        BigInteger z = k.subtract(h.multiply(s)).mod(Edwards.r);

        byte[] sig = new byte[modRMaxBytes() * 2];
        byte[] hBytes = h.toByteArray();
        byte[] zBytes = z.toByteArray();
        System.arraycopy(hBytes, 0, sig, modRMaxBytes() - hBytes.length, modRMaxBytes());
        System.arraycopy(zBytes, 0, sig, modRMaxBytes() * 2 - zBytes.length, modRMaxBytes());

        return sig;
    }

    /**
     * Calculate the maximum number of bytes that can be contained in the byte
     * representation of a BigInteger mod r.
     * 
     * @return the maximum byte length of a BigInteger mod r
     */
    private static int modRMaxBytes() {
        return Edwards.r.toByteArray().length;
    }

    /**
     * Generate a random nonce modulo Edwards.r.
     * 
     * @return a random nonce in the range [0, Edwards.r)
     */
    private static BigInteger genNonce() {
        int rbytes = (Edwards.r.bitLength() + 7) >> 3;
        return new BigInteger(RANDOM.generateSeed(rbytes << 1)).mod(Edwards.r);
    }

    /**
     * Test whether the provided service name is valid.
     * 
     * @param service the service to test
     * @return whether the service is truly a service
     */
    private static boolean isValidService(String service) {
        return (service.equals("genkey") || service.equals("ecencrypt") ||
                service.equals("ecdecrypt") || service.equals("sign") ||
                service.equals("verify") || service.equals("signencrypt"));
    }

    public static void main(String[] args) throws IOException {
        String service = args[0];

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--help":
                    switch (service) {
                        case "genkey":
                            System.out.println(
                                "Usage: \n\t java Main genkey <public_key_file> <passphrase> [options]\n\n"
                                + "Description: \n"
                                + "\tGenerate a public key from a private key based on a passphrase.\n"
                                + "\nArguments: \n"
                                + "\tpublic_key_file: Path to the public key file to write to.\n"
                                + "\tpassphrase: The passphrase to base the private key off of. \n"
                                + "\nOptions: \n"
                                + "\t--help: Show help.\n"
                            );
                            return;
                        case "ecencrypt":
                            System.out.println(
                                "Usage: \n\t java Main.java ecencrypt <input_file> <output_file> <public_key_file> [options]\n\n"
                                + "Description: \n"
                                + "\tEncrypt a message under the provided public key.\n"
                                + "\nArguments: \n"
                                + "\tinput_file: Path to the input file (plaintext).\n"
                                + "\toutput_file: Path to the output file (cryptogram). \n"
                                + "\tpublic_key_file: Path to the public key file.\n"
                                + "\nOptions: \n"
                                + "\t--help: Show help.\n"
                            );
                            return;
                        case "ecdecrypt":
                            System.out.println(
                                "Usage: \n\t java Main ecdecrypt <input_file> <output_file> <passphrase> [options]\n\n"
                                + "Description: \n"
                                + "\tDecrypt a cryptogram with the provided passphrase.\n"
                                + "\nArguments: \n"
                                + "\tinput_file: Path to the input file (cryptogram).\n"
                                + "\toutput_file: Path to the output file (decrypted message). \n"
                                + "\tpassphrase: Passphrase to decrypt with. \n"
                                + "\nOptions: \n"
                                + "\t--help: Show help.\n"
                            );
                            return;
                        case "sign":
                            System.out.println(
                                "Usage: \n\t java Main sign <signature_file> <input_file> <passphrase> [options]\n\n"
                                + "Description: \n"
                                + "\tDecrypt the provided cryptogram.\n"
                                + "\nArguments: \n"
                                + "\tsignature_file: Path to the signature file to write to. \n"
                                + "\tinput_file: Path to the input file to sign.\n"
                                + "\tpassphrase: Passphrase to sign with. \n"
                                + "\nOptions: \n"
                                + "\t--help: Show help.\n"
                            );
                            return;
                        case "verify":
                            System.out.println(
                                "Usage: \n\t java Main verify <input_file> <signature_file> <public_key_file> [options]\n\n"
                                + "Description: \n"
                                + "\tVerify that a signature file corresponds to an input file under a provided public key.\n"
                                + "\nArguments: \n"
                                + "\tinput_file: Path to the input file that was signed.\n"
                                + "\tsignature_file: Path to the signature file to verify. \n"
                                + "\tpublic_key_file: Path to the public key file.\n"
                                + "\nOptions: \n"
                                + "\t--help: Show help.\n"
                            );
                            return;
                        case "signencrypt":
                            System.out.println(
                                "Usage: \n\t java Main signencrypt <input_file> <output_file> <passphrase> <public_key_file> [options]\n\n"
                                + "Description: \n"
                                + "\tVerify that a signature file corresponds to an input file under a provided public key.\n"
                                + "\nArguments: \n"
                                + "\tinput_file: Path to the input file (message).\n"
                                + "\toutput_file: Path to the output file (cryptogram). \n"
                                + "\tpassphrase: Passphrase to sign with. \n"
                                + "\tpublic_key_file: Path to the public key file.\n"
                                + "\nOptions: \n"
                                + "\t--help: Show help.\n"
                            );
                            return;
                        default: 
                            System.out.println(
                                "Usage: \n\t java Main.java <command> [options]\n\n"
                                + "Commands: \n"
                                + "\tgenkey: Generate a public key.\n"
                                + "\tecencrypt: Encrypt a file.\n"
                                + "\tecdecrypt: Decrypt a file.\n"
                                + "\tsign: Compute the signature of a file.\n"
                                + "\tverify: Verify the signature of a file.\n"
                                + "\tsignencrypt: Encrypt a file and its signature.\n"
                                + "\nGeneral Options: \n"
                                + "\t--help: Show help.\n"
                            );
                            return;
                    }   
            }
        }

        if (!isValidService(service)) {
            System.out.println("Invalid service: \"" + service +
                    "\". Must be one of \"genkey\", \"ecencrypt\", \"ecdecrypt\", " 
                    + "\"sign\", \"verify\", or \"signencrypt\".");
            return;
        }

        try {
            if (service.equals("genkey")) {
                if (args.length != 3) {
                    System.out.println("Usage: java Main genkey <public_key_file> <passphrase> [options]");
                    return;
                }

                genkey(args[1], args[2]);
            } else if (service.equals("ecencrypt")) {
                if (args.length != 4) {
                    System.out.println(
                            "Usage: java Main ecencrypt <input_file> <output_file> <public_key_file> [options]");
                    return;
                }

                ecencrypt(args[1], args[2], args[3]);
            } else if (service.equals("ecdecrypt")) {
                if (args.length != 4) {
                    System.out.println("Usage: java Main ecdecrypt <input_file> <output_file> <passphrase> [options]");
                    return;
                }

                ecdecrypt(args[1], args[2], args[3]);
            } else if (service.equals("sign")) {
                if (args.length != 4) {
                    System.out.println("Usage: java Main sign <signature_file> <input_file> <passphrase> [options]");
                    return;
                }

                sign(args[2], args[1], args[3]);
            } else if (service.equals("verify")) {
                if (args.length != 4) {
                    System.out.println(
                            "Usage: java Main verify <input_file> <signature_file> <public_key_file> [options]");
                    return;
                }

                verify(args[1], args[2], args[3]);
            } else if (service.equals("signencrypt")) {
                if (args.length != 5) {
                    System.out.println(
                            "Usage: java Main signencrypt <input_file> <output_file> <passphrase> <public_key_file> [options]");
                    return;
                }

                signencrypt(args[1], args[2], args[3], args[4]);
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid number format: " + e.getMessage());
        }
    }
}