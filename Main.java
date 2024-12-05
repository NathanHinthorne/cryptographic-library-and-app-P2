import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * 
 * 
 * @author 🕺 Nathan Hinthorne 🕺
 * @author 🌮 Trae Claar 💧
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
        try (FileInputStream messageFile = new FileInputStream(inputPath);
                FileInputStream publicKeyFile = new FileInputStream(publicKeyPath);
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
            byte[] message = messageFile.readAllBytes();
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
            fileOutput.write(z.y.toByteArray());
            fileOutput.write(c);
            fileOutput.write(t);

        } catch (IOException e) {
            System.out.println("Failed to write cryptogram to requested file: " + e);
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

            System.out.println("Original tag (t):   " + bytesToHex(t));
            System.out.println("Computed tag (t'): " + bytesToHex(tPrime)); // should match t

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

            BigInteger s = genkey(null, passphrase);
            BigInteger k = genNonce();
            byte[] m = inputFile.readAllBytes();

            SHA3SHAKE sponge = new SHA3SHAKE();
            sponge.init(128);
            sponge.absorb(s.toByteArray());
            sponge.absorb(m);
            sponge.absorb(k.toByteArray());
            byte[] kBytes = sponge.squeeze(512);
            k = (new BigInteger(kBytes)).mod(Edwards.r);

            Edwards curve = new Edwards();
            Edwards.Point u = curve.gen().mul(k);

            sponge.init(256);
            sponge.absorb(u.y.toByteArray());
            sponge.absorb(m);
            BigInteger h = (new BigInteger(sponge.digest())).mod(Edwards.r);
            BigInteger z = k.subtract(h.multiply(s)).mod(Edwards.r);

            outputFile.write(h.toByteArray());
            outputFile.write(z.toByteArray());
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
            BigInteger h = new BigInteger(sigFile.readNBytes(32));
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
     * Generate a random nonce modulo Edwards.r.
     * 
     * @return a random nonce in the range [0, Edwards.r)
     */
    private static BigInteger genNonce() {
        int rbytes = (Edwards.r.bitLength() + 7) >> 3;
        return new BigInteger(RANDOM.generateSeed(rbytes << 1)).mod(Edwards.r);
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
                    System.out.println("Usage: java Main sign <signature_file> <output_file> <passphrase> [options]");
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

    // Debugging method to convert bytes to hex
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}