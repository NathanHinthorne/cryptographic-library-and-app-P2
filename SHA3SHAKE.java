import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * The SHA3SHAKE class will enable users to securely hash data, extract hash
 * values, and customize the hashing process according to their specific
 * requirements.
 * 
 * Some functionality is inspired by Markku-Juhani Saarinen's C implementation 
 * of SHA-3 and SHAKE, found here: 
 * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c.
 */
public class SHA3SHAKE {

    /**
     * Array of round constants to be applied to Lane(0, 0), precomputed for each
     * of the 24 rounds.
     */
    private final long[] ROUND_CONSTANTS = new long[] {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    /**
     * The width (i.e. input/output length) of KECCAK.
     */
    private final int WIDTH = 1600;

    // DATA STRUCTURES AND PARAMETERS

    /**
     * The state matrix in KECCAK is a 1600-bit (5x5x64) matrix that serves as the
     * core structure for the algorithm's operations. It is used to store
     * intermediate values during the absorbing (input) and squeezing (output)
     * phases and undergoes multiple permutations to ensure security.
     */
    private long[][] stateMatrix;

    /**
     * The rate of a KECCAK-p permutation in bits.
     */
    private int rate;

    /**
     * The length of the digest of a hash function or the requested length of the
     * output of an XOF, in bits.
     */
    private int d;

    /**
     * Holds all the input data (message, keys, random samples, etc) to be used
     * later.
     */
    private byte[] input;

    /**
     * Whether or not the sponge has been squeezed since it was last initialized.
     */
    private boolean squeezed;

    /**
     * Whether or not a digest method has been called since the sponge was last
     * initialized.
     */
    private boolean digested;

    /**
     * Whether or not the sponge has been initialized.
     */
    private boolean initialized = false;

    public SHA3SHAKE() {
    }

    /**
     * Initialize the SHA-3/SHAKE sponge.
     * The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or
     * 256 for SHAKE.
     * 
     * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bitlength = suffix, SHAKE sec
     *               level = suffix)
     */
    public void init(int suffix) {

        stateMatrix = new long[][] {
                { 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L,
                        0x0000000000000000L },
                { 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L,
                        0x0000000000000000L },
                { 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L,
                        0x0000000000000000L },
                { 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L,
                        0x0000000000000000L },
                { 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L, 0x0000000000000000L,
                        0x0000000000000000L }
        };

        // For SHA-3: capacity = 2 × output length
        // For SHAKE: capacity = 2 × security level
        int capacity = 2 * suffix;

        // The rate is what remains from the 1600 bits of state after subtracting
        // capacity
        rate = 1600 - capacity;

        // For SHA-3, d is the digest length (same as suffix)
        // For SHAKE, d will be set later during squeeze based on requested output
        // length
        d = suffix;

        input = new byte[0];

        squeezed = false;
        digested = false;
        initialized = true;
    }

    /*
     * ------------------- Absorbing Phase -------------------
     * 
     * The input message is divided into blocks (based on the rate r).
     * 
     * Each block is XORed with the first r bits of the state matrix (the rest of
     * the state, c bits, is untouched during this phase). This is done to inject
     * the input data into the state, effectively combining the message with the
     * current internal state through XOR.
     * 
     * After XORing, the entire state matrix undergoes a permutation process that
     * shuffles the bits around in a complex but deterministic way.
     */

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param pos  initial index to hash from
     * @param len  byte count on the buffer
     */
    public void absorb(byte[] data, int pos, int len) {
        if (!initialized) {
            throw new IllegalStateException("Sponge must be initialized before absorbing data");
        }
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        if (pos < 0 || len < 0 || pos + len > data.length) {
            throw new IllegalArgumentException("Invalid pos or len parameters");
        }
        if (squeezed || digested) {
            throw new IllegalStateException("Cannot absorb after squeezing or digesting");
        }

        byte[] temp = new byte[input.length + len];

        // Copy old data
        for (int i = 0; i < input.length; i++) {
            temp[i] = input[i];
        }

        // Append new data
        for (int i = 0; i < len; i++) {
            temp[input.length + i] = data[pos + i];
        }

        input = temp;
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param len  byte count on the buffer (starting at index 0)
     */
    public void absorb(byte[] data, int len) {
        absorb(data, 0, len);
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     */
    public void absorb(byte[] data) {
        absorb(data, 0, data.length);
    }

    /*
     * ------------------- Squeezing Phase -------------------
     * 
     * Once all the input data is absorbed, the squeezing phase starts.
     * 
     * In this phase, the algorithm takes the first r bits from the state matrix as
     * part of the output.
     * 
     * The permutation function is applied again to the state, and another r bits
     * are taken.
     * 
     * This process continues until the desired output length (hash size) is
     * reached.
     */

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number
     * of bytes.
     *
     * @param out hash value buffer
     * @param len desired number of squeezed bytes
     * @return the val buffer containing the desired hash value
     */
    public byte[] squeeze(byte[] out, int len) {
        if (!initialized) {
            throw new IllegalStateException("Sponge must be initialized before a squeeze() call.");
        }
        if (digested) {
            throw new IllegalStateException("Cannot call squeeze() after digest().");
        }

        if (!squeezed) {
            squeezed = true;

            finishAbsorb((byte) 0x1F, (byte) 0x80);
        }

        for (int i = 0; i < len;) {
            byte[] block = stateMatrixToByteArray(stateMatrix);
            for (int j = 0; i < len && j < blockByteLength(); i++, j++) {
                out[i] = block[j];
            }

            keccakF(block);
        }

        return out;
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number
     * of bytes.
     *
     * @param len desired number of squeezed bytes
     * @return newly allocated buffer containing the desired hash value
     */
    public byte[] squeeze(int len) {
        return squeeze(new byte[len], len);
    }

    /*
     * ------------------- Digesting -------------------
     * 
     * Digesting is the final step of the algorithm.
     * It will use the squeezing phase to extract the final hash value.
     */

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @param out hash value buffer
     * @return the val buffer containing the desired hash value
     */
    public byte[] digest(byte[] out) {
        if (!initialized) {
            throw new IllegalStateException("Sponge must be initialized before a digest() call.");
        }
        if (squeezed) {
            throw new IllegalStateException("Cannot call digest() after squeeze().");
        }

        if (!digested) {
            digested = true;

            finishAbsorb((byte) 0x06, (byte) 0x80);
        }

        byte[] block = stateMatrixToByteArray(stateMatrix);

        for (int i = 0; i < d / 8; i++) {
            out[i] = block[i];
        }

        return out;
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @return the desired hash value on a newly allocated byte array
     */
    public byte[] digest() {
        return digest(new byte[d / 8]);
    }

    // helper functions

    /**
     * Create a deep copy of the state matrix.
     * 
     * @return a copy of the state matrix
     */
    private long[][] stateMatrixCopy() {
        long[][] copy = new long[5][5];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                copy[i][j] = stateMatrix[i][j];
            }
        }
        return copy;
    }

    /**
     * The number of bytes in a block. Dependent on the rate.
     * 
     * @return the number of bytes in a block
     */
    private int blockByteLength() {
        return rate / 8;
    }

    /**
     * Perform absorb operations (padding and permutation) on the final input
     * string.
     * Should be called only after all calls to absorb.
     */
    private void finishAbsorb(byte padStart, byte padEnd) {
        byte[] p = new byte[input.length + (blockByteLength() - (input.length % blockByteLength()))];
        System.arraycopy(input, 0, p, 0, input.length);
        p[input.length] ^= padStart;
        p[p.length - 1] ^= padEnd;

        byte[] s = new byte[WIDTH];

        for (int i = 0; i < p.length; i += blockByteLength()) {
            for (int j = 0; j < blockByteLength(); j++) {
                s[j] = (byte) (s[j] ^ p[j + i]);
            }

            s = keccakF(s);
        }
    }

    /**
     * Flatten a 5x5 matrix of longs into a linear byte array.
     * 
     * @param stateMatrix 2D array of longs
     * @return byte array
     */
    private byte[] stateMatrixToByteArray(long[][] stateMatrix) {
        byte[] byteArray = new byte[200]; // Need 1,600 bits. 8 bits per byte.

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        int byteArrayIndex = 0;
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                long lane = stateMatrix[y][x];

                // Reset the buffer's position to zero before putting a new long value
                buffer.clear();
                buffer.putLong(lane);
                buffer.flip(); // Prepare the buffer for reading

                // Copy the bytes from the buffer to the byteArray
                byte[] destArray = new byte[Long.BYTES];
                buffer.get(destArray);
                System.arraycopy(destArray, 0, byteArray, byteArrayIndex, Long.BYTES);
                byteArrayIndex += Long.BYTES;
            }
        }

        return byteArray;
    }

    /**
     * Convert a byte array to a state matrix (a 2D array of longs).
     * 
     * @param byteArray the array to convert
     * @return the array in state matrix representation
     */
    private long[][] byteArrayToStateMatrix(byte[] byteArray) {
        long[][] stateMatrix = new long[5][5];
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.LITTLE_ENDIAN); // Set to little-endian byte order

        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                for (int z = 0; z < 8; z++) {
                    long nextByte = (long) byteArray[8 * (5 * y + x) + z] << 56;
                    stateMatrix[x][y] = stateMatrix[x][y] >>> 8 ^ nextByte;
                }
            }
        }

        return stateMatrix;
    }

    private long circularLeftShift(long value, int offset) {
        return (value << offset) | (value >>> (64 - offset));
    }

    /**
     * Theta (θ) - Diffusion Step.
     * 
     * Functionality: Provides mixing between all bits in the state,
     * creating diffusion across the rows and columns. It applies a parity check
     * across columns of the 5x5 matrix of slices in the state.
     * 
     * Effect: Ensures that each bit is affected by the bits of every column,
     * propagating local changes across the entire state.
     * 
     * @param stateMatrix 3D matrix of bits
     * @return 3D matrix of bits
     */
    private void stepMapTheta() {

        // Step 1: XOR every bit in a column
        long[] C = new long[5];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                C[x] ^= stateMatrix[x][y];
            }
        }

        // Step 2: XOR neighboring columns (x-1, z) and (x+1, z-1)
        long[] D = new long[5];
        for (int x = 0; x < 5; x++) {
            long neighborLane1 = C[(x + 4) % 5];
            long neighborLane2 = circularLeftShift(C[(x + 1) % 5], 1);

            D[x] = neighborLane1 ^ neighborLane2;
        }

        // Step 3: XOR each bit with resultLaneD
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                stateMatrix[x][y] ^= D[x];
            }
        }
    }

    /**
     * Rho (ρ) - Bitwise Rotation.
     * 
     * Functionality: Rotates the bits of each lane (individual segments of the
     * state matrix) by a position-dependent number of steps.
     * 
     * Effect: Provides non-linearity by rotating bits in different ways
     * for each lane.
     */
    private void stepMapRho() {

        // Step 1: Initialize (x, y) to (1, 0)
        int x = 1;
        int y = 0;

        // Step 2: Perform rotation 24 times
        for (int t = 0; t < 24; t++) {
            int offset = ((t + 1) * (t + 2)) / 2; // Calculate offset

            // "Rotate" the bits by bitshifting
            stateMatrix[x][y] = circularLeftShift(stateMatrix[x][y], offset);

            // Update (x, y) as per the given rule
            int newX = y;
            int newY = (2 * x + 3 * y) % 5;
            x = newX;
            y = newY;
        }
    }

    /**
     * Pi (π) - Transposition (Permutation).
     * 
     * Functionality: Rearranges the positions of the bits within the
     * 3D state matrix.
     * 
     * Effect: Ensures that bits are mixed across different lanes.
     */
    private void stepMapPi() {
        long[][] newStateMatrix = stateMatrixCopy();

        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                newStateMatrix[x][y] = stateMatrix[(x + 3 * y) % 5][x];
            }
        }

        stateMatrix = newStateMatrix;
    }

    /**
     * Chi (χ) - Nonlinear Mixing.
     * 
     * Functionality: XORs each bit with a combination of other bits in the same
     * row.
     * 
     * Effect: Introduces non-linearity, which is critical for creating a
     * secure cryptographic transformation that resists linear attacks.
     */
    private void stepMapChi() {

        long[][] newStateMatrix = stateMatrixCopy();

        // operation is done BY ROW using the logic gates given in the paper
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                // A′[x, y, z] = A[x, y, z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y,
                // z]).
                newStateMatrix[x][y] = stateMatrix[x][y]
                        ^ ((stateMatrix[(x + 1) % 5][y] ^ 0xFFFFFFFF) & stateMatrix[(x + 2) % 5][y]);
            }
        }

        stateMatrix = newStateMatrix;
    }

    /**
     * Iota (ι) - Round Constant Addition.
     * 
     * Functionality: Injects a round-dependent constant into the state to
     * break symmetry and ensure that each round is different.
     * 
     * Effect: Ensures that the permutations applied in each round differ,
     * preventing any symmetry or structure from weakening the hash function.
     */
    private void stepMapIota(int round) {
        // adds asymmetric, round specific CONSTANTS to the (0,0) lane

        stateMatrix[0][0] ^= ROUND_CONSTANTS[round];
    }

    private void executeRound(int round) {
        stepMapTheta();
        stepMapRho();
        stepMapPi();
        stepMapChi();
        stepMapIota(round);
    }

    private byte[] keccakP(int numRounds, byte[] byteArray) {
        stateMatrix = byteArrayToStateMatrix(byteArray);

        for (int round = 0; round < numRounds; round++) {
            executeRound(round);
        }

        return stateMatrixToByteArray(stateMatrix);
    }

    private byte[] keccakF(byte[] byteArray) {
        return keccakP(24, byteArray);
    }

    /*
     * ----------------------------------------------------------
     * Utility methods
     * These methods are specific implementations of the keccak algorithm
     * ----------------------------------------------------------
     */

    /**
     * Compute the streamlined SHA-3-<224,256,384,512> on input X.
     *
     * @param suffix desired output length in bits (one of 224, 256, 384, 512)
     * @param X      data to be hashed
     * @param out    hash value buffer (if null, this method allocates it with the
     *               required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) {
        /*
         * SHA-3: Produces a fixed output length. It is a standard cryptographic hash
         * function with variants such as SHA3-224, SHA3-256, SHA3-384, and SHA3-512,
         * each providing outputs of exactly 224, 256, 384, and 512 bits, respectively.
         */

        if (suffix != 224 && suffix != 256 && suffix != 384 && suffix != 512) {
            throw new IllegalArgumentException(
                    "Invalid suffix. Must be 224, 256, 384, or 512 for SHA-3");
        }

        SHA3SHAKE sha3 = new SHA3SHAKE();

        sha3.init(suffix);

        sha3.absorb(X);

        if (out == null) {
            out = new byte[suffix / 8];
        } else if (out.length < suffix / 8) {
            throw new IllegalArgumentException(
                    "Output buffer is too small. Needs at least " + (suffix / 8) + " bytes");
        }

        return sha3.digest(out);
    }

    /**
     * Compute the streamlined SHAKE-<128,256> on input X with output bitlength L.
     *
     * @param suffix desired security level (either 128 or 256)
     * @param X      data to be hashed
     * @param L      desired output length in bits (must be a multiple of 8)
     * @param out    hash value buffer (if null, this method allocates it with the
     *               required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHAKE(int suffix, byte[] X, int L, byte[] out) {
        /*
         * SHAKE (Secure Hash Algorithm Keccak): An extendable-output function (XOF),
         * which means the output length can be set to any desired size. SHAKE is
         * suitable when you need a variable-length hash or a longer output for
         * applications such as key generation or padding.
         */

        if (suffix != 128 && suffix != 256) {
            throw new IllegalArgumentException(
                    "Invalid suffix. Must be 128 or 256 for SHAKE");
        }

        SHA3SHAKE shake = new SHA3SHAKE();

        shake.init(suffix);

        shake.absorb(X);

        if (out == null) {
            out = new byte[L];
        } else if (out.length < L) {
            throw new IllegalArgumentException(
                    "Output buffer is too small. Needs at least " + (L) + " bytes");
        }

        return shake.squeeze(out, L);
    }

}