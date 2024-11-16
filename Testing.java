
public class Testing {

        public static void main(String[] args) {

                // byte[] message = { (byte) 0xe9 };

                // byte[] out = SHA3SHAKE.SHA3(256, message, null);

                SHA3SHAKE sponge = new SHA3SHAKE();

                // Create a value with a known pattern
                long test = 0xD201000000000000L; // D2 01 at most significant bytes

                // Rotate by 1
                long result = sponge.circularLeftShift(test, 1);

                // Print results in hex
                System.out.printf("Original: %016X%n", test);
                System.out.printf("Rotated:  %016X%n", result);

                // print results in binary
                for (int i = 0; i < 64; i++) {
                        System.out.printf("%d", (result >> i) & 1);
                }
                System.out.println();
                for (int i = 0; i < 64; i++) {
                        System.out.printf("%d", (test >> i) & 1);
                }
        }
}
