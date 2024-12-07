import java.math.BigInteger;
import java.util.Random;

/**
 * Test class to verify that the Edwards class implementation satisfies certain
 * properties.
 */
public class TestEdwards {

    /**
     * The number of values for k, l, and m with which to test the second set of
     * properties (see appendix C of project description). Higher values (e.g. 100000) 
     * will take a pretty long time.
     */
    private static final int RANDOM_SCALAR_TEST_COUNT = 10; 

    public static void main(String[] args) {
        Random rand = new Random();
        Edwards curve = new Edwards();
        boolean fail = false;

        // basic arithmetic property tests
        if (!curve.gen().mul(BigInteger.ZERO).isZero()) {
            System.out.println("Test 0 * G = O: FAILED");
            fail = true;
        }  

        if (!curve.gen().mul(BigInteger.ONE).equals(curve.gen())) {
            System.out.println("Test 1 * G = G: FAILED");
            fail = true;
        }

        if (!curve.gen().add(curve.gen().negate()).isZero()) {
            System.out.println("Test G + (-G) = O: FAILED");
            fail = true;
        }

        if (!curve.gen().mul(BigInteger.TWO).equals(curve.gen().add(curve.gen()))) {
            System.out.println("Test 2 * G = G + G: FAILED");
            fail = true;
        }

        if (!curve.gen().mul(new BigInteger("4")).equals(curve.gen().mul(BigInteger.TWO).mul(BigInteger.TWO))) {
            System.out.println("Test 4 * G = 2 * (2 * G): FAILED");
            fail = true;
        }

        if (curve.gen().mul(new BigInteger("4")).isZero()) {
            System.out.println("Test 4 * G != O: FAILED");
            fail = true;
        }

        if (!curve.gen().mul(Edwards.r).isZero()) {
            System.out.println("Test r * G = 0: FAILED");
            fail = true;
        }

        // random k, l, m property tests
        for (int i = 1; i <= RANDOM_SCALAR_TEST_COUNT; i++) {
            System.out.println("Beginning random scalar test " + i + "/" + RANDOM_SCALAR_TEST_COUNT);
            BigInteger k = new BigInteger(1024, rand);
            BigInteger l = new BigInteger(1024, rand);
            BigInteger m = new BigInteger(1024, rand);

            if (!curve.gen().mul(k).equals(curve.gen().mul(k.mod(Edwards.r)))) {
                System.out.println("Test k * G = (k mod r) * G: FAILED for k = " + k);
                fail = true;
            }

            if (!curve.gen().mul(k.add(BigInteger.ONE)).equals(curve.gen().mul(k).add(curve.gen()))) {
                System.out.println("Test (k + 1) * G = (k * G) + G: FAILED for k = " + k);
                fail = true;
            }

            if (!curve.gen().mul(k.add(l)).equals(curve.gen().mul(k).add(curve.gen().mul(l)))) {
                System.out.println("Test (k + l) * G = (k * G) + (l * G): FAILED for k = " + k + 
                    " and l = " + l);
                fail = true;
            }

            Edwards.Point lkG = curve.gen().mul(k).mul(l);
            if (!curve.gen().mul(l).mul(k).equals(lkG) && lkG.equals(curve.gen().mul(k.multiply(l)
                .mod(Edwards.r)))) {

                System.out.println("Test k * (l * G) = l * (k * G) = (k * l mod r) * G: FAILED for k = " + 
                    k + " and l = " + l);
                fail = true;
            }

            if (!curve.gen().mul(k).add(curve.gen().mul(l).add(curve.gen().mul(m)))
                .equals(curve.gen().mul(k).add(curve.gen().mul(l)).add(curve.gen().mul(m)))) {
                
                System.out.println("Test (k * G) + ((l * G) + (m * G)) = ((k * G) + (l * G)) + (m * G):" + 
                    " FAILED for k = " + k + ", l = " + l + ", and m = " + m);
                fail = true;
            }

            if (fail) {
                break;
            }
        }

        if (!fail) {
            System.out.println("All tests passed.");
        }
    }
}
