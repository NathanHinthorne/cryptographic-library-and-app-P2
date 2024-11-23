import java.math.BigInteger;

/**
 * Arithmetic on Edwards elliptic curves.
 * 
 * @author Nathan Hinthorne
 * @author Trae Claar
 */
public class Edwards {

    /**
     * The prime number that defines the finite field of the curve.
     */
    private static final BigInteger p = BigInteger.valueOf(2).pow(256)
        .subtract(new BigInteger("189"));

    /**
     * The coefficient used in the curve equation.
     */
    private static final BigInteger d = BigInteger.valueOf(15343);

    /**
     * Prime number such that 4 * r is the number of points on the curve.
     */
    private static final BigInteger r = BigInteger.valueOf(2).pow(254)
        .subtract(new BigInteger("87175310462106073678594642380840586067"));

    /**
     * Create an instance of the default curve NUMS-256.
     */
    public Edwards() { /* ... */ }

    /**
     * Determine if a given affine coordinate pair P = (x, y)
     * defines a point on the curve.
     *
     * @param x x-coordinate of presumed point on the curve
     * @param y y-coordinate of presumed point on the curve
     * @return whether P is really a point on the curve
     */
    public boolean isPoint(BigInteger x, BigInteger y) { 
        BigInteger x2 = x.multiply(x);
        BigInteger y2 = y.multiply(y);

        return x2.add(y2).mod(p).equals(BigInteger.ONE.add(d.multiply(x2)
            .mod(p).multiply(y2).mod(p)).mod(p));
    }

    /**
     * Find a generator G on the curve with the smallest possible
     * y-coordinate in absolute value.
     *
     * @return G.
     */
    public Point gen() { /* ... */ }

    /**
     * Create a point from its y-coordinate and
     * the least significant bit (LSB) of its x-coordinate.
     *
     * @param y the y-coordinate of the desired point
     * @param x_lsb the LSB of its x-coordinate
     * @return point (x, y) if it exists and has order r,
     *         otherwise the neutral element O = (0, 1)
     */
    public Point getPoint(BigInteger y, boolean x_lsb) { 
        BigInteger y2 = y.multiply(y);
        BigInteger num = BigInteger.ONE.subtract(y2).mod(p);
        BigInteger denom = BigInteger.ONE.subtract(d.multiply(y2).mod(p)).mod(p);
        BigInteger x = sqrt(num.multiply(denom.modInverse(p)).mod(p), p, x_lsb);

        Point result = new Point(x, y);

        if (!(isPoint(x, y) && result.mul(r).isZero())) {
            return new Point();
        }

        return result;
    }

    /**
     * Display a human-readable representation of this curve.
     *
     * @return a string of form "E: x^2 + y^2 = 1 + d*x^2*y^2 mod p"
     * where E is a suitable curve name (e.g. NUMS ed-256-mers*),
     * d is the actual curve equation coefficient defining this curve,
     * and p is the order of the underlying finite field F_p.
     */
    public String toString() { /* ... */ }

    /**
     * Compute a square root of v mod p with a specified least-significant bit
     * if such a root exists.
     * 
     * Credit: Dr. Paulo Barreto (from the assignment specifications)
     *
     * @param v   the radicand.
     * @param p   the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     *         if such a root exists, otherwise null.
     */
    private static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * Edwards curve point in affine coordinates.
     * NB: this is a nested class, enclosed within the Edwards class.
     */
    public class Point {

        /**
         * Create a copy of the neutral element on this curve.
         */
        public Point() { /* ... */ }

        /**
         * Create a point from its coordinates (assuming
         * these coordinates really define a point on the curve).
         *
         * @param x the x-coordinate of the desired point
         * @param y the y-coordinate of the desired point
         */
        private Point(BigInteger x, BigInteger y) { /* ... */ }

        /**
         * Determine if this point is the neutral element O on the curve.
         *
         * @return true iff this point is O
         */
        public boolean isZero() { /* ... */ }

        /**
         * Determine if a given point P stands for
         * the same point on the curve as this.
         *
         * @param P a point (presumably on the same curve as this)
         * @return true iff P stands for the same point as this
         */
        public boolean equals(Point P) { /* ... */ }

        /**
         * Given a point P = (x, y) on the curve,
         * return its opposite -P = (-x, y).
         *
         * @return -P
         */
        public Point negate() { /* ... */ }

        /**
         * Add two given points on the curve, this and P.
         *
         * @param P a point on the curve
         * @return this + P
         */
        public Point add(Point P) { /* ... */ }

        /**
         * Multiply a point P = (x, y) on the curve by a scalar m.
         *
         * @param m a scalar factor (an integer mod the curve order)
         * @return m*P
         */
        public Point mul(BigInteger m) { /* ... */ }

        /**
         * Display a human-readable representation of this point.
         *
         * @return a string of form "(x, y)" where x and y are
         * the coordinates of this point
         */
        public String toString() { /* ... */ }

    }
}