import java.util.Objects;
/**
 * @author rick_adams.
 * @version 2024 AU.
 * Based on the NIST FIPS 202 specification.
 * Considerable inspiration and borrowing from mjosaarinen/tiny_sha3.
 */
public class SHA3SHAKE {
//********************************* Constants *********************************\\
    /**
     * Used by Rho.
     */
    private static final int[] KECCAKF_ROTC = {
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20,
            3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
            18, 2, 61, 56, 14
    };
    /**
     * Used by the Iota.
     * Taken from mjosaarinen/tiny_sha3.
     */
    private static final long[] KECCAKF_RNDC = {
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
     * Number of rounds to run Keccak-f for each permutation.
     */
    private static final int KECCAKF_ROUNDS = 24;
    /**
     * Total size, in bits, of the internal state used by Keccakf.
     */
    private static final int SIZE_STATE = 1600;
    /**
     * Used for byte conversion.
     */
    private static final int MASK = 0xFF;
    /**
     * The capacity(c) of the sponge.
     */
    private int cap;
    /**
     * Rate of the sponge.
     * In bytes.
     */
    private int byte_rate;
    /**
     * Position of the sponge.
     * In bits.
     */
    private int pt;
    /**
     * Internal state used by Keccakf.
     * defined by the NIST specs.
     */
    private long[][] state;
    /**
     * Default constructor.
     */
    public SHA3SHAKE() {}
    /**
     * Initialize the SHA-3/SHAKE sponge.
     * The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or 256 for SHAKE.
     *
     * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bit length = suffix, SHAKE sec level = suffix)
     */
    public void init(int suffix) {
        cap = 2 * suffix;
        int rate_bits = SIZE_STATE - cap;
        byte_rate = rate_bits / 8;
        state = new long[5][5];
        pt = 0;
    }
    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param pos  initial index to hash from
     * @param len  byte count on the buffer
     */
    public void absorb(byte[] data, int pos, int len) {
        int j = 0;
        for (int i = pos; i < len; i++) {
            int a = (j / 8) % 5;
            int b = (j / 8) / 5;
            int c = (j % 8) * 8;
            state[b][a] ^= (long) (data[i] & 0xFF) << c;
            j++;

            if (j == byte_rate) {
                keccakF();
                j = 0;
            }
        }
        this.pt = j;
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
        absorb(data, data.length);
    }
    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     *
     * @param   out hash value buffer.
     * @param   len desired number of squeezed bytes.
     * @return  the val buffer containing the desired hash value.
     */
    public byte[] squeeze(byte[] out, int len) {
        pad(false);
        keccakF();

        for (int i = 0; i <= len / byte_rate; i++) {
            int squeeze_bytes = 0;
            for (long[] lane : state) {
                for (long value : lane) {
                    byte[] temp = longToBytes(value);
                    for (int j = temp.length - 1; j >= 0; j--) {
                        if (squeeze_bytes >= byte_rate) {
                            break;
                        }
                        int index = squeeze_bytes + i * byte_rate;
                        if (index >= out.length) {
                            break;
                        }
                        out[index] = temp[j];
                        squeeze_bytes++;
                    }
                }
            }
            keccakF();
        }
        return out;
    }
    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     *
     * @param   len desired number of squeezed bytes
     * @return  newly allocated buffer containing the desired hash value
     */
    public byte[] squeeze(int len) {
        return squeeze(new byte[len], len);
    }
    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @param out   hash value buffer.
     * @return      the val buffer containing the desired hash value.
     */
    public byte[] digest(byte[] out) {
        pad(true);
        keccakF();

        int index = 0;
        for (long[] lane : state) {
            for (long value : lane) {
                byte[] temp = longToBytes(value);
                for (int i = temp.length - 1; i >= 0 && index < out.length; i--) {
                    out[index] = temp[i];
                    index++;
                }
            }
        }
        return out;
    }
    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @return the desired hash value on a newly allocated byte array
     */
    public byte[] digest() {
        return digest(new byte[cap / 16]);
    }
    /**
     * Compute the streamlined SHA-3-<224,256,384,512> on input X.
     *
     * @param suffix desired output length in bits (one of 224, 256, 384, 512)
     * @param X      data to be hashed
     * @param out    hash value buffer (if null, this method allocates it with the required size)
     * @return       the out buffer containing the desired hash value.
     */
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) {
        byte[] output = out == null ? new byte[suffix / 8] : out;
        validSuffix(true, suffix, output.length);

        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(suffix);
        sponge.absorb(X);
        output = sponge.digest(output);
        return output;
    }
    /**
     * Compute the streamlined SHAKE-<128,256> on input X with an output bit length L.
     *
     * @param suffix desired security level (either 128 or 256)
     * @param X      data to be hashed
     * @param L      desired output length in bits (must be a multiple of 8)
     * @param out    hash value buffer (if null, this method allocates it with the required size)
     * @return       the out buffer containing the desired hash value.
     */
    public static byte[] SHAKE(int suffix, byte[] X, int L, byte[] out) {
        byte[] output;
        output = Objects.requireNonNullElseGet(out, () -> new byte[suffix / 8]);
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(suffix);
        sponge.absorb(X);
        output = sponge.squeeze(L / 8);
        return output;
    }
    //********************************* Helper Methods *********************************\\
    /**
     * The Keccakf permutation.
     */
    private void keccakF() {
        for (int r = 0; r < KECCAKF_ROUNDS; r++) {
            // Theta.
            long[] pillar = new long[5];
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    pillar[i] ^= state[j][i];
                }
            }
            for (int i = 0; i < 5; i++) {
                long sheet = pillar[(i + 4) % 5] ^ ROTL64(pillar[(i + 1) % 5], 1);
                for (int j = 0; j < 5; j++) {
                    state[j][i] ^= sheet;
                }
            }
            // Rho.
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    state[i][j] = ROTL64(state[i][j], KECCAKF_ROTC[i * 5 + j]);
                }
            }
            // Pi.
            int x = 0, y = 1, prevX, prevY;
            long temp = state[y][x];
            for (int i = 0; i < 23; i++) {
                prevX = x;
                prevY = y;
                y = x;
                x = (x + 3 * prevY) % 5;
                state[prevY][prevX] = state[y][x];
            }
            state[y][x] = temp;
            // Chi.
            long[] buffer = new long[5];
            for (int i = 0; i < 5; i++) {
                System.arraycopy(state[i], 0, buffer, 0, 5);
                for (int j = 0; j < 5; j++) {
                    state[i][j] ^= (~buffer[(j + 1) % 5]) & buffer[(j + 2) % 5];
                }
            }
            // Iota.
            state[0][0] ^= KECCAKF_RNDC[r];
        }
    }
    /**
     * Check if the arguments are valid for the SHA-3/SHAKE functions.
     *
     * @param isSha3 true if SHA-3, else false.
     * @param suffix the suffix value.
     * @param len    the length of the output buffer.
     */
    private static void validSuffix(boolean isSha3, int suffix, int len) {

        if (isSha3) {
            if (suffix != 224 && suffix != 256 && suffix != 384 && suffix != 512) {
                throw new IllegalArgumentException("Invalid suffix.");
            }
        } else {
            if (suffix != 128 && suffix != 256) {
                throw new IllegalArgumentException("Invalid suffix.");
            }
        }
        if (len != suffix / 8) {
            throw new IllegalArgumentException("Invalid buffer length.");
        }
    }
    /**
     * Bit shifts tot he left.
     * Inspired by mjosaarinen/tiny_sha3.
     *
     * @param value the value to be rotated.
     * @param shift the number of bits to shift left.
     * @return      the value shifted left a number of bits.
     */
    private static long ROTL64(long value, int shift) {
        shift %= 64;
        return (value << shift) | (value >>> (64 - shift));
    }
    /**
     * Converts long words into bytes.
     * Found on stackOverflow.
     * @param   word the word.
     * @return  the word in bytes.
     */
    public static byte[] longToBytes(long word) {
        byte[] result = new byte[Long.BYTES];
        for (int i = Long.BYTES - 1; i >= 0; i--) {
            result[i] = (byte) (word & MASK);
            word >>= Byte.SIZE;
        }
        return result;
    }
    /**
     * Pad the sponge with the appropriate padding for SHA-3 and SHAKE.
     * @param isSha3 true if padding for SHA-3, false if padding for SHAKE
     */
    private void pad(boolean isSha3) {
        long padInit;
        if (isSha3) {
            padInit = 0x06L;
        } else {
            padInit = 0x1FL;
        }
        int i = (pt / 8) % 5;
        int j = (pt / 8) / 5;
        int k = (pt % 8) * 8;

        if (state[j][i] == 0L && pt == 1) {
            state[j][i] ^= padInit;
        }
        else {
            state[j][i] ^= padInit << k;
        }
        int x = ((byte_rate - 1) / 8) % 5;
        int y = ((byte_rate - 1) / 8) / 5;
        int z = ((byte_rate - 1) % 8) * 8;
        state[y][x] ^= 0x80L << z;
    }
    //********************************* End Program *********************************\\
}

