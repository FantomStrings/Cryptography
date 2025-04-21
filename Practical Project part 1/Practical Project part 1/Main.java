
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Scanner;
/**
 * @author rick_adams.
 * @version 2024 AU.
 * Main program (driver).
 */
public class Main {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Scanner SCANNER = new Scanner(System.in);
    private static SHA3SHAKE sha3SHAKE = new SHA3SHAKE();

    /**
     * Private constructor.
     */
    private Main() {}
    /**
     *
     * @param file         the file path.
     * @param suffix       the suffix level.
     * @throws IOException throws an I/O exception upon inccorect file path, etc.
     */
    private static void computeHash(String file, int suffix) throws IOException {
        try {
            byte[] content = Files.readAllBytes(Paths.get(file));
            byte[] out = SHA3SHAKE.SHA3(suffix, content, null);
            System.out.println(HexFormat.of().formatHex(out));
        } catch (IOException e) {
            throw new IOException("Error with file path: " + file + ": " + e.getMessage());
        }
    }
    /**
     *
     * @param password      the password.
     * @param suffix        the suffix level.
     * @param len           length of the MAC.
     */
    private static void generateMACFromUserInput(String password, int suffix, int len) {
        if (len < 0) {
            throw new IllegalArgumentException("Length must be a positive integer");
        }
        byte[] content = SCANNER.nextLine().getBytes();
        sha3SHAKE.init(suffix);
        sha3SHAKE.absorb(password.getBytes());
        sha3SHAKE.absorb(content);
        byte[] mac_user = sha3SHAKE.squeeze(len);
        System.out.println(HexFormat.of().formatHex(mac_user));
    }
    /**
     *
     * @param password      the password.
     * @param suffix        the suffix level.
     * @param len           length of the MAC.
     */
    private static void generateMACFromFileInput(String file, String password, int suffix, int len) {
        if (len < 0) {
            throw new IllegalArgumentException("Length must be a positive integer");
        }
        try {
            byte[] content = Files.readAllBytes(Paths.get(file));
            sha3SHAKE.init(suffix);
            sha3SHAKE.absorb(password.getBytes());
            sha3SHAKE.absorb(content);
            byte[] mac_file = sha3SHAKE.squeeze(len);
            System.out.println(HexFormat.of().formatHex(mac_file));
        } catch (IOException e) {
            System.err.println("Error with file path: " + file + ": " + e.getMessage());
        }
    }
    /**
     *
     * @param file      the file path.
     * @param password  the passphrase.
     * @param out       the output file.
     */
    private static void symmetricEncrypt(String file, String password, String out) {
        String output = out;
        if (out == null) {
            output = file + ".enc";
        } try {
            byte[] content = Files.readAllBytes(Paths.get(file));
            byte[] nonce = new byte[16];
            RANDOM.nextBytes(nonce);
            byte[] key = SHA3SHAKE.SHAKE(128, password.getBytes(), 128, null);
            sha3SHAKE.init(128);
            sha3SHAKE.absorb(nonce);
            sha3SHAKE.absorb(key);
            byte[] cipher_text = sha3SHAKE.squeeze(content.length);

            for (int i = 0; i < content.length; i++) {
                content[i] ^= cipher_text[i];
            }
            sha3SHAKE.init(256);
            sha3SHAKE.absorb(nonce);
            sha3SHAKE.absorb(key);
            byte[] mac_encrypted = sha3SHAKE.digest();
            try (FileOutputStream fos = new FileOutputStream(output)){
                fos.write(content);
                fos.write(nonce);
                fos.write(mac_encrypted);
            }
        } catch (IOException e) {
            System.err.println("Error with file path: " + file + ": " + e.getMessage());
        }
    }
    /**
     *
     * @param file      the file path.
     * @param password  the passphrase.
     * @param out       the putput file.
     */
    private static void symmetricDecrypt(String file, String password, String out) {
        String output = out;
        if (out == null) {
            output = file.replaceAll(".enc", "");
        }
        try {
            byte[] file_content = Files.readAllBytes(Paths.get(file));
            byte[] content = new byte[file_content.length - 48];
            System.arraycopy(file_content, 0, content, 0, content.length);
            byte[] nonce = new byte[16];
            System.arraycopy(file_content, content.length, nonce, 0, content.length);
            byte[] file_mac = new byte[32];
            for (int i = 0; i < content.length; i++) {
                file_mac[i] = file_content[i + content.length + nonce.length];
            }
            byte[] key = SHA3SHAKE.SHAKE(128, password.getBytes(), 128, null);
            // for 256.
            sha3SHAKE.init(256);
            sha3SHAKE.absorb(nonce);
            sha3SHAKE.absorb(key);
            sha3SHAKE.absorb(content);
            byte[] mac_encrypted = sha3SHAKE.digest();
            if (!Arrays.equals(file_mac, mac_encrypted)) {
                System.err.println("MAC tag verification failed. The cryptogram is invalid or tampered.");
                return;
            }
            // Initialize SHA3SHAKE instance for decryption
            sha3SHAKE.init(128);
            sha3SHAKE.absorb(nonce);
            sha3SHAKE.absorb(key);
            sha3SHAKE.absorb(content);
            // Squeeze the cipher_text and decrypt via XOR
            byte[] cipher_text = sha3SHAKE.squeeze(content.length);
            for (int i = 0; i < content.length; i++) {
                content[i] ^= cipher_text[i];
            }
            try (FileOutputStream fos = new FileOutputStream(output)){
                fos.write(content);
            }
        } catch (Exception e) {
            System.err.println("Error during decryption: " + e.getMessage());
        }
    }
    /**
     * Converts bytes to hex.
     *
     * @param bytes the bytes input.
     * @return      the output toString.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    /**
     * Main method
     * @param args          command line arguments.
     * @throws IOException  throws exception with a user I/O error.
     */
    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.out.println("Error: No arguments provided.");
            return;
        }
        try {

            switch (args[0].toLowerCase()) {
                case "computehash":
                    if (args.length == 3) {
                        System.out.println(args[1]);
                        if (!args[1].matches("224|256|384|512")) {
                            System.out.println("Error: Invalid security level for hashing function. Implemented security levels include: 224, 256, 384, or 512.");
                        } else {
                            computeHash(args[2], Integer.parseInt(args[1]));
                        }
                    } else if (args.length == 2) {
                        computeHash(args[1], 512);
                    } else if (args.length == 1) {
                        System.out.println("Error: Please provide path to the file to hash.");
                    } else {
                        System.out.println("Error: Invalid number of arguments.");
                    }
                    break;
                case "mac":
                    if (args.length == 5) {
                        if (!args[1].matches("128|256")) {
                            System.out.println("Error: Invalid security level for Message Authentication Code. Implemented security levels include: 224, 256, 384, or 512.");
                        } else {
                            try {
                                int length = Integer.parseInt(args[4]);
                                int suffix = Integer.parseInt(args[1]);
                                generateMACFromFileInput(args[3], args[2], suffix, length);
                            } catch (NumberFormatException e) {
                                System.out.println("Error parsing MAC output length.");
                            }
                        }
                    } else if (args.length == 4) {
                        if (!args[1].matches("128|256")) {
                            System.out.println("Error: Invalid security level for Message Authentication Code. Implemented security levels include: 224, 256, 384, or 512.");
                        } else {
                            try {
                                int length = Integer.parseInt(args[3]);
                                int suffix = Integer.parseInt(args[1]);
                                generateMACFromUserInput(args[2], suffix, length);
                            } catch (NumberFormatException e) {
                                System.out.println("Error parsing MAC output length.");
                            }
                        }

                    } else {
                        System.out.println("Error: Invalid number of arguments.");
                    }
                    break;
                case "encrypt":
                    if (args.length == 4) {
                        symmetricEncrypt(args[2], args[1], args[3]);
                    } else if (args.length == 3) {
                        symmetricEncrypt(args[2], args[1], null);
                    } else {
                        System.out.println("Error: Invalid number of arguments.");
                    }
                    break;
                case "decrypt":
                    if (args.length == 4) {
                        symmetricDecrypt(args[2], args[1], args[3]);
                    } else if (args.length == 3) {
                        symmetricEncrypt(args[2], args[1], null);
                    } else {
                        System.out.println("Error: Invalid number of arguments.");
                    }
                    break;
                default:
                    System.out.println("Error: Argument.");
                    break;
            }
        }
        catch (FileNotFoundException e) {
            System.err.println("Error: File not found. Please provide correct file path." + e.getMessage());
        }
    }
}



