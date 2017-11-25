package wf.doyle.WarpWallet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lambdaworks.crypto.PBKDF;
import com.lambdaworks.crypto.SCrypt;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.MainNetParams;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.*;

/**
 * WarpWallet Cracker POC.
 *
 * @author Jordan Doyle
 */
public class App {
    /**
     * Get an {@link ECKey} instance from a given passphrase and salt.
     *
     * @param passphrase generated passphrase
     * @param salt salt passed by the user
     * @return {@link ECKey} instance from the given passphrase/salt combo.
     * @throws GeneralSecurityException
     */
    public static ECKey getBitcoinPair(String passphrase, String salt) throws GeneralSecurityException {
        // s1 = scrypt(key=(passphrase||0x1), salt=(salt||0x1), N=2^18, r=8, p=1, dkLen=32)
        // s2 = pbkdf2(key=(passphrase||0x2), salt=(salt||0x2), c=2^16, dkLen=32, prf=HMAC_SHA256)

        byte[] scryptPassphrase = ArrayUtils.add(passphrase.getBytes(StandardCharsets.UTF_8), (byte) 0x1);
        byte[] scryptSalt = ArrayUtils.add(salt.getBytes(StandardCharsets.UTF_8), (byte) 0x1);
        byte[] pbkdfPassphase = ArrayUtils.add(passphrase.getBytes(StandardCharsets.UTF_8), (byte) 0x2);
        byte[] pbkdfSalt = ArrayUtils.add(salt.getBytes(StandardCharsets.UTF_8), (byte) 0x2);

        byte[] s1 = SCrypt.scrypt(scryptPassphrase, scryptSalt, (int) Math.pow(2, 18), 8, 1, 32);
        byte[] s2 = PBKDF.pbkdf2("HmacSHA256", pbkdfPassphase, pbkdfSalt, (int) Math.pow(2, 16), 32);

        byte[] s3 = new byte[]{};

        for (int i = 0; i < s1.length; i++) {
            s3 = ArrayUtils.add(s3, (byte) (s1[i] ^ s2[i]));
        }

        return ECKey.fromPrivate(s3, false);
    }

    public static void main(String[] args) throws GeneralSecurityException, AddressFormatException, IOException,
            NoSuchFieldException, IllegalAccessException, InterruptedException {
        NetworkParameters params = new MainNetParams(); // use the main net, not the test net

        if (args.length != 4) {
            System.out.println("Syntax: ./file [address to find] [salt] [passphrase len]");
            return;
        }

        // check if we're using a supported operating system for quicker Scrypt operations.
        Field f = SCrypt.class.getDeclaredField("native_library_loaded");
        f.setAccessible(true);
        System.out.println("I'm using " + (f.getBoolean(null) ? "native libs" : "java libs") + " for Scrypt.");

        SecureRandom random = new SecureRandom(); // hopefully more randomness given to us by the OS.

        int length = Integer.parseInt(args[2]);

        Runnable task = () -> {
            // generate a random X character passphrase using the secure random we created above.
            String name = RandomStringUtils.random(length, 0, 0, true, true, null, random);

            ECKey pair;

            try {
                pair = getBitcoinPair(name, args[1]);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
                return;
            }

            // get the bitcoin address from the passphrase we generated above
            String address = pair.toAddress(params).toString();

            if (address.equals(args[0])) {
                // we did it! write the private key to a file and exit execution.
                System.out.println("MATCH FOUND! " + name + " - " + address + " - " + pair.getPrivateKeyAsWiF(params));

                try {
                    Files.write(Paths.get("found"), Arrays.asList(name, pair.getPrivateKeyAsWiF(params), "\n"), StandardOpenOption.APPEND);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                System.exit(0);
            } else {
                System.out.println("[-] " + name + " - " + address + " - no match");
            }
        };

        ExecutorService executor = Executors.newFixedThreadPool(4);

        while (true) {
            executor.submit(task);
            Thread.sleep(250);
        }
    }
}
