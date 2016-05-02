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
 * Hello world!
 */
public class App {
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
        NetworkParameters params = new MainNetParams();

        if (args.length != 3) {
            System.out.println("Syntax: ./file [address to find] [salt] [insight api address (or 0)]");
            return;
        }

        args[2] = StringUtils.strip(args[2], "/");

        Field f = SCrypt.class.getDeclaredField("native_library_loaded");
        f.setAccessible(true);
        System.out.println("I'm using " + (f.getBoolean(null) ? "native libs" : "java libs") + " for Scrypt.");

        ObjectMapper mapper = new ObjectMapper();
        SecureRandom random = new SecureRandom();

        Runnable task = () -> {
            String name = RandomStringUtils.random(8, 0, 0, true, true, (char[]) null, random);
            ECKey pair = null;
            try {
                pair = getBitcoinPair(name, args[1]);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
                return;
            }
            String address = pair.toAddress(params).toString();

            if (address.equals(args[0])) {
                System.out.println("MATCH FOUND! " + name + " - " + address + " - " + pair.getPrivateKeyAsWiF(params));

                try {
                    Files.write(Paths.get("found"), Arrays.asList(name, pair.getPrivateKeyAsWiF(params), "\n"), StandardOpenOption.APPEND);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                System.exit(0);
            } else {
                int balance = 0;

                if (!args[2].equals("0")) {
                    try {
                        InputStream in = new URL(args[2] + "/addr/" + address + "?noTxList=1")
                                .openStream();
                        balance = mapper.readValue(in, JsonNode.class).get("balance").asInt();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                System.out.println("[-] " + name + " - " + address + " - no match - " + balance);

                if (balance > 0) {
                    try {
                        Files.write(Paths.get("found"), Arrays.asList(name + " - " + balance, pair.getPrivateKeyAsWiF(params),
                                "\n"), StandardOpenOption.APPEND);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        };

        ExecutorService executor = Executors.newFixedThreadPool(4);

        while (true) {
            executor.submit(task);
            Thread.sleep(250);
        }
    }
}
