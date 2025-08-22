package xyz.encryption;

import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Sm2Util
 *
 * @author chaoxin.lu
 * @version V 1.0
 * @since 2024-09-24
 */
public class Sm2Util {

    public static void main(String[] args) throws Exception {

//        SM2KeyPair<String, String> keys = genKeyPairAsHex(false);
//        String pubKey = keys.getPublicKey();
//        String priKey = keys.getPrivateKey();

        String plainText = "国密算法SM2";
        String pubKey = "04ca5bf8843863d518bfbed316c6b67c7f807fc3436790556c336ddf3a1ca93ae7537f658c222c7f307be57328222256e12d2e26abb8e0160d2501306d64b41266";
        String priKey = "90bb8703d31503624a526f766cfa47d3d8c10055e94046bf99b56cecc9aa4bb6";
        BigInteger privateKey = new BigInteger(priKey, 16);
        System.out.println(privateKey);

        System.out.println(new BigInteger(priKey.getBytes(StandardCharsets.UTF_8)));
        SM2 encryption = SM2.fromHex(priKey, pubKey);
        System.out.printf("\npubKey : %s\npriKey : %s\n", pubKey, priKey);
        System.out.println("-----------------");
        byte[] encryptByts = encryption.encrypt(plainText.getBytes(StandardCharsets.UTF_8), SM2Engine.Mode.C1C3C2);
        String encrypt = Hex.toHexString(encryptByts);
        byte[] decryptByts = encryption.decrypt(encryptByts, SM2Engine.Mode.C1C3C2);
        String decrypt = new String(decryptByts, StandardCharsets.UTF_8);
        System.out.printf("加密 : %s\n解密 : %s\n", encrypt, decrypt);

        String sign = encryption.sign(plainText);
        boolean verify = encryption.verify(plainText, sign);
        System.out.printf("\n签名 : %s\n验签 : %s\s\n", sign, verify);
    }
}
