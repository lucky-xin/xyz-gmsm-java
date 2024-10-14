package xyz.encryption;

import org.bouncycastle.util.encoders.Hex;

/**
 * Sm2Util
 *
 * @author chaoxin.lu
 * @version V 1.0
 * @since 2024-09-24
 */
public class Sm4Util {

    public static void main(String[] args) throws Exception {
        String plaintext = "SM4分组密码算法是我国自主设计的分组对称密码算, SM4!";
        byte[] plaintextBytes = plaintext.getBytes();

        SM4Encryption sm4 = SM4Encryption.fromBase64(SM4Encryption.generateRandomKey(), SM4Encryption.generateRandomKey());
        // 加密
        byte[] encrypted = sm4.encrypt(plaintextBytes);
        System.out.println("Encrypted: " + Hex.toHexString(encrypted));

        // 解密
        byte[] decrypted = sm4.decrypt(encrypted);
        System.out.println("Decrypted: " + new String(decrypted));
    }
}
