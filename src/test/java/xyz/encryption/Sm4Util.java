package xyz.encryption;

import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

/**
 * Sm2Util
 *
 * @author chaoxin.lu
 * @version V 1.0
 * @since 2024-09-24
 */
public class Sm4Util {

    public static void main(String[] args) throws Exception {
        String plainText = """
                SM4分组密码算法是我国自主设计的分组对称密码算
                """;

        String key = SM4Encryption.generateRandomKey();
        SM4Encryption sm4Encryption = new SM4Encryption();
        String encrypted = sm4Encryption.encrypt2Hex(plainText.getBytes(StandardCharsets.UTF_8), key);

        System.out.println(key);
        System.out.println("密钥：" + key);
        System.out.println("密文：" + encrypted);

        byte[] decrypted = sm4Encryption.decrypt(Hex.decode(encrypted), key);
        System.out.println("解密内容：" + new String(decrypted, StandardCharsets.UTF_8));

    }
}
