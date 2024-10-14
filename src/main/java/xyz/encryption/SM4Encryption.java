package xyz.encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;

/**
 * SM4Encryption
 *
 * @author chaoxin.lu
 * @version V 1.0
 * @since 2024-09-25
 */
public class SM4Encryption {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成随机密钥的方法
     *
     * @return 128位密钥
     */
    public static String generateRandomKey() {
        byte[] keyBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(keyBytes);
        return Base64.toBase64String(keyBytes);
    }

    private static final String ALGORITHM_NAME = "SM4";
    private static final String TRANSFORMATION = "SM4/CBC/PKCS7Padding";

    private final byte[] keyBytes;
    private final byte[] ivBytes;

    public SM4Encryption(byte[] keyBytes, byte[] ivBytes) {
        this.keyBytes = keyBytes;
        this.ivBytes = ivBytes;
    }

    public static SM4Encryption from(byte[] keyBytes, byte[] ivBytes) {
        return new SM4Encryption(keyBytes, ivBytes);
    }

    public static SM4Encryption fromBase64(String key, String iv) {
        return new SM4Encryption(Base64.decode(key), Base64.decode(iv));
    }

    public static SM4Encryption fromHex(String key, String iv) {
        return new SM4Encryption(Hex.decode(key), Hex.decode(iv));
    }

    /**
     * 加密
     * @param plainText 待加密文斌
     * @return
     */
    public byte[] encrypt(byte[] plainText) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM_NAME);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            return cipher.doFinal(plainText);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * 用于解密给定的密文
     *
     * @param cipherText 待解密文本
     * @return
     */
    public byte[] decrypt(byte[] cipherText) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM_NAME);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            return cipher.doFinal(cipherText);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * SM3加密算法
     *
     * @param data 待解密的数据
     * @return 16进制密文
     */
    public String encrypt2Hex(String data) {
        return Hex.toHexString(encrypt(Hex.decode(data)));
    }

    /**
     * SM3加密算法
     *
     * @param data 待解密的数据
     * @return base64进制密文
     */
    public String encrypt2Base64(String data) {
        return Base64.toBase64String(encrypt(Base64.decode(data)));
    }
}
