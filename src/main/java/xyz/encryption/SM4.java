package xyz.encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Objects;

/**
 * SM4Encryption
 *
 * @author chaoxin.lu
 * @version V 1.0
 * @since 2024-09-25
 */
public class SM4 {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成随机密钥的方法
     *
     * @return 128位密钥
     */
    public static KeyPair generateKey() {
        try {
            // 生成SM4密钥
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
            // SM4使用128位密钥
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();
            byte[] key = secretKey.getEncoded();
            // 生成随机的IV向量
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            return new KeyPair(key, iv);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static final String ALGORITHM_NAME = "SM4";
    private static final String TRANSFORMATION = "SM4/CBC/PKCS7Padding";

    private final byte[] key;
    private final byte[] iv;

    public SM4(byte[] key, byte[] iv) {
        this.key = key;
        this.iv = iv;
    }

    public static SM4 from(byte[] keyBytes, byte[] ivBytes) {
        return new SM4(keyBytes, ivBytes);
    }

    public static SM4 fromBase64(String key, String iv) {
        return new SM4(Base64.decode(key), Base64.decode(iv));
    }

    public static SM4 fromHex(String key, String iv) {
        return new SM4(Hex.decode(key), Hex.decode(iv));
    }

    /**
     * 加密
     * @param plainText 待加密文斌
     * @return
     */
    public byte[] encrypt(byte[] plainText) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM_NAME);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
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
            SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM_NAME);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
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

    /**
     * KeyPair
     */
    public static class KeyPair {
        private final byte[] key;
        private final byte[] iv;

        public KeyPair(byte[] key, byte[] iv) {
            this.key = key;
            this.iv = iv;
        }

        public byte[] getKey() {
            return key;
        }

        public byte[] getIv() {
            return iv;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            KeyPair keyPair = (KeyPair) o;
            return Objects.deepEquals(key, keyPair.key) && Objects.deepEquals(iv, keyPair.iv);
        }

        @Override
        public int hashCode() {
            return Objects.hash(Arrays.hashCode(key), Arrays.hashCode(iv));
        }
    }
}
