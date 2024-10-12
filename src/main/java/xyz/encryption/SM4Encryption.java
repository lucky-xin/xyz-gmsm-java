package xyz.encryption;

import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;

/**
 * SM4Encryption
 *
 * @author chaoxin.lu
 * @version V 1.0
 * @since 2024-09-25
 */
public class SM4Encryption {

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

    /**
     * 加密
     *
     * @param content 明文
     * @param key     密钥
     * @return byte[]
     */
    public byte[] encrypt(byte[] content, String key) {
        byte[] keyBytes = Base64.decode(key);
        // 初始化SM4引擎
        SM4Engine engine = new SM4Engine();
        engine.init(true, new KeyParameter(keyBytes));
        byte[] out = new byte[content.length];
        int times = content.length / engine.getBlockSize();
        for (int i = 0; i < times; i++) {
            int tmp = i * engine.getBlockSize();
            engine.processBlock(content, tmp, out, tmp);
        }
        engine.processBlock(content, 0, out, 0);
        // 返回加密后的密文
        return out;
    }

    /**
     * @param encrypted 密文
     * @param key       密钥
     * @return byte[]
     */
    public byte[] decrypt(byte[] encrypted, String key) {
        byte[] keyBytes = Base64.decode(key);
        byte[] out = new byte[encrypted.length];
        // 初始化SM4引擎
        SM4Engine engine = new SM4Engine();
        engine.init(false, new KeyParameter(keyBytes));
        int times = encrypted.length / engine.getBlockSize();
        for (int i = 0; i < times; i++) {
            int tmp = i * engine.getBlockSize();
            engine.processBlock(encrypted, tmp, out, tmp);
        }
        return out;
    }

    /**
     * SM3加密算法
     *
     * @param data 待加密的数据
     * @param key  密钥
     * @return 16进制密文
     */
    public String encrypt2Hex(byte[] data, String key) {
        return Hex.toHexString(encrypt(data, key));
    }

    /**
     * SM3加密算法
     *
     * @param data 待加密的数据
     * @param key  密钥
     * @return base64进制密文
     */
    public String encrypt2Base64(byte[] data, String key) {
        return Base64.toBase64String(encrypt(data, key));
    }

}
