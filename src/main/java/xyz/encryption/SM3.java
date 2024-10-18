package xyz.encryption;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import java.util.Objects;

/**
 * SM3
 *
 * @author chaoxin.lu
 * @version V 1.0
 * @since 2024-09-25
 */
public class SM3 {

    static {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
            Security.addProvider(provider);
        }
    }

    /**
     * sm3算法加密
     *
     * @param srcData 待加密数据
     * @return 返回加密后，固定长度=32的16进制字符串
     * @explain
     */
    public static byte[] encrypt(byte[] srcData) {
        // 将字符串转换成byte数组
        // 调用hash()
        return hash(srcData);
    }

    /**
     * 返回长度=32的byte数组
     *
     * @param srcData
     * @return
     * @explain 生成对应的hash值
     */
    public static byte[] hash(byte[] srcData) {
        SM3Digest digest = new SM3Digest();
        digest.update(srcData, 0, srcData.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    /**
     * sm3算法加密
     *
     * @param paramStr 待加密字符串
     * @param key      密钥
     * @return 返回加密后，固定长度=32的16进制字符串
     * @explain
     */
    public static String encryptPlus(String paramStr, String key) {
        // 将返回的hash值转换成16进制字符串
        // 将字符串转换成byte数组
        byte[] srcData = paramStr.getBytes(StandardCharsets.UTF_8);
        // 调用hash()
        byte[] resultHash = hmac(srcData, key.getBytes(StandardCharsets.UTF_8));
        // 将返回的hash值转换成16进制字符串
        return Hex.toHexString(resultHash);
    }

    /**
     * 通过密钥进行加密
     *
     * @param key     密钥
     * @param srcData 被加密的byte数组
     * @return
     * @explain 指定密钥进行加密
     */
    public static byte[] hmac(byte[] key, byte[] srcData) {
        KeyParameter keyParameter = new KeyParameter(key);
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);
        mac.update(srcData, 0, srcData.length);
        byte[] result = new byte[mac.getMacSize()];
        mac.doFinal(result, 0);
        return result;
    }

    /**
     * 判断源数据与加密数据是否一致
     *
     * @param srcStr       原字符串
     * @param sm3HexString 16进制字符串
     * @return 校验结果
     * @explain 通过验证原数组和生成的hash数组是否为同一数组，验证2者是否为同一数据
     */
    public static boolean verify(String srcStr, String sm3HexString) {
        boolean flag = false;
        byte[] srcData = srcStr.getBytes(StandardCharsets.UTF_8);
        byte[] sm3Hash = Hex.decode(sm3HexString);
        byte[] newHash = hash(srcData);
        if (Arrays.equals(newHash, sm3Hash)) {
            flag = true;
        }
        return flag;
    }

    /**
     * SM3加密算法
     *
     * @param data 待加密的数据
     * @return 16进制密文
     */
    public static String encrypt2Hex(byte[] data) {
        return Hex.toHexString(encrypt(data));
    }

    /**
     * SM3加密算法
     *
     * @param data 待加密的数据
     * @return base64进制密文
     */
    public static String encrypt2Base64(byte[] data) {
        return Base64.toBase64String(encrypt(data));
    }

}
