package xyz.encryption;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * SM3Encryption
 *
 * @author chaoxin.lu
 * @version V 1.0
 * @since 2024-09-25
 */
public class SM3Encryption {


    /**
     * SM3加密算法
     *
     * @param data 待加密的数据
     * @return 密文
     */
    public byte[] encrypt(byte[] data, int size) {
        byte[] result = new byte[size];
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(data, 0, data.length);
        sm3Digest.doFinal(result, 0);
        return result;
    }

    /**
     * SM3加密算法
     *
     * @param data 待加密的数据
     * @return 16进制密文
     */
    public String encrypt2Hex(byte[] data, int size) {
        return Hex.toHexString(encrypt(data, size));
    }

    /**
     * SM3加密算法
     *
     * @param data 待加密的数据
     * @return base64进制密文
     */
    public String encrypt2Base64(byte[] data, int size) {
        return Base64.toBase64String(encrypt(data, size));
    }

}
