package xyz.encryption;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Objects;

/**
 * SM2Encryption
 *
 * @author chaoxin.lu
 * @version V 1.0
 * @since 2024-09-25
 */
public class SM2Encryption {
    private BigInteger privateKey;
    private byte[] publicKey;
    private static final String EC = "EC";
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    static {
        if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
            Security.addProvider(PROVIDER);
        }
    }

    public SM2Encryption(BigInteger privateKey, byte[] publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * KeyPair
     *
     * @param <U>
     * @param <V>
     */
    public static class KeyPair<U, V> {
        private final V privateKey;
        private final U publicKey;

        public KeyPair(V privateKey, U publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public V getPrivateKey() {
            return privateKey;
        }

        public U getPublicKey() {
            return publicKey;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            KeyPair<?, ?> that = (KeyPair<?, ?>) o;
            return Objects.equals(privateKey, that.privateKey) && Objects.equals(publicKey, that.publicKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(privateKey, publicKey);
        }
    }

    /**
     * SM2加密算法
     *
     * @param data 待加密的数据
     * @param mode 密文排列方式
     * @return 密文，BC库产生的密文带由04标识符，与非BC库对接时需要去掉开头的04
     */
    public byte[] encrypt(byte[] data, SM2Engine.Mode mode) throws InvalidCipherTextException {
        final ASN1ObjectIdentifier sm2p256v1 = GMObjectIdentifiers.sm2p256v1;
        // 获取一条SM2曲线参数
        X9ECParameters parameters = GMNamedCurves.getByOID(sm2p256v1);
        // 构造ECC算法参数，曲线方程、椭圆曲线G点、大整数N
        ECNamedDomainParameters namedDomainParameters = new ECNamedDomainParameters(
                sm2p256v1, parameters.getCurve(), parameters.getG(), parameters.getN());
        //提取公钥点
        ECPoint pukPoint = parameters.getCurve().decodePoint(publicKey);
        // 公钥前面的02或者03表示是压缩公钥，04表示未压缩公钥, 04的时候，可以去掉前面的04
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint, namedDomainParameters);
        SM2Engine sm2Engine = new SM2Engine(mode);
        SecureRandom secureRandom = new SecureRandom();
        // 设置sm2为加密模式
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, secureRandom));
        return sm2Engine.processBlock(data, 0, data.length);
    }

    /**
     * SM2解密算法
     *
     * @param cipherData 密文数据
     * @param mode       密文排列方式
     * @return
     */
    public byte[] decrypt(byte[] cipherData, SM2Engine.Mode mode) throws InvalidCipherTextException {
        final ASN1ObjectIdentifier sm2p256v1 = GMObjectIdentifiers.sm2p256v1;
        //获取一条SM2曲线参数
        X9ECParameters parameters = GMNamedCurves.getByOID(sm2p256v1);
        // 构造ECC算法参数，曲线方程、椭圆曲线G点、大整数N
        ECNamedDomainParameters namedDomainParameters = new ECNamedDomainParameters(
                sm2p256v1, parameters.getCurve(), parameters.getG(), parameters.getN());
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKey, namedDomainParameters);
        SM2Engine sm2Engine = new SM2Engine(mode);
        // 设置sm2为解密模式
        sm2Engine.init(false, privateKeyParameters);
        // 使用BC库加解密时密文以04开头，传入的密文前面没有04则补上
        if (cipherData[0] == 0x04) {
            return sm2Engine.processBlock(cipherData, 0, cipherData.length);
        } else {
            byte[] bytes = new byte[cipherData.length + 1];
            bytes[0] = 0x04;
            System.arraycopy(cipherData, 0, bytes, 1, cipherData.length);
            return sm2Engine.processBlock(bytes, 0, bytes.length);
        }
    }

    public static SM2Encryption fromBase64(String privateKeyStr, String publicKeyStr) {
        byte[] publicKey = Base64.getDecoder().decode(publicKeyStr);
        BigInteger privateKey = new BigInteger(Base64.getDecoder().decode(privateKeyStr));
        return new SM2Encryption(privateKey, publicKey);
    }

    public static SM2Encryption fromHex(String privateKeyStr, String publicKeyStr) {
        byte[] publicKey = Hex.decode(publicKeyStr);
        BigInteger privateKey = new BigInteger(privateKeyStr, 16);
        return new SM2Encryption(privateKey, publicKey);
    }

    /**
     * 签名
     *
     * @param plainText 待签名文本
     * @return
     * @throws GeneralSecurityException
     */
    public String sign(String plainText) throws GeneralSecurityException {
        X9ECParameters parameters = GMNamedCurves.getByOID(GMObjectIdentifiers.sm2p256v1);
        ECParameterSpec parameterSpec = new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN());
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(privateKey, parameterSpec);
        PrivateKey bcecPrivateKey = new BCECPrivateKey(EC, privateKeySpec, BouncyCastleProvider.CONFIGURATION);
        // 创建签名对象
        Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), PROVIDER);
        // 初始化为签名状态
        signature.initSign(bcecPrivateKey);
        // 传入签名字节
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        // 签名
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    /**
     * 验签
     *
     * @param plainText 待签名文本
     * @param signText
     * @return
     * @throws GeneralSecurityException
     */
    public boolean verify(String plainText, String signText) throws GeneralSecurityException {
        X9ECParameters parameters = GMNamedCurves.getByOID(GMObjectIdentifiers.sm2p256v1);
        ECParameterSpec parameterSpec = new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN());
        ECPoint ecPoint = parameters.getCurve().decodePoint(publicKey);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, parameterSpec);
        PublicKey bcecPublicKey = new BCECPublicKey(EC, publicKeySpec, BouncyCastleProvider.CONFIGURATION);
        // 创建签名对象
        Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), PROVIDER);
        // 初始化为验签状态
        signature.initVerify(bcecPublicKey);
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.getDecoder().decode(signText));
    }

    /**
     * 证书验签
     *
     * @param certText  证书串
     * @param plainText 签名原文
     * @param signText  签名产生签名值 此处的签名值实际上就是 R和S的sequence
     * @return
     * @throws GeneralSecurityException
     */
    public boolean certVerify(String certText, String plainText, String signText) throws GeneralSecurityException {
        // 解析证书
        CertificateFactory factory = new CertificateFactory();
        X509Certificate certificate = (X509Certificate) factory.engineGenerateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(certText)));
        // 验证签名
        Signature signature = Signature.getInstance(certificate.getSigAlgName(), PROVIDER);
        signature.initVerify(certificate);
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.getDecoder().decode(signText));
    }


    /**
     * 获取sm2密钥对
     * BC库使用的公钥=64个字节+1个字节（04标志位），BC库使用的私钥=32个字节
     * SM2秘钥的组成部分有 私钥D 、公钥X 、 公钥Y , 他们都可以用长度为64的16进制的HEX串表示，
     * <br/>SM2公钥并不是直接由X+Y表示 , 而是额外添加了一个头
     *
     * @return
     */
    public static KeyPair<byte[], BigInteger> genKeyPair() throws InvalidAlgorithmParameterException {
        return genKeyPair(false);
    }

    /**
     * 获取sm2密钥对
     * BC库使用的公钥=64个字节+1个字节（04标志位），BC库使用的私钥=32个字节
     * SM2秘钥的组成部分有 私钥D 、公钥X 、 公钥Y , 他们都可以用长度为64的16进制的HEX串表示，
     * <br/>SM2公钥并不是直接由X+Y表示 , 而是额外添加了一个头，当启用压缩时:公钥=有头+公钥X ，即省略了公钥Y的部分
     *
     * @param compressed 是否压缩公钥（加密解密都使用BC库才能使用压缩）
     * @return
     */
    public static KeyPair<byte[], BigInteger> genKeyPair(boolean compressed) throws InvalidAlgorithmParameterException {
        //1.创建密钥生成器
        KeyPairGeneratorSpi.EC spi = new KeyPairGeneratorSpi.EC();
        //获取一条SM2曲线参数
        X9ECParameters parameters = GMNamedCurves.getByOID(GMObjectIdentifiers.sm2p256v1);
        //构造spec参数
        ECParameterSpec parameterSpec = new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN());
        SecureRandom secureRandom = new SecureRandom();
        //2.初始化生成器,带上随机数
        spi.initialize(parameterSpec, secureRandom);
        //3.生成密钥对
        java.security.KeyPair asymmetricCipherKeyPair = spi.generateKeyPair();
        // 把公钥放入map中,默认压缩公钥
        // 公钥前面的02或者03表示是压缩公钥,04表示未压缩公钥,04的时候,可以去掉前面的04
        BCECPublicKey publicKeyParameters = (BCECPublicKey) asymmetricCipherKeyPair.getPublic();
        ECPoint ecPoint = publicKeyParameters.getQ();
        byte[] publicKey = ecPoint.getEncoded(compressed);
        // 把私钥放入map中
        BCECPrivateKey privateKeyParameters = (BCECPrivateKey) asymmetricCipherKeyPair.getPrivate();
        BigInteger intPrivateKey = privateKeyParameters.getD();
        return new KeyPair<>(intPrivateKey, publicKey);
    }

    public static KeyPair<String, String> genKeyPairAsHex() throws InvalidAlgorithmParameterException {
        return genKeyPairAsHex(false);
    }

    public static KeyPair<String, String> genKeyPairAsHex(boolean compressed) throws InvalidAlgorithmParameterException {
        final KeyPair<byte[], BigInteger> pair = genKeyPair(compressed);
        return new KeyPair<>(
                pair.getPrivateKey().toString(16),
                Hex.toHexString(pair.getPublicKey())
        );
    }

    public static KeyPair<String, String> genKeyPairAsBase64() throws InvalidAlgorithmParameterException {
        return genKeyPairAsBase64(false);
    }

    public static KeyPair<String, String> genKeyPairAsBase64(boolean compressed) throws InvalidAlgorithmParameterException {
        final KeyPair<byte[], BigInteger> pair = genKeyPair(compressed);
        return new KeyPair<>(
                Base64.getEncoder().encodeToString(pair.getPrivateKey().toByteArray()),
                Base64.getEncoder().encodeToString(pair.getPublicKey())
        );
    }
}