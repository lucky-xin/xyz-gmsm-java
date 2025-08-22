# xyz-gmsm-java

国密算法 SM2/SM3/SM4 的 Java 实现，支持 Gradle 9.0+。

## 项目状态

✅ **Gradle 9.0 兼容性已修复**  
✅ **项目构建成功**  
✅ **支持 Java 17+**  

## 构建说明

本项目已升级到 Gradle 9.0，修复了所有兼容性问题：

```bash
# 构建项目
./gradlew build

# 生成 JAR 包
./gradlew jar

# 清理构建
./gradlew clean
```

## 功能特性

- **SM2**: 椭圆曲线公钥密码算法
- **SM3**: 密码杂凑算法  
- **SM4**: 分组密码算法
- 支持 Java 17 及以上版本
- 使用 BouncyCastle 加密库

---

### Java、Python、GO、JS实现SM2加密解密

## 1.Java代码SM2加密/解密

### 1.1 生成公钥和私钥

```java
SM2KeyPair<String, String> keys = genKeyPairAsHex(false);
String pubKey = keys.getPublicKey();
String priKey = keys.getPrivateKey();
```

### 1.2 Java加密/解密

```java
    public static void main(String[] args) throws Exception {
//        SM2KeyPair<String, String> keys = genKeyPairAsHex(false);
//        String pubKey = keys.getPublicKey();
//        String priKey = keys.getPrivateKey();

    String plainText = "国密算法SM2";
    String pubKey = "04ca5bf8843863d518bfbed316c6b67c7f807fc3436790556c336ddf3a1ca93ae7537f658c222c7f307be57328222256e12d2e26abb8e0160d2501306d64b41266";
    String priKey = "90bb8703d31503624a526f766cfa47d3d8c10055e94046bf99b56cecc9aa4bb6";
    SM2Encryption encryption = SM2Encryption.fromHex(priKey, pubKey);
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
```

## 2.Python代码SM2加密/解密

安装gmssl

```
pip install gmssl
```

```python
from gmssl import sm2

# public_key，private_key为Java生成公钥和私钥
private_key = '90bb8703d31503624a526f766cfa47d3d8c10055e94046bf99b56cecc9aa4bb6'
public_key = '04ca5bf8843863d518bfbed316c6b67c7f807fc3436790556c336ddf3a1ca93ae7537f658c222c7f307be57328222256e12d2e26abb8e0160d2501306d64b41266'
sm2_crypt = sm2.CryptSM2(
    public_key=public_key,
    private_key=private_key,
    asn1=True,
    mode=1)
plaintext = "国密算法SM2".encode()
enc_data = sm2_crypt.encrypt(plaintext)
print(enc_data.hex())
print('------------------')
# cipher_text为Java加密内容
cipher_text = '04b89e21ff8434dc55f0f60563c86a976234bf6fc2ccb2d4b7fb9948b52dc5319efd2619faf5c289c2ea638cf33523b3fbf9df41dd115f1edec5d9a9f922d754e1bc30e3368265d4728bf3e0d5473d2d96b0d9e498e5cbcaaef179f45bd52e50af0155ef410651f47b238593817eb8ed'
text = cipher_text.lstrip("04") if cipher_text.startswith("04") else cipher_text
dec_data2 = sm2_crypt.decrypt(bytes.fromhex(text))
print(dec_data2.decode())
print(plaintext == dec_data2)
```

## 3.Golang代码SM2加密/解密

```golang
package examples

import (
	"github.com/lucky-xin/xyz-gmsm-go/encryption"
	"github.com/tjfoc/gmsm/sm2"
	"testing"
)

func TestSm2(t *testing.T) {
	text := "国密算法SM2"
	// publicKey，privateKey为Java生成公钥和私钥
	publicKey := "04ca5bf8843863d518bfbed316c6b67c7f807fc3436790556c336ddf3a1ca93ae7537f658c222c7f307be57328222256e12d2e26abb8e0160d2501306d64b41266"
	privateKey := "90bb8703d31503624a526f766cfa47d3d8c10055e94046bf99b56cecc9aa4bb6"
	sm2e, err := encryption.NewSM2Encryption(publicKey, privateKey)
	if err != nil {
		t.Error(err)
	}
	mode := sm2.C1C3C2
	encryptText, err := sm2e.Encrypt(text, mode)
	if err != nil {
		t.Error(err)
	}
	println(encryptText)
	decrypt, err := sm2e.Decrypt(encryptText, mode)
	if err != nil {
		t.Error(err)
	}

	println(decrypt)
	// cipherText为Java加密内容
	cipherText := "04b89e21ff8434dc55f0f60563c86a976234bf6fc2ccb2d4b7fb9948b52dc5319efd2619faf5c289c2ea638cf33523b3fbf9df41dd115f1edec5d9a9f922d754e1bc30e3368265d4728bf3e0d5473d2d96b0d9e498e5cbcaaef179f45bd52e50af0155ef410651f47b238593817eb8ed"
	decrypt, err = sm2e.Decrypt(cipherText, mode)
	if err != nil {
		t.Error(err)
	}
	println(decrypt)
}

```

## 4.Javascript代码SM2加密/解密

```javascript
const sm2 = require('sm-crypto').sm2

let pubKey = "04ca5bf8843863d518bfbed316c6b67c7f807fc3436790556c336ddf3a1ca93ae7537f658c222c7f307be57328222256e12d2e26abb8e0160d2501306d64b41266";
let priKey = "90bb8703d31503624a526f766cfa47d3d8c10055e94046bf99b56cecc9aa4bb6";
let plaintext = '国密算法SM2'
let encrypt = sm2.doEncrypt(plaintext, pubKey);
// 密文要加前缀'04'
console.log("encrypt:" + '04' + encrypt)
let decrypt = sm2.doDecrypt(encrypt, priKey);
console.log("encrypt:" + decrypt)

let encryptData = '04b89e21ff8434dc55f0f60563c86a976234bf6fc2ccb2d4b7fb9948b52dc5319efd2619faf5c289c2ea638cf33523b3fbf9df41dd115f1edec5d9a9f922d754e1bc30e3368265d4728bf3e0d5473d2d96b0d9e498e5cbcaaef179f45bd52e50af0155ef410651f47b238593817eb8ed'
let text = encryptData.startsWith('04') ? encryptData.slice(2) : encryptData;
decrypt = sm2.doDecrypt(text, priKey);
console.log("encrypt:" + decrypt)
```


