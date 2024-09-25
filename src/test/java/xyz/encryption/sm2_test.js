// https://www.npmjs.com/package/sm-crypto
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