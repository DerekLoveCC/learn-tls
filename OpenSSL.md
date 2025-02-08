# RSA

## 生成RSA密钥
- openssl genrsa -out rsa-key.pem 2048 # Generate private key

## 查看密钥信息
- openssl rsa -in rsa-key.pem -text # View private key details
- openssl rsa -in rsa-key.pem -text -noout # View private key details, without private key appended to output

### 输出解析
![](./image/rsa_key的组成.png)

## 提取公钥
- openssl rsa -in rsa-key.pem -pubout # Generate public key
- openssl rsa -in rsa-key.pem -pubout -out rsa-public-key.pem # Generate public key

## 加解密测试
- openssl pkeyutl -encrypt -inkey rsa-public-key.pem -pubin -in file.txt -out encrypted-file.txt #使用公钥加密文件
- openssl pkeyutl -decrypt -inkey rsa-key.pem -in encrypted-file.txt -out decrypted-file.txt #使用私钥解密文件

# ECC

## 查看Curves
- openssl ecparam -list_curves # View available curves

## 生成ECC密钥
- openssl ecparam -name prime256v1 -genkey -out ecc-key.pem # Generate private key
- openssl ecparam -name prime256v1 -genkey -noout -out ecc-key.pem # Generate private key, without EC parameters appended to output

## 查看密钥信息
- openssl ec -in ecc-key.pem -text # View private key details
- openssl ec -in ecc-key.pem -text -noout # View private key details, without private key appended to output

## 提取公钥
- openssl ec -in ecc-key.pem -pubout # Generate public key
- openssl ec -in ecc-key.pem -pubout -out ecc-public-key.pem # Generate public key并输出到ecc-public-key.pem文件中

## 加解密测试

# Certificate
## 生成证书
- openssl req -x509 -sha256 -days 365 -key ecc-key.pem -out ecc-ca-cert.pem -subj "/C=US/ST=CA/L=San Francisco/O=My Company/OU=My Department/CN=www.example.com" #生成自签名的证书 
- openssl req -x509 -days 365 -key private-key.pem -config certificate.conf -out cert-from-config.pem #使用配置文件certificate.conf生成自签名的证书
- openssl req -x509 -days 365 -key private-key.pem -config certificate-noprompt.conf -out cert-from-config-noprompt.pem -extensions v3_extensions #使用配置文件certificate.conf生成自签名的证书,并包含v3_extensions扩展中的信息
## 查看证书信息
openssl x509 -in ecc-cert.pem -text -noout

## 请求证书
由于CA签发证书需要使用CA的私钥，所以需要申请者把所有想要在证书中包含的信息发给CA，CA会根据这些信息数据创建证书并签名。此时就需要CSR即Certificate Signing Request
1. generate private key and public key
- openssl ecparam -name prime256v1 -genkey -noout -out intermediary-ca-ecc-key.pem
2. generate CSR
- openssl req -new -key intermediary-ca-ecc-key.pem -out intermediary-ca-ecc-csr.pem -config certificate-csr.conf
- openssl req -in .\intermediary-ca-ecc-csr.pem -text -noout #查看CSR信息
3. send CSR to CA
4. CA sign CSR and send back certificate
- openssl x509 -req -CA ca-rsa-root-cert.pem -CAkey ca-rsa-key.pem -in intermediary-ca-ecc-csr.pem -out intermediary-ca-ecc-cert.pem -days 365 
5. install certificate to server
- openssl req -new -key rsa-key.pem -out csr.pem # Generate CSR (Certificate Signing Request)
- openssl x509 -req -days 365 -in csr.pem -signkey rsa-key.pem -out certificate.pem # Generate Certificate