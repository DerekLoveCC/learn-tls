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
openssl req -x509 -sha256 -days 365 -key ecc-key.pem -out ecc-cert.pem -subj "/C=US/ST=CA/L=San Francisco/O=My Company/OU=My Department/CN=www.example.com" # Generate Certificate


# Generate CSR (Certificate Signing Request)
- openssl req -new -key rsa-key.pem -out csr.pem # Generate CSR (Certificate Signing Request)
- openssl x509 -req -days 365 -in csr.pem -signkey rsa-key.pem -out certificate.pem # Generate Certificate