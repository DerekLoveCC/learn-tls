# TLS从入门到精通

## 什么是SSL/TLS
SSL（Secure Socket Layer，安全套接层）和 TLS（Transport Layer Security，传输层安全）是一种安全协议，它建立在Internet协议（IP）之上，用于两个应用程序之间提供保密性和数据完整性。

## TLS vs SSL
- 使用PKI certificates和相关的密钥保证网络通信安全
- 使用加密套件保证数据安全
- 使用Hash和数字签名保证数据完整性，认证和防止数据篡改
- 通过配置为其他应用层协议提供安全性, 如HTTPS、FTPS, SMTPS等

### SSL有三个版本：SSL 1.0, SSL 2.0, SSL 3.0。
### TLS有四个版本：TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3
目前推荐使用TLS 1.2或TLS 1.3，其中TLS 1.3是最新版本，具有更好的性能、安全性和隐私保护， 而TLS 1.2应用最广泛。SSL则不再推荐使用。

### Security Protocol Downgrade Attacks
在初始握手阶段，客户端和服务器协商使用的TLS/SSL协议版本，如果中间人攻击者（MITM - man in the middle）窃听了通信过程，他可以修改通信内容，将通信协议降级到SSL 3.0或更低版本，从而导致通信不安全，这种攻击称为Security Protocol Downgrade Attacks。TLS_FALLBACK_SCSV可以防止这种攻击。通常应禁用SSL和TLS 1.0，使用TLS 1.2或更高版本。

### POODLE Attack
TLS 1.0和TLS 1.1中存在一个漏洞，称为POODLE，它允许攻击者利用中间人攻击（MITM）将SSL 3.0或更低版本的通信内容修改为TLS 1.0或TLS 1.1的通信内容，从而导致通信不安全。TLS 1.2和TLS 1.3都没有这个漏洞。

### Heartbleed Attack
TLS 1.0和TLS 1.1中存在一个漏洞，称为Heartbleed，它允许攻击者窃听或篡改TLS连接中的数据，从而导致通信不安全。TLS 1.2和TLS 1.3都没有这个漏洞。

### BEAST Attack
TLS 1.1中存在一个漏洞，称为BEAST，它允许攻击者利用中间人攻击（MITM）将SSL 3.0或更低版本的通信内容修改为TLS 1.1的通信内容，从而导致通信不安全。TLS 1.2和TLS 1.3都没有这个漏洞。

### CRIME Attack
TLS 1.2和TLS 1.3中存在一个漏洞，称为CRIME，它允许攻击者利用中间人攻击（MITM）将TLS 1.2或TLS 1.3的通信内容修改为不安全的形式，从而导致通信不安全。

### DROWN Attack
TLS 1.2和TLS 1.3中存在一个漏洞，称为DROWN，它允许攻击者利用中间人攻击（MITM）将TLS 1.2或TLS 1.3的通信内容修改为不安全的形式，从而导致通信不安全。

### 总结
TLS协议是SSL协议的升级版本，它在SSL的基础上添加了更高级的安全功能，如加密套件、数字签名、身份验证等。TLS协议的版本从SSL 3.0升级到TLS 1.0，再升级到TLS 1.1，最后升级到TLS 1.2和TLS 1.3。TLS协议的版本越高，安全性越高，但性能也会下降。因此，在选择TLS协议版本时，应根据应用场景、硬件性能、网络环境等因素进行权衡。

## TLS用到的工具
1. 数字证书
- Intended Purposes
2. 加密套件

即预期用途或扩展密钥使用（EKU））是指证书所标识的公钥预期被用于哪些特定目的。EKU扩展字段用于指定证书的公钥可以用于哪些类型的加密操作，例如服务器身份验证、客户端身份验证、代码签名、电子邮件保护等。通过明确证书的预期用途，可以限制证书的使用范围，从而提高安全性，防止证书被误用或滥用。


## PKI（Public Key Infrastructure，公钥基础设施）
PKI（Public Key Infrastructure，公钥基础设施）是一种管理数字证书的系统，它包括证书颁发机构（CA）、证书吊销机构（CA）、证书注册机构（RA）、证书存储库、证书利用系统。PKI的主要功能是为用户和组织提供数字证书，并验证证书的有效性、真实性、完整性。












# 什么是SSL/TLS
SSL（Secure Socket Layer，安全套接层）和 TLS（Transport Layer Security，传输层安全）是一种安全协议，它建立在Internet协议（IP）之上，用于两个应用程序之间提供保密性和数据完整性。TLS协议由两部分组成：

- 记录协议（Record Protocol）：它负责在两端之间传输数据。
- 加密协议（Encryption Protocol）：它负责对数据进行加密和解密。

TLS协议的主要目的是为了建立一个安全的连接，防止中间人攻击、数据篡改、身份伪造等安全问题。TLS协议的实现需要一定的时间，因此，在建立连接之前，客户端和服务器必须协商一个加密套件，并使用该套件进行通信。
TLS协议的主要优点如下：

- 身份验证：TLS协议可以验证客户端和服务器的身份，确保通信双方都是可信的。
- 数据完整性：TLS协议可以确保数据在传输过程中没有被篡改。
- 加密：TLS协议可以对数据进行加密，防止中间人攻击。
- 隐私保护：TLS协议可以保护用户的隐私，防止数据泄露。
- 性能：TLS协议的性能要优于其他安全协议。

TLS协议的主要缺点如下：

- 性能：TLS协议的性能较低，在某些情况下，它会影响应用的性能。
- 兼容性：TLS协议的兼容性不如其他安全协议。
- 部署难度：TLS协议的部署难度较高，需要大量的服务器端配置。
- 成本：TLS协议的部署成本较高，需要购买专门的证书。

总结：TLS协议是一种安全协议，它建立在Internet协议（IP）之上，用于两个应用程序之间提供保密性和数据完整性。TLS协议的实现需要一定的时间，因此，在建立连接之前，客户端和服务器必须协商一个加密套件，并使用该套件进行通信。TLS协议的主要优点是身份验证、数据完整性、加密、隐私保护、性能，主要缺点是性能、兼容性、部署难度、成本。


SSL和TLS是两种不同的协议，它们的主要区别如下：

- 名称：SSL是Secure Socket Layer的缩写，TLS是Transport Layer Security的缩写。
- 协议版本：SSL 3.0和TLS 1.0是SSL协议的初始版本，SSL 2.0和TLS 1.1是SSL协议的更新版本。
- 加密算法：SSL协议使用的是RC4加密算法，TLS协议使用的是更安全的AES加密算法。
- 加密套件：SSL协议的加密套件有SSLv2、SSLv3、TLSv1.0、TLSv1.1、TLSv1.2等，TLS协议的加密套件有TLS_RSA_WITH_AES_128_CBC_SHA、TLS_RSA_WITH_AES_256_CBC_SHA、TLS_RSA_WITH_AES_128_CBC_SHA256、TLS_RSA_WITH_AES_256_CBC_SHA256等。
- 密钥交换：SSL协议使用的是RSA公钥加密算法，TLS协议使用的是ECDHE（Elliptic Curve Diffie-Hellman Ephemeral）密钥交换算法。
- 证书类型：SSL协议的证书类型有X.509、SDSI、PKCS#12等，TLS协议的证书类型有X.509、SDSI、PKCS#12、OpenPGP等。
- 密钥长度：SSL协议的密钥长度有56位、128位、256位等，TLS协议的密钥长度有128位、256位、512位等。
- 加密模式：SSL协议的加密模式有CBC、GCM等，TLS协议的加密模式有CBC、GCM、CCM等。
- 证书管理：SSL协议的证书管理是手动的，TLS协议的证书管理是自动的。
- 部署难度：SSL协议的部署难度较低，因为它是SSL 3.0和TLS 1.0的升级版本，部署起来比较简单。TLS协议的部署难度较高，因为它支持的加密套件、加密模式等都比较多，需要配置服务器端的各种参数。
- 成本：SSL协议的部署成本较低，因为它是SSL 3.0和TLS 1.0的升级版本，部署起来比较简单。TLS协议的部署成本较高，因为它支持的加密套件、加密模式等都比较多，需要购买专门的证书。

总结：SSL和TLS是两种不同的协议，它们的主要区别是协议版本、加密算法、加密套件、密钥交换、证书类型、密钥长度、加密模式、证书管理、部署难度、成本。SSL协议的主要缺点是性能、兼容性、部署难度、成本，TLS协议的主要优点是性能、安全性、隐私保护。


# PKI（Public Key Infrastructure，公钥基础设施）
PKI（Public Key Infrastructure，公钥基础设施）是一种管理数字证书的系统，它包括证书颁发机构（CA）、证书吊销机构（CA）、证书注册机构（RA）、证书存储库、证书利用系统。PKI的主要功能是为用户和组织提供数字证书，并验证证书的有效性、真实性、完整性。PKI的主要优点如下：

- 数字证书：PKI可以为用户和组织提供数字证书，可以用于身份验证、数据加密、数据签名等。
- 管理证书：PKI可以管理证书的生命周期，包括证书的创建、更新、吊销等。
- 安全性：PKI可以确保证书的安全性，防止证书被伪造、篡改、泄露等。
- 透明度：PKI可以提供证书的透明度，使得证书的颁发、管理、使用过程可见。
- 灵活性：PKI可以提供灵活的证书管理机制，支持多种证书类型、多种密钥算法、多种密钥长度、多种证书签名算法等。
PKI的主要缺点如下：

- 成本：PKI的部署和维护成本较高，需要购买专门的服务器、硬件、软件等。
- 复杂性：PKI的复杂性较高，需要大量的服务器端配置、网络配置、证书管理工具等。
- 管理难度：PKI的管理难度较高，需要熟练的证书管理人员、网络管理员、系统管理员等。

总结：PKI是一种管理数字证书的系统，它包括证书颁发机构（CA）、证书吊销机构（CA）、证书注册机构（RA）、证书存储库、证书利用系统。PKI的主要功能是为用户和组织提供数字证书，并验证证书的有效性、真实性、完整性。PKI的主要优点是数字证书、管理证书、安全性、透明度、灵活性，主要缺点是成本、复杂性、管理难度。

PKI证书并不与TLS或SSL协议绑定，可以单独使用在任何需要的地方。

# PKI CA实现
## 微软AD CS（Active Directory Certificate Services）
微软AD CS（Active Directory Certificate Services）是微软提供的PKI CA产品，它可以集成到Windows Active Directory中，可以为Active Directory域中的用户和计算机颁发数字证书。AD CS的主要优点如下：

- 集成：AD CS可以集成到Windows Active Directory中，可以为Active Directory域中的用户和计算机颁发数字证书。   
- 自动化：AD CS可以自动化证书的创建、更新、吊销等流程，可以节省大量的人力、财力和时间。
- 易用：AD CS的管理界面简洁易用，可以轻松管理证书。
- 安全：AD CS可以提供安全的证书存储库，可以防止证书被篡改、泄露等。
## Linux OpenSSL PKI
OpenSSL PKI（Public Key Infrastructure，公钥基础设施）是一种开源PKI产品，它可以为Linux系统颁发数字证书。OpenSSL PKI的主要优点如下：

- 开源：OpenSSL PKI是开源产品，可以自由使用、修改、分发。
- 易用：OpenSSL PKI的管理界面简洁易用，可以轻松管理证书。
- 安全：OpenSSL PKI可以提供安全的证书存储库，可以防止证书被篡改、泄露等。
OpenSSL PKI的主要缺点如下：

- 性能：OpenSSL PKI的性能较低，在某些情况下，它会影响应用的性能。
- 兼容性：OpenSSL PKI的兼容性不如其他PKI产品。
- 部署难度：OpenSSL PKI的部署难度较高，需要大量的服务器端配置。
- 成本：OpenSSL PKI的部署成本较高，需要购买专门的证书。

总结：OpenSSL PKI是一种开源PKI产品，它可以为Linux系统颁发数字证书。OpenSSL PKI的主要优点是开源、易用、安全、性能，主要缺点是兼容性、部署难度、成本。

1. 生产RSA CA证书
    - openssl genrsa -aes256 -out CAPrivate.key 2048 #生成CA私钥
    - openssl req -new -x509 -key CAPrivate.key -sha256 -days 365 -out CA.crt #生成CA证书
    - openssl x509 -in CA.crt -text -noout #查看CA证书信息
2. 创建CSR(Certificate Signing Request)文件
    - openssl req -new -key CAPrivate.key -sha256 -days 365 -out fakedomain.csr #创建请求文件
3. 签发证书
    - openssl x509 -req -in fakedomain.csr -CA CA.crt -CAkey CAPrivate.key -CAcreateserial -extfile otherinfo.ext -out www.fakedomain.crt -days 365 -sha256 #生成证书
 - 其他信息文件otherinfo.ext
```
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,nonRepudiation,dataEncipherment
subjectAltName= @alt_names

[alt_names]
DNS.1 = www.fakedomain.com
DNS.2 = www.fakedomain.org
```
4. 验证证书
    - openssl verify -CAfile CA.crt www.fakedomain.crt #验证证书

5. 查看支持的密码套件版本
    - openssl ciphers -v
# PKI证书获取

# PKI证书使用

# 参考

- https://badssl.com/
- https://www.sslchecker.com/sslchecker
- https://www.ssllabs.com/ssltest/

