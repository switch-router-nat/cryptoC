`cryptoC` 是一个供密码学初学者入门的密码学库，包含以下密码系统的经典实现：
+ 对称密码系统
  + DES (DES 3-DES)
  + AES  
+ 公钥密码系统
  + RSA
  + ECC
+ MAC
  + SHA (SHA1 SHA512)
  + MD5
+ 数字签名
  + DSA
+ 大数运算
+ 其他工具
  + base64
  + asn1

----------
### 安装方法

1. 下载代码

```shell
# git clone https://github.com/qshchenmo/cryptoC.git
```

2. 编译安装

```
# make
# make install
```
3. 运行测试程序
```
# cd example/rsa
# make
# ./test_rsa
```

----------

### 说明

 1. 本程序的目的是供密码学初学者了解对经典密码系统的实现，因此未对性能进行优化。

### 参考资料
[1] [Understanding Cryptography, Christof Paar / Jan Pelzl ][1]
[2] [密码学与网络安全][2]


  [1]: https://book.douban.com/subject/4246128/
  [2]: https://book.douban.com/subject/3639387/
