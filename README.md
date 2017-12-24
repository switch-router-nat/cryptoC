Welcome to cryptoC
==================

**cryptoC**是一个由ANSI C编写密码学库
The cryptoC is a Cryptographylib implement by ANSI C


----------
###Build example

在工程目录下，使用scons进行构建，这需要你提前安装了scons,以及依赖的python环境
This assumes you have a shell in the project directory, and scons (python) is installed

1.  `% scons`

一条命令即可生成了静态库文件
We build a static library **libcryptoc.a** 

ut文件中的文件是使用Cryptolib的例子，同样可以使用scons进行构建
1.  `% cd ./ut/rsa`
2.  `% scons`

We build a executable file **ut_rsa** 

-----------
###Road map

+ Block Cipher
  + DES (DES 3-DES)
  + AES
+ Public Key Cryptography
  + RSA
  + ECC
+ MAC
  + SHA (SHA1 SHA512)
+ Big Num Operation
+ Tool
  + base64
  + asn1



