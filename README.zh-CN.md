# Tuxera NTFS Keygen

## 1. Tuxera NTFS是什么

Tuxera NTFS是个可用于内部和外部存储、经过性能优化，具备容错性和完全兼容性的文件系统解决方案。Tuxera NTFS已经在市场上一些最新的高端电视、电视机顶盒、智能手机、平板电脑、路由器、网络附属存储和其他设备上使用。Tuxera NTFS目前适用于安卓和其他Linux平台、还有QNX、WinCE Series 40、Nucleus RTOS和 VxWorks等。Tuxera同时也适用于许多构架，如ARM、MIPS、PowerPC、SuperH和x86等。

来自 [百度百科](https://baike.baidu.com/item/Tuxera/7826353)

## 2. 激活密钥是如何生成的？

在Tuxera NTFS中有两类激活密钥，它们分别是

|Key Type         |Key Length|Format                            |
|-----------------|----------|----------------------------------|
|Long Product Key |34 chars  |xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx|
|Short Product Key|23 chars  |xxxxx-xxxxx-xxxxx-xxxxx           |

`Format`列中的`x`字符代表的是下面编码表中的字符：

```cpp
// defined in CustomBase32Encode function, helper.c file.
const char SubstitutionTable[33] = "0123456789ACDEFGHJKLMNPQRTUVWXYZ";
```

其中`\0`字符并不包含在其中

### 2.1 长激活密钥是如何生成的？

Tuxera NTFS是使用 __ECC (Elliptic-curve Cryptography)__ 来生成长激活密钥的。

其中用到的曲线为`secp112r1`，是基于有限域![](http://latex.codecogs.com/gif.latex?GF_p)的曲线，方程为

<p align="center">
<img src="https://latex.codecogs.com/gif.latex?y%5E2%5Cequiv%20x%5E3&plus;ax&plus;b%5C%20%5C%20%28mod%5C%20p%29">
</p>

其中

 <p align="center">
<img src="http://latex.codecogs.com/gif.latex?p%3D%5Ctextrm%7B0xDB7C2ABF62E35E668076BEAD208B%7D">
</br>
<img src="http://latex.codecogs.com/gif.latex?a%3D%5Ctextrm%7B0xDB7C2ABF62E35E668076BEAD2088%7D">
</br>
<img src="http://latex.codecogs.com/gif.latex?b%3D%5Ctextrm%7B0x659EF8BA043916EEDE8911702B22%7D">
</p>

使用的基点![](http://latex.codecogs.com/gif.latex?%5Cmathbf%7BG%7D)为

<p align="center">
<img src="https://latex.codecogs.com/gif.latex?%5Cbegin%7Balign*%7D%20%5Cmathbf%7BG%7D%26%3D%28G_x%2C%20G_y%29%5C%5C%20%26%3D%28%5Ctextrm%7B0x09487239995A5EE76B55F9C2F098%7D%2C%5Ctextrm%7B0xA89CE5AF8724C0A23E0E0FF77500%7D%29%20%5Cend%7Balign*%7D">
</p>

基点![](http://latex.codecogs.com/gif.latex?%5Cmathbf%7BG%7D)的阶为

<p align="center">
<img src="http://latex.codecogs.com/gif.latex?n%3D%5Ctextrm%7B0xDB7C2ABF62E35E7628DFAC6561C5%7D">
</p>

Tuxera NTFS将官方ECC公钥写在了`/Library/PreferencePanes/Tuxera\ NTFS.prefPane/Contents/MacOS/Tuxera\ NTFS`二进制文件中，具体的值为

<p align="center">
<img src="https://latex.codecogs.com/gif.latex?%5Cbegin%7Balign*%7D%20%5Cmathbf%7BP%7D%26%3D%28P_x%2C%20P_y%29%5C%5C%20%26%3D%28%5Ctextrm%7B0x47CFB5F7E8931EC93D42D1221E7F%7D%2C%5Ctextrm%7B0x985D74AF455370F347398E1B1D3E%7D%29%20%5Cend%7Balign*%7D">
</p>

目前我并不知道对应的私钥 ![](http://latex.codecogs.com/gif.latex?k) 是什么。如果你知道请告诉我，我将非常感谢你的慷慨。

以下将说明长激活密钥是如何生成的：

  1. 生成一个大数 ![](http://latex.codecogs.com/gif.latex?r) ，其中 ![](http://latex.codecogs.com/gif.latex?r )必须满足 ![](http://latex.codecogs.com/gif.latex?0%3Cr%3Cn)  。
  
  2. 计算![](http://latex.codecogs.com/gif.latex?r%5Cmathbf%7BG%7D)。

  3. 准备好一个buffer `uint8_t bin_rG[2][14]`。将大数 ![](http://latex.codecogs.com/gif.latex?%28r%5Cmathbf%7BG%7D%29_x) 和 ![](http://latex.codecogs.com/gif.latex?%28r%5Cmathbf%7BG%7D%29_y) 按照 __大端字节序__ 分别写入到`bin_rG[0]` 和 `bin_rG[1]`中。如果大数没有14个字节，则在高位补“0”字节即可。

  4. 准备好一个buffer `uint8_t Hash[5]`。用`argon2_hash`函数计算`bin_rG`的哈希，这个函数的定义可在`argon2`中找到。

     ```cpp
     argon2_hash(1,
                 1 << 16,
                 1,
                 bin_rG,
                 sizeof(bin_rG),
                 salt,
                 sizeof(salt),
                 Hash,
                 sizeof(Hash),
                 NULL,
                 0,
                 Argon2_d,
                 ARGON2_VERSION_13);
     ```

     其中`salt`为

     ```cpp
     const uint8_t salt[16] = {
         0xa1, 0x38, 0x11, 0x98, 0x12, 0x2f, 0x28, 0xee,
         0x2c, 0x3a, 0xa0, 0x57, 0xbd, 0xcf, 0x2d, 0x83
     };
     ```

     计算完成后，清除`Hash[4]`的低两位。换句话说执行`Hash[4] &= 0xFC;`。

  5. 将`Hash`（5字节）按 __大端字节序__ 转化为一个大数 ![](http://latex.codecogs.com/gif.latex?h) 。

  6. 准备好一个buffer `uint8_t bin_s[14]`。计算

     <p align="center">
     <img src="http://latex.codecogs.com/gif.latex?s%5Cequiv%20r-h%5Ccdot%20k%5C%20%5C%20%28mod%5C%20n%29">
     </p>

     并将![](http://latex.codecogs.com/gif.latex?s)按照 __大端字节序__ 写入到`bin_s`中。同样如果大数不满14字节，则在高位补“0”字节。

  7. 将`bin_s`（14字节）和`Hash`（5字节）拼接，则会得到`uint8_t key_data[14 + 5]`，其中`key_data`的前14字节为`bin_s`。

  8. 使用变种Base32编码方式编码`key_data`，然后你可以得到`prekey_str`字符串（包含31个字符）。变种Base32和标准Base32的区别在于：

     1. 在变种Base32中，代换表为`0123456789ACDEFGHJKLMNPQRTUVWXYZ`；而在标准Base32中，代换表为`ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`。

     2. 当5比特长的编码单元跨过了某个字节时，交换编码单元中在该字节和下一字节的两个部分。

        例如：

        如果有两字节的待编码数据————`10111010` `11110100`————那么在变种Base32中编码单元为`10111` `11010` `11010` `00000`，而在标准Base32中编码单元为`10111` `01011` `11010` `00000`；即标准Base32中`01011`编码单元的两部分————`010`和`11`————在变种Base32中交换了，因为该编码单元跨过了两个字节。

     3. 在变种Base32中，没有`=`填充字符。

  9. 在`prekey_str`中，最后一个字符肯定是`'0'`，因为`Hash[4]`的低两位被清空了。移除掉这个字符，那么`prekey_str`的长度就变为30个字符了。

  10. 将`prekey_str`倒序。然后按照每6个字符分块，总共分成5块。将这个5块用英文连字符`'-'`连接就可以得到长激活密钥。

### 2.2 短激活密钥是如何生成的？

  * todo

## 3. 激活密钥是如何被验证的？

### 3.1 长激活密钥是如何被验证的？

1. 将长激活密钥解码成19字节长的`key_data`

2. 将`key_data`的前14字节和后5字节按照 __大端字节序__ 转化成大数 ![](http://latex.codecogs.com/gif.latex?s) 和 ![](http://latex.codecogs.com/gif.latex?h) 。

3. 计算 ![](https://latex.codecogs.com/gif.latex?s%5Cmathbf%7BG%7D&plus;h%5Cmathbf%7BP%7D) 并将结果按照 __大端字节序__ 写入到`uint8_t bin_R[2][14]`中，同样若大数不满足14字节则在高位补“0”字节。

4. 使用`argon2_hash`函数计算`bin_R`的哈希`uint8_t Hash[5]`。

5. 检查`Hash`是否与`key_data`的后5字节相同。如果相同则长激活密钥有效，反之无效。

为什么？因为如果长激活密钥是有效的，则必有

<p align="center">
 <img src="https://latex.codecogs.com/gif.latex?%5Cbegin%7Balign*%7D%20s%5Cmathbf%7BG%7D&plus;h%5Cmathbf%7BP%7D%26%3D%28r-h%5Ccdot%20k%29%5Cmathbf%7BG%7D&plus;h%5Cmathbf%7BP%7D%5C%5C%20%26%3Dr%5Cmathbf%7BG%7D-h%5Ccdot%20k%5Cmathbf%7BG%7D&plus;h%5Cmathbf%7BP%7D%5C%5C%20%26%3Dr%5Cmathbf%7BG%7D-h%5Cmathbf%7BP%7D&plus;h%5Cmathbf%7BP%7D%5C%5C%20%26%3Dr%5Cmathbf%7BG%7D%20%5Cend%7Balign*%7D">
</p>

所以`key_data`的后5字必然与`Hash`相同。如果不等，则长激活密钥必然不等。

### 3.2 短激活密钥是如何被验证的？

  * todo

## 4. 如何编译？

  1. __请确保你有`openssl`和`argon2`。你可以通过Homebrew安装它们。__

     ```bash
     $ brew install openssl
     $ brew install argon2
     ```

  2. 如果要编译patcher，在控制台中：

     ```bash
     $ make patcher
     ```

     之后你会得到`TuxeraNTFS-patcher`。

     如果要编译keygen，在控制台中：

     ```bash
     $ make keygen
     ```

     之后你会得到`TuxeraNTFS-keygen`。

     如果要清理，则

     ```bash
     $ make clean
     ```

## 5. 如何使用？

__上次测试时间：2018-07-07__

__上次测试版本：2018 (released 2018-01-25)__

  1. 编译patcher和keygen。

  2. 使用`TuxeraNTFS-patcher`给Tuxera NTFS打个补丁。在控制台中：

     ```bash
     $ sudo ./TuxeraNTFS-patcher /Library/PreferencePanes/Tuxera\ NTFS.prefPane/Contents/MacOS/Tuxera\ NTFS
     ```

     例如:

     ```bash
     $ sudo ./TuxeraNTFS-patcher /Library/PreferencePanes/Tuxera\ NTFS.prefPane/Contents/MacOS/Tuxera\ NTFS
     Password:
     -----secp112r1 Private Key-----
     Bin: 36 25 23 22 B3 36 41 75 49 FC 9C FE CF EC

     -----secp112r1 Public Key-----
     Bin: X = CE E5 BB 00 29 F1 10 5B 41 7C FD FE 78 7E
     Bin: Y = C3 07 5A CE DE 75 2E E1 F1 AC 4D 59 22 6C

     Write private key to tuxera_key.bin successfully.

     patching......
     Open file successfully.
     Get file size successfully: 3669616 byte(s).
     Map file successfully.
     offset = 0x000000000002ec2a, writing data.....patching is done.
     offset = 0x000000000014f05e, writing data.....patching is done.
     offset = 0x0000000000284c40, writing data.....patching is done.
     Modified: 3
     ```

     你会在当前目录下得到`tuxera_key.bin`文件。

  3. 对Tuxera NTFS重新进行代码签名。因为我们对`Tuxera NTFS.prefPane`打了补丁，原先的代码签名已经失效。我们必须进行重签名。在控制台中：

     ```bash
     $ sudo codesign -f -s "your code-sign certificate name" /Library/PreferencePanes/Tuxera\ NTFS.prefPane
     ```

     __NOTICE:__ `"your code-sign certificate name"` 应该是你代码签名证书的名字，它应该显示在你的`Keychain.app`中。

  4. 运行`TuxeraNTFS-keygen`来生成激活密钥。在控制台中：

     ```bash
     $ ./TuxeraNTFS-keygen ./tuxera_key.bin
     ```

     Example:

     ```bash
     $ ./TuxeraNTFS-keygen ./tuxera_key.bin
     -----secp112r1 Private Key-----
     Bin: 36 25 23 22 B3 36 41 75 49 FC 9C FE CF EC

     -----secp112r1 Public Key-----
     Bin: X = CE E5 BB 00 29 F1 10 5B 41 7C FD FE 78 7E
     Bin: Y = C3 07 5A CE DE 75 2E E1 F1 AC 4D 59 22 6C

     Long product key: H49PUJ-4EFXEY-2017P6-2CCG55-364RM6
     ```

  5. 现在你可以看到激活密钥了。用它激活Tuxera NTFS即可。

