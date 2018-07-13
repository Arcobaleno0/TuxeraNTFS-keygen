# Tuxera NTFS keygen

[中文版README](README.zh-CN.md)

## 1. What is Tuxera NTFS?

Tuxera NTFS is a performance optimized, fail-safe, fully compatible NTFS file system driver. It ships for example in smart TVs, set-top boxes, smartphones, tablets, routers, NAS and other devices. It is available for Android and other Linux platforms, QNX, WinCE Series 40, Nucleus RTOS and VxWorks. Supported architectures are ARM architecture, MIPS architecture, PowerPC, SuperH and x86.

From [Wikipedia](https://en.wikipedia.org/wiki/Tuxera#Tuxera_NTFS)

## 2. How is the key generated?

There are 2 types of keys (also called `Product Key` in Tuxera NTFS) that can activate Tuxera NTFS, which are:

|Key Type         |Key Length|Format                            |
|-----------------|----------|----------------------------------|
|Long Product Key |34 chars  |xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx|
|Short Product Key|23 chars  |xxxxx-xxxxx-xxxxx-xxxxx           |

The `x` in `Format` column represents a character in encoding table. This encoding table is:

```cpp
// defined in CustomBase32Encode function, helper.c file.
const char SubstitutionTable[33] = "0123456789ACDEFGHJKLMNPQRTUVWXYZ";
```

where null-terminator `\0` is not contained.

### 2.1 How is Long Product Key generated?

  Tuxera NTFS uses __ECC (Elliptic-curve Cryptography)__ to generate long product keys.

  The curve it uses is `secp112r1` of which the equation is

  <p align="center">
  <img src="https://latex.codecogs.com/gif.latex?y%5E2%5Cequiv%20x%5E3&plus;ax&plus;b%5C%20%5C%20%28mod%5C%20p%29">
  </p>

  over finite field ![](http://latex.codecogs.com/gif.latex?GF_p) where

  <p align="center">
  <img src="http://latex.codecogs.com/gif.latex?p%3D%5Ctextrm%7B0xDB7C2ABF62E35E668076BEAD208B%7D">
  </br>
  <img src="http://latex.codecogs.com/gif.latex?a%3D%5Ctextrm%7B0xDB7C2ABF62E35E668076BEAD2088%7D">
  </br>
  <img src="http://latex.codecogs.com/gif.latex?b%3D%5Ctextrm%7B0x659EF8BA043916EEDE8911702B22%7D">
  </p>

  The base point ![](http://latex.codecogs.com/gif.latex?%5Cmathbf%7BG%7D) is

  <p align="center">
  <img src="https://latex.codecogs.com/gif.latex?%5Cbegin%7Balign*%7D%20%5Cmathbf%7BG%7D%26%3D%28G_x%2C%20G_y%29%5C%5C%20%26%3D%28%5Ctextrm%7B0x09487239995A5EE76B55F9C2F098%7D%2C%5Ctextrm%7B0xA89CE5AF8724C0A23E0E0FF77500%7D%29%20%5Cend%7Balign*%7D">
  </p>

  whose order is

  <p align="center">
  <img src="http://latex.codecogs.com/gif.latex?n%3D%5Ctextrm%7B0xDB7C2ABF62E35E7628DFAC6561C5%7D">
  </p>

  Tuxera NTFS has stored its official public key in the following files:

  |Path|
  |----|
  |`/Library/PreferencePanes/Tuxera\ NTFS.prefPane/Contents/MacOS/Tuxera\ NTFS`|
  |`/Library/PreferencePanes/Tuxera\ NTFS.prefPane/Contents/Resources/WriteActivationData`|
  |`/Library/PreferencePanes/Tuxera\ NTFS.prefPane/Contents/Resources/WriteActivationDataTiger`|
  |`/Library/Filesystems/tuxera_ntfs.fs/Contents/Resources/Support/10.4/ntfsck`|
  |`/Library/Filesystems/tuxera_ntfs.fs/Contents/Resources/Support/10.4/tuxera_ntfs`|
  |`/Library/Filesystems/tuxera_ntfs.fs/Contents/Resources/Support/10.5/ntfsck`|
  |`/Library/Filesystems/tuxera_ntfs.fs/Contents/Resources/Support/10.5/tuxera_ntfs`|

  The public key is

  <p align="center">
  <img src="https://latex.codecogs.com/gif.latex?%5Cbegin%7Balign*%7D%20%5Cmathbf%7BP%7D%26%3D%28P_x%2C%20P_y%29%5C%5C%20%26%3D%28%5Ctextrm%7B0x47CFB5F7E8931EC93D42D1221E7F%7D%2C%5Ctextrm%7B0x985D74AF455370F347398E1B1D3E%7D%29%20%5Cend%7Balign*%7D">
  </p>

  So far I don't know what its private key ![](http://latex.codecogs.com/gif.latex?k) is. If you know, please tell me and I will be appreciated with your generous.

  The following is how long product key is generated:

  1. Generate random big number ![](http://latex.codecogs.com/gif.latex?r). ![](http://latex.codecogs.com/gif.latex?r) must be ![](http://latex.codecogs.com/gif.latex?0%3Cr%3Cn).

  2. Calculate ![](http://latex.codecogs.com/gif.latex?r%5Cmathbf%7BG%7D).

  3. Prepare a buffer `uint8_t bin_rG[2][14]`. Save big number ![](http://latex.codecogs.com/gif.latex?%28r%5Cmathbf%7BG%7D%29_x) and ![](http://latex.codecogs.com/gif.latex?%28r%5Cmathbf%7BG%7D%29_y) to `bin_rG[0]` and `bin_rG[1]` respectively with __big-endian__. If big number is not 14-bytes-long, pad zero byte at __Most Significant Bit__.

  4. Prepare a buffer `uint8_t Hash[5]`. Calculate the hash of `bin_rG` with `argon2_hash` function.

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

     where `salt` is

     ```cpp
     const uint8_t salt[16] = {
         0xa1, 0x38, 0x11, 0x98, 0x12, 0x2f, 0x28, 0xee,
         0x2c, 0x3a, 0xa0, 0x57, 0xbd, 0xcf, 0x2d, 0x83
     };
     ```

     Then clear `Hash[4]`'s lower two bits. In other words, execute `Hash[4] &= 0xFC;`.

  5. Convert `Hash`(5 bytes) to a big number ![](http://latex.codecogs.com/gif.latex?h) with __big endian__.

  6. Prepare a buffer `uint8_t bin_s[14]`. Calculate

     <p align="center">
     <img src="http://latex.codecogs.com/gif.latex?s%5Cequiv%20r-h%5Ccdot%20k%5C%20%5C%20%28mod%5C%20n%29">
     </p>

     and save ![](http://latex.codecogs.com/gif.latex?s) to `bin_s` with __big-endian__. If big number is not 14-bytes-long, pad zero byte at __Most Significant Bit__.

  7. Join `bin_s`(14 bytes) and `Hash`(5 bytes) and you will get `uint8_t key_data[14 + 5]` where the first 14 bytes are `bin_s`.

  8. Encode `key_data` by custom Base32 and you will get `prekey_str` that has 31 chars. The differences between custom Base32 and standard Base32 are:

     1. The alphabet table in custom Base32 is `0123456789ACDEFGHJKLMNPQRTUVWXYZ` while `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567` in standard Base32.

     2. When a 5-bits-long unit crosses over a byte, swap bits in the byte and bits in the next byte.

        Example:

        If 2-bytes-long data to encode is `10111010` `11110100`, the units to encode are `10111` `11010` `11010` `00000` in custom Base32 while `10111` `01011` `11010` `00000` in standard Base32. That means `010` and `11` in unit `01011` in standard Base32 are swapped because `01011` crossed those two bytes.

     3. No `=` padding in custom Base32.

  9. The last character in `prekey_str` must be `'0'` because `Hash[4]` was &-masked by `0xFC`. Remove the last character and the length of `prekey_str` becomes 30.

  10. Reverse `prekey_str`. And divide 30 chars in `prekey_str` to five 6-chars-long blocks. Join them with hyphen(`'-'`) and you will get long product key.

### 2.2 How is Short Product Key generated?

  * todo

## 3. How is the key verified?

### 3.1 How is Long Product Key verified?

  1. Decode long product key to 19-bytes-long `key_data`;

  2. Convert the first 14 bytes and the latter 5 bytes to big number ![](http://latex.codecogs.com/gif.latex?s) and ![](http://latex.codecogs.com/gif.latex?h) with __big endian__.

  3. Calculate ![](https://latex.codecogs.com/gif.latex?s%5Cmathbf%7BG%7D&plus;h%5Cmathbf%7BP%7D) and convert the result to `uint8_t bin_R[2][14]`.

  4. Use `argon2_hash` to hash `bin_R` and you will `uint8_t Hash[5]`.

  5. Check if `Hash` is equal to the latter 5 bytes in `key_data`. If true the long product key is valid, otherwise invalid.

  Why? Because if the long product key is valid, we must have

  <p align="center">
  <img src="https://latex.codecogs.com/gif.latex?%5Cbegin%7Balign*%7D%20s%5Cmathbf%7BG%7D&plus;h%5Cmathbf%7BP%7D%26%3D%28r-h%5Ccdot%20k%29%5Cmathbf%7BG%7D&plus;h%5Cmathbf%7BP%7D%5C%5C%20%26%3Dr%5Cmathbf%7BG%7D-h%5Ccdot%20k%5Cmathbf%7BG%7D&plus;h%5Cmathbf%7BP%7D%5C%5C%20%26%3Dr%5Cmathbf%7BG%7D-h%5Cmathbf%7BP%7D&plus;h%5Cmathbf%7BP%7D%5C%5C%20%26%3Dr%5Cmathbf%7BG%7D%20%5Cend%7Balign*%7D">
  </p>

  So that `Hash` shall be equal to the latter 5 bytes in `key_data`. If not equal, the long product key must not be a valid key.

### 3.2 How is Short Product Key verified?

  * todo

## 4. How to build?

  1. __PLEASE MAKE SURE YOU HAVE `openssl` and `argon2`. You can install them by Homebrew.__

     ```bash
     $ brew install openssl
     $ brew install argon2
     ```

  2. To make patcher, in console:

     ```bash
     $ make patcher
     ```

     and you will get file `TuxeraNTFS-patcher`.

     To make keygen, in console:

     ```bash
     $ make keygen
     ```

     and you will get file `TuxeraNTFS-keygen`.

     To clean, in console:

     ```bash
     $ make clean
     ```

## 5. How to use?

  __Last Test Time: 2018-07-13__

  __Last Test Version: 2018 (released 2018-01-25)__ Download from [here](https://www.tuxera.com/products/tuxera-ntfs-for-mac/):

  1. Build patcher and keygen.

  2. Use `TuxeraNTFS-patcher` to make a patch for Tuxera NTFS. In console:

     ```bash
     $ sudo ./TuxeraNTFS-patcher
     ```

     Example:

     ```bash
     $ sudo ./TuxeraNTFS-patcher
     Password:
     -----secp112r1 Private Key-----
     Bin: 42 EE 5D 2C CD 53 0A 06 43 B9 9A 9E 29 B0

     -----secp112r1 Public Key-----
     Bin: X = C3 15 26 EC 75 DE AA 90 4C 70 7B 09 2B EC
     Bin: Y = 68 49 70 AA 04 3D 9F B3 DF 42 63 3D 55 FF

     Write private key to tuxera_key.bin successfully.

     Patching...
     Target file: /Library/PreferencePanes/Tuxera NTFS.prefPane/Contents/MacOS/Tuxera NTFS
     Open file successfully!
     File size: 3669616 byte(s).
     Map file successfully!
     offset = 0x000000000002ec2a, writing data.....Patch is done.
     offset = 0x000000000014f05e, writing data.....Patch is done.
     offset = 0x0000000000284c40, writing data.....Patch is done.
     Modified: 3

     Target file: /Library/PreferencePanes/Tuxera NTFS.prefPane/Contents/Resources/WriteActivationData
     Open file successfully!
     File size: 3180416 byte(s).
     Map file successfully!
     offset = 0x000000000002366e, writing data.....Patch is done.
     offset = 0x000000000011eae6, writing data.....Patch is done.
     offset = 0x0000000000226c74, writing data.....Patch is done.
     Modified: 3

     Target file: /Library/PreferencePanes/Tuxera NTFS.prefPane/Contents/Resources/WriteActivationDataTiger
     Open file successfully!
     File size: 2132524 byte(s).
     Map file successfully!
     offset = 0x0000000000023c6b, writing data.....Patch is done.
     offset = 0x0000000000126c84, writing data.....Patch is done.
     Modified: 2

     Target file: /Library/Filesystems/tuxera_ntfs.fs/Contents/Resources/Support/10.4/ntfsck
     Open file successfully!
     File size: 3135728 byte(s).
     Map file successfully!
     offset = 0x0000000000099d07, writing data.....Patch is done.
     offset = 0x000000000021bd4c, writing data.....Patch is done.
     Modified: 2

     Target file: /Library/Filesystems/tuxera_ntfs.fs/Contents/Resources/Support/10.4/tuxera_ntfs
     Open file successfully!
     File size: 3005576 byte(s).
     Map file successfully!
     offset = 0x000000000008a747, writing data.....Patch is done.
     offset = 0x00000000001fc754, writing data.....Patch is done.
     Modified: 2

     Target file: /Library/Filesystems/tuxera_ntfs.fs/Contents/Resources/Support/10.5/ntfsck
     Open file successfully!
     File size: 6195032 byte(s).
     Map file successfully!
     offset = 0x0000000000098bc2, writing data.....Patch is done.
     offset = 0x000000000021d890, writing data.....Patch is done.
     offset = 0x0000000000379f0a, writing data.....Patch is done.
     offset = 0x00000000005057a0, writing data.....Patch is done.
     Modified: 4

     Target file: /Library/Filesystems/tuxera_ntfs.fs/Contents/Resources/Support/10.5/tuxera_ntfs
     Open file successfully!
     File size: 5958616 byte(s).
     Map file successfully!
     offset = 0x0000000000089382, writing data.....Patch is done.
     offset = 0x00000000001fe27c, writing data.....Patch is done.
     offset = 0x000000000034ec42, writing data.....Patch is done.
     offset = 0x00000000004cc178, writing data.....Patch is done.
     Modified: 4
     ```

     You will get `tuxera_key.bin` file at current directory.

  3. Re-codesign Tuxera NTFS. Because we made a patch to `tuxera_ntfs.fs` and `Tuxera NTFS.prefPane`, their original code signatures became invalid. So we have to re-codesign them. In console:

     ```bash
     $ sudo codesign -f -s "your code-sign certificate name" /Library/Filesystems/tuxera_ntfs.fs
     $ sudo codesign -f -s "your code-sign certificate name" /Library/PreferencePanes/Tuxera\ NTFS.prefPane
     ```

     __NOTICE:__ `"your code-sign certificate name"` should be the name of your code-sign certificate, which is displayed in `Keychain.app`.

  4. Run `TuxeraNTFS-keygen` to generate the product key. In console:

     ```bash
     $ ./TuxeraNTFS-keygen ./tuxera_key.bin
     ```

     Example:

     ```bash
     $ ./TuxeraNTFS-keygen ./tuxera_key.bin
     -----secp112r1 Private Key-----
     Bin: 42 EE 5D 2C CD 53 0A 06 43 B9 9A 9E 29 B0

     -----secp112r1 Public Key-----
     Bin: X = C3 15 26 EC 75 DE AA 90 4C 70 7B 09 2B EC
     Bin: Y = 68 49 70 AA 04 3D 9F B3 DF 42 63 3D 55 FF

     Long product key: 4KPGHH-147M3Q-UHN3M2-C4DYAN-ENACL0
     ```

  5. Now you can see product key. Just use it to activate your Tuxera NTFS.
