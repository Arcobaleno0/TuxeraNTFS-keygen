# Tuxera NTFS keygen

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
  <img src="http://latex.codecogs.com/gif.latex?y%5E2%3Dx%5E3&plus;ax&plus;b">
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
  <img src="http://latex.codecogs.com/gif.latex?%5Cmathbf%7BG%7D%3D%28G_x%2CG_y%29%3D%5Cpar%20%28%5Ctextrm%7B0x09487239995A5EE76B55F9C2F098%7D%2C%20%5Ctextrm%7B0xA89CE5AF8724C0A23E0E0FF77500%7D%29">
  </p>

  whose order is

  <p align="center">
  <img src="http://latex.codecogs.com/gif.latex?n%3D%5Ctextrm%7B0xDB7C2ABF62E35E7628DFAC6561C5%7D">
  </p>

  Tuxera NTFS has stored its official public key in `/Library/PreferencePanes/Tuxera\ NTFS.prefPane/Contents/MacOS/Tuxera\ NTFS` which is

  <p align="center">
  <img src="http://latex.codecogs.com/gif.latex?%5Cmathbf%7BP%7D%3D%28P_x%2CP_y%29%3D%20%5Cpar%20%28%5Ctextrm%7B0x47CFB5F7E8931EC93D42D1221E7F%7D%2C%20%5Ctextrm%7B0x985D74AF455370F347398E1B1D3E%7D%29">
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

  6. Prepare a buffer `uint8_t bin_S[14]`. Calculate

     <p align="center">
     <img src="http://latex.codecogs.com/gif.latex?S%5Cequiv%20r-h%5Ccdot%20k%5C%20%5C%20%28mod%5C%20n%29">
     </p>

     and save ![](http://latex.codecogs.com/gif.latex?S) to `bin_S` with __big-endian__. If big number is not 14-bytes-long, pad zero byte at __Most Significant Bit__.

  7. Join `bin_S`(14 bytes) and `Hash`(5 bytes) and you will get `uint8_t key_data[14 + 5]` where the first 14 bytes are `bin_S`.

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

  * todo

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

  __Last Test Time: 2018-07-07__

  __Last Test Version: 2018 (released 2018-01-25)__

  1. Build patcher and keygen.

  2. Use `TuxeraNTFS-patcher` to make a patch for Tuxera NTFS. In console:

     ```bash
     $ sudo ./TuxeraNTFS-patcher /Library/PreferencePanes/Tuxera\ NTFS.prefPane/Contents/MacOS/Tuxera\ NTFS
     ```

     Example:

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

     You will get `tuxera_key.bin` file at current directory.

  3. Re-codesign Tuxera NTFS. Because we made a patch to `Tuxera NTFS.prefPane`, the original code signature became invalid. So we have to re-codesign it. In console:

     ```bash
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
     Bin: 36 25 23 22 B3 36 41 75 49 FC 9C FE CF EC

     -----secp112r1 Public Key-----
     Bin: X = CE E5 BB 00 29 F1 10 5B 41 7C FD FE 78 7E
     Bin: Y = C3 07 5A CE DE 75 2E E1 F1 AC 4D 59 22 6C

     Long product key: H49PUJ-4EFXEY-2017P6-2CCG55-364RM6
     ```

  5. Now you can see product key. Just use it to activate your Tuxera NTFS.
