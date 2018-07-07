# Tuxera NTFS keygen

## 1. How does it work?

  * TODO

## 2. How to build?

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

## 3. How to use?

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
