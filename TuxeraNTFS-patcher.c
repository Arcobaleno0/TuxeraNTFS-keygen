#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <memory.h>

#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/mman.h>

//--------in helper.c
extern void PrintBytes(const uint8_t* bytes, size_t len);
extern unsigned long PrintKeyInfo(const EC_KEY* lpcECKey, int* lperrno);
//--------end


const uint8_t OfficialPublicKey[] = {
    0x47, 0xcf, 0xb5, 0xf7, 0xe8, 0x93, 0x1e, 0xc9, 0x3d, 0x42, 0xd1, 0x22, 0x1e, 0x7f,
    0x98, 0x5d, 0x74, 0xaf, 0x45, 0x53, 0x70, 0xf3, 0x47, 0x39, 0x8e, 0x1b, 0x1d, 0x3e
};

void DoPatch(uint8_t* lpFileContent,
             off_t Offset,
             const uint8_t* lpcNewPublicKey,
             size_t KeySize) {
    memset(lpFileContent + Offset,
           0,
           sizeof(OfficialPublicKey));
    memcpy(lpFileContent + Offset,
           lpcNewPublicKey,
           KeySize);
}

off_t SearchOfficialPublicKey(uint8_t* lpFileContent, size_t FileSize, off_t start_offset) {
    off_t ret = -1;
    for (off_t i = start_offset; i + sizeof(uintptr_t) < FileSize; ++i)
        if (*(uintptr_t*)(lpFileContent + i) == *(uintptr_t*)OfficialPublicKey)
            if (0 == memcmp(lpFileContent + i, OfficialPublicKey, sizeof(OfficialPublicKey))) {
                ret = (off_t)i;
                break;
            }

    return ret;
}

void StartPatch(const char* lpszFilePath, const uint8_t* lpcNewPublicKey, size_t KeySize) {
    off_t offset = -1;
    int fd = -1;
    struct stat fd_stat = {};
    uint8_t* lpFileContent = NULL;

    printf("patching......\n");

    fd = open(lpszFilePath, O_RDWR, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        printf("Failed to open file. CODE: 0x%08x\n", errno);
        goto On_SearchOfficialPublicKey_Error;
    } else {
        printf("Open file successfully.\n");
    }

    if (fstat(fd, &fd_stat) != 0) {
        printf("Failed to get file size. CODE: 0x%08x\n", errno);
        goto On_SearchOfficialPublicKey_Error;
    } else {
        printf("Get file size successfully: %zu byte(s).\n", fd_stat.st_size);
    }

    lpFileContent = mmap(NULL, fd_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (lpFileContent == (void*)-1) {
        printf("Failed to map file. CODE: 0x%08x\n", errno);
        goto On_SearchOfficialPublicKey_Error;
    } else {
        printf("Map file successfully.\n");
    }

    int found = 0;
    while (1) {
        offset = SearchOfficialPublicKey(lpFileContent, fd_stat.st_size, offset + 1);
        if (offset == -1)
            break;
        found++;
        printf("offset = 0x%016llx, writing data.....", offset);
        DoPatch(lpFileContent, offset, lpcNewPublicKey, KeySize);
        printf("patching is done.\n");
    }

    printf("Modified: %d\n", found);

On_SearchOfficialPublicKey_Error:
    if (lpFileContent != NULL)
        munmap(lpFileContent, fd_stat.st_size);
    if (fd != -1)
        close(fd);
}

char SaveKey(const char* lpcszFileName,
             const uint8_t* lpcPrivateKey, size_t PrivateKeySize,
             const uint8_t* lpcPublicKey, size_t PublicKeySize) {
    int fd = open(lpcszFileName, O_RDWR | O_CREAT, 0666);
    if (fd == -1) {
        printf("Failed to create %s. CODE: 0x%08x\n", lpcszFileName, errno);
        return 0;
    }

    if (PrivateKeySize != write(fd, lpcPrivateKey, PrivateKeySize)) {
        printf("Failed to write private key or write incompletely. CODE: 0x%08x\n", errno);
        close(fd);
        return 0;
    }

    if (PublicKeySize != write(fd, lpcPublicKey, PublicKeySize)) {
        printf("Failed to write public key or write incompletely. CODE: 0x%08x\n", errno);
        close(fd);
        return 0;
    }

    printf("Write private key to %s successfully.\n", lpcszFileName);
    close(fd);
    return 1;
}

void help() {
    printf("Usage:\n");
    printf("    ./TuxeraNTFS-patcher <TuxeraNTFS.prefPane executable file>\n");
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        help();
        return 0;
    }

    unsigned long ErrorCode = 0;

    EC_KEY* newKey = NULL;
    const BIGNUM* PrivateKey = NULL;
    const EC_POINT* PublicKey = NULL;
    BIGNUM* PublicKeyX = NULL;
    BIGNUM* PublicKeyY = NULL;

    uint8_t binPrivateKey[14] = { };
    uint8_t binPublicKey[2][14] = { };

    newKey = EC_KEY_new_by_curve_name(NID_secp112r1);
    if (newKey == NULL) {
        ErrorCode = ERR_get_error();
        goto On_main_Error;
    }

    if (!EC_KEY_generate_key(newKey)) {
        ErrorCode = ERR_get_error();
        goto On_main_Error;
    }

    ErrorCode = PrintKeyInfo(newKey, NULL);
    if (ErrorCode) {
        goto On_main_Error;
    } else if (errno) {
        ErrorCode = (unsigned long)errno;
        goto On_main_Error;
    }

    PrivateKey = EC_KEY_get0_private_key(newKey);
    if (PrivateKey == NULL) {
        ErrorCode = ERR_get_error();
        goto On_main_Error;
    }

    PublicKey = EC_KEY_get0_public_key(newKey);
    if (PublicKey == NULL) {
        ErrorCode = ERR_get_error();
        goto On_main_Error;
    }

    PublicKeyX = BN_new();
    if (PublicKeyX == NULL) {
        ErrorCode = ERR_get_error();
        goto On_main_Error;
    }

    PublicKeyY = BN_new();
    if (PublicKeyY == NULL) {
        ErrorCode = ERR_get_error();
        goto On_main_Error;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(newKey),
                                             PublicKey,
                                             PublicKeyX,
                                             PublicKeyY,
                                             NULL)) {
        ErrorCode = ERR_get_error();
        goto On_main_Error;
    }

    if (!BN_bn2bin(PrivateKey, binPrivateKey + sizeof(binPrivateKey) - BN_num_bytes(PrivateKey))) {
        ErrorCode = ERR_get_error();
        goto On_main_Error;
    }
    if (!BN_bn2bin(PublicKeyX, binPublicKey[0] + sizeof(binPublicKey[0]) - BN_num_bytes(PublicKeyX))) {
        ErrorCode = ERR_get_error();
        goto On_main_Error;
    }
    if (!BN_bn2bin(PublicKeyY, binPublicKey[1] + sizeof(binPublicKey[1]) - BN_num_bytes(PublicKeyY))) {
        ErrorCode = ERR_get_error();
        goto On_main_Error;
    }

    if(!SaveKey("tuxera_key.bin",
                binPrivateKey, sizeof(binPrivateKey),
                (uint8_t*)binPublicKey, sizeof(binPublicKey))) {
        goto On_main_Error;
    }
    printf("\n");

    StartPatch(argv[1], (uint8_t*)binPublicKey, sizeof(binPublicKey));

On_main_Error:
    if (PublicKeyY)
        BN_free(PublicKeyY);
    if (PublicKeyX)
        BN_free(PublicKeyX);
    if (newKey)
        EC_KEY_free(newKey);
    if (ErrorCode)
        printf("%s\n", ERR_error_string(ErrorCode, NULL));
    return (int)ErrorCode;
}
