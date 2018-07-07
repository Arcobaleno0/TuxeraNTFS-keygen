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

#include <argon2.h>

//--------in helper.c
extern void PrintBytes(const uint8_t* bytes, size_t len);
extern size_t CustomBase32Encode(const void* __restrict src, size_t len,
                                 char* __restrict out_buf, size_t out_len);
extern unsigned long PrintKeyInfo(const EC_KEY* lpcECKey, int* lperrno);
//--------end

const uint8_t salt[16] = {
    0xa1, 0x38, 0x11, 0x98, 0x12, 0x2f, 0x28, 0xee,
    0x2c, 0x3a, 0xa0, 0x57, 0xbd, 0xcf, 0x2d, 0x83
};

// sn = (r - hash * PrivateKey) * EllipticCurveGenerator
unsigned long CalculateSN(const BIGNUM* r, const BIGNUM* hash, const BIGNUM* PrivateKey, const BIGNUM* order, uint8_t* lpSN) {
    unsigned long ErrorCode = 0;
    BIGNUM* sn = NULL;
    BIGNUM* tmp = NULL;
    BN_CTX* bn_ctx = NULL;

    sn = BN_new();
    if (sn == NULL) {
        ErrorCode = ERR_get_error();
        goto On_CalculateSN_Error;
    }

    tmp = BN_new();
    if (tmp == NULL) {
        ErrorCode = ERR_get_error();
        goto On_CalculateSN_Error;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ErrorCode = ERR_get_error();
        goto On_CalculateSN_Error;
    }

    if (!BN_mod_mul(tmp, hash, PrivateKey, order, bn_ctx)) {    // tmp = hash * PrivateKey
        ErrorCode = ERR_get_error();
        goto On_CalculateSN_Error;
    }

    if (!BN_mod_sub(sn, r, tmp, order, bn_ctx)) {    // sn = r - tmp
        ErrorCode = ERR_get_error();
        goto On_CalculateSN_Error;
    }

    memset(lpSN, 0, 14);

    if (!BN_bn2bin(sn, lpSN)) {
        ErrorCode = ERR_get_error();
        goto On_CalculateSN_Error;
    }

On_CalculateSN_Error:
    if (bn_ctx)
        BN_CTX_free(bn_ctx);
    if (tmp)
        BN_free(tmp);
    if (sn)
        BN_free(sn);
    return ErrorCode;
}

unsigned long CalculateHash(const BIGNUM* r, const EC_KEY* ecKey, uint8_t* lpHash) {
    unsigned long ErrorCode = 0;
    EC_POINT* rG = NULL;
    BIGNUM* rG_x = NULL;
    BIGNUM* rG_y = NULL;
    uint8_t bin_rG[2][14] = {};

    rG = EC_POINT_new(EC_KEY_get0_group(ecKey));
    if (rG == NULL) {
        ErrorCode = ERR_get_error();
        goto On_CalculateHash_Error;
    }

    if (!EC_POINT_mul(EC_KEY_get0_group(ecKey), rG, r, NULL, NULL, NULL)) {
        ErrorCode = ERR_get_error();
        goto On_CalculateHash_Error;
    }

    rG_x = BN_new();
    if (rG_x == NULL) {
        ErrorCode = ERR_get_error();
        goto On_CalculateHash_Error;
    }

    rG_y = BN_new();
    if (rG_y == NULL) {
        ErrorCode = ERR_get_error();
        goto On_CalculateHash_Error;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(ecKey), rG, rG_x, rG_y, NULL)) {
        ErrorCode = ERR_get_error();
        goto On_CalculateHash_Error;
    }

    if (!BN_bn2bin(rG_x, bin_rG[0] + sizeof(bin_rG[0]) - BN_num_bytes(rG_x))) {
        ErrorCode = ERR_get_error();
        goto On_CalculateHash_Error;
    }
    if (!BN_bn2bin(rG_y, bin_rG[1] + sizeof(bin_rG[1]) - BN_num_bytes(rG_y))) {
        ErrorCode = ERR_get_error();
        goto On_CalculateHash_Error;
    }

    argon2_hash(1, 1 << 16, 1, bin_rG, sizeof(bin_rG), salt, sizeof(salt), lpHash, 5, NULL, 0, Argon2_d, ARGON2_VERSION_13);
    lpHash[5 - 1] &= 0xFC;

On_CalculateHash_Error:
    if (rG_y)
        BN_free(rG_y);
    if (rG_x)
        BN_free(rG_x);
    if (rG)
        EC_POINT_free(rG);
    return ErrorCode;
}

// Long product key has 34 chars, like "xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx"
char* GetEncodedLongProductKey(const uint8_t* lpSN, const uint8_t* lpHash) {
    uint8_t ProductKeyData[19];
    char buffer[128] = {};
    char* lpszEncodedLongProductKey = NULL;

    memcpy(ProductKeyData, lpSN, 14);
    memcpy(ProductKeyData + 14, lpHash, 5);

    size_t len = CustomBase32Encode(ProductKeyData, sizeof(ProductKeyData), buffer, sizeof(buffer) - 1);
    if (sizeof(buffer) - 1 < len) {
        // overflow
        return lpszEncodedLongProductKey;
    }

    lpszEncodedLongProductKey = malloc(34 + 1);
    if (lpszEncodedLongProductKey == NULL)
        return lpszEncodedLongProductKey;

    buffer[len - 1] = 0;    // ProductKey[len - 1] must be '0' because lpHash[4] was &-masked by 0xFC, remove it
    len--;

    {   // reverse ProductKey
        char* start = buffer;
        char* end = buffer + len - 1;
        while (start < end) {
            char tmp = *start;
            *start = *end;
            *end = tmp;
            start++;
            end--;
        }
    }

    sprintf(lpszEncodedLongProductKey,
            "%.6s-%.6s-%.6s-%.6s-%.6s",
            buffer,
            buffer + 6,
            buffer + 6 * 2,
            buffer + 6 * 3,
            buffer + 6 * 4);
    return lpszEncodedLongProductKey;
}

unsigned long PrintLongProductKey(const uint8_t* lpPrivateKey) {
    unsigned long ErrorCode = 0;
    BIGNUM* PrivateKey = NULL;
    EC_KEY* ecKey = NULL;
    BIGNUM* r = NULL;
    BIGNUM* order = NULL;
    BIGNUM* hash = NULL;

    uint8_t binSN[14] = {};
    uint8_t binHash[5] = {};

    PrivateKey = BN_bin2bn(lpPrivateKey, 112 / 8, NULL);
    if (PrivateKey == NULL) {
        ErrorCode = ERR_get_error();
        goto On_PrintLongProductKey_Error;
    }

    ecKey = EC_KEY_new_by_curve_name(NID_secp112r1);
    if (ecKey == NULL) {
        ErrorCode = ERR_get_error();
        goto On_PrintLongProductKey_Error;
    }

    if (!EC_KEY_set_private_key(ecKey, PrivateKey)) {
        ErrorCode = ERR_get_error();
        goto On_PrintLongProductKey_Error;
    }

    {   // set public key
        EC_POINT* PublicKey = EC_POINT_new(EC_KEY_get0_group(ecKey));
        if (PublicKey == NULL) {
            ErrorCode = ERR_get_error();
            goto On_PrintLongProductKey_Error;
        }

        if (!EC_POINT_mul(EC_KEY_get0_group(ecKey), PublicKey, PrivateKey, NULL, NULL, NULL)) {
            ErrorCode = ERR_get_error();
            EC_POINT_free(PublicKey);
            goto On_PrintLongProductKey_Error;
        }

        if (!EC_KEY_set_public_key(ecKey, PublicKey)) {
            ErrorCode = ERR_get_error();
            EC_POINT_free(PublicKey);
            goto On_PrintLongProductKey_Error;
        }

        EC_POINT_free(PublicKey);
    }

    ErrorCode = PrintKeyInfo(ecKey, NULL);
    if (ErrorCode)
        goto On_PrintLongProductKey_Error;

    r = BN_new();
    if (r == NULL) {
        ErrorCode = ERR_get_error();
        goto On_PrintLongProductKey_Error;
    }

    order = BN_new();
    if (order == NULL) {
        ErrorCode = ERR_get_error();
        goto On_PrintLongProductKey_Error;
    }

    if (!EC_GROUP_get_order(EC_KEY_get0_group(ecKey), order, NULL)) {
        ErrorCode = ERR_get_error();
        goto On_PrintLongProductKey_Error;
    }

    if (!BN_rand_range(r, order)) {
        ErrorCode = ERR_get_error();
        goto On_PrintLongProductKey_Error;
    }

    ErrorCode = CalculateHash(r, ecKey, binHash);
    if (ErrorCode)
        goto On_PrintLongProductKey_Error;

    hash = BN_bin2bn(binHash, sizeof(binHash), NULL);
    if (hash == NULL) {
        ErrorCode = ERR_get_error();
        goto On_PrintLongProductKey_Error;
    }

    ErrorCode = CalculateSN(r, hash, PrivateKey, order, binSN);
    if (ErrorCode)
        goto On_PrintLongProductKey_Error;

    char* key = GetEncodedLongProductKey(binSN, binHash);
    if (key != NULL) {
        printf("Long product key: %s\n", key);
        free(key);
    } else {
        printf("GetEncodedLongProductKey failed!\n");
    }

On_PrintLongProductKey_Error:
    if (hash)
        BN_free(hash);
    if (order)
        BN_free(order);
    if (r)
        BN_free(r);
    if (ecKey)
        EC_KEY_free(ecKey);
    if (PrivateKey)
        BN_free(PrivateKey);
    return ErrorCode;
}

unsigned long PrintShortProductKey(const uint8_t* binPrivateKey) {
    // todo
    return 0;
}

char ReadPrivateKey(const char* lpszFilePath, uint8_t* lpPrivateKey, size_t KeyLength) {
    int fd = open(lpszFilePath, O_RDONLY);
    if (fd == -1) {
        printf("Failed to open file. CODE: 0x%08x\n", errno);
        return 0;
    }

    if (KeyLength != read(fd, lpPrivateKey, KeyLength)) {
        printf("Failed to read file or read incompletely. CODE: 0x%08x\n", errno);
        return 0;
    }

    close(fd);
    return 1;
}

void help() {
    printf("Usage:\n");
    printf("    ./TuxeraNTFS-keygen <path to tuxera_key.bin>\n");
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        help();
        return 0;
    }

    unsigned long ErrorCode = 0;
    uint8_t binPrivateKey[14] = {};

    if (!ReadPrivateKey(argv[1], binPrivateKey, sizeof(binPrivateKey)))
        goto OnError;

    PrintLongProductKey(binPrivateKey);
OnError:
    return (int)ErrorCode;
}
