#include <stdint.h>
#include <stdio.h>
#include <memory.h>

#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/ec.h>

void PrintBytes(const uint8_t* bytes, size_t len) {
    if (len == 0) return;
    for (size_t i = 0; i + 1< len; ++i)
        printf("%02X ", bytes[i]);
    printf("%02X", bytes[len - 1]);
}

// recommended curve only
unsigned long PrintKeyInfo(const EC_KEY* lpcECKey, int* lperrno) {
    unsigned long ErrorCode = 0;

    const char* CurveName = NULL;

    const BIGNUM* PrivateKey = NULL;
    uint8_t* binPrivateKey = NULL;
    size_t binPrivateKeyLength = 0;

    const EC_POINT* PublicKey = NULL;
    BIGNUM* PublicKeyX = NULL;
    BIGNUM* PublicKeyY = NULL;
    uint8_t* binPublicKeyX = NULL;
    size_t binPublicKeyXLength = 0;
    uint8_t* binPublicKeyY = NULL;
    size_t binPublicKeyYLength = 0;

    // get curve name, no need to free
    int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(lpcECKey));
    CurveName = OBJ_nid2sn(nid);
    if (CurveName == NULL) {
        ErrorCode = ERR_get_error();
        goto On_PrintKeyInfo_Error;
    }

    // get private key, no need to free
    PrivateKey = EC_KEY_get0_private_key(lpcECKey);
    if (PrivateKey == NULL) {
        ErrorCode = ERR_get_error();
        goto On_PrintKeyInfo_Error;
    }

    // get public key, no need to free
    PublicKey = EC_KEY_get0_public_key(lpcECKey);
    if (PublicKey == NULL) {
        ErrorCode = ERR_get_error();
        goto On_PrintKeyInfo_Error;
    }

    // new BIGNUM, ready to receive Px
    PublicKeyX = BN_new();
    if (PublicKeyX == NULL) {
        ErrorCode = ERR_get_error();
        goto On_PrintKeyInfo_Error;
    }
    // new BIGNUM, ready to receive Py
    PublicKeyY = BN_new();
    if (PublicKeyY == NULL) {
        ErrorCode = ERR_get_error();
        goto On_PrintKeyInfo_Error;
    }

    // receive Px and Py
    if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(lpcECKey),
                                             PublicKey,
                                             PublicKeyX,
                                             PublicKeyY,
                                             NULL)) {
        ErrorCode = ERR_get_error();
        goto On_PrintKeyInfo_Error;
    }

    // determine binPrivateKey length
    binPrivateKeyLength = (size_t)BN_num_bytes(PrivateKey);
    if (binPrivateKeyLength == 0) {
        ErrorCode = ERR_get_error();
        goto On_PrintKeyInfo_Error;
    }

    // alloc binPrivateKeyX
    binPrivateKey = malloc(binPrivateKeyLength);
    if (binPrivateKey == NULL) {
        if (lperrno) *lperrno = errno;
        goto On_PrintKeyInfo_Error;
    }

    // determine binPublicKeyX length
    binPublicKeyXLength = (size_t)BN_num_bytes(PublicKeyX);
    if (binPublicKeyXLength == 0) {
        ErrorCode = ERR_get_error();
        goto On_PrintKeyInfo_Error;
    }

    // alloc binPublicKeyX
    binPublicKeyX = malloc(binPublicKeyXLength);
    if (binPublicKeyX == NULL) {
        if (lperrno) *lperrno = errno;
        goto On_PrintKeyInfo_Error;
    }

    // determine binPublicKeyY length
    binPublicKeyYLength = (size_t)BN_num_bytes(PublicKeyY);
    if (binPublicKeyYLength == 0) {
        ErrorCode = ERR_get_error();
        goto On_PrintKeyInfo_Error;
    }

    // alloc binPrivateKeyY
    binPublicKeyY = malloc(binPublicKeyYLength);
    if (binPublicKeyY == NULL) {
        if (lperrno) *lperrno = errno;
        goto On_PrintKeyInfo_Error;
    }

    // write to binPrivateKey
    if (!BN_bn2bin(PrivateKey, binPrivateKey)) {
        ErrorCode = ERR_get_error();
        goto On_PrintKeyInfo_Error;
    }
    // write to binPublicKeyX
    if (!BN_bn2bin(PublicKeyX, binPublicKeyX)) {
        ErrorCode = ERR_get_error();
        goto On_PrintKeyInfo_Error;
    }
    // write to binPublicKeyY
    if (!BN_bn2bin(PublicKeyY, binPublicKeyY)) {
        ErrorCode = ERR_get_error();
        goto On_PrintKeyInfo_Error;
    }

    printf("-----%s Private Key-----\n", CurveName);
    printf("Bin: ");
    PrintBytes(binPrivateKey, binPrivateKeyLength);
    printf("\n\n");

    printf("-----%s Public Key-----\n", CurveName);
    printf("Bin: X = ");
    PrintBytes(binPublicKeyX, binPublicKeyXLength);
    printf("\n");

    printf("Bin: Y = ");
    PrintBytes(binPublicKeyY, binPublicKeyYLength);
    printf("\n\n");

On_PrintKeyInfo_Error:
    if (binPublicKeyY)
        free(binPublicKeyY);
    if (binPublicKeyX)
        free(binPublicKeyX);
    if (binPrivateKey)
        free(binPrivateKey);
    if (PublicKeyY)
        BN_free(PublicKeyY);
    if (PublicKeyX)
        BN_free(PublicKeyX);
    errno = 0;
    return ErrorCode;
}

size_t CustomBase32Encode(const void* __restrict src, size_t len,
                          char* __restrict out_buf, size_t out_len) {
    static const char SubstitutionTable[33] = "0123456789ACDEFGHJKLMNPQRTUVWXYZ";

    if (len == 0)
        return 0;

    size_t minimum_buf_len = (8 * len + 4) / 5;
    if (out_len < minimum_buf_len)
        return minimum_buf_len;

    const uint8_t* src_bytes = src;
    size_t read_ptr = 0;
    int read_bits = 0;
    for (size_t i = 0; i < minimum_buf_len && read_ptr < len; ++i) {
        switch (read_bits) {
            case 0:
            case 1:
            case 2:
                out_buf[i] = SubstitutionTable[(src_bytes[read_ptr] >> (3 - read_bits)) % 32];
                read_bits += 5;
                break;
            case 3:
                out_buf[i] = SubstitutionTable[src_bytes[read_ptr] % 32];
                read_bits = 0;
                read_ptr++;
                break;
            case 4:
            case 5:
            case 6:
            case 7: {
                uint8_t temp = src_bytes[read_ptr++];
                temp &= ((1 << (8 - read_bits)) - 1);
                if (read_ptr < len) {
                    temp |= src_bytes[read_ptr] >> (8 - (5 - (8 - read_bits))) << (8 - read_bits);
                    out_buf[i] = SubstitutionTable[temp];
                    read_bits = 5 - (8 - read_bits);
                } else {
                    out_buf[i] = SubstitutionTable[temp];
                }
            }
                break;
            default:
                break;
        }
    }

    return minimum_buf_len;
}
