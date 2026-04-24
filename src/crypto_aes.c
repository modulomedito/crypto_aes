//==================================================================================================
/// @file       crypto_aes.c
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      AES algorithm
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==================================================================================================
//==================================================================================================
// INCLUDE
//==================================================================================================
#include "crypto_aes.h"
#include <string.h>

//==================================================================================================
// IMPORTED SWITCH CHECK
//==================================================================================================

//==================================================================================================
// PRIVATE DEFINE
//==================================================================================================
/// The number of columns comprising a state in AES. This is a constant in AES. Value = 4
#define CRYPTO_AES__NB (4)

//==================================================================================================
// PRIVATE TYPEDEF
//==================================================================================================

//==================================================================================================
// PRIVATE ENUM
//==================================================================================================

//==================================================================================================
// PRIVATE STRUCT
//==================================================================================================
typedef struct {
    u8 col[4];
} crypto_aes__StateRow;

typedef struct {
    crypto_aes__StateRow row[4];
} crypto_aes__State;

//==================================================================================================
// PRIVATE UNION
//==================================================================================================

//==================================================================================================
// PRIVATE FUNCTION DECLARATION
//==================================================================================================
static void crypto_aes__sub_bytes(crypto_aes__State* state_mut);
static void crypto_aes__shift_rows(crypto_aes__State* state_mut);
static void crypto_aes__mix_columns(crypto_aes__State* state_mut);
static void crypto_aes__inv_sub_bytes(crypto_aes__State* state_mut);
static void crypto_aes__inv_mix_columns(crypto_aes__State* state_mut);
static void crypto_aes__inv_shift_rows(crypto_aes__State* state_mut);
static void crypto_aes__Obj_cipher(crypto_aes__Obj* self, crypto_aes__State* state_mut);
static void crypto_aes__Obj_inv_cipher(crypto_aes__Obj* self, crypto_aes__State* state_mut);
static void crypto_aes__xor_with_iv(u8* buf_mut, const u8* iv_ref);
static u8 crypto_aes__multiply(u8 x, u8 y);
static u8 crypto_aes__xtime(u8 x);
static void crypto_aes__Obj_add_round_key(
    crypto_aes__Obj* self,
    u8 round,
    crypto_aes__State* state_mut
);

static void crypto_aes__Obj_key_expansion(crypto_aes__Obj* self);
static void crypto_aes__Obj_ecb_encrypt(crypto_aes__Obj* self);
static void crypto_aes__Obj_ecb_decrypt(crypto_aes__Obj* self, u8* buf_mut);
static void crypto_aes__Obj_cbc_encrypt(crypto_aes__Obj* self);
static void crypto_aes__Obj_cbc_decrypt(crypto_aes__Obj* self, u8* buf_mut);
static void crypto_aes__Obj_ctr_xcrypt(crypto_aes__Obj* self);

//==================================================================================================
// PRIVATE VARIABLE DEFINITION
//==================================================================================================
static const u8 crypto_aes__sbox_tbl[256] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const u8 crypto_aes__rsbox_tbl[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const u8 crypto_aes__rcon_tbl[11] =
    {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

//==================================================================================================
// PUBLIC VARIABLE DEFINITION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DEFINITION
//==================================================================================================
i32 crypto_aes__encrypt(
    crypto_aes__KeyLen keylen,
    crypto_aes__Mode mode,
    const u8* in_ref,
    u32 in_len,
    const u8* key_ref,
    const u8* iv_ref,
    u8* out_mut
) {
    crypto_aes__Obj obj;
    i32 ret = crypto_aes__Obj_init(
        &obj,
        keylen,
        mode,
        crypto_aes__Direction_Encrypt,
        key_ref,
        iv_ref,
        out_mut
    );
    if (ret != 0) {
        return ret;
    }

    ret = crypto_aes__Obj_update(&obj, in_ref, in_len);
    if (ret != 0) {
        crypto_aes__Obj_finalize(&obj);
        return ret;
    }

    return crypto_aes__Obj_finalize(&obj);
}

i32 crypto_aes__decrypt(
    crypto_aes__KeyLen keylen,
    crypto_aes__Mode mode,
    const u8* in_ref,
    u32 in_len,
    const u8* key_ref,
    const u8* iv_ref,
    u8* out_mut
) {
    crypto_aes__Obj obj;
    i32 ret = crypto_aes__Obj_init(
        &obj,
        keylen,
        mode,
        crypto_aes__Direction_Decrypt,
        key_ref,
        iv_ref,
        out_mut
    );
    if (ret != 0) {
        return ret;
    }

    ret = crypto_aes__Obj_update(&obj, in_ref, in_len);
    if (ret != 0) {
        crypto_aes__Obj_finalize(&obj);
        return ret;
    }

    return crypto_aes__Obj_finalize(&obj);
}

i32 crypto_aes__Obj_init(
    crypto_aes__Obj* self,
    crypto_aes__KeyLen keylen,
    crypto_aes__Mode mode,
    crypto_aes__Direction dir,
    const u8* key_ref,
    const u8* iv_ref,
    u8* out_mut
) {
    if ((keylen <= crypto_aes__KeyLen_Min) || (keylen >= crypto_aes__KeyLen_Max)) {
        return -1;
    }
    if ((mode <= crypto_aes__Mode_Min) || (mode >= crypto_aes__Mode_Max)) {
        return -1;
    }
    switch (mode) {
    case crypto_aes__Mode_Cbc:
    case crypto_aes__Mode_Ctr:
        if (iv_ref == NULL) {
            return -1;
        }
        self->iv_ref = iv_ref;
        memcpy(self->ctx.iv_buf, iv_ref, CRYPTO_AES__BLOCK_U8_SIZE);
        break;
    }

    self->key_ref = key_ref;
    self->out_mut = out_mut;
    self->mode = mode;
    self->dir = dir;
    self->keylen = keylen;
    self->buf_len = 0;
    memset(self->buf, 0, CRYPTO_AES__BLOCK_U8_SIZE);

    switch (keylen) {
    case crypto_aes__KeyLen_128:
        self->key_u32_num = 4;
        self->round_num = 10;
        break;
    case crypto_aes__KeyLen_192:
        self->key_u32_num = 6;
        self->round_num = 12;
        break;
    case crypto_aes__KeyLen_256:
        self->key_u32_num = 8;
        self->round_num = 14;
        break;
    }

    crypto_aes__Obj_key_expansion(self);

    return 0;
}

i32 crypto_aes__Obj_update(crypto_aes__Obj* self, const u8* in_ref, u32 in_len) {
    u32 in_pos = 0;

    if (self == NULL || in_ref == NULL || self->out_mut == NULL) {
        return -1;
    }

    if (in_len == 0) {
        return 0;
    }

    while (in_pos < in_len) {
        // For ECB/CBC Decryption, we delay processing a full 16-byte block
        // until we know it's not the last block (i.e. more data is coming).
        if ((self->mode == crypto_aes__Mode_Ecb || self->mode == crypto_aes__Mode_Cbc) &&
            self->dir == crypto_aes__Direction_Decrypt) {

            if (self->buf_len == CRYPTO_AES__BLOCK_U8_SIZE) {
                memcpy(self->out_mut, self->buf, CRYPTO_AES__BLOCK_U8_SIZE);
                if (self->mode == crypto_aes__Mode_Ecb) {
                    crypto_aes__Obj_ecb_decrypt(self, self->out_mut);
                } else {
                    crypto_aes__Obj_cbc_decrypt(self, self->out_mut);
                }
                self->out_mut += CRYPTO_AES__BLOCK_U8_SIZE;
                self->buf_len = 0;
            }
        }

        u32 space = CRYPTO_AES__BLOCK_U8_SIZE - self->buf_len;
        u32 copy_len = (in_len - in_pos) < space ? (in_len - in_pos) : space;
        memcpy(self->buf + self->buf_len, in_ref + in_pos, copy_len);
        self->buf_len += copy_len;
        in_pos += copy_len;

        // For Encryption and CTR mode, process as soon as we have 16 bytes
        if (self->buf_len == CRYPTO_AES__BLOCK_U8_SIZE) {
            if ((self->mode == crypto_aes__Mode_Ecb || self->mode == crypto_aes__Mode_Cbc) &&
                self->dir == crypto_aes__Direction_Decrypt) {
                // Skip processing here, will process in the next iteration or finalize
                continue;
            }

            memcpy(self->out_mut, self->buf, CRYPTO_AES__BLOCK_U8_SIZE);
            if (self->mode == crypto_aes__Mode_Ecb) {
                crypto_aes__Obj_ecb_encrypt(self);
            } else if (self->mode == crypto_aes__Mode_Cbc) {
                crypto_aes__Obj_cbc_encrypt(self);
            } else if (self->mode == crypto_aes__Mode_Ctr) {
                crypto_aes__Obj_ctr_xcrypt(self);
            }
            self->out_mut += CRYPTO_AES__BLOCK_U8_SIZE;
            self->buf_len = 0;
        }
    }

    return 0;
}

i32 crypto_aes__Obj_finalize(crypto_aes__Obj* self) {
    if (self == NULL) {
        return -1;
    }

    i32 ret = 0;

    if (self->mode == crypto_aes__Mode_Ecb || self->mode == crypto_aes__Mode_Cbc) {
        if (self->dir == crypto_aes__Direction_Encrypt) {
            // PKCS#7 Padding
            u8 pad_val = CRYPTO_AES__BLOCK_U8_SIZE - self->buf_len;
            memset(self->buf + self->buf_len, pad_val, pad_val);
            memcpy(self->out_mut, self->buf, CRYPTO_AES__BLOCK_U8_SIZE);
            if (self->mode == crypto_aes__Mode_Ecb) {
                crypto_aes__Obj_ecb_encrypt(self);
            } else {
                crypto_aes__Obj_cbc_encrypt(self);
            }
            self->out_mut += CRYPTO_AES__BLOCK_U8_SIZE;
        } else {
            // PKCS#7 Unpadding
            if (self->buf_len != CRYPTO_AES__BLOCK_U8_SIZE) {
                ret = -1; // Error: Ciphertext not a multiple of block size
                goto cleanup;
            }
            u8 temp[CRYPTO_AES__BLOCK_U8_SIZE];
            memcpy(temp, self->buf, CRYPTO_AES__BLOCK_U8_SIZE);
            if (self->mode == crypto_aes__Mode_Ecb) {
                crypto_aes__Obj_ecb_decrypt(self, temp);
            } else {
                crypto_aes__Obj_cbc_decrypt(self, temp);
            }

            u8 pad_val = temp[CRYPTO_AES__BLOCK_U8_SIZE - 1];
            if (pad_val < 1 || pad_val > CRYPTO_AES__BLOCK_U8_SIZE) {
                ret = -1; // Padding error
                goto cleanup;
            }

            for (u8 i = CRYPTO_AES__BLOCK_U8_SIZE - pad_val; i < CRYPTO_AES__BLOCK_U8_SIZE; ++i) {
                if (temp[i] != pad_val) {
                    ret = -1; // Padding error
                    goto cleanup;
                }
            }

            u32 out_len = CRYPTO_AES__BLOCK_U8_SIZE - pad_val;
            memcpy(self->out_mut, temp, out_len);
            self->out_mut += out_len;
        }
    } else if (self->mode == crypto_aes__Mode_Ctr) {
        if (self->buf_len > 0) {
            memcpy(self->out_mut, self->buf, self->buf_len);
            crypto_aes__Obj_ctr_xcrypt(self);
            self->out_mut += self->buf_len;
        }
    }

cleanup:
    // Securely wipe sensitive key material and internal state from memory
    memset(self, 0, sizeof(crypto_aes__Obj));
    return ret;
}

static void crypto_aes__Obj_cbc_encrypt(crypto_aes__Obj* self) {
    u8* buf_mut = self->out_mut;
    u8* iv_mut = self->ctx.iv_buf;

    crypto_aes__xor_with_iv(buf_mut, iv_mut);
    crypto_aes__Obj_cipher(self, (crypto_aes__State*)buf_mut);
    iv_mut = buf_mut;

    memcpy(self->ctx.iv_buf, iv_mut, CRYPTO_AES__BLOCK_U8_SIZE);
}

static void crypto_aes__Obj_cbc_decrypt(crypto_aes__Obj* self, u8* buf_mut) {
    u32 i;
    u8 store_next_iv_buf[CRYPTO_AES__BLOCK_U8_SIZE];
    for (i = 0; i < self->buf_len; i += CRYPTO_AES__BLOCK_U8_SIZE) {
        memcpy(store_next_iv_buf, buf_mut, CRYPTO_AES__BLOCK_U8_SIZE);
        crypto_aes__Obj_inv_cipher(self, (crypto_aes__State*)buf_mut);
        crypto_aes__xor_with_iv(buf_mut, self->ctx.iv_buf);
        memcpy(self->ctx.iv_buf, store_next_iv_buf, CRYPTO_AES__BLOCK_U8_SIZE);
        buf_mut += CRYPTO_AES__BLOCK_U8_SIZE;
    }
}

static void crypto_aes__Obj_ctr_xcrypt(crypto_aes__Obj* self) {
    u8 buffer[CRYPTO_AES__BLOCK_U8_SIZE];

    u32 i;
    i32 bi;
    for (i = 0, bi = CRYPTO_AES__BLOCK_U8_SIZE; i < self->buf_len; ++i, ++bi) {
        if (bi == CRYPTO_AES__BLOCK_U8_SIZE) {
            memcpy(buffer, self->ctx.iv_buf, CRYPTO_AES__BLOCK_U8_SIZE);
            crypto_aes__Obj_cipher(self, (crypto_aes__State*)buffer);

            // Increment Iv and handle overflow
            for (bi = (CRYPTO_AES__BLOCK_U8_SIZE - 1); bi >= 0; --bi) {
                // inc will overflow
                if (self->ctx.iv_buf[bi] == 255) {
                    self->ctx.iv_buf[bi] = 0;
                    continue;
                }
                self->ctx.iv_buf[bi] += 1;
                break;
            }
            bi = 0;
        }

        self->out_mut[i] = (self->out_mut[i] ^ buffer[bi]);
    }
}

//==================================================================================================
// PRIVATE FUNCTION DEFINITION
//==================================================================================================
static void crypto_aes__Obj_ecb_encrypt(crypto_aes__Obj* self) {
    crypto_aes__Obj_cipher(self, (crypto_aes__State*)self->out_mut);
}

static void crypto_aes__inv_sub_bytes(crypto_aes__State* state_mut) {
    u8 i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state_mut->row[j].col[i] = crypto_aes__rsbox_tbl[state_mut->row[j].col[i]];
        }
    }
}

static void crypto_aes__xor_with_iv(u8* buf_mut, const u8* iv_ref) {
    u8 i;
    // The block in AES is always 128bit no matter the key size
    for (i = 0; i < CRYPTO_AES__BLOCK_U8_SIZE; ++i) {
        buf_mut[i] ^= iv_ref[i];
    }
}

static void crypto_aes__Obj_add_round_key(
    crypto_aes__Obj* self,
    u8 round,
    crypto_aes__State* state_mut
) {
    u8 i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state_mut->row[i].col[j] ^= self->ctx.round_key_buf[(round * 16) + (i * 4) + j];
        }
    }
}

static void crypto_aes__sub_bytes(crypto_aes__State* state_mut) {
    u8 i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state_mut->row[j].col[i] = crypto_aes__sbox_tbl[state_mut->row[j].col[i]];
        }
    }
}

static void crypto_aes__shift_rows(crypto_aes__State* state_mut) {
    u8 temp;

    // Rotate first row 1 columns to left
    temp = state_mut->row[0].col[1];
    state_mut->row[0].col[1] = state_mut->row[1].col[1];
    state_mut->row[1].col[1] = state_mut->row[2].col[1];
    state_mut->row[2].col[1] = state_mut->row[3].col[1];
    state_mut->row[3].col[1] = temp;

    // Rotate second row 2 columns to left
    temp = state_mut->row[0].col[2];
    state_mut->row[0].col[2] = state_mut->row[2].col[2];
    state_mut->row[2].col[2] = temp;

    temp = state_mut->row[1].col[2];
    state_mut->row[1].col[2] = state_mut->row[3].col[2];
    state_mut->row[3].col[2] = temp;

    // Rotate third row 3 columns to left
    temp = state_mut->row[0].col[3];
    state_mut->row[0].col[3] = state_mut->row[3].col[3];
    state_mut->row[3].col[3] = state_mut->row[2].col[3];
    state_mut->row[2].col[3] = state_mut->row[1].col[3];
    state_mut->row[1].col[3] = temp;
}

static u8 crypto_aes__xtime(u8 x) {
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void crypto_aes__mix_columns(crypto_aes__State* state_mut) {
    u8 i;
    u8 tmp;
    u8 tm;
    u8 t;
    for (i = 0; i < 4; ++i) {
        t = state_mut->row[i].col[0];
        tmp = state_mut->row[i].col[0] ^ //
              state_mut->row[i].col[1] ^ //
              state_mut->row[i].col[2] ^ //
              state_mut->row[i].col[3];

        tm = state_mut->row[i].col[0] ^ state_mut->row[i].col[1];
        tm = crypto_aes__xtime(tm);
        state_mut->row[i].col[0] ^= tm ^ tmp;

        tm = state_mut->row[i].col[1] ^ state_mut->row[i].col[2];
        tm = crypto_aes__xtime(tm);
        state_mut->row[i].col[1] ^= tm ^ tmp;

        tm = state_mut->row[i].col[2] ^ state_mut->row[i].col[3];
        tm = crypto_aes__xtime(tm);
        state_mut->row[i].col[2] ^= tm ^ tmp;

        tm = state_mut->row[i].col[3] ^ t;
        tm = crypto_aes__xtime(tm);
        state_mut->row[i].col[3] ^= tm ^ tmp;
    }
}

static u8 crypto_aes__multiply(u8 x, u8 y) {
    u8 xtime_x;
    u8 result = ((y & 1) * x);

    xtime_x = crypto_aes__xtime(x);
    result ^= ((y >> 1 & 1) * xtime_x);

    xtime_x = crypto_aes__xtime(x);
    xtime_x = crypto_aes__xtime(xtime_x);
    result ^= ((y >> 2 & 1) * xtime_x);

    xtime_x = crypto_aes__xtime(x);
    xtime_x = crypto_aes__xtime(xtime_x);
    xtime_x = crypto_aes__xtime(xtime_x);
    result ^= ((y >> 3 & 1) * xtime_x);

    xtime_x = crypto_aes__xtime(x);
    xtime_x = crypto_aes__xtime(xtime_x);
    xtime_x = crypto_aes__xtime(xtime_x);
    xtime_x = crypto_aes__xtime(xtime_x);
    result ^= ((y >> 4 & 1) * xtime_x);

    return result;
}

static void crypto_aes__inv_mix_columns(crypto_aes__State* state_mut) {
    i32 i;
    u8 a, b, c, d;

    for (i = 0; i < 4; ++i) {
        a = state_mut->row[i].col[0];
        b = state_mut->row[i].col[1];
        c = state_mut->row[i].col[2];
        d = state_mut->row[i].col[3];

        state_mut->row[i].col[0] = crypto_aes__multiply(a, 0x0e) ^ crypto_aes__multiply(b, 0x0b) ^
                                   crypto_aes__multiply(c, 0x0d) ^ crypto_aes__multiply(d, 0x09);
        state_mut->row[i].col[1] = crypto_aes__multiply(a, 0x09) ^ crypto_aes__multiply(b, 0x0e) ^
                                   crypto_aes__multiply(c, 0x0b) ^ crypto_aes__multiply(d, 0x0d);
        state_mut->row[i].col[2] = crypto_aes__multiply(a, 0x0d) ^ crypto_aes__multiply(b, 0x09) ^
                                   crypto_aes__multiply(c, 0x0e) ^ crypto_aes__multiply(d, 0x0b);
        state_mut->row[i].col[3] = crypto_aes__multiply(a, 0x0b) ^ crypto_aes__multiply(b, 0x0d) ^
                                   crypto_aes__multiply(c, 0x09) ^ crypto_aes__multiply(d, 0x0e);
    }
}

static void crypto_aes__inv_shift_rows(crypto_aes__State* state_mut) {
    u8 temp;

    // Rotate first row 1 columns to right
    temp = state_mut->row[3].col[1];
    state_mut->row[3].col[1] = state_mut->row[2].col[1];
    state_mut->row[2].col[1] = state_mut->row[1].col[1];
    state_mut->row[1].col[1] = state_mut->row[0].col[1];
    state_mut->row[0].col[1] = temp;

    // Rotate second row 2 columns to right
    temp = state_mut->row[0].col[2];
    state_mut->row[0].col[2] = state_mut->row[2].col[2];
    state_mut->row[2].col[2] = temp;

    temp = state_mut->row[1].col[2];
    state_mut->row[1].col[2] = state_mut->row[3].col[2];
    state_mut->row[3].col[2] = temp;

    // Rotate third row 3 columns to right
    temp = state_mut->row[0].col[3];
    state_mut->row[0].col[3] = state_mut->row[1].col[3];
    state_mut->row[1].col[3] = state_mut->row[2].col[3];
    state_mut->row[2].col[3] = state_mut->row[3].col[3];
    state_mut->row[3].col[3] = temp;
}

// crypto_aes__Obj_cipher is the main function that encrypts the PlainText.
static void crypto_aes__Obj_cipher(crypto_aes__Obj* self, crypto_aes__State* state_mut) {
    u8 round = 0;

    // Add the First round key to the state before starting the rounds.
    crypto_aes__Obj_add_round_key(self, 0, state_mut);

    for (round = 1;; ++round) {
        crypto_aes__sub_bytes(state_mut);
        crypto_aes__shift_rows(state_mut);
        if (round == self->round_num) {
            break;
        }
        crypto_aes__mix_columns(state_mut);
        crypto_aes__Obj_add_round_key(self, round, state_mut);
    }
    // Add round key to last round
    crypto_aes__Obj_add_round_key(self, self->round_num, state_mut);
}

static void crypto_aes__Obj_inv_cipher(crypto_aes__Obj* self, crypto_aes__State* state_mut) {
    u8 round = 0;

    // Add the First round key to the state before starting the rounds.
    crypto_aes__Obj_add_round_key(self, self->round_num, state_mut);

    for (round = (self->round_num - 1);; --round) {
        crypto_aes__inv_shift_rows(state_mut);
        crypto_aes__inv_sub_bytes(state_mut);
        crypto_aes__Obj_add_round_key(self, round, state_mut);
        if (round == 0) {
            break;
        }
        crypto_aes__inv_mix_columns(state_mut);
    }
}

static void crypto_aes__Obj_key_expansion(crypto_aes__Obj* self) {
    u32 i, j, k;
    u8 tempa[4];
    u8* round_key_mut = self->ctx.round_key_buf;
    const u8* key_ref = self->key_ref;
    u32 key_u32_num = self->key_u32_num;
    u32 round_num = self->round_num;

    // The first round key is the key itself.
    for (i = 0; i < key_u32_num; ++i) {
        round_key_mut[(i * 4) + 0] = key_ref[(i * 4) + 0];
        round_key_mut[(i * 4) + 1] = key_ref[(i * 4) + 1];
        round_key_mut[(i * 4) + 2] = key_ref[(i * 4) + 2];
        round_key_mut[(i * 4) + 3] = key_ref[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for (i = key_u32_num; i < CRYPTO_AES__NB * (round_num + 1); ++i) {
        {
            k = (i - 1) * 4;
            tempa[0] = round_key_mut[k + 0];
            tempa[1] = round_key_mut[k + 1];
            tempa[2] = round_key_mut[k + 2];
            tempa[3] = round_key_mut[k + 3];
        }

        if (i % key_u32_num == 0) {
            const u8 u8tmp = tempa[0];
            tempa[0] = tempa[1];
            tempa[1] = tempa[2];
            tempa[2] = tempa[3];
            tempa[3] = u8tmp;

            tempa[0] = crypto_aes__sbox_tbl[tempa[0]];
            tempa[1] = crypto_aes__sbox_tbl[tempa[1]];
            tempa[2] = crypto_aes__sbox_tbl[tempa[2]];
            tempa[3] = crypto_aes__sbox_tbl[tempa[3]];

            tempa[0] = tempa[0] ^ crypto_aes__rcon_tbl[i / key_u32_num];
        }

        // AES256, 256/32 = 8
        if (key_u32_num == 8) {
            if (i % key_u32_num == 4) {
                tempa[0] = crypto_aes__sbox_tbl[tempa[0]];
                tempa[1] = crypto_aes__sbox_tbl[tempa[1]];
                tempa[2] = crypto_aes__sbox_tbl[tempa[2]];
                tempa[3] = crypto_aes__sbox_tbl[tempa[3]];
            }
        }

        j = i * 4;
        k = (i - key_u32_num) * 4;
        round_key_mut[j + 0] = round_key_mut[k + 0] ^ tempa[0];
        round_key_mut[j + 1] = round_key_mut[k + 1] ^ tempa[1];
        round_key_mut[j + 2] = round_key_mut[k + 2] ^ tempa[2];
        round_key_mut[j + 3] = round_key_mut[k + 3] ^ tempa[3];
    }
}

static void crypto_aes__Obj_ecb_decrypt(crypto_aes__Obj* self, u8* buf_mut) {
    crypto_aes__Obj_inv_cipher(self, (crypto_aes__State*)buf_mut);
}

//==================================================================================================
// TEST
//==================================================================================================
