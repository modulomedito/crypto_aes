//==================================================================================================
/// @file       crypto_aes.h
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      AES algorithm
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==================================================================================================
//==================================================================================================
// GUARD START
//==================================================================================================
#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H
#ifdef __cplusplus
extern "C" {
#endif

//==================================================================================================
// INCLUDE
//==================================================================================================
#include "rustlike_types.h"
#include <stddef.h>
#include <stdint.h>

//==================================================================================================
// PUBLIC TYPEDEF
//==================================================================================================

//==================================================================================================
// PUBLIC DEFINE
//==================================================================================================
/// Block length in bytes - AES is 128b block only
#define CRYPTO_AES_M_BLOCK_U8_SIZE (16)

//==================================================================================================
// PUBLIC ENUM
//==================================================================================================
typedef enum {
    crypto_aes_m_KeyLen_128,
    crypto_aes_m_KeyLen_192,
    crypto_aes_m_KeyLen_256,
} crypto_aes_m_KeyLen;

typedef enum {
    crypto_aes_m_Mode_Ecb,
    crypto_aes_m_Mode_Cbc,
    crypto_aes_m_Mode_Ctr,
} crypto_aes_m_Mode;

typedef enum {
    crypto_aes_m_Direction_Encrypt,
    crypto_aes_m_Direction_Decrypt,
} crypto_aes_m_Direction;

//==================================================================================================
// PUBLIC STRUCT
//==================================================================================================
typedef struct {
    /// Use the maxium key exp size for compatibility
    /// - AES128, key len = 16, key exp size = 176
    /// - AES192, key len = 24, key exp size = 208
    /// - AES256, key len = 32, key exp size = 240
    u8 round_key_buf[240];
    u8 iv_buf[CRYPTO_AES_M_BLOCK_U8_SIZE];
} crypto_aes_m_Ctx;

typedef struct {
    crypto_aes_m_Ctx ctx;
    crypto_aes_m_KeyLen keylen;
    crypto_aes_m_Mode mode;
    crypto_aes_m_Direction dir;
    const u8* key_ref;
    const u8* iv_ref;
    u8* out_mut;
    u32 key_u32_num;
    u32 round_num;
    u32 buf_len;
    u8 buf[CRYPTO_AES_M_BLOCK_U8_SIZE];
} crypto_aes_m_Obj;

//==================================================================================================
// PUBLIC UNION
//==================================================================================================

//==================================================================================================
// PUBLIC VARIABLE DECLARATION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DECLARATION
//==================================================================================================
extern i32 crypto_aes_m_encrypt(
    crypto_aes_m_KeyLen keylen,
    crypto_aes_m_Mode mode,
    const u8* in_ref,
    u32 in_len,
    const u8* key_ref,
    const u8* iv_ref,
    u8* out_mut
);
extern i32 crypto_aes_m_decrypt(
    crypto_aes_m_KeyLen keylen,
    crypto_aes_m_Mode mode,
    const u8* in_ref,
    u32 in_len,
    const u8* key_ref,
    const u8* iv_ref,
    u8* out_mut
);

extern i32 crypto_aes_m_Obj_init(
    crypto_aes_m_Obj* self,
    crypto_aes_m_KeyLen keylen,
    crypto_aes_m_Mode mode,
    crypto_aes_m_Direction dir,
    const u8* key_ref,
    const u8* iv_ref,
    u8* out_mut
);
extern i32 crypto_aes_m_Obj_update(crypto_aes_m_Obj* self, const u8* in_ref, u32 in_len);
extern i32 crypto_aes_m_Obj_finalize(crypto_aes_m_Obj* self);

//==================================================================================================
// GUARD END
//==================================================================================================
#ifdef __cplusplus
}
#endif
#endif // #ifndef CRYPTO_AES_H
