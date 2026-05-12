# crypto_aes

AES (Advanced Encryption Standard) cryptography algorithm.
Supports AES128, AES192, AES256.

## How To Use?

### 1. Copy all files in the `src` folder to your project, which are:

- crypto_aes.c
- crypto_aes.h
- rustlike_types.h

### 2. In your cryptography source code:

#### If you want to execute the AES algorithm synchronously

```c
// File: main.c

#include "crypto_aes.h"

u8 main__plain_buf[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};
u8 main__key_buf[128 / 8] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};
u8 main__cipher_buf[64];

i32 main(void) {
    crypto_aes__encrypt(
        crypto_aes__KeyLen_128, // Input, the AES key length
        crypto_aes__Mode_Ecb,   // Input, the AES mode
        main__plain_buf,        // Input, plain text buffer
        64,                     // Input, plain text buffer size in bytes
        main__key_buf,          // Input, secret key buffer
        NULL,                   // Input, the IV buffer of AES algorithm
        main__cipher_buf        // Output, the cipher text
    );
}
```

#### If you want to execute the AES algorithm asynchronously

```c
// File: myfile.c

#include "crypto_aes.h"
#include <string.h>

crypto_aes__Obj myfile__aes_obj;

// Plain text
const u8 myfile__plain_buf[] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
};

// Index for looping through the plain text
u32 myfile__index = 0;

// AES256 key
const u8 myfile__key_buf[256 / 8] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

// A big enough buffer for saving the result of AES
static u8 myfile__cipher_buf[2048];

// Your init function
void myfile__init(void) {
    crypto_aes__Obj_init(
        &myfile__aes_obj,
        crypto_aes__KeyLen_256,
        crypto_aes__Mode_Ecb,
        crypto_aes__Direction_Encrypt,
        myfile__key_buf,
        NULL,
        myfile__cipher_buf
    );
}

// Your preriodical task function, called multiple times
void myfile__task(void) {
    if (myfile__index <= 16) {
        crypto_aes__Obj_update(
            &myfile__aes_obj,
            &myfile__plain_buf[myfile__index],
            8
        );
        myfile__index += 8;
    }
}

// Your finalize function, where you want to use the AES result
void myfile__final(void) {
    u8* result_buf_mut;
    u32 result_len;

    crypto_aes__Obj_finalize(&myfile__aes_obj, &result_buf_mut, &result_len);

    // Compare the result with your expected value:
    i32 ret = memcmp(YOUR_EXPECTED_BUF, result_buf_mut, result_len * sizeof(u8));
    if (ret != 0) {
        // Compare failed handling
    }
}
```
