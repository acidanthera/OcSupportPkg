/** @file

OcCryptoLib

Copyright (c) 2018, savvas

All rights reserved.

This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef OC_CRYPTO_LIB_H
#define OC_CRYPTO_LIB_H

//
// RSA signatures sizes
//
#define CONFIG_RSA2048_NUM_BYTES 256
#define CONFIG_RSA4096_NUM_BYTES 512
#define CONFIG_RSA8192_NUM_BYTES 1024

//
// Default to 128-bit key length for AES.
//
#ifndef CONFIG_AES_KEY_SIZE
#define CONFIG_AES_KEY_SIZE 16
#endif

//
// Digest sizes.
//
#define MD5_DIGEST_SIZE     16
#define SHA1_DIGEST_SIZE    20
#define SHA256_DIGEST_SIZE  32
#define SHA384_DIGEST_SIZE  48
#define SHA512_DIGEST_SIZE  64

//
// Block sizes.
//
#define SHA256_BLOCK_SIZE  64
#define SHA512_BLOCK_SIZE  128
#define SHA384_BLOCK_SIZE  SHA512_BLOCK_SIZE

//
// Derived parameters.
//
#define AES_BLOCK_SIZE 16

//
// Support all AES key sizes.
//
#if CONFIG_AES_KEY_SIZE == 32
#define AES_KEY_EXP_SIZE 240
#elif CONFIG_AES_KEY_SIZE == 24
#define AES_KEY_EXP_SIZE 208
#elif CONFIG_AES_KEY_SIZE == 16
#define AES_KEY_EXP_SIZE 176
#else
#error "Only AES-128, AES-192, and AES-256 are supported!"
#endif


//
// Possible digest types supported by OcCryptoLib
// for RSA verification
//
typedef enum RSA_DIGEST_TYPES_ {
  RSA_DIGEST_TYPE_SHA256,
  RSA_DIGEST_TYPE_SHA512,
  RSA_DIGEST_TYPE_SHA384,
} RSA_DIGEST_TYPES;

//
// Possible RSA algorithm types supported by OcCryptoLib
// for RSA digital signature verification
//
typedef enum RSA_ALGORITHM_TYPES_ {
  RSA_ALGORITHM_TYPE_NONE,
  RSA_ALGORITHM_TYPE_SHA256_RSA2048,
  RSA_ALGORITHM_TYPE_SHA256_RSA4096,
  RSA_ALGORITHM_TYPE_SHA256_RSA8192,
  RSA_ALGORITHM_TYPE_SHA512_RSA2048,
  RSA_ALGORITHM_TYPE_SHA512_RSA4096,
  RSA_ALGORITHM_TYPE_SHA512_RSA8192,
  RSA_ALGORITHM_TYPE_SHA384_RSA2048,
  RSA_ALGORITHM_TYPE_SHA384_RSA4096,
  RSA_ALGORITHM_TYPE_SHA384_RSA8192,
  RSA_ALGORITHM_NUM_TYPES
} RSA_ALGORITHM_TYPES;

//
// Holds algorithm-specific data
// The Padding is needed by RsaVerify
//
typedef struct RSA_ALGORITHM_DATA_ {
  CONST UINT8  Padding;
  UINTN        PaddingLen;
  UINTN        HashLen;
} RSA_ALGORITHM_DATA;

#pragma pack(push, 1)

/**
  The header for a serialized RSA public key.
   
  Following this header is key_num_bits bits of N.
  KeyNumBits of Rr. Both values are stored with most
  significant bit first. Each serialized number takes up
  KeyNumBits/8 bytes.

 */
typedef struct RSA_PUBLIC_KEY_HEADER_ {
  UINT32  KeyNumBits;
  UINT32  N0Inv;
} RSA_PUBLIC_KEY_HEADER;

#pragma pack(pop)


#pragma pack(push, 1)

typedef struct RSA_PUBLIC_KEY_ {
  //
  // Length of N[] in number of UINT32
  //
  UINT32  Size;
  //
  // -1 / n[0] mod 2^32
  //
  UINT32  N0Inv;
  //
  // Modulus as array (host-byte order)
  //
  UINT32  *N;
  //
  // R^2 as array (host-byte order)
  //
  UINT32  *Rr;
} RSA_PUBLIC_KEY;

#pragma pack(pop)

typedef struct AES_CONTEXT_ {
  UINT8 RoundKey[AES_KEY_EXP_SIZE];
  UINT8 Iv[AES_BLOCK_SIZE];
} AES_CONTEXT;

typedef struct MD5_CONTEXT_ {
  UINT8   Data[64];
  UINT32  DataLen;
  UINT64  BitLen;
  UINT32  State[4];
} MD5_CONTEXT;

typedef struct SHA1_CONTEXT_ {
  UINT8   Data[64];
  UINT32  DataLen;
  UINT64  BitLen;
  UINT32  State[5];
  UINT32  K[4];
} SHA1_CONTEXT;

typedef struct SHA256_CONTEXT_ {
  UINT8   Data[64];
  UINT32  DataLen;
  UINT64  BitLen;
  UINT32  State[8];
} SHA256_CONTEXT;

typedef struct SHA512_CONTEXT_ {
  UINT64 TotalLength;
  UINTN  Length;
  UINT8  Block[2 * SHA512_BLOCK_SIZE];
  UINT64 State[8];
} SHA512_CONTEXT;

typedef SHA512_CONTEXT SHA384_CONTEXT;

//
// Functions prototypes
//

//
// Provides algorithm-specific data for a given algorithm.
// Returns NULL if algorithm is invalid.
//
CONST 
RSA_ALGORITHM_DATA 
*RsaGetAlgorithmData (
  RSA_ALGORITHM_TYPES  Algo
  );

BOOLEAN
RsaVerify (
  UINT8        *Key,
  UINTN        KeyNumBytes,
  CONST UINT8  *Signature,
  UINTN        SigNumBytes,
  CONST UINT8  *Hash,
  UINTN        HashNumBytes,
  CONST UINT8  *Padding,
  UINTN        PaddingNumBytes
  );

VOID
AesInitCtxIv (
  AES_CONTEXT  *Context,
  CONST UINT8  *Key,
  CONST UINT8  *Iv
  );

VOID
AesSetCtxIv (
  AES_CONTEXT  *Context,
  CONST UINT8  *Iv
  );

//
// Data size MUST be mutiple of AES_BLOCK_SIZE;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for Padding scheme
// NOTES: you need to set Iv in Context via AesInitCtxIv() or AesSetCtxIv()
//        no Iv should ever be reused with the same key
//
VOID
AesCbcEncryptBuffer (
  AES_CONTEXT  *Context,
  UINT8        *Data,
  UINT32       Len
  );

VOID
AesCbcDecryptBuffer (
  AES_CONTEXT  *Context,
  UINT8        *Data,
  UINT32       Len
  );

//
// Same function for encrypting as for decrypting.
// Iv is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for Padding scheme
// NOTES: you need to set Iv in Context via AesInitCtxIv() or AesSetCtxIv()
//        no Iv should ever be reused with the same key
//
VOID
AesCtrXcryptBuffer (
  AES_CONTEXT  *Context,
  UINT8        *Data,
  UINT32       Len
  );

VOID
Md5Init (
  MD5_CONTEXT  *Context
  );

VOID
Md5Update (
  MD5_CONTEXT  *Context,
  CONST UINT8  *Data,
  UINTN        Len
  );

VOID
Md5Final (
  MD5_CONTEXT  *Context,
  UINT8        *Hash
  );

VOID
Md5 (
  UINT8  *Hash,
  UINT8  *Data,
  UINTN  Len
  );

VOID
Sha1Init (
  SHA1_CONTEXT  *Context
  );

VOID
Sha1Update (
  SHA1_CONTEXT  *Context,
  CONST UINT8   *Data,
  UINTN         Len
  );

VOID
Sha1Final (
  SHA1_CONTEXT  *Context,
  UINT8         *Hash
  );

VOID
Sha1 (
  UINT8  *Hash,
  UINT8  *Data,
  UINTN  Len
  );

VOID
Sha256Init (
  SHA256_CONTEXT  *Context
  );

VOID
Sha256Update (
  SHA256_CONTEXT  *Context,
  CONST UINT8     *Data,
  UINTN           Len
  );

VOID
Sha256Final (
  SHA256_CONTEXT  *Context,
  UINT8           *HashDigest
  );

VOID
Sha256 (
  UINT8        *Hash,
  CONST UINT8  *Data,
  UINTN        Len
  );

VOID
Sha512Init (
  SHA512_CONTEXT  *Context
  );

VOID
Sha512Update (
  SHA512_CONTEXT  *Context,
  CONST UINT8     *Data,
  UINTN           Len
  );

VOID
Sha512Final (
  SHA512_CONTEXT  *Context,
  UINT8           *HashDigest
  );

VOID
Sha512 (
  UINT8        *Hash,
  CONST UINT8  *Data,
  UINTN        Len
  );

VOID
Sha384Init (
  SHA384_CONTEXT  *Context
  );

VOID 
Sha384Update (
  SHA384_CONTEXT  *Context,
  CONST UINT8     *Data,
  UINTN           Len
  );

VOID 
Sha384Final (
  SHA384_CONTEXT  *Context,
  UINT8           *HashDigest
  );

VOID 
Sha384 (
  UINT8        *Hash,
  CONST UINT8  *Data,
  UINTN        Len
  );

/**
  Performs a cryptographically secure comparison of the contents of two
  buffers.

  This function compares Length bytes of SourceBuffer to Length bytes of
  DestinationBuffer in a cryptographically secure fashion. This especially
  implies that different lengths of the longest shared prefix do not change
  execution time in a way relevant to security.

  If Length > 0 and DestinationBuffer is NULL, then ASSERT().
  If Length > 0 and SourceBuffer is NULL, then ASSERT().
  If Length is greater than (MAX_ADDRESS - DestinationBuffer + 1), then ASSERT().
  If Length is greater than (MAX_ADDRESS - SourceBuffer + 1), then ASSERT().

  @param  DestinationBuffer The pointer to the destination buffer to compare.
  @param  SourceBuffer      The pointer to the source buffer to compare.
  @param  Length            The number of bytes to compare.

  @return 0                 All Length bytes of the two buffers are identical.
  @retval -1                The two buffers are not identical within Length
                            bytes.
**/
INTN
SecureCompareMem (
  IN CONST VOID  *DestinationBuffer,
  IN CONST VOID  *SourceBuffer,
  IN UINTN       Length
  );

/**
  Verify Password and Salt against RefHash.  The used hash function is SHA-512,
  thus the caller must ensure RefHash is at least 64 bytes in size.

  @param[in] Password      The entered password to verify.
  @param[in] PasswordSize  The size, in bytes, of Password.
  @param[in] Salt          The cryptographic salt appended to Password on hash.
  @param[in] SaltSize      The size, in bytes, of Salt.
  @param[in] RefHash       The SHA-512 hash of the reference password and Salt.

  @returns Whether Password and Salt cryptographically match RefHash.

**/
BOOLEAN
OcVerifyPasswordSha512 (
  IN CONST UINT8  *Password,
  IN UINT32       PasswordSize,
  IN CONST UINT8  *Salt,
  IN UINT32       SaltSize,
  IN CONST UINT8  *RefHash
  );

#endif // OC_CRYPTO_LIB_H
