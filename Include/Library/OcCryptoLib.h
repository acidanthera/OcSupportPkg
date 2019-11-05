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

#include <Library/OcGuardLib.h>

///
/// A BIGNUM word. This is at best an integer of the platform's natural size
/// to optimize memory accesses and arithmetic operation count.
///
typedef UINTN OC_BN_WORD;
//
// Declarations regarding the Word size.
//
#define OC_BN_WORD_SIZE      (sizeof (OC_BN_WORD))
#define OC_BN_WORD_NUM_BITS  (OC_BN_WORD_SIZE * 8U)
//
// Declarations regarding the maximum size of OC_BN structures.
//
typedef UINT16 OC_BN_NUM_WORDS;
typedef UINT32 OC_BN_NUM_BITS;
#define OC_BN_MAX_SIZE  MAX_UINT16
#define OC_BN_MAX_LEN   (OC_BN_MAX_SIZE / OC_BN_WORD_SIZE)

typedef struct {
  ///
  /// The number of Words in Words.
  ///
  OC_BN_NUM_WORDS NumWords;
  ///
  /// The number data in reverse byte order (LSB first).
  ///
  OC_BN_WORD      Words[];
} OC_BN;

/**
  Declares a fixed-size OC_BN structure with a _##Bytes suffix.

  @param[in] AlignSize  The aligned size of the data array.

**/
#define OC_BN_DECLARE(AlignSize)                      \
  OC_STATIC_ASSERT (                                  \
    ((AlignSize) % OC_BN_WORD_SIZE == 0),             \
    "OC_BN declaration used an unaligned size."       \
    );                                                \
                                                      \
  OC_STATIC_ASSERT (                                  \
    ((AlignSize) / OC_BN_WORD_SIZE <= OC_BN_MAX_LEN), \
    "OC_BN declaration used a too large size."        \
    );                                                \
                                                      \
  typedef struct {                                    \
    OC_BN_NUM_WORDS NumWords;                         \
    union {                                           \
      UINT8      Bytes[bytes];                        \
      OC_BN_WORD Words[(bytes) / OC_BN_WORD_SIZE];    \
    };                                                \
  } OC_BN_##AlignSize

/**
  Calculates the size of A's data array.

  @param[in] A  The number to be to retrieve the data size of.

  @returns  The data array size of A.

**/
#define OC_BN_DSIZE(A) ((UINTN)(A)->NumWords * OC_BN_WORD_SIZE)

/**
  Calculates the size of a OC_BN structure with a data array size of AlignSize.
  AlignSize must be aligned on a sizeof (OC_BN_WORD) boundary. The size
  returned is aligned on a OC_ALIGNOF (OC_BN) boundary.

  @param[in] AlignSize  The aligned size of the data array.

  @returns  The requested size of the OC_BN structure.
**/
#define OC_BN_SIZE(AlignSize) \
  (ALIGN_VALUE (sizeof (OC_BN) + (AlignSize), OC_ALIGNOF (OC_BN)))

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

#define OC_MAX_SHA_DIGEST_SIZE  SHA512_DIGEST_SIZE

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
// Possible RSA algorithm types supported by OcCryptoLib
// for RSA digital signature verification
//
typedef enum OC_RSA_ALGO_TYPE_ {
  RSA_ALGO_TYPE_SHA256,
  RSA_ALGO_TYPE_SHA384, 
  RSA_ALGO_TYPE_SHA512,
  RSA_ALGO_TYPE_MAX
} OC_RSA_ALGO_TYPE;

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

#pragma pack(push, 1)

typedef PACKED struct {
  ///
  /// The number of 64-bit values in Data.
  ///
  UINT16 NumQwords;
  ///
  /// Padding for 64-bit alignment. Must be 0 to allow future extensions.
  ///
  UINT8  Reserved[6];
  ///
  /// The Montgomery Inverse in 64-bit space: -1 / N[0] mod 2^64.
  ///
  UINT64 N0Inv;
} RSA_PUBLIC_KEY_HDR;

typedef PACKED struct {
  ///
  /// The RSA Public Key header structure.
  ///
  RSA_PUBLIC_KEY_HDR Hdr;
  ///
  /// The Modulus and Montgomery's R^2 mod N in little endian byte order.
  ///
  UINT64             Data[];
} RSA_PUBLIC_KEY;

#pragma pack(pop)

//
// Functions prototypes
//

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
  Verify a RSA PKCS1.5 signature against an expected hash.

  @param[in] Modulus        The RSA modulus byte array.
  @param[in] ModulusSize    The size, in bytes, of Modulus.
  @param[in] Exponent       The RSA exponent.
  @param[in] Signature      The RSA signature to be verified.
  @param[in] SignatureSize  Size, in bytes, of Signature.
  @param[in] Hash           The Hash digest of the signed data.
  @param[in] HashSize       Size, in bytes, of Hash.
  @param[in] Algorithm      The RSA algorithm used.

  @returns  Whether the signature has been successfully verified as valid.

**/
BOOLEAN
RsaVerifyFromKey (
  IN CONST RSA_PUBLIC_KEY  *Key,
  IN CONST UINT8           *Signature,
  IN UINTN                 SignatureSize,
  IN CONST UINT8           *Hash,
  IN UINTN                 HashSize,
  IN OC_RSA_ALGO_TYPE      Algorithm
  );

/**
  Verify RSA PKCS1.5 signed data against its signature.
  The modulus' size must be a multiple of the configured BIGNUM word size.
  This will be true for any conventional RSA, which use two's potencies.

  @param[in] Modulus        The RSA modulus byte array.
  @param[in] ModulusSize    The size, in bytes, of Modulus.
  @param[in] Exponent       The RSA exponent.
  @param[in] Signature      The RSA signature to be verified.
  @param[in] SignatureSize  Size, in bytes, of Signature.
  @param[in] Data           The signed data to verify.
  @param[in] DataSize       Size, in bytes, of Data.
  @param[in] Algorithm      The RSA algorithm used.

  @returns  Whether the signature has been successfully verified as valid.

**/
BOOLEAN
VerifySignatureFromProcessed (
  IN CONST OC_BN_WORD  *N,
  IN OC_BN_WORD        N0Inv,
  IN CONST OC_BN_WORD  *RSqrMod,
  IN UINTN             NumWords,
  IN UINT32            Exponent,
  IN CONST UINT8       *Signature,
  IN UINTN             SignatureSize,
  IN CONST UINT8       *Data,
  IN UINTN             DataSize,
  IN OC_RSA_ALGO_TYPE  Algorithm
  );

/**
  Verify RSA PKCS1.5 signed data against its signature.
  The modulus' size must be a multiple of the configured BIGNUM word size.
  This will be true for any conventional RSA, which use two's potencies.

  @param[in] Modulus        The RSA modulus byte array.
  @param[in] ModulusSize    The size, in bytes, of Modulus.
  @param[in] Exponent       The RSA exponent.
  @param[in] Signature      The RSA signature to be verified.
  @param[in] SignatureSize  Size, in bytes, of Signature.
  @param[in] Data           The signed data to verify.
  @param[in] DataSize       Size, in bytes, of Data.
  @param[in] Algorithm      The RSA algorithm used.

  @returns  Whether the signature has been successfully verified as valid.

**/
BOOLEAN
VerifySignatureFromData (
  IN CONST UINT8       *Modulus,
  IN UINTN             ModulusSize,
  IN UINT32            Exponent,
  IN CONST UINT8       *Signature,
  IN UINTN             SignatureSize,
  IN CONST UINT8       *Data,
  IN UINTN             DataSize,
  IN OC_RSA_ALGO_TYPE  Algorithm
  );

/**
  Verify RSA PKCS1.5 signed data against its signature.
  The modulus' size must be a multiple of the configured BIGNUM word size.
  This will be true for any conventional RSA, which use two's potencies.

  @param[in] Modulus        The RSA modulus byte array.
  @param[in] ModulusSize    The size, in bytes, of Modulus.
  @param[in] Exponent       The RSA exponent.
  @param[in] Signature      The RSA signature to be verified.
  @param[in] SignatureSize  Size, in bytes, of Signature.
  @param[in] Data           The signed data to verify.
  @param[in] DataSize       Size, in bytes, of Data.
  @param[in] Algorithm      The RSA algorithm used.

  @returns  Whether the signature has been successfully verified as valid.

**/
BOOLEAN
VerifySignatureFromKey (
  IN CONST RSA_PUBLIC_KEY  *Key,
  IN CONST UINT8           *Signature,
  IN UINTN                 SignatureSize,
  IN CONST UINT8           *Data,
  IN UINTN                 DataSize,
  IN OC_RSA_ALGO_TYPE      Algorithm
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
