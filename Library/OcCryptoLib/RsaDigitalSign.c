/** @file
  This library performs RSA-based cryptography operations.

  SECURITY: Currently, no security measures have been taken. This code is
            vulnerable to both timing and side channel attacks for value
            leakage. However, its current purpose is the verification of public
            binaries with public certificates, for which this is perfectly
            acceptable, especially in regards to performance.

  Copyright (C) 2019, Download-Fritz. All rights reserved.

This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Base.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/OcCryptoLib.h>
#include <Library/OcGuardLib.h>

#include "BigNumLib.h"

//
// RFC 3447, 9.2 EMSA-PKCS1-v1_5, Notes 1.
//
STATIC CONST UINT8 mPkcsDigestEncodingPrefixSha256[] = {
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

STATIC CONST UINT8 mPkcsDigestEncodingPrefixSha384[] = {
  0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};

STATIC CONST UINT8 mPkcsDigestEncodingPrefixSha512[] = {
  0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

/**
  Verifies Data against Hash with the appropiate SHA2 algorithm for HashSize.

  @param[in] Data      The data to verify the hash of.
  @param[in] DataSize  The, in bytes, of Data.
  @param[in] Hash      The reference hash to verify against.
  @param[in] HashSize  The size, in bytes, of Hash.

  @return 0         All HashSize bytes of the two buffers are identical.
  @retval Non-zero  If HashSize is not a valid SHA2 digest size, -1. Otherwise,
                    the first mismatched byte in Data's hash subtracted from
                    the first mismatched byte in Hash.

**/
INTN
SigVerifyShaHashBySize (
  IN CONST VOID   *Data,
  IN UINTN        DataSize,
  IN CONST UINT8  *Hash,
  IN UINTN        HashSize
  )
{
  UINT8 DataDigest[OC_MAX_SHA_DIGEST_SIZE];

  ASSERT (Data != NULL);
  ASSERT (DataSize > 0);
  ASSERT (Hash != NULL);
  ASSERT (HashSize > 0);
  ASSERT (HashSize <= sizeof (DataDigest));

  switch (HashSize) {
    case SHA512_DIGEST_SIZE:
    {
      Sha512 (DataDigest, Data, DataSize);
      break;
    }

    case SHA384_DIGEST_SIZE:
    {
      Sha384 (DataDigest, Data, DataSize);
      break;
    }

    case SHA256_DIGEST_SIZE:
    {
      Sha256 (DataDigest, Data, DataSize);
      break;
    }

    default:
    {
      return -1;
    }
  }

  return CompareMem (DataDigest, Hash, HashSize);
}

/**
  Verify a RSA PKCS1.5 signature against an expected hash.

  @param[in] N              The RSA modulus.
  @param[in] N0Inv          The Montgomery Inverse of N.
  @param[in] RSqrMod        Montgomery's R^2 mod N.
  @param[in] NumWords       The number of Words of N and RSqrMod.
  @param[in] Exponent       The RSA exponent.
  @param[in] Signature      The RSA signature to be verified.
  @param[in] SignatureSize  Size, in bytes, of Signature.
  @param[in] Hash           The Hash digest of the signed data.
  @param[in] HashSize       Size, in bytes, of Hash.
  @param[in] Algorithm      The RSA algorithm used.

  @returns  Whether the signature has been successfully verified as valid.

**/
BOOLEAN
RsaVerifySigHashFromProcessed (
  IN CONST OC_BN_WORD  *N,
  IN OC_BN_WORD        N0Inv,
  IN CONST OC_BN_WORD  *RSqrMod,
  IN UINTN             NumWords,
  IN UINT32            Exponent,
  IN CONST UINT8       *Signature,
  IN UINTN             SignatureSize,
  IN CONST UINT8       *Hash,
  IN UINTN             HashSize,
  IN OC_SIG_HASH_TYPE  Algorithm
  )
{
  BOOLEAN     Result;
  INTN        CmpResult;

  UINTN       ModulusSize;

  VOID        *Memory;
  OC_BN_WORD  *EncryptedSigNum;
  OC_BN_WORD  *DecryptedSigNum;

  CONST UINT8 *Padding;
  UINTN       PaddingSize;
  UINTN       DigestSize;
  UINTN       Index;

  OC_BN_WORD  Tmp;

  ASSERT (N != NULL);
  ASSERT (RSqrMod != NULL);
  ASSERT (NumWords > 0);
  ASSERT (Signature != NULL);
  ASSERT (SignatureSize > 0);
  ASSERT (Hash != NULL);
  ASSERT (HashSize > 0);

  OC_STATIC_ASSERT (
    OcSigHashTypeSha512 == OcSigHashTypeMax - 1,
    "New switch cases have to be added for every introduced algorithm."
    );

  if (NumWords > OC_BN_MAX_LEN) {
    return FALSE;
  }

  switch (Algorithm) {
    case OcSigHashTypeSha256:
    {
      ASSERT (HashSize == SHA256_DIGEST_SIZE);

      Padding     = mPkcsDigestEncodingPrefixSha256;
      PaddingSize = sizeof (mPkcsDigestEncodingPrefixSha256);
      break;
    }

    case OcSigHashTypeSha384:
    {
      ASSERT (HashSize == SHA384_DIGEST_SIZE);

      Padding     = mPkcsDigestEncodingPrefixSha384;
      PaddingSize = sizeof (mPkcsDigestEncodingPrefixSha384);
      break;
    }

    case OcSigHashTypeSha512:
    {
      ASSERT (HashSize == SHA512_DIGEST_SIZE);

      Padding     = mPkcsDigestEncodingPrefixSha512;
      PaddingSize = sizeof (mPkcsDigestEncodingPrefixSha512);
      break;
    }

    default:
    {
      ASSERT (FALSE);
    }
  }
  //
  // Verify the Signature size matches the Modulus size.
  // This implicitly verifies it's a multiple of the Word size.
  //
  ModulusSize = NumWords * OC_BN_WORD_SIZE;
  if (SignatureSize != ModulusSize) {
    DEBUG ((DEBUG_INFO, "OCCR: Signature length does not match key length"));
    return FALSE;
  }

  Memory = AllocatePool (2 * ModulusSize);
  if (Memory == NULL) {
    DEBUG ((DEBUG_INFO, "OCCR: Memory allocation failure\n"));
    return FALSE;
  }

  EncryptedSigNum = Memory;
  DecryptedSigNum = (OC_BN_WORD *)((UINTN)EncryptedSigNum + ModulusSize);

  BigNumParseBuffer (
    EncryptedSigNum,
    (OC_BN_NUM_WORDS)NumWords,
    Signature,
    SignatureSize
    );

  Result = BigNumPowMod (
             DecryptedSigNum,
             EncryptedSigNum,
             Exponent,
             N,
             N0Inv,
             RSqrMod,
             (OC_BN_NUM_WORDS)NumWords
             );
  if (!Result) {
    FreePool (Memory);
    return FALSE;
  }
  //
  // Convert the result to a big-endian byte array.
  // Re-use EncryptedSigNum as it is not required anymore.
  // FIXME: Doing this as part of the comparison could speed up the process
  //        and clean up the code.
  //
  Index = NumWords;
  while (Index > 0) {
    --Index;
    Tmp = BigNumSwapWord (
            DecryptedSigNum[NumWords - 1 - Index]
            );
    EncryptedSigNum[Index] = Tmp;
  }
  Signature = (UINT8 *)EncryptedSigNum;

  //
  // From RFC 3447, 9.2 EMSA-PKCS1-v1_5:
  //
  // 5. Concatenate PS, the DER encoding T, and other padding to form the
  //    encoded message EM as
  // 
  //     EM = 0x00 || 0x01 || PS || 0x00 || T.
  //

  //
  // 3. If emLen < tLen + 11, output "intended encoded message length too
  //    short" and stop.
  //
  // The additions cannot overflow because both PaddingSize and HashSize are
  // sane at this point.
  //
  DigestSize = PaddingSize + HashSize;
  if (SignatureSize < DigestSize + 11) {
    FreePool (Memory);
    return FALSE;
  }

  if (Signature[0] != 0x00 || Signature[1] != 0x01) {
    FreePool (Memory);
    return FALSE;
  }
  //
  // 4. Generate an octet string PS consisting of emLen - tLen - 3 octets with
  //    hexadecimal value 0xff.  The length of PS will be at least 8 octets.
  //
  // The additions and subtractions cannot overflow as per 3.
  //
  for (Index = 2; Index < SignatureSize - DigestSize - 3 + 2; ++Index) {
    if (Signature[Index] != 0xFF) {
      FreePool (Memory);
      return FALSE;
    }
  }

  if (Signature[Index] != 0x00) {
    FreePool (Memory);
    return FALSE;
  }

  ++Index;

  CmpResult = CompareMem (&Signature[Index], Padding, PaddingSize);
  if (CmpResult != 0) {
    FreePool (Memory);
    return FALSE;
  }

  Index += PaddingSize;

  CmpResult = CompareMem (&Signature[Index], Hash, HashSize);
  if (CmpResult != 0) {
    FreePool (Memory);
    return FALSE;
  }
  //
  // The code above must have covered the entire Signature range.
  //
  ASSERT (Index + HashSize == SignatureSize);

  FreePool (Memory);
  return TRUE;
}

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
RsaVerifySigDataFromProcessed (
  IN CONST OC_BN_WORD  *N,
  IN OC_BN_WORD        N0Inv,
  IN CONST OC_BN_WORD  *RSqrMod,
  IN UINTN             NumWords,
  IN UINT32            Exponent,
  IN CONST UINT8       *Signature,
  IN UINTN             SignatureSize,
  IN CONST UINT8       *Data,
  IN UINTN             DataSize,
  IN OC_SIG_HASH_TYPE  Algorithm
  )
{
  UINT8 Hash[OC_MAX_SHA_DIGEST_SIZE];
  UINTN HashSize;

  ASSERT (N != NULL);
  ASSERT (RSqrMod != NULL);
  ASSERT (NumWords > 0);
  ASSERT (Exponent > 0);
  ASSERT (Signature != NULL);
  ASSERT (SignatureSize > 0);
  ASSERT (Data != NULL);
  ASSERT (DataSize > 0);

  OC_STATIC_ASSERT (
    OcSigHashTypeSha512 == OcSigHashTypeMax - 1,
    "New switch cases have to be added for every introduced algorithm."
    );

  switch (Algorithm) {
    case OcSigHashTypeSha256:
    {
      Sha256 (Hash, Data, DataSize);
      HashSize = SHA256_DIGEST_SIZE;
      break;
    }

    case OcSigHashTypeSha384:
    {
      Sha384 (Hash, Data, DataSize);
      HashSize = SHA384_DIGEST_SIZE;
      break;
    }

    case OcSigHashTypeSha512:
    {
      Sha512 (Hash, Data, DataSize);
      HashSize = SHA512_DIGEST_SIZE;
      break;
    }

    default:
    {
      //
      // New switch cases have to be added for every introduced algorithm.
      //
      ASSERT (FALSE);
      return FALSE;
    }
  }

  return RsaVerifySigHashFromProcessed (
           N,
           N0Inv,
           RSqrMod,
           NumWords,
           Exponent,
           Signature,
           SignatureSize,
           Hash,
           HashSize,
           Algorithm
           );
}

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
RsaVerifySigDataFromData (
  IN CONST UINT8       *Modulus,
  IN UINTN             ModulusSize,
  IN UINT32            Exponent,
  IN CONST UINT8       *Signature,
  IN UINTN             SignatureSize,
  IN CONST UINT8       *Data,
  IN UINTN             DataSize,
  IN OC_SIG_HASH_TYPE  Algorithm
  )
{
  UINTN      ModulusNumWords;

  VOID       *Memory;
  OC_BN_WORD *N;
  OC_BN_WORD *RSqrMod;

  OC_BN_WORD N0Inv;
  BOOLEAN    Result;

  ASSERT (Modulus != NULL);
  ASSERT (ModulusSize > 0);
  ASSERT (Exponent > 0);
  ASSERT (Signature != NULL);
  ASSERT (SignatureSize > 0);
  ASSERT (Data != NULL);
  ASSERT (DataSize > 0);

  ModulusNumWords = ModulusSize / OC_BN_WORD_SIZE;
  if (ModulusNumWords > OC_BN_MAX_LEN
   || (ModulusSize % OC_BN_WORD_SIZE) != 0) {
    return FALSE;
  }

  OC_STATIC_ASSERT (
    OC_BN_MAX_SIZE <= MAX_UINTN / 2,
    "An overflow verification must be added"
    );

  Memory = AllocatePool (2 * ModulusSize);
  if (Memory == NULL) {
    return FALSE;
  }

  N       = (OC_BN_WORD *)Memory;
  RSqrMod = (OC_BN_WORD *)((UINTN)N + ModulusSize);

  BigNumParseBuffer (N, ModulusNumWords, Modulus, ModulusSize);

  N0Inv = BigNumCalculateMontParams (RSqrMod, N, ModulusNumWords);
  if (N0Inv == 0) {
    FreePool (Memory);
    return FALSE;
  }

  Result = RsaVerifySigDataFromProcessed (
             N,
             N0Inv,
             RSqrMod,
             ModulusNumWords,
             Exponent,
             Signature,
             SignatureSize,
             Data,
             DataSize,
             Algorithm
             );

  FreePool (Memory);
  return Result;
}

/**
  Verify a RSA PKCS1.5 signature against an expected hash.
  The exponent is always 65537 as per the format specification.

  @param[in] Key            The RSA Public Key.
  @param[in] Signature      The RSA signature to be verified.
  @param[in] SignatureSize  Size, in bytes, of Signature.
  @param[in] Hash           The Hash digest of the signed data.
  @param[in] HashSize       Size, in bytes, of Hash.
  @param[in] Algorithm      The RSA algorithm used.

  @returns  Whether the signature has been successfully verified as valid.

**/
BOOLEAN
RsaVerifySigHashFromKey (
  IN CONST OC_RSA_PUBLIC_KEY  *Key,
  IN CONST UINT8              *Signature,
  IN UINTN                    SignatureSize,
  IN CONST UINT8              *Hash,
  IN UINTN                    HashSize,
  IN OC_SIG_HASH_TYPE         Algorithm
  )
{
  ASSERT (Key != NULL);
  ASSERT (Signature != NULL);
  ASSERT (SignatureSize > 0);
  ASSERT (Hash != NULL);
  ASSERT (HashSize > 0);

  OC_STATIC_ASSERT (
    OC_BN_WORD_SIZE <= 8,
    "The parentheses need to be changed to avoid truncation."
    );
  //
  // When OC_BN_WORD is not UINT64, this violates the strict aliasing rule.
  // However, due to packed-ness and byte order, this is perfectly safe.
  //
  return RsaVerifySigHashFromProcessed (
           (OC_BN_WORD *)Key->Data,
           (OC_BN_WORD)Key->Hdr.N0Inv,
           (OC_BN_WORD *)&Key->Data[Key->Hdr.NumQwords],
           Key->Hdr.NumQwords * (8 / OC_BN_WORD_SIZE),
           0x10001,
           Signature,
           SignatureSize,
           Hash,
           HashSize,
           Algorithm
           );
}

/**
  Verify RSA PKCS1.5 signed data against its signature.
  The modulus' size must be a multiple of the configured BIGNUM word size.
  This will be true for any conventional RSA, which use two's potencies.
  The exponent is always 65537 as per the format specification.

  @param[in] Key            The RSA Public Key.
  @param[in] Signature      The RSA signature to be verified.
  @param[in] SignatureSize  Size, in bytes, of Signature.
  @param[in] Data           The signed data to verify.
  @param[in] DataSize       Size, in bytes, of Data.
  @param[in] Algorithm      The RSA algorithm used.

  @returns  Whether the signature has been successfully verified as valid.

**/
BOOLEAN
RsaVerifySigDataFromKey (
  IN CONST OC_RSA_PUBLIC_KEY  *Key,
  IN CONST UINT8              *Signature,
  IN UINTN                    SignatureSize,
  IN CONST UINT8              *Data,
  IN UINTN                    DataSize,
  IN OC_SIG_HASH_TYPE         Algorithm
  )
{
  ASSERT (Key != NULL);
  ASSERT (Signature != NULL);
  ASSERT (SignatureSize > 0);
  ASSERT (Data != NULL);
  ASSERT (DataSize > 0);

  OC_STATIC_ASSERT (
    OC_BN_WORD_SIZE <= 8,
    "The parentheses need to be changed to avoid truncation."
    );
  //
  // When OC_BN_WORD is not UINT64, this violates the strict aliasing rule.
  // However, due to packed-ness and byte order, this is perfectly safe.
  //
  return RsaVerifySigDataFromProcessed (
           (OC_BN_WORD *)Key->Data,
           (OC_BN_WORD)Key->Hdr.N0Inv,
           (OC_BN_WORD *)&Key->Data[Key->Hdr.NumQwords],
           Key->Hdr.NumQwords * (8 / OC_BN_WORD_SIZE),
           0x10001,
           Signature,
           SignatureSize,
           Data,
           DataSize,
           Algorithm
           );
}