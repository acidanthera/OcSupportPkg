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

/**
  Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
  Use of this source code is governed by a BSD-style license that can be
  found in the LICENSE file.

  Implementation of RSA signature verification which uses a pre-processed key
  for computation.
**/

#ifdef EFIAPI
#include <Library/BaseMemoryLib.h>
#endif

#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/OcGuardLib.h>
#include <Library/OcCryptoLib.h>

/**
  PKCS#1 padding (from the RSA PKCS#1 v2.1 standard)

  The DER-encoded padding is defined as follows :
  0x00 || 0x01 || PS || 0x00 || T

  T: DER Encoded DigestInfo value which depends on the hash function used,
  for SHA-256:
  (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.

  Length(T) = 51 octets for SHA-256

  PS: octet string consisting of {Length(RSA Key) - Length(T) - 3} 0xFF
 **/
#define PKCS_PAD_SIZE (CONFIG_RSA_KEY_SIZE - SHA256_DIGEST_SIZE)

STATIC  UINT8 mSha256Tail[] = {
  0x00, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
  0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
  0x05, 0x00, 0x04, 0x20
};

UINT64
Mula32 (
  UINT32  A,
  UINT32  B,
  UINT32  C
  )
{
  UINT64 Ret = A;

  Ret *= B;
  Ret += C;
  return Ret;
}

UINT64
Mulaa32 (
  UINT32  A,
  UINT32  B,
  UINT32  C,
  UINT32  D
  )
{
  UINT64 Ret = A;

  Ret *= B;
  Ret += C;
  Ret += D;
  return Ret;
}

//
//  A[] -= Mod
//
STATIC
VOID
SubMod (
  RSA_PUBLIC_KEY  *Key,
  UINT32          *A
  )
{
  INT64  B     = 0;
  UINT32 Index = 0;
  for (Index = 0; Index < Key->Size; Index++) {
    B += (UINT64) A[Index] - Key->N[Index];
    A[Index] = (UINT32) B;
    B >>= 32;
  }
}

//
// Return A[] >= Mod
//
STATIC
INT32
GeMod (
  RSA_PUBLIC_KEY  *Key,
  CONST UINT32    *A
  )
{
  UINT32 Index = 0;

  for (Index = Key->Size; Index;) {
    Index--;
    if (A[Index] < Key->N[Index]){
      return 0;
    }
    if (A[Index] > Key->N[Index]){
      return 1;
    }
  }
  return 1;
}

//
// Montgomery c[] += a * b[] / R % mod
//
STATIC
VOID
MontMulAdd (
  RSA_PUBLIC_KEY  *Key,
  UINT32          *C,
  UINT32          Aa,
  UINT32          *Bb
  )
{
  UINT64 A, B;
  UINT32 D0, Index;

  A = Mula32 (Aa, Bb[0], C[0]);
  D0 = (UINT32) A * Key->N0Inv;
  B = Mula32 (D0, Key->N[0], (UINT32) A);

  for (Index = 1; Index < Key->Size; Index++) {
    A = Mulaa32 (Aa, Bb[Index], C[Index], (UINT32) (A >> 32));
    B = Mulaa32 (D0, Key->N[Index], (UINT32) A, (UINT32) (B >> 32));
    C[Index - 1] = (UINT32) B;
  }

  A = (A >> 32) + (B >> 32);
  C[Index - 1] = (UINT32) A;

  if (A >> 32) {
    SubMod (Key, C);
  }
}

//
// Montgomery c[] = a[] * b[] / R % mod
//
STATIC
VOID
MontMul (
  RSA_PUBLIC_KEY  *Key,
  UINT32          *C,
  UINT32          *A,
  UINT32          *B
  )
{
  UINT32 Index;

  ZeroMem (C, Key->Size);

  for (Index = 0; Index < Key->Size; Index++) {
    MontMulAdd (Key, C, A[Index], B);
  }
}

/**
  In-place public exponentiation.
  Exponent depends on the configuration (65537 (default), or 3).

  @param Key        Key to use in signing
  @param InOut      Input and output big-endian byte array
 **/
STATIC
VOID
ModPow (
  RSA_PUBLIC_KEY  *Key,
  UINT8           *InOut
  )
{
  UINT32 *A     = NULL;
  UINT32 *Ar    = NULL;
  UINT32 *Aar   = NULL;
  UINT32 *Aaa   = NULL;
  INT32  Index  = 0;
  UINT32 Tmp    = 0;

  A = AllocateZeroPool (Key->Size * sizeof (UINT32));
  Ar = AllocateZeroPool (Key->Size * sizeof (UINT32));
  Aar = AllocateZeroPool (Key->Size * sizeof (UINT32));
  if (A == NULL || Ar == NULL || Aar == NULL) {
    if (A != NULL) {
      FreePool (A);
    }
    if (Ar != NULL) {
      FreePool (Ar);
    }
    if (Aar != NULL) {
      FreePool (Aar);
      // TODO: debug_error about efi memory alocation
    }
    return;
  }

  //
  // Re-use location
  //
  Aaa = Aar;

  //
  // Convert from big endian byte array to little endian word array
  //
  for (Index = 0; Index < (INT32) Key->Size; Index++) {
    Tmp =
      ((UINT32)InOut[((Key->Size - 1 - Index) * 4) + 0] << 24) |
      ((UINT32)InOut[((Key->Size - 1 - Index) * 4) + 1] << 16) |
      ((UINT32)InOut[((Key->Size - 1 - Index) * 4) + 2] << 8) |
      ((UINT32)InOut[((Key->Size - 1 - Index) * 4) + 3] << 0);
    A[Index] = Tmp;
  }

  //
  // Ar = A * Rr / R mod M
  //
  MontMul (Key, Ar, A, Key->Rr);
  //
  // Exponent 65537
  //
  for (Index = 0; Index < 16; Index += 2) {
    //
    // Aar = Ar * Ar / R mod M 
    //
    MontMul (Key, Aar, Ar, Ar);
    //
    // Ar = Aar * Aar / R mod M 
    //
    MontMul (Key, Ar, Aar, Aar);
  }
  //
  // Aaa = Ar * A / R mod M
  //
  MontMul (Key, Aaa, Ar, A);

  //
  // Make sure Aaa < Mod; Aaa is at most 1x mod too large.
  //
  if (GeMod (Key, Aaa)){
    SubMod (Key, Aaa);
  }

  //
  // Convert to bigendian byte array
  //
  for (Index = (INT32) Key->Size - 1; Index >= 0; --Index) {
    Tmp = Aaa[Index];

    *InOut++ = (UINT8) (Tmp >> 24);
    *InOut++ = (UINT8) (Tmp >> 16);
    *InOut++ = (UINT8) (Tmp >>  8);
    *InOut++ = (UINT8) (Tmp >>  0);
  }

  //
  // Free work buffers before return
  //
  if (A != NULL) {
    FreePool (A);
  }
  if (Ar != NULL) {
    FreePool (Ar);
  }
  if (Aar != NULL) {
    FreePool (Aar);
  }  
}

/**
  This routine parses key data from RsaPublicKey Header

  @ param KeyData         RSA public key data
  @ param Length          RSA public key size
 */
STATIC
RSA_PUBLIC_KEY
*RsaParseKeyData (
  UINT8  *KeyData,
  UINTN  Length
  )
{
  RSA_PUBLIC_KEY_HEADER  KeyHeader;
  CONST UINT8            *N;
  CONST UINT8            *Rr;
  UINT32                 Index           = 0;
  UINT32                 RsaKeyStructLen = 0;
  RSA_PUBLIC_KEY         *RsaPublicKey   = NULL;
  UINTN                  ExpectedLength  = 0;

  //
  // Copy KeyHeader
  //
  CopyMem (&KeyHeader, KeyData, sizeof (RSA_PUBLIC_KEY_HEADER));

  /*
  //
  // Validate KeyHeader
  //
  if (!RsaPkValidateByteswape ((CONST RSA_PUBLIC_KEY_HEADER *) KeyData, &KeyHeader)) {
    //
    // Ooops. Invalid key
    //
    DEBUG ((DEBUG_INFO, "Invalid key.\n"));

    if (RsaPublicKey != NULL) {
      FreePool (RsaPublicKey);  
    }
    return NULL;
  }
  */

  //
  // Validate key num bits
  //
  if (    KeyHeader.KeyNumBits != 2048 
       || KeyHeader.KeyNumBits != 4096
       || KeyHeader.KeyNumBits != 8192 ) {
    DEBUG ((DEBUG_INFO, "Unexpected key length.\n"));
    if (RsaPublicKey != NULL) {
      FreePool (RsaPublicKey);
    }
    return NULL;
  }

  //
  // Calculate expected key length based on key num bits
  //
  ExpectedLength = sizeof (RSA_PUBLIC_KEY_HEADER) + 2 * KeyHeader.KeyNumBits / 8;

  //
  // Validate expected key length with passed length from function args
  //
  if (Length != ExpectedLength) {
    DEBUG ((DEBUG_INFO, "Key does not match expected length\n"));
    if (RsaPublicKey != NULL) {
      FreePool (RsaPublicKey);
    }
    return NULL;    
  }

  //
  // Extract N
  //
  N = KeyData + sizeof (RSA_PUBLIC_KEY_HEADER);
  //
  // Extract R^2
  //
  Rr = KeyData + sizeof (RSA_PUBLIC_KEY_HEADER) + KeyHeader.KeyNumBits / 8;

  RsaKeyStructLen = sizeof (RSA_PUBLIC_KEY) + 2 * KeyHeader.KeyNumBits / 8;
  RsaPublicKey = (RSA_PUBLIC_KEY *) (AllocateZeroPool (RsaKeyStructLen));
  
  if (RsaPublicKey == NULL) {
    DEBUG ((DEBUG_INFO, "RsaPublicKey allocation failure.\n"));
    return NULL;
  }

  RsaPublicKey->Size = KeyHeader.KeyNumBits / 32;
  RsaPublicKey->N0Inv = KeyHeader.N0Inv;
  RsaPublicKey->N = (UINT32 *) (RsaPublicKey + 1);
  RsaPublicKey->Rr = RsaPublicKey->N + RsaPublicKey->Size;

  for (Index = 0; Index < RsaPublicKey->Size; Index++) {
    RsaPublicKey->N[Index] = ((UINT32 *) N)[RsaPublicKey->Size - Index - 1];
    RsaPublicKey->Rr[Index] = ((UINT32 *) Rr)[RsaPublicKey->Size - Index - 1];
  }
  
  return RsaPublicKey;
}


/**
  Verify a SHA256WithRSA PKCS#1 v1.5 signature against an expected
  SHA256 hash.

  @param Key         RSA public key
  @param Signature   RSA signature
  @param Sha256      SHA-256 digest of the content to verify

  @return FALSE on failure, TRUE on success.
 **/
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
  )
{
  BOOLEAN         IsSuccess;  
  RSA_PUBLIC_KEY  *ParsedKey;
  UINT8           *WorkBuffer;
  UINTN           *CalulatedPaddingNumBytes;

  IsSuccess = FALSE;
  ParsedKey = NULL;
  WorkBuffer = NULL;

  //
  // Check input data
  //
  if (Key == NULL || Signature == NULL || Hash == NULL || Padding == NULL) {
    DEBUG ((DEBUG_INFO, "Invalid input.\n"));
    goto Exit;
  }

  //
  // Parse key data
  //
  ParsedKey = RsaParseKeyData(Key, KeyNumBytes);
  if (ParsedKey == NULL) {
    DEBUG ((DEBUG_INFO, "Error parsing key.\n"));
    goto Exit;
  }

  //
  // Check signature length
  //
  if (SigNumBytes != (ParsedKey->Size * sizeof (UINT32))) {
    DEBUG ((DEBUG_INFO, "Signature length does not match key length."));
    goto Exit;
  }

  if (OcOverflowSubUN (SigNumBytes, HashNumBytes, CalulatedPaddingNumBytes)) {
    DEBUG ((DEBUG_INFO, "Integer overflow while calculating real padding num bytes."));
    goto Exit;
  }

  if (PaddingNumBytes != *CalulatedPaddingNumBytes) {
    DEBUG ((DEBUG_INFO, "Padding length does not match hash and signature lengths."));
    goto Exit;    
  }

  WorkBuffer = (UINT8 *) AllocateZeroPool (SigNumBytes);
  if (WorkBuffer == NULL) {
    DEBUG ((DEBUG_INFO, "WorkBuffer allocation failure.\n"));
    goto Exit;    
  }

  //
  // Copy input to local workspace
  //
  CopyMem (WorkBuffer, Signature, SigNumBytes);

  //
  // In-place exponentiation
  //
  ModPow (ParsedKey, WorkBuffer);

  //
  // Check padding bytes.
  //
  if (SecureCompareMem (WorkBuffer, Padding, PaddingNumBytes)) {
    DEBUG ((DEBUG_INFO, "Padding check failed.\n"));
    goto Exit;   
  }

  //
  // Check the hash digest
  //
  if (SecureCompareMem (WorkBuffer + PaddingNumBytes, Hash, HashNumBytes)) {
    DEBUG ((DEBUG_INFO, "Hash digest check failed.\n"));
    goto Exit;
  }

  //
  // All checked out OK
  //
  IsSuccess = TRUE;

Exit:
  if (ParsedKey != NULL) {
    FreePool (ParsedKey);
  }

  if (WorkBuffer != NULL) {
    FreePool (WorkBuffer);
  }
  return IsSuccess; 
}
