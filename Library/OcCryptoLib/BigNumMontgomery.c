/**
  This library performs arbitrary precision Montgomery operations.
  All results are returned into caller-provided buffers. The caller is
  responsible to ensure the buffers can hold the full result of the operation.

  https://chromium.googlesource.com/chromiumos/platform/ec/+/master/common/rsa.c
  has served as a template for several algorithmic ideas.

  This code is not to be considered general-purpose but solely to support
  cryptographic operations such as RSA encryption. As such, there are arbitrary
  limitations, such as requirement of equal precision, to limit the complexity
  of the operations to the bare minimum required to support such use caes.

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

#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/OcCryptoLib.h>

#include "BigNumLibInternal.h"

/**
  Calculates the Montgomery Inverse -1 / A mod 2^#Bits(Word).
  This algorithm is based on the Extended Euclidean Algorithm, which returns
  1 / A mod 2^#Bits(Word).

  @param[in] A  The number to calculate the Montgomery Inverse of.

  @retval 0      The Montgomery Inverse of A could not be computed.
  @retval other  The Montgomery Inverse of A.

**/
STATIC
OC_BN_WORD
BigNumMontInverse (
  IN CONST OC_BN  *A
  )
{
  OC_BN_WORD Dividend;
  OC_BN_WORD Divisor;
  OC_BN_WORD X;
  OC_BN_WORD Y;
  OC_BN_WORD Mod;
  OC_BN_WORD Div;
  OC_BN_WORD Tmp;

  ASSERT (A != NULL);
  //
  // We cannot compute the Montgomery Inverse of 0.
  //
  if (A->Words[0] == 0) {
    return 0;
  }

  //
  // The initial divisor 2^Bits(Word) obviously cannot be represented as a
  // variable value. For this reason, the first two iterations of the loop are
  // unrolled. 2^Bits(Word) is represented as 0 as those two values are
  // congruent modulo 2^Bits(Word), which is the variable storage space.
  // The modulo operation is therefor implemented as a subtraction loop.
  //

  //
  // === INITIALISATION ===
  //
  // Divisor  = 1U << sizeof(A->Words[0]) * 8;
  // Dividend = A->Words[0];
  //
  // Y = 1;
  // X = 0;
  //
  // === LOOP UNROLL 1) ===
  //
  // Div = Dividend / Divisor; // => 0
  // Mod = Dividend % Divisor; // => A->Words[0]
  //
  // Dividend = Divisor;       // => 2^Bits(Word)
  // Divisor  = Mod;           // => A->Words[0]
  //
  Dividend = 0;
  Divisor  = A->Words[0];
  //
  // Tmp = Y - Div * X;        // => 1
  // Y   = X;                  // => 0
  // X   = Tmp;                // => 1
  //
  // === LOOP UNROLL 2) ===
  //
  // Div = Dividend / Divisor;
  // Mod = Dividend % Divisor;
  //
  Div = 0;
  do { 
    Dividend -= Divisor;
    ++Div;
  } while (Dividend >= Divisor);

  Mod = Dividend;
  //
  // Dividend = Divisor;
  // Divisor  = Mod;
  //
  Dividend = Divisor;
  Divisor  = Mod;
  //
  // Tmp = Y - Div * X;        // => -Div
  // Y   = X;                  // => 1
  // X   = Tmp;                // => -Div
  //
  Y = 1;
  X = (OC_BN_WORD)0U - Div;

  while (Divisor != 0) {
    //
    // FIXME: This needs a good source for an algorithm specification.
    //
    Div = Dividend / Divisor;
    Mod = Dividend % Divisor;

    Dividend = Divisor;
    Divisor  = Mod;

    Tmp = Y - Div * X;
    Y   = X;
    X   = Tmp;
  }
  //
  // When the loop ends, Dividend contains the Greatest Common Divisor.
  // If it is not 1, we cannot compute the Montgomery Inverse.
  //
  if (Dividend != 1) {
    return 0;
  }
  //
  // As per above, Y is 1 / A mod 2^#Bits(Word), so invert the result to yield
  // -1 / A mod 2^#Bits(Word).
  //
  return (OC_BN_WORD)0U - Y;
}

/**
  Calculates the Montgomery Inverse and R� mod N.

  @param[in,out] RSqrMod  The buffer to return R� mod N into.
  @param[in]     N        The Montgomery Modulus.

  @returns  The Montgomery Inverse of N.

**/
OC_BN_WORD
BigNumCalculateMontParams (
  IN OUT OC_BN        *RSqrMod,
  IN     CONST OC_BN  *N
  )
{
  OC_BN_WORD N0Inv;
  UINT32     NumBits;
  UINTN      Size;
  OC_BN      *RSqr;

  ASSERT (RSqrMod != NULL);
  ASSERT (N != NULL);
  ASSERT (RSqrMod->NumWords == N->NumWords);
  //
  // Calculate the Montgomery Inverse.
  // This is a reduced approach of the algorithmic -1 / N mod 2^#Bits(N),
  // where the modulus is reduced from 2^#Bits(N) to 2^#Bits(Word). This
  // reduces N to N[0] and yields an inverse valid in the Word domain.
  //
  N0Inv = BigNumMontInverse (N);
  if (N0Inv == 0) {
    return 0;
  }

  NumBits = BigNumSignificantBits (N);

  OC_STATIC_ASSERT (
    OC_BN_MAX_SIZE * 8 <= (MAX_UINTN / 2) - 2 - 7,
    "An overflow verification must be added"
    );
  //
  // Considering NumBits can at most be MAX_UINT16 * 8, this cannot overflow.
  // 7 is added to achieve rounding towards the next Byte boundary.
  //
  Size = ALIGN_VALUE (((2 * (NumBits + 1) + 7) / 8), OC_BN_WORD_SIZE);
  if (Size > OC_BN_MAX_SIZE) {
    return 0;
  }

  RSqr = AllocatePool (OC_BN_SIZE (Size));
  if (RSqr == NULL) {
    return 0;
  }
  RSqr->NumWords = (OC_BN_NUM_WORDS)(Size / OC_BN_WORD_SIZE);
  //
  // Calculate Montgomery's R^2 mod N.
  //
  BigNumAssign0 (RSqr);
  //
  // 2 * NumBits cannot overflow as per above.
  //
  BigNumOrWord (RSqr, 1, 2 * NumBits);
  BigNumMod (RSqrMod, RSqr, N);

  FreePool (RSqr);

  return N0Inv;
}

/**
  Calculates the sum of C and the product of A and B.

  @param[out] Hi  Buffer in which the high Word of the result is returned.
  @param[in]  C   The addend.
  @param[in]  A   The multiplicant.
  @param[in]  B   The multiplier.

  @returns  The low Word of the result.

**/
STATIC
OC_BN_WORD
BigNumWordAddMul (
  OUT OC_BN_WORD  *Hi,
  IN  OC_BN_WORD  C,
  IN  OC_BN_WORD  A,
  IN  OC_BN_WORD  B
  )
{
  OC_BN_WORD ResHi;
  OC_BN_WORD ResLo;

  ASSERT (Hi != NULL);

  ResLo = BigNumWordMul (&ResHi, A, B) + C;
  if (ResLo < C) {
    ++ResHi;
  }

  *Hi = ResHi;
  return ResLo;
}

/**
  Calculates the sum of C, the product of A and B, and Carry.

  @param[out] Hi     Buffer in which the high Word of the result is returned.
  @param[in]  C      The addend.
  @param[in]  A      The multiplicant.
  @param[in]  B      The multiplier.
  @param[in]  Carry  The carry of the previous multiplication.

  @returns  The low Word of the result.

**/
STATIC
OC_BN_WORD
BigNumWordAddMulCarry (
  OUT OC_BN_WORD  *Hi,
  IN  OC_BN_WORD  C,
  IN  OC_BN_WORD  A,
  IN  OC_BN_WORD  B,
  IN  OC_BN_WORD  Carry
  )
{
  OC_BN_WORD MulResHi;
  OC_BN_WORD MulResLo;

  ASSERT (Hi != NULL);

  MulResLo = BigNumWordAddMul (&MulResHi, C, A, B);
  MulResLo += Carry;
  if (MulResLo < Carry) {
    ++MulResHi;
  }
  
  *Hi = MulResHi;
  return MulResLo;
}

/**
  Calculates a row of the product of A and B mod N.

  @param[in,out] Result    The result buffer.
  @param[in]     AWord     The current row's Word of the multiplicant.
  @param[in]     B         The multiplier.
  @param[in]     N         The modulus.
  @param[in]     N0Inv     The Montgomery Inverse of N.
  @param[in]     NumWords  The number of Words of Result, B and N.

**/
STATIC
VOID
BigNumDataMontMulRow (
  IN OUT OC_BN_WORD        *Result,
  IN     OC_BN_WORD        AWord,
  IN     CONST OC_BN_WORD  *B,
  IN     CONST OC_BN_WORD  *N,
  IN     OC_BN_WORD        N0Inv,
  IN     OC_BN_NUM_WORDS   NumWords
  )
{
  UINTN      CompIndex;

  OC_BN_WORD CCurMulHi;
  OC_BN_WORD CCurMulLo;
  OC_BN_WORD CCurMontHi;
  OC_BN_WORD CCurMontLo;
  OC_BN_WORD TFirst;

  ASSERT (Result != NULL);
  ASSERT (B != NULL);
  ASSERT (N != NULL);
  ASSERT (N0Inv != 0);
  //
  // Standard multiplication
  // C = C + A*B
  //
  CCurMulLo = BigNumWordAddMul (
                &CCurMulHi,
                Result[0],
                AWord,
                B[0]
                );
  //
  // Montgomery Reduction preparation
  // As N_first is reduced mod 2^#Bits (word), we're operating in this domain
  // and reduce both C and the result as well.
  // t_first = C * N_first
  //
  TFirst = CCurMulLo * N0Inv;
  //
  // Montgomery Reduction
  // 1. C = C + t_first * N
  // 2. In the first step, only the carries are actually used, which implies
  //    division by R.
  //
  CCurMontLo = BigNumWordAddMul (&CCurMontHi, CCurMulLo, TFirst, N[0]);

  for (CompIndex = 1; CompIndex < NumWords; ++CompIndex) {
    //
    // Standard multiplication
    // C = C + A*B + carry
    //
    CCurMulLo = BigNumWordAddMulCarry (
                  &CCurMulHi,
                  Result[CompIndex],
                  AWord,
                  B[CompIndex],
                  CCurMulHi
                  );
    //
    // Montgomery Reduction
    // 1. C = C + t_first * N + carry
    //
    CCurMontLo = BigNumWordAddMulCarry (
                   &CCurMontHi,
                   CCurMulLo,
                   TFirst,
                   N[CompIndex],
                   CCurMontHi
                   );
    //
    // 2. The index shift translates to a bitshift equivalent to the division
    //    by R = 2^#Bits (word).
    //    C = C / R
    //
    Result[CompIndex - 1] = CCurMontLo;
  }
  //
  // Assign the most significant byte the remaining carrys.
  //
  CCurMulLo = CCurMulHi + CCurMontHi;
  Result[CompIndex - 1] = CCurMulLo;
  //
  // If the result has wrapped around, C >= N is true and we reduce mod N.
  //
  if (CCurMulLo < CCurMulHi) {
    //
    // The discarded most significant word must be the last borrow of the
    // subtraction, as C_actual = (CCurMul >> WORD_BITS)||C.
    //
    BigNumDataSub (Result, Result, N, NumWords);
  }
}

/**
  Calculates the Montgomery product of A and B mod N.

  @param[in,out] Result    The result buffer.
  @param[in]     A         The multiplicant.
  @param[in]     B         The multiplier.
  @param[in]     N         The modulus.
  @param[in]     N0Inv     The Montgomery Inverse of N.
  @param[in]     NumWords  The number of Words of Result, A, B and N.

**/
STATIC
VOID
BigNumDataMontMul (
  IN OUT OC_BN_WORD        *Result,
  IN     CONST OC_BN_WORD  *A,
  IN     CONST OC_BN_WORD  *B,
  IN     CONST OC_BN_WORD  *N,
  IN     OC_BN_WORD        N0Inv,
  IN     OC_BN_NUM_WORDS   NumWords
  )
{
  UINTN RowIndex;

  ASSERT (Result != NULL);
  ASSERT (A != NULL);
  ASSERT (B != NULL);
  ASSERT (N != NULL);
  ASSERT (N0Inv != 0);

  ZeroMem (Result, (UINTN)NumWords * OC_BN_WORD_SIZE);
  //
  // RowIndex is used as an index into the words of A. Because this domain
  // operates in mod 2^#Bits (word), 'row results' do not require multiplication
  // as the positional factor is stripped by the word-size modulus.
  //
  for (RowIndex = 0; RowIndex < NumWords; ++RowIndex) {
    BigNumDataMontMulRow (Result, A[RowIndex], B, N, N0Inv, NumWords);
  }
  //
  // As this implementation only reduces mod N on overflow and not for every
  // yes-instance of C >= N, any sequence of Montgomery Multiplications must be
  // completed with a final reduction step.
  //
}

/**
  This is an optimized version of the call
  BigNumMontMulRow (C, 0, A, N, N0Inv)

  Calculates a row of the product of 0 and A mod N.

  @param[in,out] Result  The result buffer.
  @param[in]     N       The modulus.
  @param[in]     N0Inv   The Montgomery Inverse of N.
  @param[in]     NumWords  The number of Words of Result and N.

**/
STATIC
VOID
BigNumDataMontMulRow0 (
  IN OUT OC_BN_WORD        *Result,
  IN     CONST OC_BN_WORD  *N,
  IN     OC_BN_WORD        N0Inv,
  IN     OC_BN_NUM_WORDS   NumWords
  )
{
  UINTN      CompIndex;

  OC_BN_WORD CCurMontHi;
  OC_BN_WORD CCurMontLo;
  OC_BN_WORD TFirst;

  ASSERT (Result != NULL);
  ASSERT (N != NULL);
  ASSERT (N0Inv != 0);
  //
  // Montgomery Reduction preparation
  // As N_first is reduced mod 2^#Bits (word), we reduce C as well.
  // Due to the reduction, the high bits are discarded safely.
  // t_first = C * N_first
  //
  TFirst = Result[0] * N0Inv;
  //
  // Montgomery Reduction
  // 1. C = C + t_first * N
  // 2. In the first step, only the carries are actually used, so the
  //    division by R can be omited.
  //
  CCurMontLo = BigNumWordAddMul (&CCurMontHi, Result[0], TFirst, N[0]);
  for (CompIndex = 1; CompIndex < NumWords; ++CompIndex) {
    //
    // Montgomery Reduction
    // 1. C = C + t_first * N + carry
    //
    CCurMontLo = BigNumWordAddMulCarry (
                   &CCurMontHi,
                   Result[CompIndex],
                   TFirst,
                   N[CompIndex],
                   CCurMontHi
                   );
    //
    // 2. The index shift translates to a bitshift equivalent to the division
    //    by R = 2^#Bits (word).
    //    C = C / R
    //
    Result[CompIndex - 1] = CCurMontLo;
  }
  //
  // Assign the most significant byte the remaining carry.
  //
  Result[CompIndex - 1] = CCurMontHi;
}

/**
  This is an optimized version of the call
  BigNumMontMul (C, 1, A, N, N0Inv)

  @param[in,out] Result    The result buffer.
  @param[in]     A         The multiplicant.
  @param[in]     N         The modulus.
  @param[in]     N0Inv     The Montgomery Inverse of N.
  @param[in]     NumWords  The number of Words of Result, A and N.

**/
STATIC
VOID
BigNumDataMontMul1 (
  IN OUT OC_BN_WORD        *Result,
  IN     CONST OC_BN_WORD  *A,
  IN     CONST OC_BN_WORD  *N,
  IN     OC_BN_WORD        N0Inv,
  IN     OC_BN_NUM_WORDS   NumWords
  )
{
  UINTN RowIndex;

  ASSERT (Result != NULL);
  ASSERT (A != NULL);
  ASSERT (N != NULL);
  ASSERT (N0Inv != 0);

  ZeroMem (Result, (UINTN)NumWords * OC_BN_WORD_SIZE);
  //
  // Perform the entire standard multiplication and one Montgomery Reduction.
  //
  BigNumDataMontMulRow (Result, 1, A, N, N0Inv, NumWords);
  //
  // Perform the remaining Montgomery Reductions.
  //
  for (RowIndex = 1; RowIndex < NumWords; ++RowIndex) {
    BigNumDataMontMulRow0 (Result, N, N0Inv, NumWords);
  }
  //
  // As this implementation only reduces mod N on overflow and not for every
  // yes-instance of C >= N, any sequence of Montgomery Multiplications must be
  // completed with a final reduction step.
  //
}

/**
  Caulculates the exponentiation of A with B mod N.

  @param[in,out] Result    The buffer to return the result into.
  @param[in]     A         The base.
  @param[in]     B         The exponent.
  @param[in]     N         The modulus.
  @param[in]     N0Inv     The Montgomery Inverse of N.
  @param[in]     RSqrMod   Montgomery's R^2 mod N.
  @param[in]     NumWords  The number of Words of Result, A, N and RSqrMod.

  @returns  Whether the operation was completes successfully.

**/
BOOLEAN
BigNumDataPowMod (
  IN OUT OC_BN_WORD        *Result,
  IN     CONST OC_BN_WORD  *A,
  IN     UINT32            B,
  IN     CONST OC_BN_WORD  *N,
  IN     OC_BN_WORD        N0Inv,
  IN     CONST OC_BN_WORD  *RSqrMod,
  IN     OC_BN_NUM_WORDS   NumWords
  )
{
  OC_BN_WORD *ATmp;

  UINTN      Index;

  ASSERT (Result != NULL);
  ASSERT (A != NULL);
  ASSERT (N != NULL);
  ASSERT (N0Inv != 0);
  ASSERT (RSqrMod != NULL);
  //
  // Currently, only the most frequent exponents are supported.
  //
  if (B != 0x10001 && B != 3) {
    DEBUG ((DEBUG_INFO, "OCCR: Unsupported exponent: %x\n", B));
    return FALSE;
  }

  ATmp = AllocatePool ((UINTN)NumWords * OC_BN_WORD_SIZE);
  if (ATmp == NULL) {
    DEBUG ((DEBUG_INFO, "OCCR: Memory allocation failure in ModPow\n"));
    return FALSE;
  }
  //
  // Convert A into the Montgomery Domain.
  // ATmp = MM (A, R^2 mod N)
  //
  BigNumDataMontMul (ATmp, A, RSqrMod, N, N0Inv, NumWords);

  if (B == 0x10001) {
    //
    // Squaring the intermediate results 16 times yields A'^ (2^16).
    //
    for (Index = 0; Index < 16; Index += 2) {
      //
      // Result = MM (ATmp, ATmp)
      //
      BigNumDataMontMul (Result, ATmp, ATmp, N, N0Inv, NumWords);
      //
      // ATmp = MM (Result, Result)
      //
      BigNumDataMontMul (ATmp, Result, Result, N, N0Inv, NumWords);
    }
    //
    // Because A is not within the Montgomery Domain, this implies another
    // division by R, which takes the result out of the Montgomery Domain.
    // C = MM (ATmp, A)
    //
    BigNumDataMontMul (Result, ATmp, A, N, N0Inv, NumWords);
  } else {
    //
    // Result = MM (ATmp, ATmp)
    //
    BigNumDataMontMul (Result, ATmp, ATmp, N, N0Inv, NumWords);
    //
    // ATmp = MM (Result, ATmp)
    //
    BigNumDataMontMul (ATmp, Result, ATmp, N, N0Inv, NumWords);
    //
    // Perform a Montgomery Multiplication with 1, which effectively is a
    // division by R, taking the result out of the Montgomery Domain.
    // C = MM (ATmp, 1)
    // TODO: Is this needed or can we just multiply with A above?
    //
    BigNumDataMontMul1 (Result, ATmp, N, N0Inv, NumWords);
  }
  //
  // The Montgomery Multiplications above only ensure the result is mod N when
  // it does not fit within #Bits(N). For N != 0, which is an obvious
  // requirement, #Bits(N) can only ever fit values smaller than 2*N, so the
  // result is at most one modulus too large.
  // C = C mod N
  //
  if (BigNumDataCmp (Result, N, NumWords) >= 0){
    BigNumDataSub (Result, Result, N, NumWords);
  }

  FreePool (ATmp);
  return TRUE;
}
