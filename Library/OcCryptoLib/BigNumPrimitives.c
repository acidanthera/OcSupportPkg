/**
  This library performs unsigned arbitrary precision arithmetic operations.
  All results are returned into caller-provided buffers. The caller is
  responsible to ensure the buffers can hold a value of the precision it
  desires. Too large results will be truncated without further notification for
  public APIs.

  https://github.com/kokke/tiny-bignum-c has served as a template for several
  algorithmic ideas.

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

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/OcCryptoLib.h>
#include <Library/OcGuardLib.h>

#include "BigNumLibInternal.h"

#define OC_BN_MAX_VAL  ((OC_BN_WORD)0U - 1U)

OC_STATIC_ASSERT (
  OC_BN_WORD_SIZE == 4 || OC_BN_WORD_SIZE == 8,
  "OC_BN_WORD_SIZE and OC_BN_WORD_NUM_BITS usages must be adapted."
  );

/**
  Swaps the byte order of Word.

  @param[in] Word  The Word to swap.

  @returns  The byte-swapped value of Word.

**/
OC_BN_WORD
BigNumSwapWord (
  IN OC_BN_WORD  Word
  )
{
  if (OC_BN_WORD_SIZE == 4) {
    return SwapBytes32 ((UINT32)Word);
  } else if (OC_BN_WORD_SIZE == 8) {
    return SwapBytes64 ((UINT64)Word);
  }

  ASSERT (FALSE);
}

/**
  Shifts A left by Exponent Words.

  @param[in,out] A         The number to be word-shifted.
  @param[in]     Exponent  The Word shift exponent.

**/
STATIC 
VOID
BigNumLeftShiftWords (
  IN OUT OC_BN        *A,
  IN     CONST OC_BN  *B,
  IN     UINTN        Exponent
  )
{
  ASSERT (A != NULL);
  ASSERT (B != NULL);
  ASSERT (Exponent < A->NumWords);
  ASSERT (A->NumWords - Exponent >= B->NumWords);

  CopyMem (&A->Words[Exponent], B->Words, (A->NumWords - Exponent) * OC_BN_WORD_SIZE);
  ZeroMem (A->Words, Exponent * OC_BN_WORD_SIZE);
  if (A->NumWords - Exponent > B->NumWords) {
    ZeroMem (&A->Words[B->NumWords + Exponent], (A->NumWords - Exponent - B->NumWords) * OC_BN_WORD_SIZE);
  }
}

/**
  Shifts A left by Exponent Bits for 0 < Exponent < #Bits(Word).

  @param[in,out] Result    T he buffer to return the result into.
  @param[in]     A          The base.
  @param[in]     NumWords   The Word shift exponent.
  @param[in]     NumBits    The Bit shift exponent.

**/
STATIC
VOID
BigNumLeftShiftWordsAndBits (
  IN OUT OC_BN        *Result,
  IN     CONST OC_BN  *A,
  IN     UINTN        NumWords,
  IN     UINT8        NumBits
  )
{
  UINTN Index;

  ASSERT (Result != NULL);
  ASSERT (A != NULL);
  ASSERT (Result->NumWords >= NumWords);
  //
  // NumBits must not be 0 because a shift of a Word by its Bit width or
  // larger is Undefined Behaviour.
  //
  ASSERT (NumBits > 0);
  ASSERT (NumBits < OC_BN_WORD_NUM_BITS);
  //
  // This, assuming below, is required to avoid overflows, which purely
  // internal calls should never produce.
  //
  ASSERT (Result->NumWords - NumWords > A->NumWords);
  //
  // This is not an algorithmic requirement, but BigNumLeftShiftWords shall be
  // called if TRUE.
  //
  ASSERT (NumWords > 0);

  for (Index = (A->NumWords - 1); Index > 0; --Index) {
    Result->Words[Index + NumWords] = (A->Words[Index] << NumBits) | (A->Words[Index - 1] >> (OC_BN_WORD_NUM_BITS - NumBits));
  }
  //
  // Handle the edge-cases at the beginning and the end of the value.
  //
  Result->Words[NumWords] = A->Words[0] << NumBits;
  Result->Words[A->NumWords + NumWords] = A->Words[A->NumWords - 1] >> (OC_BN_WORD_NUM_BITS - NumBits);
  //
  // Zero everything outside of the previously set ranges.
  //
  ZeroMem (&Result->Words[A->NumWords + NumWords + 1], (Result->NumWords - NumWords - A->NumWords - 1) * OC_BN_WORD_SIZE);
  ZeroMem (Result->Words, NumWords * OC_BN_WORD_SIZE);
}

/**
  Shifts A left by Exponent Bits for 0 < Exponent < #Bits(Word).

  @param[in,out] A         The base.
  @param[in]     Exponent  The Bit shift exponent.

**/
STATIC
VOID
BigNumLeftShiftBitsSmall (
  IN OUT OC_BN  *A,
  IN     UINT8  Exponent
  )
{
  UINTN Index;

  ASSERT (A != NULL);
  //
  // Exponent must not be 0 because a shift of a Word by its Bit width or
  // larger is Undefined Behaviour.
  //
  ASSERT (Exponent > 0);
  ASSERT (Exponent < OC_BN_WORD_NUM_BITS);

  for (Index = (A->NumWords - 1); Index > 0; --Index) {
    A->Words[Index] = (A->Words[Index] << Exponent) | (A->Words[Index - 1] >> (OC_BN_WORD_NUM_BITS - Exponent));
  }
  A->Words[0] <<= Exponent;
}

/**
  Shifts A right by Exponent Bits for 0 < Exponent < #Bits(Word).

  @param[in,out] A         The base.
  @param[in]     Exponent  The Bit shift exponent.

**/
STATIC
VOID
BigNumRightShiftBitsSmall (
  IN OUT OC_BN  *A,
  IN     UINT8  Exponent
  )
{
  UINTN Index;

  ASSERT (A != NULL);
  //
  // Exponent must not be 0 because a shift of a Word by its Bit width or
  // larger is Undefined Behaviour.
  //
  ASSERT (Exponent > 0);
  ASSERT (Exponent < OC_BN_WORD_NUM_BITS);

  for (Index = 0; Index < (A->NumWords - 1); ++Index) {
    A->Words[Index] = (A->Words[Index] >> Exponent) | (A->Words[Index + 1] << (OC_BN_WORD_NUM_BITS - Exponent));
  }
  A->Words[Index] >>= Exponent;
}

#if defined(_MSC_VER) && !defined(__clang__)
  #include <intrin.h>
  #pragma intrinsic(_umul128)
#endif

/**
  Calculates the product of A and B.

  @param[out] Hi  Buffer in which the high Word of the result is returned.
  @param[in]  A   The multiplicant.
  @param[in]  B   The multiplier.

  @returns  The low Word of the result.

**/
OC_BN_WORD
BigNumWordMul (
  OUT OC_BN_WORD  *Hi,
  IN  OC_BN_WORD  A,
  IN  OC_BN_WORD  B
  )
{
  ASSERT (Hi != NULL);

  if (OC_BN_WORD_SIZE == 4) {
    UINT64 Result = (UINT64)A * B;
    //
    // FIXME: The subtraction in the shift is a dirty hack to shut up MSVC.
    //
    *Hi = (OC_BN_WORD)(Result >> (OC_BN_WORD_NUM_BITS - (OC_BN_WORD_SIZE != 4)));
    return (OC_BN_WORD)Result;
  } else if (OC_BN_WORD_SIZE == 8) {
  #if !defined(_MSC_VER) || defined(__clang__)
    //
    // Clang and GCC support the __int128 type for edk2 builds.
    //
    unsigned __int128 Result = (unsigned __int128)A * B;
    *Hi = (OC_BN_WORD)(Result >> OC_BN_WORD_NUM_BITS);
    return (OC_BN_WORD)Result;
  #else
    //
    // MSVC does not support the __int128 type for edk2 builds.
    //
    return _umul128 (A, B, Hi);
  #endif
  /*
    //
    // This is to be used when the used compiler lacks support for both the
    // __int128 type and a suiting intrinsic to perform the calculation.
    //
    // Source: https://stackoverflow.com/a/31662911
    //
    CONST OC_BN_WORD SubWordShift = OC_BN_WORD_NUM_BITS / 2;
    CONST OC_BN_WORD SubWordMask  = ((OC_BN_WORD)1U << SubWordShift) - 1;

    OC_BN_WORD ALo;
    OC_BN_WORD AHi;
    OC_BN_WORD BLo;
    OC_BN_WORD BHi;

    OC_BN_WORD P0;
    OC_BN_WORD P1;
    OC_BN_WORD P2;
    OC_BN_WORD P3;

    OC_BN_WORD Cy;

    ALo = A & SubWordMask;
    AHi = A >> SubWordShift;
    BLo = B & SubWordMask;
    BHi = B >> SubWordShift;

    P0 = ALo * BLo;
    P1 = ALo * BHi;
    P2 = AHi * BLo;
    P3 = AHi * BHi;

    Cy = (((P0 >> SubWordShift) + (P1 & SubWordMask) + (P2 & SubWordMask)) >> SubWordShift) & SubWordMask;

    *Hi = P3 + (P1 >> SubWordShift) + (P2 >> SubWordShift) + Cy;
    return P0 + (P1 << SubWordShift) + (P2 << SubWordShift);
  */
  }
}

/**
  Assigns A to Result.

  @param[in,out] Result  The buffer to store the result in.
  @param[in]     A       The number to assign.

**/
STATIC
VOID
BigNumAssign (
  IN OUT OC_BN        *Result,
  IN     CONST OC_BN  *A
  )
{
  UINTN Size;

  ASSERT (Result != NULL);
  ASSERT (A != NULL);

  if (Result->NumWords > A->NumWords) {
    ZeroMem (Result->Words + A->NumWords, OC_BN_DSIZE (Result) - OC_BN_DSIZE (A));
    Size = OC_BN_DSIZE (A);
  } else {
    Size = OC_BN_DSIZE (Result);
  }

  CopyMem (Result->Words, A->Words, Size);
}

/**
  Assigns A the value 0.

  @param[in,out] A  The number to assign to.

**/
VOID
BigNumAssign0 (
  IN OUT OC_BN  *A
  )
{
  ASSERT (A != NULL);

  ZeroMem (A->Words, OC_BN_DSIZE (A));
}

/**
  Calulates the difference of A and B.
  A must have the same precision as B. Result must have a precision at most as
  bit as A and B.

  @param[in,out] Result  The buffer to return the result into.
  @param[in]     A       The minuend.
  @param[in]     B       The subtrahend.

**/
VOID
BigNumDataSub (
  IN OUT OC_BN_WORD        *Result,
  IN     CONST OC_BN_WORD  *A,
  IN     CONST OC_BN_WORD  *B,
  IN     OC_BN_NUM_WORDS   NumWords
  )
{
  OC_BN_WORD TmpResult;
  OC_BN_WORD Tmp1;
  OC_BN_WORD Tmp2;
  UINTN      Index;
  UINT8      Borrow;

  ASSERT (Result != NULL);
  ASSERT (A != NULL);
  ASSERT (B != NULL);
  //
  // As the same indices are ever accessed at a step, the index is always
  // increased per step, the preexisting values in c are unused and all are
  // are set, it is safe to call this function with c = a or c = b
  // ATTENTION: This might conflict with future "top" optimizations
  //
  Borrow = 0;
  for (Index = 0; Index < NumWords; ++Index) {
    Tmp1      = A[Index];
    Tmp2      = B[Index] + Borrow;
    TmpResult = (Tmp1 - Tmp2);
    //
    // When a subtraction wraps around, the result must be bigger than either
    // operand.
    //
    Borrow = (Tmp2 < Borrow) | (Tmp1 < TmpResult);
    Result[Index] = TmpResult;
  }
}

/**
  Calulates the difference of A and B.
  A must have the same precision as B. Result must have a precision at most as
  bit as A and B.

  @param[in,out] Result  The buffer to return the result into.
  @param[in]     A       The minuend.
  @param[in]     B       The subtrahend.

**/
VOID
BigNumSub (
  IN OUT OC_BN        *Result,
  IN     CONST OC_BN  *A,
  IN     CONST OC_BN  *B
  )
{
  ASSERT (Result != NULL);
  ASSERT (A != NULL);
  ASSERT (B != NULL);
  ASSERT (A->NumWords == B->NumWords && B->NumWords >= Result->NumWords);
  BigNumDataSub (Result->Words, A->Words, B->Words, Result->NumWords);
}

/**
  Propagates multiplicative Carry from the result at Index - 1 within Result.

  @param[in,out] Result  The number to propagate Carry in.
  @param[in]     Index   The index from which on to add Carry.
  @param[in]     Carry   The carry from the multiplication of Index - 1.

**/
STATIC
VOID
BigNumMulPropagateCarry (
  IN OUT OC_BN       *A,
  IN     UINTN       Index,
  IN     OC_BN_WORD  Carry
  )
{
  OC_BN_WORD Tmp;

  ASSERT (A != NULL);

  for (; Index < A->NumWords && Carry != 0; ++Index) {
    Tmp = A->Words[Index] + Carry;
    //
    // When an addition wraps around, the result must be smaller than either
    // operand.
    //
    Carry           = (Tmp < Carry);
    A->Words[Index] = Tmp;
  }
}

/**
  Returns the number of significant bits in a Word.

  @param[in] Word  The word to gather the number of significant bits of.

  @returns  The number of significant bits in Word.

**/
STATIC
UINT8
BigNumSignificantBitsWord (
  IN OC_BN_WORD  Word
  )
{
  UINT8      NumBits;
  OC_BN_WORD Mask;
  //
  // The values we are receiving are very likely large, thus this approach
  // should be reasonably fast.
  //
  NumBits = OC_BN_WORD_NUM_BITS;
  Mask    = (OC_BN_WORD)1U << (OC_BN_WORD_NUM_BITS - 1);
  while ((Word & Mask) == 0) {
    --NumBits;
    Mask >>= 1U;
  }

  return NumBits;
}

/**
  Returns the most significant word index of A.

  @param[in] A  The number to gather the most significant Word index of.

  @returns  The index of the most significant Word in A.

**/
STATIC
OC_BN_NUM_WORDS
BigNumMostSignificantWord (
  IN CONST OC_BN  *A
  )
{
  OC_BN_NUM_WORDS Index;

  ASSERT (A != NULL);

  Index = A->NumWords;
  do {
    --Index;
    if (A->Words[Index] != 0) {
      return Index;
    }
  } while (Index != 0);

  return 0;
}

/**
  Returns the number of significant bits in a number.
  Logically matches OpenSSL's BN_num_bits.

  @param[in] A  The number to gather the number of significant bits of.

  @returns  The number of significant bits in A.

**/
OC_BN_NUM_BITS
BigNumSignificantBits (
  IN CONST OC_BN  *A
  )
{
  OC_BN_NUM_BITS Index;

  ASSERT (A != NULL);

  Index = BigNumMostSignificantWord (A);
  return ((Index * OC_BN_WORD_NUM_BITS) + BigNumSignificantBitsWord (A->Words[Index]));
}

/**
  Calculates the product of A and B.

  @param[in,out] Result  The buffer to store the result in.
  @param[in]     A       The multiplicant.
  @param[in]     B       The multiplier.

**/
STATIC
VOID
BigNumMul (
  IN OUT OC_BN        *Result,
  IN     CONST OC_BN  *A,
  IN     CONST OC_BN  *B
  )
{
  //
  // Given a better modulo function, this is subject for removal.
  // This algorithm is based on a space-optimised version of the conventional
  // Long Multiplication.
  // https://en.wikipedia.org/wiki/Multiplication_algorithm#Optimizing_space_complexity
  //
  OC_BN_WORD CurWord;
  OC_BN_WORD MulHi;
  OC_BN_WORD MulLo;
  OC_BN_WORD CurCarry;

  UINTN      LengthA;
  UINTN      LengthB;
  UINTN      LengthTmp;

  UINTN      IndexRes;
  UINTN      IndexA;
  UINTN      IndexB;

  ASSERT (Result != NULL);
  ASSERT (A != NULL);
  ASSERT (B != NULL);
  ASSERT (A != Result);
  ASSERT (B != Result);

  BigNumAssign0 (Result);
  //
  // These additions cannot overflow because NumWords fits UINTN.
  //
  LengthA = BigNumMostSignificantWord (A) + 1;
  LengthB = BigNumMostSignificantWord (B) + 1;
  //
  // This cannot overflow for sane outputs due to the address space limitation.
  //
  ASSERT (LengthA + LengthB > LengthA);
  //
  // This is required to avoid overflows, which purely internal calls should
  // never produce.
  //
  ASSERT (LengthA + LengthB - 1 < Result->NumWords);

  CurCarry = 0;
  for (IndexRes = 0; IndexRes < LengthA + LengthB - 1; ++IndexRes) {
    //
    // Add the carry from the last iteration.
    //
    CurWord  = Result->Words[IndexRes] + CurCarry;
    CurCarry = (CurWord < CurCarry);
    //
    // When IndexB is out of bounds for B, the value at the requested position
    // would be 0 and hence no calculation would be performed.
    //
    if (IndexRes < LengthB) {
      IndexA    = 0;
      LengthTmp = IndexRes + 1;
      IndexB    = IndexRes;
    } else {
      IndexA    = IndexRes - LengthB + 1;
      LengthTmp = LengthA;
      IndexB    = LengthB - 1;
    }

    for (; IndexA < LengthTmp; ++IndexA, --IndexB) {
      //
      // No arithmetics need to be performed when both operands are 0.
      //
      if ((A->Words[IndexA] | B->Words[IndexB]) == 0) {
        continue;
      }

      MulLo = BigNumWordMul (&MulHi, A->Words[IndexA], B->Words[IndexB]);
      //
      // FIXME:
      // This is hard to read and probably not optimal, however during
      // simplification of various operations, it turned out multiplication
      // itself is only required as part of the current modulo implementation.
      // Instead of cleaning and tweaking this algorithm, an optimised modulo
      // algorithm that does not depend on this multiplication algorithm should
      // be found and imported, rendering this function subject for removal.
      //
      CurCarry += MulHi;
      if (CurCarry < MulHi) {
        //
        // If the current Carry overflows, propagate a carry of maximum value
        // upwards and start counting anew.
        //
        BigNumMulPropagateCarry (Result, IndexRes + 1, OC_BN_MAX_VAL);
        ++CurCarry;
      }

      CurWord += MulLo;
      if (CurWord < MulLo) {
        CurCarry += 1;
        if (CurCarry < 1) {
          //
          // If the current Carry overflows, propagate a carry of maximum value
          // upwards and start counting anew.
          //
          BigNumMulPropagateCarry (Result, IndexRes + 1, OC_BN_MAX_VAL);
          ++CurCarry;
        }
      }
    }

    Result->Words[IndexRes] = CurWord;
  }
  //
  // Set the MSB to the carry of the last iteration.
  //
  Result->Words[IndexRes] = CurCarry;
}

/**
  Calculates the binary union of A and (Value << Exponent).

  @param[in,out] A         The number to OR with and store the result into.
  @param[in]     Value     The Word value to OR with.
  @param[in]     Exponent  The Word shift exponent.

**/
VOID
BigNumOrWord (
  IN OUT OC_BN       *A,
  IN     OC_BN_WORD  Value,
  IN     UINTN       Exponent
  )
{
  UINTN WordIndex;
  UINT8 NumBits;

  ASSERT (A != NULL);
  ASSERT (Exponent / OC_BN_WORD_NUM_BITS < A->NumWords);

  WordIndex = Exponent / OC_BN_WORD_NUM_BITS;
  if (WordIndex < A->NumWords) {
    NumBits = Exponent % OC_BN_WORD_NUM_BITS;
    A->Words[WordIndex] |= (Value << NumBits);
  }
}

/**
  Returns the relative order of A and B. A and B must have the same precision.

  @param[in] A  The first number to compare.
  @param[in] B  The second number to compare.

  @retval < 0  A is lower than B.
  @retval 0    A is as big as B.
  @retval > 0  A is greater than B.

**/
INTN
BigNumDataCmp (
  IN CONST OC_BN_WORD  *A,
  IN CONST OC_BN_WORD  *B,
  IN OC_BN_NUM_WORDS   NumWords
  )
{
  UINTN Index;

  ASSERT (A != NULL);
  ASSERT (B != NULL);

  Index = NumWords;
  do {
    --Index;
    if (A[Index] > B[Index]) {
      return 1;
    } else if (A[Index] < B[Index]) {
      return -1;
    }
  } while (Index != 0);

  return 0;
}

/**
  Returns the relative order of A and B. A and B must have the same precision.

  @param[in] A  The first number to compare.
  @param[in] B  The second number to compare.

  @retval < 0  A is lower than B.
  @retval 0    A is as big as B.
  @retval > 0  A is greater than B.

**/
STATIC
INTN
BigNumCmp (
  IN CONST OC_BN  *A,
  IN CONST OC_BN  *B
  )
{
  ASSERT (A != NULL);
  ASSERT (B != NULL);
  ASSERT (A->NumWords == B->NumWords);

  return BigNumDataCmp (A->Words, B->Words, A->NumWords);
}

/**
  Calculates the left-shift of A by Exponent Bits.

  @param[in,out] Result    The buffer to return the result into.
  @param[in]     A         The number to shift.
  @param[in]     Exponent  The amount of Bits to shift by.

**/
STATIC
VOID
BigNumLeftShift (
  IN OUT OC_BN        *Result,
  IN     CONST OC_BN  *A,
  IN     UINTN        Exponent
  )
{
  UINTN NumWords;
  UINT8 NumBits;

  ASSERT (Result != NULL);
  ASSERT (A != NULL);

  NumWords = Exponent / OC_BN_WORD_NUM_BITS;
  NumBits  = Exponent % OC_BN_WORD_NUM_BITS;

  if (NumBits != 0) {
    BigNumLeftShiftWordsAndBits (Result, A, NumWords, NumBits);
  } else {
    BigNumLeftShiftWords (Result, A, NumWords);
  }
}

/**
  Calculates the quotient of A and B.

  @param[in,out] Result  The buffer to return the result into.
  @param[in]     A       The dividend.
  @param[in]     B       The divisor.

  @returns  Whether the operation was completes successfully.

**/
STATIC
VOID
BigNumDiv (
  IN OUT OC_BN        *Result,
  IN     CONST OC_BN  *A,
  IN     CONST OC_BN  *B,
  IN     OC_BN        *DenomBuf,
  IN     OC_BN        *DividendBuf
  )
{
  //
  // As for multiplication, this is subject for removal.
  //
  UINTN   CurBitIndex;
  BOOLEAN Overflow;

  UINT32  NumBitsA;
  UINT32  NumBitsB;

  ASSERT (Result != NULL);
  ASSERT (A != NULL);
  ASSERT (B != NULL);
  ASSERT (DenomBuf != NULL);
  ASSERT (DividendBuf != NULL);
  ASSERT (Result->NumWords == A->NumWords);
  ASSERT (DenomBuf->NumWords    == A->NumWords);
  ASSERT (DividendBuf->NumWords == A->NumWords);
  //
  // Use an integer of natural size to store the current Bit index as 'current'
  // is always a 2's potency. While a BIGNUM can theoretically hold a
  // 2's potency eight times larger than what can represent as Bit index with a
  // natural integer (Bytes vs Bits), this cannot happen within this function
  // as 'a' aligned to the next 2's potency would need to be just as big for
  // this to be the case. This cannot happen due to the address space
  // limitation.
  //
  CurBitIndex = 0;
  Overflow    = FALSE;
  //
  // Shift b to the left so it has the same amount of significant bits as a.
  // This would, without this speedup, be done on per-bit basis by the loop
  // below.
  //
  NumBitsA = BigNumSignificantBits (A);
  NumBitsB = BigNumSignificantBits (B);
  if (NumBitsA > NumBitsB) {
    CurBitIndex = NumBitsA - NumBitsB;                // int Current = 1 << (numBitsA - numBitsB);
    BigNumLeftShift (DenomBuf, B, CurBitIndex);       // Denom = B << CurBitIndex
  } else {
    CurBitIndex = 0;                                  // int Current = 1;
    BigNumAssign (DenomBuf, B);                       // Denom = B
  }

  while (BigNumCmp (DenomBuf, A) <= 0) {              // while (Denom <= a) {
    if (DenomBuf->Words[DenomBuf->NumWords - 1] > (OC_BN_MAX_VAL / 2U)) {
      Overflow = TRUE;
      break;
    }
    ++CurBitIndex;                                    //   Current <<= 1;                 
    BigNumLeftShiftBitsSmall (DenomBuf, 1);           //   Denom   <<= 1;
  }
  if (!Overflow) {
    BigNumRightShiftBitsSmall (DenomBuf, 1);          // Denom   >>= 1;
    --CurBitIndex;                                    // Current >>= 1;                 
  }
  BigNumAssign0 (Result);                             // int Result = 0;
  BigNumAssign (DividendBuf, A);                      // Dividend = A
  //
  // currentBitIndex cannot add-wraparound to reach this value as reasoned in
  // the comment before.
  //
  while (CurBitIndex != (0ULL - 1ULL)) {              // while (Current != 0)
    if (BigNumCmp (DividendBuf, DenomBuf) >= 0) {     //   if (Dividend >= Denom)
      BigNumSub (DividendBuf, DividendBuf, DenomBuf); //     Dividend -= denom;            
      BigNumOrWord (Result, 1, CurBitIndex);     //     Result |= current;
    }
    --CurBitIndex;                                    //   Current >>= 1;
    BigNumRightShiftBitsSmall (DenomBuf, 1);          //   Denom >>= 1;
  }                                                   // return Result;
}

/**
  Calculates the remainder of A and B.

  @param[in,out] Result  The buffer to return the result into.
  @param[in]     A       The dividend.
  @param[in]     B       The divisor.

  @returns  Whether the operation was completes successfully.

**/
BOOLEAN
BigNumMod (
  IN OUT OC_BN        *Result,
  IN     CONST OC_BN  *A,
  IN     CONST OC_BN  *B
  )
{
  //
  // FIXME:
  // The algorithm is rather expensive and slow. It utilitises the current
  // suboptimal multiplication and division algorithms. An optimised algorithm
  // should be imported and formerly mentioned functions be removed as they'd
  // be dead code.
  //
  UINTN TempsBnSize;

  VOID  *Memory;
  OC_BN *TmpDiv;
  OC_BN *TmpMod;
  OC_BN *TmpDenom;
  OC_BN *TmpDividend;

  ASSERT (Result != NULL);
  ASSERT (A != NULL);
  ASSERT (B != NULL);

  OC_STATIC_ASSERT (
    OC_BN_MAX_SIZE <= MAX_UINTN / 4,
    "An overflow verification must be added"
    );

  TempsBnSize = OC_BN_SIZE (OC_BN_DSIZE (A));
  Memory      = AllocatePool (4 * TempsBnSize);
  if (Memory == NULL) {
    return FALSE;
  }

  TmpDiv      = Memory;
  TmpMod      = (OC_BN *)((UINTN)TmpDiv   + TempsBnSize);
  TmpDenom    = (OC_BN *)((UINTN)TmpMod   + TempsBnSize);
  TmpDividend = (OC_BN *)((UINTN)TmpDenom + TempsBnSize);

  TmpDiv->NumWords      = A->NumWords;
  TmpMod->NumWords      = A->NumWords;
  TmpDenom->NumWords    = A->NumWords;
  TmpDividend->NumWords = A->NumWords;

  BigNumDiv (TmpDiv, A, B, TmpDenom, TmpDividend);
  BigNumMul (TmpMod, TmpDiv, B);
  BigNumSub (Result, A, TmpMod);

  FreePool (Memory);
  return TRUE;
}

/**
  Parses a data array into a number. The buffer size must be a multiple of the
  Word size. The length of Result must precisely fit the required size.

  @param[in,out] Result      The buffer to store the result in.
  @param[in]     Buffer      The buffer to parse.
  @param[in]     BufferSize  The size, in bytes, of Buffer.
  @param[in]     NumWords    The number of Words of Result.

**/
VOID
BigNumDataParseBuffer (
  IN OUT OC_BN_WORD       *Result,
  IN     CONST UINT8      *Buffer,
  IN     UINTN            BufferSize,
  IN     OC_BN_NUM_WORDS  NumWords
  )
{
  UINTN      Index;
  OC_BN_WORD Tmp;

  ASSERT (Result != NULL);
  ASSERT (Buffer != NULL);
  ASSERT (BufferSize > 0);
  ASSERT (NumWords * OC_BN_WORD_SIZE == BufferSize);
  ASSERT ((BufferSize % OC_BN_WORD_SIZE) == 0);

  for (Index = OC_BN_WORD_SIZE; Index <= BufferSize; Index += OC_BN_WORD_SIZE) {
    if (OC_BN_WORD_SIZE == 4) {
      Tmp = 
        ((OC_BN_WORD)Buffer[(BufferSize - Index) + 0] << 24U) |
        ((OC_BN_WORD)Buffer[(BufferSize - Index) + 1] << 16U) |
        ((OC_BN_WORD)Buffer[(BufferSize - Index) + 2] << 8U) |
        ((OC_BN_WORD)Buffer[(BufferSize - Index) + 3] << 0U);
    } else if (OC_BN_WORD_SIZE == 8) {
      Tmp =
        ((OC_BN_WORD)Buffer[(BufferSize - Index) + 0] << 56U) |
        ((OC_BN_WORD)Buffer[(BufferSize - Index) + 1] << 48U) |
        ((OC_BN_WORD)Buffer[(BufferSize - Index) + 2] << 40U) |
        ((OC_BN_WORD)Buffer[(BufferSize - Index) + 3] << 32U) |
        ((OC_BN_WORD)Buffer[(BufferSize - Index) + 4] << 24U) |
        ((OC_BN_WORD)Buffer[(BufferSize - Index) + 5] << 16U) |
        ((OC_BN_WORD)Buffer[(BufferSize - Index) + 6] << 8U) |
        ((OC_BN_WORD)Buffer[(BufferSize - Index) + 7] << 0U);
    }

    Result[(Index / OC_BN_WORD_SIZE) - 1] = Tmp;
  }
}

/**
  Parses a data array into a number. The buffer size must be a multiple of the
  Word size. The length of Result must precisely fit the required size.

  @param[in,out] Result      The buffer to store the result in.
  @param[in]     Buffer      The buffer to parse.
  @param[in]     BufferSize  The size, in bytes, of Buffer.

**/
VOID
BigNumParseBuffer (
  IN OUT OC_BN        *Result,
  IN     CONST UINT8  *Buffer,
  IN     UINTN        BufferSize
  )
{
  ASSERT (Result != NULL);
  ASSERT (Buffer != NULL);
  ASSERT (BufferSize > 0);

  BigNumDataParseBuffer (
    Result->Words,
    Buffer,
    BufferSize,
    Result->NumWords
    );
}
