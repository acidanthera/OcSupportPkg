#include <Base.h>

#include <Library/OcCryptoLib.h>
#include <Library/OcAppleKeysLib.h>

#include <BigNumLib.h>

int main (void)
{
  UINT32     Index;
  OC_BN_WORD N0Inv;

  for (Index = 0; Index < ARRAY_SIZE (PkDataBase); ++Index) {
    UINTN ModulusSize = PkDataBase[Index].PublicKey->Hdr.NumQwords * sizeof (UINT64);

    OC_BN_WORD *RSqrMod = malloc(ModulusSize);
    if (RSqrMod == NULL) {
      printf ("memory allocation error!\n");
      return -1;
    }

    N0Inv = BigNumCalculateMontParams (
              RSqrMod,
              ModulusSize / OC_BN_WORD_SIZE,
              PkDataBase[Index].PublicKey->Data
              );

    printf (
      "Key %u: results: %d %d\n",
      Index + 1,
      memcmp (
        RSqrMod,
        &PkDataBase[Index].PublicKey->Data[PkDataBase[Index].PublicKey->Hdr.NumQwords],
        ModulusSize
        ),
      N0Inv != PkDataBase[Index].PublicKey->Hdr.N0Inv
      );

    free(RSqrMod);
  }

  return 0;
}
