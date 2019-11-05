/** @file
  Copyright (C) 2019, vit9696. All rights reserved.

  All rights reserved.

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include <Uefi.h>
#include <Guid/FileInfo.h>
#include <Protocol/SimpleFileSystem.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/OcStringLib.h>
#include <Library/OcStorageLib.h>
#include <Library/UefiBootServicesTableLib.h>

OC_STRUCTORS (OC_STORAGE_VAULT_HASH, ())
OC_MAP_STRUCTORS (OC_STORAGE_VAULT_FILES)
OC_STRUCTORS (OC_STORAGE_VAULT, ())

#pragma pack(push, 1)

typedef PACKED struct {
  VENDOR_DEFINED_DEVICE_PATH Vendor;
  EFI_DEVICE_PATH_PROTOCOL   End;
} DUMMY_BOOT_DEVICE_PATH;

typedef PACKED struct {
  VENDOR_DEFINED_DEVICE_PATH Vendor;
  VENDOR_DEFINED_DEVICE_PATH VendorFile;
  EFI_DEVICE_PATH_PROTOCOL   End;
} DUMMY_BOOT_DEVICE_FILE_PATH;

#pragma pack(pop)

//
// We do not want to expose these for the time being!.
//

#define INTERNAL_STORAGE_GUID \
  { 0x33B5C65A, 0x5B82, 0x403D, {0x87, 0xA5, 0xD4, 0x67, 0x62, 0x50, 0xEC, 0x59} }

#define INTERNAL_STORAGE_FILE_GUID \
  { 0x1237EC17, 0xD3CE, 0x401D, {0xA8, 0x41, 0xB1, 0xD8, 0x18, 0xF8, 0xAF, 0x1A} }

STATIC
DUMMY_BOOT_DEVICE_PATH
mDummyBootDevicePath = {
  .Vendor = {
    .Header = {
      .Type    = HARDWARE_DEVICE_PATH,
      .SubType = HW_VENDOR_DP,
      .Length  = {sizeof (VENDOR_DEFINED_DEVICE_PATH), 0}
    },
    .Guid = INTERNAL_STORAGE_GUID
  },
  .End = {
    .Type    = END_DEVICE_PATH_TYPE,
    .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
    .Length  = {END_DEVICE_PATH_LENGTH, 0}
  }
};

STATIC
DUMMY_BOOT_DEVICE_FILE_PATH
mDummyBootDeviceFilePath = {
  .Vendor = {
    .Header = {
      .Type    = HARDWARE_DEVICE_PATH,
      .SubType = HW_VENDOR_DP,
      .Length  = {sizeof (VENDOR_DEFINED_DEVICE_PATH), 0}
    },
    .Guid = INTERNAL_STORAGE_GUID
  },
  .VendorFile = {
    .Header = {
      .Type    = HARDWARE_DEVICE_PATH,
      .SubType = HW_VENDOR_DP,
      .Length  = {sizeof (VENDOR_DEFINED_DEVICE_PATH), 0}
    },
    .Guid = INTERNAL_STORAGE_FILE_GUID
  },
  .End = {
    .Type    = END_DEVICE_PATH_TYPE,
    .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
    .Length  = {END_DEVICE_PATH_LENGTH, 0}
  }
};

STATIC
OC_SCHEMA
mVaultFilesSchema = OC_SCHEMA_DATAF (NULL, UINT8 [SHA256_DIGEST_SIZE]);

///
/// WARNING: Field list must be alpabetically ordered here!
///
STATIC
OC_SCHEMA
mVaultNodesSchema[] = {
  OC_SCHEMA_MAP_IN     ("Files",   OC_STORAGE_VAULT, Files, &mVaultFilesSchema),
  OC_SCHEMA_INTEGER_IN ("Version", OC_STORAGE_VAULT, Version),
};

STATIC
OC_SCHEMA_INFO
mVaultSchema = {
  .Dict = {mVaultNodesSchema, ARRAY_SIZE (mVaultNodesSchema)}
};


STATIC
EFI_STATUS
OcStorageInitializeVault (
  IN OUT OC_STORAGE_CONTEXT  *Context,
  IN     VOID                *Vault        OPTIONAL,
  IN     UINT32              VaultSize,
  IN     OC_RSA_PUBLIC_KEY   *StorageKey   OPTIONAL,
  IN     VOID                *Signature    OPTIONAL,
  IN     UINT32              SignatureSize OPTIONAL
  )
{
  if (Signature != NULL && Vault == NULL) {
    DEBUG ((DEBUG_ERROR, "OCS: Missing vault with signature\n"));
    return EFI_SECURITY_VIOLATION;
  }

  if (Vault == NULL) {
    DEBUG ((DEBUG_INFO, "OCS: Missing vault data, ignoring...\n"));
    return EFI_SUCCESS;
  }

  if (Signature != NULL) {
    ASSERT (StorageKey != NULL);

    if (!RsaVerifySigDataFromKey (StorageKey, Signature, SignatureSize, Vault, VaultSize, OcSigHashTypeSha256)) {
      DEBUG ((DEBUG_ERROR, "OCS: Invalid vault signature\n"));
      return EFI_SECURITY_VIOLATION;
    }
  }

  OC_STORAGE_VAULT_CONSTRUCT (&Context->Vault, sizeof (Context->Vault));
  if (!ParseSerialized (&Context->Vault, &mVaultSchema, Vault, VaultSize)) {
    OC_STORAGE_VAULT_DESTRUCT (&Context->Vault, sizeof (Context->Vault));
    DEBUG ((DEBUG_ERROR, "OCS: Invalid vault data\n"));
    return EFI_INVALID_PARAMETER;
  }

  if (Context->Vault.Version != OC_STORAGE_VAULT_VERSION) {
    OC_STORAGE_VAULT_DESTRUCT (&Context->Vault, sizeof (Context->Vault));
    DEBUG ((
      DEBUG_ERROR,
      "OCS: Unsupported vault data verion %u vs %u\n",
      Context->Vault.Version,
      OC_STORAGE_VAULT_VERSION
      ));
    return EFI_UNSUPPORTED;
  }

  Context->HasVault = TRUE;

  return EFI_SUCCESS;
}

STATIC
UINT8 *
OcStorageGetDigest (
  IN OUT OC_STORAGE_CONTEXT  *Context,
  IN     CONST CHAR16        *Filename
  )
{
  UINT32             Index;
  UINTN              StrIndex;
  CHAR8              *VaultFilePath;
  UINTN              FilenameSize;

  if (!Context->HasVault) {
    return NULL;
  }

  FilenameSize = StrLen (Filename) + 1;

  for (Index = 0; Index < Context->Vault.Files.Count; ++Index) {
    if (Context->Vault.Files.Keys[Index]->Size != (UINT32) FilenameSize) {
      continue;
    }

    VaultFilePath = OC_BLOB_GET (Context->Vault.Files.Keys[Index]);

    for (StrIndex = 0; StrIndex < FilenameSize; ++StrIndex) {
      if (Filename[StrIndex] != VaultFilePath[StrIndex]) {
        break;
      }
    }

    if (StrIndex == FilenameSize) {
      return &Context->Vault.Files.Values[Index]->Hash[0];
    }
  }

  return NULL;
}

EFI_STATUS
OcStorageInitFromFs (
  OUT OC_STORAGE_CONTEXT               *Context,
  IN  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *FileSystem,
  IN  CONST CHAR16                     *Path,
  IN  OC_RSA_PUBLIC_KEY                *StorageKey OPTIONAL
  )
{
  EFI_STATUS         Status;
  EFI_FILE_PROTOCOL  *RootVolume;
  VOID               *Vault;
  VOID               *Signature;
  UINT32             DataSize;
  UINT32             SignatureSize;

  ZeroMem (Context, sizeof (*Context));

  Context->FileSystem = FileSystem;

  Status = FileSystem->OpenVolume (FileSystem, &RootVolume);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "OCS: FileSystem volume cannot be opened - %r\n", Status));
    return Status;
  }

  Status = RootVolume->Open (
    RootVolume,
    &Context->StorageRoot,
    (CHAR16 *) Path,
    EFI_FILE_MODE_READ,
    0
    );

  RootVolume->Close (RootVolume);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "OCS: Directory %s cannot be opened - %r\n", Path, Status));
    return Status;
  }

  SignatureSize = 0;

  if (StorageKey) {
    Signature = OcStorageReadFileUnicode (
      Context,
      OC_STORAGE_VAULT_SIGNATURE_PATH,
      &SignatureSize
      );

    if (Signature == NULL) {
      DEBUG ((DEBUG_ERROR, "OCS: Missing vault signature\n"));
      OcStorageFree (Context);
      return EFI_SECURITY_VIOLATION;
    }
  } else {
    Signature = NULL;
  }

  DataSize = 0;
  Vault = OcStorageReadFileUnicode (
    Context,
    OC_STORAGE_VAULT_PATH,
    &DataSize
    );

  Status = OcStorageInitializeVault (Context, Vault, DataSize, StorageKey, Signature, SignatureSize);

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "OCS: Vault init failure %p (%u) - %r\n", Vault, DataSize, Status));
  }

  gBS->InstallProtocolInterface (
    &Context->StorageHandle,
    &gEfiDevicePathProtocolGuid,
    EFI_NATIVE_INTERFACE,
    &mDummyBootDevicePath
    );
  Context->DummyDevicePath = (EFI_DEVICE_PATH_PROTOCOL *) &mDummyBootDeviceFilePath;

  if (Signature != NULL) {
    FreePool (Signature);
  }

  if (Vault != NULL) {
    FreePool (Vault);
  }

  return Status;
}

VOID
OcStorageFree (
  IN OUT OC_STORAGE_CONTEXT            *Context
  )
{
  if (Context->StorageRoot != NULL) {
    Context->StorageRoot->Close (Context->StorageRoot);
    Context->StorageRoot = NULL;
  }

  if (Context->HasVault) {
    OC_STORAGE_VAULT_DESTRUCT (&Context->Vault, sizeof (Context->Vault));
    Context->HasVault = FALSE;
  }
}

VOID *
OcStorageReadFileUnicode (
  IN  OC_STORAGE_CONTEXT               *Context,
  IN  CONST CHAR16                     *FilePath,
  OUT UINT32                           *FileSize OPTIONAL
  )
{
  EFI_STATUS         Status;
  EFI_FILE_PROTOCOL  *File;
  UINT32             Size;
  UINT8              *FileBuffer;
  UINT8              *VaultDigest;
  UINT8              FileDigest[SHA256_DIGEST_SIZE];

  //
  // Using this API with empty filename is also not allowed.
  //
  ASSERT (Context != NULL);
  ASSERT (FilePath != NULL);
  ASSERT (StrLen (FilePath) > 0);

  VaultDigest = OcStorageGetDigest (Context, FilePath);

  if (Context->HasVault && VaultDigest == NULL) {
    DEBUG ((DEBUG_ERROR, "OCS: Aborting %s file access not present in vault\n", FilePath));
    return NULL;
  }

  if (Context->StorageRoot == NULL) {
    //
    // TODO: expand support for other contexts.
    //
    return NULL;
  }

  Status = Context->StorageRoot->Open (
    Context->StorageRoot,
    &File,
    (CHAR16 *) FilePath,
    EFI_FILE_MODE_READ,
    0
    );

  if (EFI_ERROR (Status)) {
    return NULL;
  }

  Status = GetFileSize (File, &Size);
  if (EFI_ERROR (Status) || Size >= MAX_UINT32 - 1) {
    File->Close (File);
    return NULL;
  }

  FileBuffer = AllocatePool (Size + 2);
  if (FileBuffer == NULL) {
    File->Close (File);
    return NULL;
  }

  Status = GetFileData (File, 0, Size, FileBuffer);
  File->Close (File);
  if (EFI_ERROR (Status)) {
    FreePool (FileBuffer);
    return NULL;
  }

  if (VaultDigest != 0) {
    Sha256 (FileDigest, FileBuffer, Size);
    if (CompareMem (FileDigest, VaultDigest, SHA256_DIGEST_SIZE) != 0) {
      DEBUG ((DEBUG_ERROR, "OCS: Aborting corrupted %s file access\n", FilePath));
      FreePool (FileBuffer);
      return NULL;
    }
  }

  FileBuffer[Size]     = 0;
  FileBuffer[Size + 1] = 0;

  if (FileSize != NULL) {
    *FileSize = Size;
  }

  return FileBuffer;
}
