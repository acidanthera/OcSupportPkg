/** @file
  Copyright (C) 2013, dmazar. All rights reserved.
  Copyright (C) 2017, vit9696. All rights reserved.

  All rights reserved.

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include "BootCompatInternal.h"

#include <Guid/OcVariables.h>

#include <IndustryStandard/AppleHibernate.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/OcBootManagementLib.h>
#include <Library/OcMemoryLib.h>
#include <Library/OcMiscLib.h>
#include <Library/OcStringLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Protocol/OcFirmwareRuntime.h>

/**
  Helper function to call ExitBootServices that can handle outdated MapKey issues.

  @param[in]  ExitBootServices  ExitBootServices function pointer, optional.
  @param[in]  GetMemoryMap      GetMemoryMap function pointer, optional.
  @param[in]  ImageHandle       Image handle to call ExitBootServices on.
  @param[in]  MapKey            MapKey to call ExitBootServices on.

  @retval EFI_SUCCESS on success.
**/
STATIC
EFI_STATUS
ForceExitBootServices (
  IN EFI_HANDLE              ImageHandle,
  IN UINTN                   MapKey,
  IN EFI_EXIT_BOOT_SERVICES  ExitBootServices  OPTIONAL,
  IN EFI_GET_MEMORY_MAP      GetMemoryMap  OPTIONAL
  )
{
  EFI_STATUS               Status;
  EFI_MEMORY_DESCRIPTOR    *MemoryMap;
  UINTN                    MemoryMapSize;
  UINTN                    DescriptorSize;
  UINT32                   DescriptorVersion;

  if (ExitBootServices == NULL) {
    ExitBootServices = gBS->ExitBootServices;
  }

  if (GetMemoryMap == NULL) {
    GetMemoryMap = gBS->GetMemoryMap;
  }

  //
  // Firstly try the easy way.
  //
  Status = ExitBootServices (ImageHandle, MapKey);

  if (EFI_ERROR (Status)) {
    //
    // It is too late to free memory map here, but it does not matter, because boot.efi has an old one
    // and will freely use the memory.
    // It is technically forbidden to allocate pool memory here, but we should not hit this code
    // in the first place, and for older firmwares, where it was necessary (?), it worked just fine.
    //
    Status = GetCurrentMemoryMapAlloc (
      &MemoryMapSize,
      &MemoryMap,
      &MapKey,
      &DescriptorSize,
      &DescriptorVersion,
      GetMemoryMap,
      NULL
      );
    if (Status == EFI_SUCCESS) {
      //
      // We have the latest memory map and its key, try again!
      //
      Status = ExitBootServices (ImageHandle, MapKey);
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_WARN, "OCABC: ExitBootServices failed twice - %r\n", Status));
      }
    } else {
      DEBUG ((DEBUG_WARN, "OCABC: Failed to get MapKey for ExitBootServices - %r\n", Status));
      Status = EFI_INVALID_PARAMETER;
    }

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_WARN, "OCABC: Waiting 10 secs...\n"));
      gBS->Stall (SECONDS_TO_MICROSECONDS (10));
    }
  }

  return Status;
}

/**
  Protect CSM region in memory map from relocation.

  @param[in,out]  MemoryMapSize      Memory map size in bytes, updated on shrink.
  @param[in,out]  MemoryMap          Memory map to shrink.
  @param[in]      DescriptorSize     Memory map descriptor size in bytes.
**/
STATIC
VOID
ProtectCsmRegion (
  IN     UINTN                  MemoryMapSize,
  IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  IN     UINTN                  DescriptorSize
  )
{
  UINTN                   NumEntries;
  UINTN                   Index;
  EFI_MEMORY_DESCRIPTOR   *Desc;
  UINTN                   PhysicalEnd;

  //
  // AMI CSM module allocates up to two regions for legacy video output.
  // 1. For PMM and EBDA areas.
  //    On Ivy Bridge and below it ends at 0xA0000-0x1000-0x1 and has EfiBootServicesCode type.
  //    On Haswell and above it is allocated below 0xA0000 address with the same type.
  // 2. For Intel RC S3 reserved area, fixed from 0x9F000 to 0x9FFFF.
  //    On Sandy Bridge and below it is not present in memory map.
  //    On Ivy Bridge and newer it is present as EfiRuntimeServicesData.
  //    Starting from at least SkyLake it is present as EfiReservedMemoryType.
  //
  // Prior to AptioMemoryFix EfiRuntimeServicesData could have been relocated by boot.efi,
  // and the 2nd region could have been overwritten by the kernel. Now it is no longer the
  // case, and only the 1st region may need special handling.
  // For the 1st region there appear to be (unconfirmed) reports that it may still be accessed
  // after waking from sleep. This does not seem to be valid according to AMI code, but we still
  // protect it in case such systems really exist.
  //
  // Initially researched and fixed on GIGABYTE boards by Slice.
  //

  Desc       = MemoryMap;
  NumEntries = MemoryMapSize / DescriptorSize;

  for (Index = 0; Index < NumEntries; ++Index) {
    if (Desc->NumberOfPages > 0 && Desc->Type == EfiBootServicesData) {
      PhysicalEnd = LAST_DESCRIPTOR_ADDR (Desc) + 1;

      if (PhysicalEnd >= 0x9E000 && PhysicalEnd < 0xA0000) {
        Desc->Type = EfiACPIMemoryNVS;
        break;
      }
    }

    Desc = NEXT_MEMORY_DESCRIPTOR (Desc, DescriptorSize);
  }
}

/**
  UEFI Boot Services StartImage override. Called to start an efi image.
  If this is boot.efi, then our overrides are enabled.
**/
STATIC
EFI_STATUS
EFIAPI
OcStartImage (
  IN     EFI_HANDLE  ImageHandle,
     OUT UINTN       *ExitDataSize,
     OUT CHAR16      **ExitData  OPTIONAL
  )
{
  EFI_STATUS                  Status;
  EFI_LOADED_IMAGE_PROTOCOL   *AppleLoadedImage;
  BOOT_COMPAT_CONTEXT         *BootCompat;
  OC_FWRT_CONFIG              Config;
  UINTN                       DataSize;

  BootCompat        = GetBootCompatContext ();
  AppleLoadedImage  = OcGetAppleBootLoadedImage (ImageHandle);

  //
  // Clear monitoring vars
  //
  BootCompat->ServiceState.MinAllocatedAddr = 0;

  if (AppleLoadedImage != NULL) {
    //
    // Report about macOS being loaded.
    //
    ++BootCompat->ServiceState.AppleBootNestedCount;
    BootCompat->ServiceState.AppleHibernateWake = OcIsAppleHibernateWake ();
    BootCompat->ServiceState.AppleCustomSlide = OcCheckArgumentFromEnv (
      AppleLoadedImage,
      BootCompat->ServicePtrs.GetVariable,
      "slide=",
      L_STR_LEN ("slide=")
      );

    if (BootCompat->Settings.EnableSafeModeSlide) {
      AppleSlideUnlockForSafeMode (
        (UINT8 *) AppleLoadedImage->ImageBase,
        AppleLoadedImage->ImageSize
        );
    }

    AppleMapPrepareBooterState (
      BootCompat,
      AppleLoadedImage,
      BootCompat->ServicePtrs.GetMemoryMap
      );
  }

  if (BootCompat->ServiceState.FwRuntime != NULL) {
    BootCompat->ServiceState.FwRuntime->GetCurrent (&Config);

    //
    // Support for ReadOnly and WriteOnly variables is OpenCore & Lilu security basics.
    // For now always enable it.
    //
    Config.RestrictedVariables = TRUE;

    //
    // Enable Boot#### variable redirection if OpenCore requested it.
    // Do NOT disable it once enabled for stability reasons.
    //
    DataSize = sizeof (Config.BootVariableRedirect);
    BootCompat->ServicePtrs.GetVariable (
      OC_BOOT_REDIRECT_VARIABLE_NAME,
      &gOcVendorVariableGuid,
      NULL,
      &DataSize,
      &Config.BootVariableRedirect
      );

    //
    // Enable Apple-specific changes if requested.
    // Disable them when this is no longer Apple.
    //
    if (BootCompat->ServiceState.AppleBootNestedCount > 0) {
      Config.WriteProtection  = BootCompat->Settings.DisableVariableWrite;
      Config.WriteUnprotector = BootCompat->Settings.EnableWriteUnprotector;
    } else {
      Config.WriteProtection  = FALSE;
      Config.WriteUnprotector = FALSE;
    }

    BootCompat->ServiceState.FwRuntime->SetMain (
      &Config
      );
  }

  Status = BootCompat->ServicePtrs.StartImage (
    ImageHandle,
    ExitDataSize,
    ExitData
    );

  if (AppleLoadedImage != NULL) {
    //
    // We failed but other operating systems should be loadable.
    //
    --BootCompat->ServiceState.AppleBootNestedCount;
  }

  return Status;
}

/**
  UEFI Boot Services AllocatePages override.
  Returns pages from free memory block to boot.efi for kernel boot image.
**/
STATIC
EFI_STATUS
EFIAPI
OcAllocatePages (
  IN     EFI_ALLOCATE_TYPE     Type,
  IN     EFI_MEMORY_TYPE       MemoryType,
  IN     UINTN                 NumberOfPages,
  IN OUT EFI_PHYSICAL_ADDRESS  *Memory
  )
{
  EFI_STATUS              Status;
  BOOT_COMPAT_CONTEXT     *BootCompat;

  BootCompat = GetBootCompatContext ();

  Status = BootCompat->ServicePtrs.AllocatePages (
    Type,
    MemoryType,
    NumberOfPages,
    Memory
    );

  if (!EFI_ERROR (Status) && BootCompat->ServiceState.AppleBootNestedCount > 0) {
    if (Type == AllocateAddress && MemoryType == EfiLoaderData) {
      //
      // Called from boot.efi.
      // Store minimally allocated address to find kernel image start.
      //
      if (BootCompat->ServiceState.MinAllocatedAddr == 0
        || *Memory < BootCompat->ServiceState.MinAllocatedAddr) {
        BootCompat->ServiceState.MinAllocatedAddr = *Memory;
      }
    } else if (BootCompat->ServiceState.AppleHibernateWake
      && Type == AllocateAnyPages && MemoryType == EfiLoaderData
      && BootCompat->ServiceState.HibernateImageAddress == 0) {
      //
      // Called from boot.efi during hibernate wake,
      // first such allocation is for hibernate image
      //
      BootCompat->ServiceState.HibernateImageAddress = *Memory;
    }
  }

  return Status;
}

/**
  UEFI Boot Services GetMemoryMap override.
  Returns shrinked memory map as XNU can handle up to PMAP_MEMORY_REGIONS_SIZE (128) entries.
  Also applies any further memory map alterations as necessary.
**/
STATIC
EFI_STATUS
EFIAPI
OcGetMemoryMap (
  IN OUT UINTN                  *MemoryMapSize,
  IN OUT EFI_MEMORY_DESCRIPTOR  *MemoryMap,
     OUT UINTN                  *MapKey,
     OUT UINTN                  *DescriptorSize,
     OUT UINT32                 *DescriptorVersion
  )
{
  EFI_STATUS            Status;
  BOOT_COMPAT_CONTEXT   *BootCompat;

  BootCompat = GetBootCompatContext ();

  Status = BootCompat->ServicePtrs.GetMemoryMap (
    MemoryMapSize,
    MemoryMap,
    MapKey,
    DescriptorSize,
    DescriptorVersion
    );

  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (BootCompat->ServiceState.AppleBootNestedCount > 0) {
    if (BootCompat->Settings.ProtectCsmRegion) {
      ProtectCsmRegion (
        *MemoryMapSize,
        MemoryMap,
        *DescriptorSize
        );
    }

    if (BootCompat->Settings.ShrinkMemoryMap) {
      ShrinkMemoryMap (
        MemoryMapSize,
        MemoryMap,
        *DescriptorSize
        );
    }

    //
    // Remember some descriptor size, since we will not have it later
    // during hibernate wake to be able to iterate memory map.
    //
    BootCompat->ServiceState.MemoryMapDescriptorSize = *DescriptorSize;
  }

  return Status;
}

/**
  UEFI Boot Services ExitBootServices override.
  Patches kernel entry point with jump to our KernelEntryPatchJumpBack().
**/
STATIC
EFI_STATUS
EFIAPI
OcExitBootServices (
  IN EFI_HANDLE  ImageHandle,
  IN UINTN       MapKey
  )
{
  EFI_STATUS               Status;
  BOOT_COMPAT_CONTEXT      *BootCompat;

  BootCompat = GetBootCompatContext ();

  //
  // For non-macOS operating systems return directly.
  //
  if (BootCompat->ServiceState.AppleBootNestedCount == 0) {
    return BootCompat->ServicePtrs.ExitBootServices (
      ImageHandle,
      MapKey
      );
  }

  if (BootCompat->Settings.ForceExitBootServices) {
    Status = ForceExitBootServices (
      ImageHandle,
      MapKey,
      BootCompat->ServicePtrs.ExitBootServices,
      BootCompat->ServicePtrs.GetMemoryMap
      );
  } else {
    Status = BootCompat->ServicePtrs.ExitBootServices (
      ImageHandle,
      MapKey
      );
  }

  //
  // Abort on error.
  //
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (!BootCompat->ServiceState.AppleHibernateWake) {
    AppleMapPrepareKernelJump (
      BootCompat,
      (UINTN) BootCompat->ServiceState.MinAllocatedAddr,
      FALSE
      );
  } else {
    AppleMapPrepareKernelJump (
      BootCompat,
      (UINTN) BootCompat->ServiceState.HibernateImageAddress,
      TRUE
      );
  }

  return Status;
}

/**
  UEFI Runtime Services SetVirtualAddressMap override.
  Fixes virtualizing of RT services.
**/
STATIC
EFI_STATUS
EFIAPI
OcSetVirtualAddressMap (
  IN UINTN                  MemoryMapSize,
  IN UINTN                  DescriptorSize,
  IN UINT32                 DescriptorVersion,
  IN EFI_MEMORY_DESCRIPTOR  *MemoryMap
  )
{
  EFI_STATUS             Status;
  BOOT_COMPAT_CONTEXT    *BootCompat;

  BootCompat = GetBootCompatContext ();

  //
  // This is the time for us to remove our hacks.
  // Make SetVirtualAddressMap useable once again.
  // We do not need to recover BS, since they already are invalid.
  //
  gRT->SetVirtualAddressMap = BootCompat->ServicePtrs.SetVirtualAddressMap;
  gRT->Hdr.CRC32 = 0;
  gRT->Hdr.CRC32 = CalculateCrc32 (gRT, gRT->Hdr.HeaderSize);

  if (BootCompat->ServiceState.AppleBootNestedCount == 0) {
    Status = gRT->SetVirtualAddressMap (
      MemoryMapSize,
      DescriptorSize,
      DescriptorVersion,
      MemoryMap
      );
  } else {
    Status = AppleMapPrepareMemState (
      BootCompat,
      MemoryMapSize,
      DescriptorSize,
      DescriptorVersion,
      MemoryMap
      );
  }

  return Status;
}

/**
  UEFI Runtime Services GetVariable override.
  Used to return customised values for boot-args and csr-active-config variables.
**/
STATIC
EFI_STATUS
EFIAPI
OcGetVariable (
  IN     CHAR16    *VariableName,
  IN     EFI_GUID  *VendorGuid,
  OUT    UINT32    *Attributes OPTIONAL,
  IN OUT UINTN     *DataSize,
  OUT    VOID      *Data
  )
{
  EFI_STATUS             Status;
  BOOT_COMPAT_CONTEXT    *BootCompat;

  BootCompat = GetBootCompatContext ();

  if (BootCompat->ServiceState.AppleBootNestedCount > 0
    && BootCompat->Settings.ProvideCustomSlide) {
    Status = AppleSlideGetVariable (
      BootCompat,
      BootCompat->ServicePtrs.GetVariable,
      BootCompat->ServicePtrs.GetMemoryMap,
      VariableName,
      VendorGuid,
      Attributes,
      DataSize,
      Data
      );
  } else {
    Status = BootCompat->ServicePtrs.GetVariable (
      VariableName,
      VendorGuid,
      Attributes,
      DataSize,
      Data
      );
  }

  return Status;
}

/**
  UEFI Runtime Services GetVariable override event handler.
  We do not override GetVariable ourselves but let our runtime do that.

  @param[in]  Event    Event handle.
  @param[in]  Context  Apple boot compatibility context.
**/
STATIC
VOID
EFIAPI
SetGetVariableHookHandler (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS                    Status;
  OC_FIRMWARE_RUNTIME_PROTOCOL  *FwRuntime;
  BOOT_COMPAT_CONTEXT           *BootCompat;

  BootCompat = (BOOT_COMPAT_CONTEXT *) Context;

  if (BootCompat->ServicePtrs.GetVariable == NULL) {
    Status = gBS->LocateProtocol (
      &gOcFirmwareRuntimeProtocolGuid,
      NULL,
      (VOID **) &FwRuntime
      );

    if (!EFI_ERROR (Status) && FwRuntime->Revision == OC_FIRMWARE_RUNTIME_REVISION) {
      Status = FwRuntime->OnGetVariable (OcGetVariable, &BootCompat->ServicePtrs.GetVariable);
    } else {
      Status = EFI_UNSUPPORTED;
    }

    //
    // Mark protocol as useable.
    //
    if (!EFI_ERROR (Status)) {
      BootCompat->ServiceState.FwRuntime = FwRuntime;
    }
  }
}

VOID
InstallServiceOverrides (
  IN OUT BOOT_COMPAT_CONTEXT  *BootCompat
  )
{
  EFI_STATUS              Status;
  VOID                    *Registration;
  UEFI_SERVICES_POINTERS  *ServicePtrs;
  EFI_TPL                 OriginalTpl;

  ServicePtrs = &BootCompat->ServicePtrs;

  OriginalTpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);

  ServicePtrs->AllocatePages        = gBS->AllocatePages;
  ServicePtrs->GetMemoryMap         = gBS->GetMemoryMap;
  ServicePtrs->ExitBootServices     = gBS->ExitBootServices;
  ServicePtrs->StartImage           = gBS->StartImage;
  ServicePtrs->SetVirtualAddressMap = gRT->SetVirtualAddressMap;

  gBS->AllocatePages        = OcAllocatePages;
  gBS->GetMemoryMap         = OcGetMemoryMap;
  gBS->ExitBootServices     = OcExitBootServices;
  gBS->StartImage           = OcStartImage;
  gRT->SetVirtualAddressMap = OcSetVirtualAddressMap;

  gBS->Hdr.CRC32 = 0;
  gBS->Hdr.CRC32 = CalculateCrc32 (gBS, gBS->Hdr.HeaderSize);

  gRT->Hdr.CRC32 = 0;
  gRT->Hdr.CRC32 = CalculateCrc32 (gRT, gRT->Hdr.HeaderSize);

  gBS->RestoreTPL (OriginalTpl);

  //
  // Allocate memory pool if needed.
  //
  if (BootCompat->Settings.SetupVirtualMap) {
    AppleMapPrepareMemoryPool (
      BootCompat
      );
  }

  //
  // Update GetVariable handle with the help of external runtime services.
  //
  SetGetVariableHookHandler (NULL, BootCompat);

  if (BootCompat->ServicePtrs.GetVariable != NULL) {
    return;
  }

  Status = gBS->CreateEvent (
    EVT_NOTIFY_SIGNAL,
    TPL_NOTIFY,
    SetGetVariableHookHandler,
    BootCompat,
    &BootCompat->ServiceState.GetVariableEvent
    );

  if (!EFI_ERROR (Status)) {
    Status = gBS->RegisterProtocolNotify (
      &gOcFirmwareRuntimeProtocolGuid,
      BootCompat->ServiceState.GetVariableEvent,
      &Registration
      );

    if (EFI_ERROR (Status)) {
      gBS->CloseEvent (&BootCompat->ServiceState.GetVariableEvent);
    }
  }
}
