/** @file
  Commonly used kext patches.

Copyright (c) 2018, vit9696. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Base.h>

#include <IndustryStandard/AppleIntelCpuInfo.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/OcAppleKernelLib.h>
#include <Library/PrintLib.h>
#include <Library/OcFileLib.h>
#include <Library/UefiLib.h>

STATIC
UINT8
mAppleIntelCPUPowerManagementPatchFind[] = {
  0xB9, 0xE2, 0x00, 0x00, 0x00,     // mov ecx, 0xe2
  0x0F, 0x30                        // wrmsr
};

STATIC
UINT8
mAppleIntelCPUPowerManagementPatchReplace[] = {
  0xB9, 0xE2, 0x00, 0x00, 0x00,     // mov ecx, 0xe2
  0x90, 0x90                        // nop nop
};

STATIC
PATCHER_GENERIC_PATCH
mAppleIntelCPUPowerManagementPatch = {
  .Base        = NULL,
  .Find        = mAppleIntelCPUPowerManagementPatchFind,
  .Mask        = NULL,
  .Replace     = mAppleIntelCPUPowerManagementPatchReplace,
  .ReplaceMask = NULL,
  .Size        = sizeof (mAppleIntelCPUPowerManagementPatchFind),
  .Count       = 0,
  .Skip        = 0
};

STATIC
UINT8
mAppleIntelCPUPowerManagementPatch2Find[] = {
  0xB9, 0xE2, 0x00, 0x00, 0x00,       // mov ecx, 0xe2
  0x48, 0x89, 0xF0,                   // mov rax, <some register>
  0x0F, 0x30                          // wrmsr
};

STATIC
UINT8
mAppleIntelCPUPowerManagementPatch2FindMask[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xF0,
  0xFF, 0xFF
};

STATIC
UINT8
mAppleIntelCPUPowerManagementPatch2Replace[] = {
  0x00, 0x00, 0x00, 0x00, 0x00,       // leave as is
  0x00, 0x00, 0x00,                   // leave as is
  0x90, 0x90                          // nop nop
};

STATIC
UINT8
mAppleIntelCPUPowerManagementPatch2ReplaceMask[] = {
  0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00,
  0xFF, 0xFF
};

STATIC
PATCHER_GENERIC_PATCH
mAppleIntelCPUPowerManagementPatch2 = {
  .Base        = NULL,
  .Find        = mAppleIntelCPUPowerManagementPatch2Find,
  .Mask        = mAppleIntelCPUPowerManagementPatch2FindMask,
  .Replace     = mAppleIntelCPUPowerManagementPatch2Replace,
  .ReplaceMask = mAppleIntelCPUPowerManagementPatch2ReplaceMask,
  .Size        = sizeof (mAppleIntelCPUPowerManagementPatch2Find),
  .Count       = 0,
  .Skip        = 0
};

RETURN_STATUS
PatchAppleCpuPmCfgLock (
  IN OUT PRELINKED_CONTEXT  *Context
  )
{
  RETURN_STATUS       Status;
  RETURN_STATUS       Status2;
  PATCHER_CONTEXT     Patcher;

  Status = PatcherInitContextFromPrelinked (
    &Patcher,
    Context,
    "com.apple.driver.AppleIntelCPUPowerManagement"
    );

  if (!RETURN_ERROR (Status)) {
    Status = PatcherApplyGenericPatch (&Patcher, &mAppleIntelCPUPowerManagementPatch);
    if (!RETURN_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "OCAK: Patch v1 success com.apple.driver.AppleIntelCPUPowerManagement\n"));
    }

    Status2 = PatcherApplyGenericPatch (&Patcher, &mAppleIntelCPUPowerManagementPatch2);
    if (!RETURN_ERROR (Status2)) {
      DEBUG ((DEBUG_INFO, "OCAK: Patch v2 success com.apple.driver.AppleIntelCPUPowerManagement\n"));
    }

    if (RETURN_ERROR (Status) && RETURN_ERROR (Status2)) {
      DEBUG ((DEBUG_INFO, "OCAK: Failed to apply patches com.apple.driver.AppleIntelCPUPowerManagement - %r/%r\n", Status, Status2));
    }
  } else {
    DEBUG ((DEBUG_INFO, "OCAK: Failed to find com.apple.driver.AppleIntelCPUPowerManagement - %r\n", Status));
  }

  //
  // At least one patch must be successful for this to work (e.g. first for 10.14).
  //
  return !RETURN_ERROR (Status) ? Status : Status2;
}

#pragma pack(push, 1)

//
// XCPM record definition, extracted from XNU debug kernel.
//
typedef struct XCPM_MSR_RECORD_ {
  UINT32  xcpm_msr_num;
  UINT32  xcpm_msr_applicable_cpus;
  UINT32  *xcpm_msr_flag_p;
  UINT64  xcpm_msr_bits_clear;
  UINT64  xcpm_msr_bits_set;
  UINT64  xcpm_msr_initial_value;
  UINT64  xcpm_msr_rb_value;
} XCPM_MSR_RECORD;

#pragma pack(pop)

STATIC
UINT8
mXcpmCfgLockRelFind[] = {
  0xB9, 0xE2, 0x00, 0x00, 0x00, 0x0F, 0x30 // mov ecx, 0xE2 ; wrmsr
};

STATIC
UINT8
mXcpmCfgLockRelReplace[] = {
  0xB9, 0xE2, 0x00, 0x00, 0x00, 0x90, 0x90 // mov ecx, 0xE2 ; nop
};

STATIC
PATCHER_GENERIC_PATCH
mXcpmCfgLockRelPatch = {
  .Base        = "_xcpm_idle",
  .Find        = mXcpmCfgLockRelFind,
  .Mask        = NULL,
  .Replace     = mXcpmCfgLockRelReplace,
  .ReplaceMask = NULL,
  .Size        = sizeof (mXcpmCfgLockRelFind),
  .Count       = 2,
  .Skip        = 0,
  .Limit       = 4096
};

STATIC
UINT8
mXcpmCfgLockDbgFind[] = {
  0xBF, 0xE2, 0x00, 0x00, 0x00, 0xE8 // mov edi, 0xE2 ; call (wrmsr64)
};

STATIC
UINT8
mXcpmCfgLockDbgReplace[] = {
  0xEB, 0x08, 0x90, 0x90, 0x90, 0xE8 // jmp LBL ; nop; nop; nop; call (wrmsr64); LBL:
};

STATIC
PATCHER_GENERIC_PATCH
mXcpmCfgLockDbgPatch = {
  .Base        = "_xcpm_cst_control_evaluate",
  .Find        = mXcpmCfgLockDbgFind,
  .Mask        = NULL,
  .Replace     = mXcpmCfgLockDbgReplace,
  .ReplaceMask = NULL,
  .Size        = sizeof (mXcpmCfgLockDbgFind),
  .Count       = 2,
  .Skip        = 0,
  .Limit       = 4096
};

RETURN_STATUS
PatchAppleXcpmCfgLock (
  IN OUT PATCHER_CONTEXT  *Patcher
  )
{
  RETURN_STATUS       Status;
  XCPM_MSR_RECORD     *Record;
  XCPM_MSR_RECORD     *Last;

  UINT32              Replacements;

  Last = (XCPM_MSR_RECORD *) ((UINT8 *) MachoGetMachHeader64 (&Patcher->MachContext)
    + MachoGetFileSize (&Patcher->MachContext) - sizeof (XCPM_MSR_RECORD));

  Replacements = 0;

  Status = PatcherGetSymbolAddress (Patcher, "_xcpm_core_scope_msrs", (UINT8 **) &Record);
  if (!RETURN_ERROR (Status)) {
    while (Record < Last) {
      if (Record->xcpm_msr_num == 0xE2) {
        DEBUG ((
          DEBUG_INFO,
          "OCAK: Replacing _xcpm_core_scope_msrs data %u %u\n",
          Record->xcpm_msr_num,
          Record->xcpm_msr_applicable_cpus
          ));
        Record->xcpm_msr_applicable_cpus = 0;
        ++Replacements;
      } else {
        DEBUG ((
          DEBUG_INFO,
          "OCAK: Not matching _xcpm_core_scope_msrs data %u %u\n",
          Record->xcpm_msr_num,
          Record->xcpm_msr_applicable_cpus
          ));
        break;
      }
      ++Record;
    }

    //
    // Now the HWP patch.
    //
    Status = PatcherApplyGenericPatch (
      Patcher,
      &mXcpmCfgLockRelPatch
      );
    if (RETURN_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "OCAK: Failed to locate _xcpm_idle release patch - %r, trying dbg\n", Status));
      Status = PatcherApplyGenericPatch (
        Patcher,
        &mXcpmCfgLockDbgPatch
        );
      if (RETURN_ERROR (Status)) {
        DEBUG ((DEBUG_WARN, "OCAK: Failed to locate _xcpm_idle patches - %r\n", Status));
      }
    }
  } else {
    DEBUG ((DEBUG_WARN, "OCAK: Failed to locate _xcpm_core_scope_msrs - %r\n", Status));
  }

  return Replacements > 0 ? EFI_SUCCESS : EFI_NOT_FOUND;
}

STATIC
UINT8
mMiscPwrMgmtRelFind[] = {
  0xB9, 0xAA, 0x01, 0x00, 0x00, 0x0F, 0x30 // mov ecx, 0x1aa; wrmsr
};

STATIC
UINT8
mMiscPwrMgmtRelReplace[] = {
  0xB9, 0xAA, 0x01, 0x00, 0x00, 0x90, 0x90 // mov ecx, 0x1aa; nop
};

STATIC
PATCHER_GENERIC_PATCH
mMiscPwrMgmtRelPatch = {
  .Base        = NULL,
  .Find        = mMiscPwrMgmtRelFind,
  .Mask        = NULL,
  .Replace     = mMiscPwrMgmtRelReplace,
  .ReplaceMask = NULL,
  .Size        = sizeof (mMiscPwrMgmtRelFind),
  .Count       = 0,
  .Skip        = 0,
  .Limit       = 0
};


STATIC
UINT8
mMiscPwrMgmtDbgFind[] = {
  0xBF, 0xAA, 0x01, 0x00, 0x00, 0xE8 // mov edi, 0x1AA ; call (wrmsr64)
};

STATIC
UINT8
mMiscPwrMgmtDbgReplace[] = {
  0xEB, 0x08, 0x90, 0x90, 0x90, 0xE8 // jmp LBL ; nop; nop; nop; call (wrmsr64); LBL:
};

STATIC
PATCHER_GENERIC_PATCH
mMiscPwrMgmtDbgPatch = {
  .Base        = NULL,
  .Find        = mMiscPwrMgmtDbgFind,
  .Mask        = NULL,
  .Replace     = mMiscPwrMgmtDbgReplace,
  .ReplaceMask = NULL,
  .Size        = sizeof (mMiscPwrMgmtDbgFind),
  .Count       = 0,
  .Skip        = 0,
  .Limit       = 0
};

RETURN_STATUS
PatchAppleXcpmExtraMsrs (
  IN OUT PATCHER_CONTEXT  *Patcher
  )
{
  RETURN_STATUS       Status;
  XCPM_MSR_RECORD     *Record;
  XCPM_MSR_RECORD     *Last;
  UINT32              Replacements;

  Last = (XCPM_MSR_RECORD *) ((UINT8 *) MachoGetMachHeader64 (&Patcher->MachContext)
    + MachoGetFileSize (&Patcher->MachContext) - sizeof (XCPM_MSR_RECORD));

  Replacements = 0;

  Status = PatcherGetSymbolAddress (Patcher, "_xcpm_pkg_scope_msrs", (UINT8 **) &Record);
  if (!RETURN_ERROR (Status)) {
    while (Record < Last) {
      if ((Record->xcpm_msr_applicable_cpus & 0xFF0000FDU) == 0xDC) {
        DEBUG ((
          DEBUG_INFO,
          "OCAK: Replacing _xcpm_pkg_scope_msrs data %u %u\n",
          Record->xcpm_msr_num,
          Record->xcpm_msr_applicable_cpus
          ));
        Record->xcpm_msr_applicable_cpus = 0;
        ++Replacements;
      } else {
        DEBUG ((
          DEBUG_INFO,
          "OCAK: Not matching _xcpm_pkg_scope_msrs data %u %u\n",
          Record->xcpm_msr_num,
          Record->xcpm_msr_applicable_cpus
          ));
        break;
      }
      ++Record;
    }
  } else {
    DEBUG ((DEBUG_WARN, "OCAK: Failed to locate _xcpm_pkg_scope_msrs - %r\n", Status));
  }

  Status = PatcherGetSymbolAddress (Patcher, "_xcpm_SMT_scope_msrs", (UINT8 **) &Record);
  if (!RETURN_ERROR (Status)) {
    while (Record < Last) {
      if (Record->xcpm_msr_flag_p == NULL) {
        DEBUG ((
          DEBUG_INFO,
          "OCAK: Replacing _xcpm_SMT_scope_msrs data %u %u\n",
          Record->xcpm_msr_num,
          Record->xcpm_msr_applicable_cpus
          ));
        Record->xcpm_msr_applicable_cpus = 0;
        ++Replacements;
      } else {
        DEBUG ((
          DEBUG_INFO,
          "OCAK: Not matching _xcpm_SMT_scope_msrs data %u %u %p\n",
          Record->xcpm_msr_num,
          Record->xcpm_msr_applicable_cpus,
          Record->xcpm_msr_flag_p
          ));
        break;
      }
      ++Record;
    }
  } else {
    DEBUG ((DEBUG_WARN, "OCAK: Failed to locate _xcpm_SMT_scope_msrs - %r\n", Status));
  }

  //
  // Now patch writes to MSR_MISC_PWR_MGMT
  //
  Status = PatcherApplyGenericPatch (Patcher, &mMiscPwrMgmtRelPatch);
  if (RETURN_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "OCAK: Failed to patch writes to MSR_MISC_PWR_MGMT - %r, trying dbg\n", Status));
    Status = PatcherApplyGenericPatch (Patcher, &mMiscPwrMgmtDbgPatch);
  }

  if (!RETURN_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "OCAK: Patched writes to MSR_MISC_PWR_MGMT\n"));
    ++Replacements;
  } else {
    DEBUG ((DEBUG_WARN, "OCAK: Failed to patch writes to MSR_MISC_PWR_MGMT - %r\n", Status));
  }

  return Replacements > 0 ? EFI_SUCCESS : EFI_NOT_FOUND;
}

STATIC
UINT8
mRemoveUsbLimitV1Find[] = {
  0xff, 0xff, 0x10
};

STATIC
UINT8
mRemoveUsbLimitV1Replace[] = {
  0xff, 0xff, 0x40
};

STATIC
PATCHER_GENERIC_PATCH
mRemoveUsbLimitV1Patch = {
  .Base        = "__ZN15AppleUSBXHCIPCI11createPortsEv",
  .Find        = mRemoveUsbLimitV1Find,
  .Mask        = NULL,
  .Replace     = mRemoveUsbLimitV1Replace,
  .ReplaceMask = NULL,
  .Size        = sizeof (mRemoveUsbLimitV1Replace),
  .Count       = 1,
  .Skip        = 0,
  .Limit       = 4096
};

STATIC
UINT8
mRemoveUsbLimitV2Find[] = {
  0x0f, 0x0f, 0x83
};

STATIC
UINT8
mRemoveUsbLimitV2Replace[] = {
  0x40, 0x0f, 0x83
};

STATIC
PATCHER_GENERIC_PATCH
mRemoveUsbLimitV2Patch = {
  .Base        = "__ZN12AppleUSBXHCI11createPortsEv",
  .Find        = mRemoveUsbLimitV2Find,
  .Mask        = NULL,
  .Replace     = mRemoveUsbLimitV2Replace,
  .ReplaceMask = NULL,
  .Size        = sizeof (mRemoveUsbLimitV2Replace),
  .Count       = 1,
  .Skip        = 0,
  .Limit       = 4096
};

STATIC
UINT8
mRemoveUsbLimitIoP1Find[] = {
  0x0f, 0x0f, 0x87
};

STATIC
UINT8
mRemoveUsbLimitIoP1Replace[] = {
  0x40, 0x0f, 0x87
};

STATIC
PATCHER_GENERIC_PATCH
mRemoveUsbLimitIoP1Patch = {
  .Base        = "__ZN16AppleUSBHostPort15setPortLocationEj",
  .Find        = mRemoveUsbLimitIoP1Find,
  .Mask        = NULL,
  .Replace     = mRemoveUsbLimitIoP1Replace,
  .ReplaceMask = NULL,
  .Size        = sizeof (mRemoveUsbLimitIoP1Replace),
  .Count       = 1,
  .Skip        = 0,
  .Limit       = 4096
};

RETURN_STATUS
PatchUsbXhciPortLimit (
  IN OUT PRELINKED_CONTEXT  *Context
  )
{
  RETURN_STATUS       Status;
  PATCHER_CONTEXT  Patcher;

  //
  // On 10.14.4 and newer IOUSBHostFamily also needs limit removal.
  // Thanks to ydeng discovering this.
  //
  Status = PatcherInitContextFromPrelinked (
    &Patcher,
    Context,
    "com.apple.iokit.IOUSBHostFamily"
    );

  if (!RETURN_ERROR (Status)) {
    Status = PatcherApplyGenericPatch (&Patcher, &mRemoveUsbLimitIoP1Patch);
    if (RETURN_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "OCAK: Failed to apply P1 patch com.apple.iokit.IOUSBHostFamily - %r\n", Status));
    } else {
      DEBUG ((DEBUG_INFO, "OCAK: Patch success com.apple.iokit.IOUSBHostFamily\n"));
    }
  } else {
    DEBUG ((DEBUG_INFO, "OCAK: Failed to find com.apple.iokit.IOUSBHostFamily - %r\n", Status));
  }

  //
  // TODO: Implement some locationID hack in IOUSBHFamily.
  // The location ID is a 32 bit number which is unique among all USB devices in the system,
  // and which will not change on a system reboot unless the topology of the bus itself changes.
  // See AppleUSBHostPort::setPortLocation():
  // locationId = getLocationId();
  // if (!(locationId & 0xF)) {
  //   int32_t shift = 20;
  //   while (locationId & (0xF << shift)) {
  //     shift -= 4;
  //     if (Shift < 0) { setLocationId(locationId); return; }
  //   }
  //   setLocationId(locationId | ((portNumber & 0xF) << shift));
  // }
  // The value (e.g. 0x14320000) is represented as follows: 0xAABCDEFG
  // AA  — Ctrl number 8 bits (e.g. 0x14, aka XHCI)
  // B   - Port number 4 bits (e.g. 0x3, aka SS03)
  // C~F - Bus number  4 bits (e.g. 0x2, aka IOUSBHostHIDDevice)
  //
  // C~F are filled as many times as many USB Hubs are there on the port.
  //

  Status = PatcherInitContextFromPrelinked (
    &Patcher,
    Context,
    "com.apple.driver.usb.AppleUSBXHCI"
    );

  if (!RETURN_ERROR (Status)) {
    Status = PatcherApplyGenericPatch (&Patcher, &mRemoveUsbLimitV2Patch);
    if (!RETURN_ERROR (Status)) {
      //
      // We do not need to patch com.apple.driver.usb.AppleUSBXHCI if this patch was successful.
      // Only legacy systems require com.apple.driver.usb.AppleUSBXHCI to be patched.
      //
      DEBUG ((DEBUG_INFO, "OCAK: Patch success com.apple.driver.usb.AppleUSBXHCI\n"));
      return RETURN_SUCCESS;
    }

    DEBUG ((DEBUG_INFO, "OCAK: Failed to apply patch com.apple.driver.usb.AppleUSBXHCI - %r\n", Status));
  } else {
    DEBUG ((DEBUG_INFO, "OCAK: Failed to find com.apple.driver.usb.AppleUSBXHCI - %r\n", Status));
  }

  //
  // If we are here, we are on legacy 10.13 or below, try the oldest patch.
  //
  Status = PatcherInitContextFromPrelinked (
    &Patcher,
    Context,
    "com.apple.driver.usb.AppleUSBXHCIPCI"
    );

  if (!RETURN_ERROR (Status)) {
    Status = PatcherApplyGenericPatch (&Patcher, &mRemoveUsbLimitV1Patch);
    if (RETURN_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "OCAK: Failed to apply patch com.apple.driver.usb.AppleUSBXHCIPCI - %r\n", Status));
    } else {
      DEBUG ((DEBUG_INFO, "OCAK: Patch success com.apple.driver.usb.AppleUSBXHCIPCI\n"));
    }
  } else {
    DEBUG ((DEBUG_INFO, "OCAK: Failed to find com.apple.driver.usb.AppleUSBXHCIPCI - %r\n", Status));
  }

  return Status;
}

STATIC
UINT8
mIOAHCIBlockStoragePatchFind[] = {
  0x41, 0x50, 0x50, 0x4C, 0x45, 0x20, 0x53, 0x53, 0x44, 0x00
};

STATIC
UINT8
mIOAHCIBlockStoragePatchReplace[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

STATIC
PATCHER_GENERIC_PATCH
mIOAHCIBlockStoragePatch = {
  .Base        = NULL,
  .Find        = mIOAHCIBlockStoragePatchFind,
  .Mask        = NULL,
  .Replace     = mIOAHCIBlockStoragePatchReplace,
  .ReplaceMask = NULL,
  .Size        = sizeof (mIOAHCIBlockStoragePatchFind),
  .Count       = 1,
  .Skip        = 0
};

RETURN_STATUS
PatchThirdPartySsdTrim (
  IN OUT PRELINKED_CONTEXT  *Context
  )
{
  RETURN_STATUS       Status;
  PATCHER_CONTEXT  Patcher;

  Status = PatcherInitContextFromPrelinked (
    &Patcher,
    Context,
    "com.apple.iokit.IOAHCIBlockStorage"
    );

  if (!RETURN_ERROR (Status)) {
    Status = PatcherApplyGenericPatch (&Patcher, &mIOAHCIBlockStoragePatch);
    if (RETURN_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "OCAK: Failed to apply patch com.apple.iokit.IOAHCIBlockStorage - %r\n", Status));
    } else {
      DEBUG ((DEBUG_INFO, "OCAK: Patch success com.apple.iokit.IOAHCIBlockStorage\n"));
    }
  } else {
    DEBUG ((DEBUG_INFO, "OCAK: Failed to find com.apple.iokit.IOAHCIBlockStorage - %r\n", Status));
  }

  return Status;
}

STATIC
UINT8
mIOAHCIPortPatchFind[] = {
  0x45, 0x78, 0x74, 0x65, 0x72, 0x6E, 0x61, 0x6C
};

STATIC
UINT8
mIOAHCIPortPatchReplace[] = {
  0x49, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x61, 0x6C
};

STATIC
PATCHER_GENERIC_PATCH
mIOAHCIPortPatch = {
  .Base    = NULL,
  .Find    = mIOAHCIPortPatchFind,
  .Mask    = NULL,
  .Replace = mIOAHCIPortPatchReplace,
  .ReplaceMask = NULL,
  .Size    = sizeof (mIOAHCIPortPatchFind),
  .Count   = 1,
  .Skip    = 0
};

RETURN_STATUS
PatchForceInternalDiskIcons (
  IN OUT PRELINKED_CONTEXT  *Context
  )
{
  RETURN_STATUS       Status;
  PATCHER_CONTEXT     Patcher;

  Status = PatcherInitContextFromPrelinked (
    &Patcher,
    Context,
    "com.apple.driver.AppleAHCIPort"
    );

  if (!RETURN_ERROR (Status)) {
    Status = PatcherApplyGenericPatch (&Patcher, &mIOAHCIPortPatch);
    if (RETURN_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "OCAK: Failed to apply patch com.apple.driver.AppleAHCIPort - %r\n", Status));
    } else {
      DEBUG ((DEBUG_INFO, "OCAK: Patch success com.apple.driver.AppleAHCIPort\n"));
    }
  } else {
    DEBUG ((DEBUG_INFO, "OCAK: Failed to find com.apple.driver.AppleAHCIPort - %r\n", Status));
  }

  return Status;
}

STATIC
UINT8
mAppleIoMapperPatchFind[] = {
  0x44, 0x4D, 0x41, 0x52, 0x00 // DMAR\0
};

STATIC
UINT8
mAppleIoMapperPatchReplace[] = {
  0x52, 0x41, 0x4D, 0x44, 0x00 // RAMD\0
};

STATIC
PATCHER_GENERIC_PATCH
mAppleIoMapperPatch = {
  .Base        = NULL,
  .Find        = mAppleIoMapperPatchFind,
  .Mask        = NULL,
  .Replace     = mAppleIoMapperPatchReplace,
  .ReplaceMask = NULL,
  .Size        = sizeof (mAppleIoMapperPatchFind),
  .Count       = 1,
  .Skip        = 0
};

RETURN_STATUS
PatchAppleIoMapperSupport (
  IN OUT PRELINKED_CONTEXT  *Context
  )
{
  RETURN_STATUS       Status;
  PATCHER_CONTEXT     Patcher;

  Status = PatcherInitContextFromPrelinked (
    &Patcher,
    Context,
    "com.apple.iokit.IOPCIFamily"
    );

  if (!RETURN_ERROR (Status)) {
    Status = PatcherApplyGenericPatch (&Patcher, &mAppleIoMapperPatch);
    if (RETURN_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "OCAK: Failed to apply patch com.apple.iokit.IOPCIFamily - %r\n", Status));
    } else {
      DEBUG ((DEBUG_INFO, "OCAK: Patch success com.apple.iokit.IOPCIFamily\n"));
    }
  } else {
    DEBUG ((DEBUG_INFO, "OCAK: Failed to find com.apple.iokit.IOPCIFamily - %r\n", Status));
  }

  return Status;
}

STATIC
CONST UINT8
mKernelCpuIdFindRelNew[] = {
  0xB9, 0x8B, 0x00, 0x00, 0x00, 0x31, 0xC0, 0x31, 0xD2, 0x0F, 0x30, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x31, 0xDB, 0x31, 0xC9, 0x31, 0xD2, 0x0F, 0xA2
};

STATIC
CONST UINT8
mKernelCpuIdFindRelOld[] = {
  0xB9, 0x8B, 0x00, 0x00, 0x00, 0x31, 0xD2, 0x0F, 0x30, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x31, 0xDB, 0x31, 0xC9, 0x31, 0xD2, 0x0F, 0xA2
};

STATIC
CONST UINT8
mKernelCpuidFindMcRel[] = {
  0xB9, 0x8B, 0x00, 0x00, 0x00, 0x0F, 0x32
};

/**
  cpu->cpuid_signature           = 0x11111111;
  cpu->cpuid_stepping            = 0x22;
  cpu->cpuid_model               = 0x33;
  cpu->cpuid_family              = 0x44;
  cpu->cpuid_type                = 0x55555555;
  cpu->cpuid_extmodel            = 0x66;
  cpu->cpuid_extfamily           = 0x77;
  cpu->cpuid_features            = 0x8888888888888888;
  cpu->cpuid_logical_per_package = 0x99999999;
  cpu->cpuid_cpufamily           = 0xAAAAAAAA;
  return 0xAAAAAAAA;
**/
STATIC
CONST UINT8
mKernelCpuidReplaceDbg[] = {
  0xC7, 0x47, 0x68, 0x11, 0x11, 0x11, 0x11,                   ///< mov dword ptr [rdi+68h], 11111111h
  0xC6, 0x47, 0x50, 0x22,                                     ///< mov byte ptr [rdi+50h], 22h
  0x48, 0xB8, 0x55, 0x55, 0x55, 0x55, 0x44, 0x33, 0x66, 0x77, ///< mov rax, 7766334455555555h
  0x48, 0x89, 0x47, 0x48,                                     ///< mov [rdi+48h], rax
  0x48, 0xB8, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, ///< mov rax, 8888888888888888h
  0x48, 0x89, 0x47, 0x58,                                     ///< mov [rdi+58h], rax
  0xC7, 0x87, 0xCC, 0x00, 0x00, 0x00, 0x99, 0x99, 0x99, 0x99, ///< mov dword ptr [rdi+0CCh], 99999999h
  0xC7, 0x87, 0x88, 0x01, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, ///< mov dword ptr [rdi+188h], 0AAAAAAAAh
  0xB8, 0xAA, 0xAA, 0xAA, 0xAA,                               ///< mov eax, 0AAAAAAAAh
  0xC3                                                        ///< retn
};

#pragma pack(push, 1)

typedef struct {
  UINT8   Code1[3];
  UINT32  Signature;
  UINT8   Code2[3];
  UINT8   Stepping;
  UINT8   Code3[2];
  UINT32  Type;
  UINT8   Family;
  UINT8   Model;
  UINT8   ExtModel;
  UINT8   ExtFamily;
  UINT8   Code4[6];
  UINT64  Features;
  UINT8   Code5[10];
  UINT32  LogicalPerPkg;
  UINT8   Code6[6];
  UINT32  AppleFamily1;
  UINT8   Code7;
  UINT32  AppleFamily2;
  UINT8   Code8;
} INTERNAL_CPUID_FN_PATCH;

OC_STATIC_ASSERT (
  sizeof (INTERNAL_CPUID_FN_PATCH) == sizeof (mKernelCpuidReplaceDbg),
  "Check your CPUID patch layout"
  );

typedef struct {
  UINT8   EaxCmd;
  UINT32  EaxVal;
  UINT8   EbxCmd;
  UINT32  EbxVal;
  UINT8   EcxCmd;
  UINT32  EcxVal;
  UINT8   EdxCmd;
  UINT32  EdxVal;
} INTERNAL_CPUID_PATCH;

typedef struct {
  UINT8   EdxCmd;
  UINT32  EdxVal;
} INTERNAL_MICROCODE_PATCH;

#pragma pack(pop)

RETURN_STATUS
PatchKernelCpuId (
  IN OUT PATCHER_CONTEXT  *Patcher,
  IN     OC_CPU_INFO      *CpuInfo,
  IN     UINT32           *Data,
  IN     UINT32           *DataMask
  )
{
  RETURN_STATUS             Status;
  UINT8                     *Record;
  UINT8                     *Last;
  UINT32                    Index;
  UINT32                    FoundSize;
  INTERNAL_CPUID_PATCH      *CpuidPatch;
  INTERNAL_MICROCODE_PATCH  *McPatch;
  INTERNAL_CPUID_FN_PATCH   *FnPatch;
  CPUID_VERSION_INFO_EAX    Eax;
  CPUID_VERSION_INFO_EBX    Ebx;
  CPUID_VERSION_INFO_ECX    Ecx;
  CPUID_VERSION_INFO_EDX    Edx;

  OC_STATIC_ASSERT (
    sizeof (mKernelCpuIdFindRelNew) > sizeof (mKernelCpuIdFindRelOld),
    "Kernel CPUID patch seems wrong"
    );

  ASSERT (mKernelCpuIdFindRelNew[0] == mKernelCpuIdFindRelOld[0]
    && mKernelCpuIdFindRelNew[1] == mKernelCpuIdFindRelOld[1]
    && mKernelCpuIdFindRelNew[2] == mKernelCpuIdFindRelOld[2]
    && mKernelCpuIdFindRelNew[3] == mKernelCpuIdFindRelOld[3]
    );

  Last = ((UINT8 *) MachoGetMachHeader64 (&Patcher->MachContext)
    + MachoGetFileSize (&Patcher->MachContext) - EFI_PAGE_SIZE*2 - sizeof (mKernelCpuIdFindRelNew));

  Status = PatcherGetSymbolAddress (Patcher, "_cpuid_set_info", (UINT8 **) &Record);
  if (RETURN_ERROR (Status) || Record >= Last) {
    DEBUG ((DEBUG_WARN, "OCAK: Failed to locate _cpuid_set_info (%p) - %r\n", Record, Status));
    return EFI_NOT_FOUND;
  }

  FoundSize = 0;

  for (Index = 0; Index < EFI_PAGE_SIZE; ++Index, ++Record) {
    if (Record[0] == mKernelCpuIdFindRelNew[0]
      && Record[1] == mKernelCpuIdFindRelNew[1]
      && Record[2] == mKernelCpuIdFindRelNew[2]
      && Record[3] == mKernelCpuIdFindRelNew[3]) {

      if (CompareMem (Record, mKernelCpuIdFindRelNew, sizeof (mKernelCpuIdFindRelNew)) == 0) {
        FoundSize = sizeof (mKernelCpuIdFindRelNew);
        break;
      } else if (CompareMem (Record, mKernelCpuIdFindRelOld, sizeof (mKernelCpuIdFindRelOld)) == 0) {
        FoundSize = sizeof (mKernelCpuIdFindRelOld);
        break;
      }
    }
  }

  Eax.Uint32 = (Data[0] & DataMask[0]) | (CpuInfo->CpuidVerEax.Uint32 & ~DataMask[0]);
  Ebx.Uint32 = (Data[1] & DataMask[1]) | (CpuInfo->CpuidVerEbx.Uint32 & ~DataMask[1]);
  Ecx.Uint32 = (Data[2] & DataMask[2]) | (CpuInfo->CpuidVerEcx.Uint32 & ~DataMask[2]);
  Edx.Uint32 = (Data[3] & DataMask[3]) | (CpuInfo->CpuidVerEdx.Uint32 & ~DataMask[3]);

  if (FoundSize > 0) {
    CpuidPatch         = (INTERNAL_CPUID_PATCH *) Record;
    CpuidPatch->EaxCmd = 0xB8;
    CpuidPatch->EaxVal = Eax.Uint32;
    CpuidPatch->EbxCmd = 0xBB;
    CpuidPatch->EbxVal = Ebx.Uint32;
    CpuidPatch->EcxCmd = 0xB9;
    CpuidPatch->EcxVal = Ecx.Uint32;
    CpuidPatch->EdxCmd = 0xBA;
    CpuidPatch->EdxVal = Edx.Uint32;
    SetMem (
      Record + sizeof (INTERNAL_CPUID_PATCH),
      FoundSize - sizeof (INTERNAL_CPUID_PATCH),
      0x90
      );
    Record += FoundSize;

    for (Index = 0; Index < EFI_PAGE_SIZE - sizeof (mKernelCpuidFindMcRel); ++Index, ++Record) {
      if (CompareMem (Record, mKernelCpuidFindMcRel, sizeof (mKernelCpuidFindMcRel)) == 0) {
        McPatch         = (INTERNAL_MICROCODE_PATCH *) Record;
        McPatch->EdxCmd = 0xBA;
        McPatch->EdxVal = CpuInfo->MicrocodeRevision;
        SetMem (
          Record + sizeof (INTERNAL_MICROCODE_PATCH),
          sizeof (mKernelCpuidFindMcRel) - sizeof (INTERNAL_MICROCODE_PATCH),
          0x90
          );
        return EFI_SUCCESS;
      }
    }
  } else {
    //
    // Handle debug kernel here...
    //
    Status = PatcherGetSymbolAddress (Patcher, "_cpuid_set_cpufamily", (UINT8 **) &Record);
    if (RETURN_ERROR (Status) || Record >= Last) {
      DEBUG ((DEBUG_WARN, "OCAK: Failed to locate _cpuid_set_cpufamily (%p) - %r\n", Record, Status));
      return EFI_NOT_FOUND;
    }

    CopyMem (Record, mKernelCpuidReplaceDbg, sizeof (mKernelCpuidReplaceDbg));
    FnPatch = (INTERNAL_CPUID_FN_PATCH *) Record;
    FnPatch->Signature     = Eax.Uint32;
    FnPatch->Stepping      = (UINT8) Eax.Bits.SteppingId;
    FnPatch->ExtModel      = (UINT8) Eax.Bits.ExtendedModelId;
    FnPatch->Model         = (UINT8) Eax.Bits.Model | (UINT8) (Eax.Bits.ExtendedModelId << 4U);
    FnPatch->Family        = (UINT8) Eax.Bits.FamilyId;
    FnPatch->Type          = (UINT8) Eax.Bits.ProcessorType;
    FnPatch->ExtFamily     = (UINT8) Eax.Bits.ExtendedFamilyId;
    FnPatch->Features      = ((UINT64) Ecx.Uint32 << 32ULL) | (UINT64) Edx.Uint32;
    if (FnPatch->Features & CPUID_FEATURE_HTT) {
      FnPatch->LogicalPerPkg = (UINT16) Ebx.Bits.MaximumAddressableIdsForLogicalProcessors;
    } else {
      FnPatch->LogicalPerPkg = 1;
    }

    FnPatch->AppleFamily1 = FnPatch->AppleFamily2 = OcCpuModelToAppleFamily (Eax);

    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_WARN, "OCAK: Failed to find either CPUID patch (%u)\n", FoundSize));

  return RETURN_UNSUPPORTED;
}

STATIC
UINT8
mCustomSmbiosGuidPatchFind[] = {
  0x45, 0x42, 0x39, 0x44, 0x32, 0x44, 0x33, 0x31
};

STATIC
UINT8
mCustomSmbiosGuidPatchReplace[] = {
  0x45, 0x42, 0x39, 0x44, 0x32, 0x44, 0x33, 0x35
};

STATIC
PATCHER_GENERIC_PATCH
mCustomSmbiosGuidPatch = {
  .Base    = NULL,
  .Find    = mCustomSmbiosGuidPatchFind,
  .Mask    = NULL,
  .Replace = mCustomSmbiosGuidPatchReplace,
  .ReplaceMask = NULL,
  .Size    = sizeof (mCustomSmbiosGuidPatchFind),
  .Count   = 1,
  .Skip    = 0
};

RETURN_STATUS
PatchCustomSmbiosGuid (
  IN OUT PRELINKED_CONTEXT  *Context
  )
{
  RETURN_STATUS       Status;
  PATCHER_CONTEXT     Patcher;
  UINT32              Index;
  
  STATIC CONST CHAR8 *Kexts[] = {
    "com.apple.driver.AppleSMBIOS",
    "com.apple.driver.AppleACPIPlatform"
  };
  
  for (Index = 0; Index < ARRAY_SIZE (Kexts); ++Index) {
    Status = PatcherInitContextFromPrelinked (
      &Patcher,
      Context,
      Kexts[Index]
      );
    
    if (!RETURN_ERROR (Status)) {
      Status = PatcherApplyGenericPatch (&Patcher, &mCustomSmbiosGuidPatch);
      if (!RETURN_ERROR (Status)) {
        DEBUG ((DEBUG_INFO, "OCAK: SMBIOS Patch success %a\n", Kexts[Index]));
      } else {
        DEBUG ((DEBUG_INFO, "OCAK: Failed to apply SMBIOS patch %a - %r\n", Kexts[Index], Status));
      }
    } else {
      DEBUG ((DEBUG_INFO, "OCAK: Failed to find SMBIOS kext %a - %r\n", Kexts[Index], Status));
    }
  }

  return Status;
}

STATIC
UINT8
mPanicKextDumpPatchFind[] = {
  0x00, 0x25, 0x2E, 0x2A, 0x73, 0x00 ///< \0%.*s\0
};

STATIC
UINT8
mPanicKextDumpPatchReplace[] = {
  0x00, 0x00, 0x2E, 0x2A, 0x73, 0x00
};

STATIC
PATCHER_GENERIC_PATCH
mPanicKextDumpPatch = {
  .Base    = NULL,
  .Find    = mPanicKextDumpPatchFind,
  .Mask    = NULL,
  .Replace = mPanicKextDumpPatchReplace,
  .ReplaceMask = NULL,
  .Size    = sizeof (mPanicKextDumpPatchFind),
  .Count   = 1,
  .Skip    = 0
};

RETURN_STATUS
PatchPanicKextDump (
  IN OUT PATCHER_CONTEXT  *Patcher
  )
{
  RETURN_STATUS       Status;
  UINT8               *Record;
  UINT8               *Last;

  Last = ((UINT8 *) MachoGetMachHeader64 (&Patcher->MachContext)
    + MachoGetFileSize (&Patcher->MachContext) - EFI_PAGE_SIZE);

  //
  // This should work on 10.15 and all debug kernels.
  //
  Status = PatcherGetSymbolAddress (
    Patcher,
    "__ZN6OSKext19printKextPanicListsEPFiPKczE",
    (UINT8 **) &Record
    );
  if (RETURN_ERROR (Status) || Record >= Last) {
    DEBUG ((DEBUG_WARN, "OCAK: Failed to locate printKextPanicLists (%p) - %r\n", Record, Status));
    return EFI_NOT_FOUND;
  }

  *Record = 0xC3;

  //
  // This one is for 10.13~10.14 release kernels, which do dumping inline.
  // A bit risky, but let's hope it works well.
  //
  Status = PatcherApplyGenericPatch (Patcher, &mPanicKextDumpPatch);
  if (RETURN_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "OCAK: Failed to apply kext dump patch - %r\n", Status));
  } else {
    DEBUG ((DEBUG_INFO, "OCAK: Patch success kext dump\n"));
  }

  return RETURN_SUCCESS;
}

STATIC
UINT8
mLapicKernelPanicPatchFind[] = {
  // mov eax, gs:1Ch
  // cmp eax, cs:_master_cpu <- address masked out
  0x65, 0x8B, 0x04, 0x25, 0x1C, 0x00, 0x00, 0x00, 0x3B, 0x00, 0x00, 0x00, 0x00, 0x00
};

STATIC
UINT8
mLapicKernelPanicPatchMask[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00
};

STATIC
UINT8
mLapicKernelPanicPatchReplace[] = {
  // xor eax, eax ; nop further
  0x31, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

STATIC
PATCHER_GENERIC_PATCH
mLapicKernelPanicPatch = {
  .Base    = "_lapic_interrupt",
  .Find    = mLapicKernelPanicPatchFind,
  .Mask    = mLapicKernelPanicPatchMask,
  .Replace = mLapicKernelPanicPatchReplace,
  .ReplaceMask = NULL,
  .Size    = sizeof (mLapicKernelPanicPatchReplace),
  .Count   = 1,
  .Skip    = 0,
  .Limit   = 4096
};

STATIC
UINT8
mLapicKernelPanicMasterPatchFind[] = {
  // cmp cs:_debug_boot_arg, 0 <- address masked out
  0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

STATIC
UINT8
mLapicKernelPanicMasterPatchMask[] = {
  0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF
};

STATIC
UINT8
mLapicKernelPanicMasterPatchReplace[] = {
  // xor eax, eax ; nop further
  0x31, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x90
};

STATIC
PATCHER_GENERIC_PATCH
mLapicKernelPanicMasterPatch = {
  .Base    = "_lapic_interrupt",
  .Find    = mLapicKernelPanicMasterPatchFind,
  .Mask    = mLapicKernelPanicMasterPatchMask,
  .Replace = mLapicKernelPanicMasterPatchReplace,
  .ReplaceMask = NULL,
  .Size    = sizeof (mLapicKernelPanicMasterPatchFind),
  .Count   = 1,
  .Skip    = 0,
  .Limit   = 4096
};

RETURN_STATUS
PatchLapicKernelPanic (
  IN OUT PATCHER_CONTEXT  *Patcher
  )
{
  RETURN_STATUS  Status;

  //
  // This one is for <= 10.15 release kernels.
  // TODO: Fix debug kernels and check whether we want more patches.
  //
  Status = PatcherApplyGenericPatch (Patcher, &mLapicKernelPanicPatch);
  if (RETURN_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "OCAK: Failed to apply lapic patch - %r\n", Status));
  } else {
    DEBUG ((DEBUG_INFO, "OCAK: Patch success lapic\n"));

    //
    // Also patch away the master core check to never require lapic_dont_panic=1.
    // This one is optional, and seems to never be required in real world.
    //
    Status = PatcherApplyGenericPatch (Patcher, &mLapicKernelPanicMasterPatch);
    if (RETURN_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "OCAK: Failed to apply extended lapic patch - %r\n", Status));
    } else {
      DEBUG ((DEBUG_INFO, "OCAK: Patch success extended lapic\n"));
    }
  }

  return Status;
}
