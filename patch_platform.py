#!/usr/bin/env python3
"""
patch_platform.py — Patch visionOS (XROS) Mach-O binaries and .app bundles to appear as iOS apps.

Patches:
  - Mach-O LC_BUILD_VERSION: platform XROS(11) → IOS(2), minos/sdk → 15.0.0
  - Info.plist: CFBundleSupportedPlatforms, DTPlatformName, MinimumOSVersion, UIDeviceFamily, etc.

Usage:
  python3 patch_platform.py <path_to_.app_or_binary> [--ios-version 15.0]

Examples:
  python3 patch_platform.py testdecyrpt.app
  python3 patch_platform.py testdecyrpt.app/testdecyrpt
  python3 patch_platform.py Payload/SomeApp.app --ios-version 16.0
"""

import argparse
import os
import plistlib
import struct
import sys

# --- Constants ---

PLATFORM_IOS = 2
PLATFORM_XROS = 11

PLATFORM_NAMES = {
    1: "MACOS",
    2: "IOS",
    3: "TVOS",
    4: "WATCHOS",
    6: "MACCATALYST",
    7: "IOSSIMULATOR",
    8: "TVOSSIMULATOR",
    9: "WATCHOSSIMULATOR",
    10: "DRIVERKIT",
    11: "XROS",
    12: "XROS_SIMULATOR",
}

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
LC_BUILD_VERSION = 0x32  # 50
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018

CPU_TYPE_ARM64 = 0x0100000C

# Frameworks that only exist on visionOS and should be weak-linked
VISIONOS_EXCLUSIVE_PATTERNS = [
    "_RealityKit_SwiftUI",
    "_CompositorServices_SwiftUI",
    "CompositorServices",
    "RealityKit",
    "RealityFoundation",
    "_StoreKit_SwiftUI",
]


def encode_version(major, minor=0, patch=0):
    """Encode version as Mach-O packed uint32: major.minor.patch."""
    return (major << 16) | (minor << 8) | patch


def decode_version(v):
    """Decode Mach-O packed version uint32 to (major, minor, patch)."""
    return (v >> 16, (v >> 8) & 0xFF, v & 0xFF)


def version_str(v):
    """Format a packed version as string."""
    major, minor, patch = decode_version(v)
    if patch:
        return f"{major}.{minor}.{patch}"
    return f"{major}.{minor}"


# --- Mach-O Binary Patching ---

def _extract_dylib_name(data, endian, offset, cmdsize):
    """Extract the dylib name string from an LC_LOAD_DYLIB command."""
    # struct dylib_command { cmd, cmdsize, dylib { name_offset, timestamp, current_version, compat_version } }
    name_offset = struct.unpack_from(f"{endian}I", data, offset + 8)[0]
    name_start = offset + name_offset
    name_end = offset + cmdsize
    name_bytes = data[name_start:name_end]
    # Null-terminated string
    null_pos = name_bytes.find(b'\x00')
    if null_pos >= 0:
        name_bytes = name_bytes[:null_pos]
    return name_bytes.decode("utf-8", errors="replace")


def _is_visionos_exclusive(dylib_name):
    """Check if a dylib is a visionOS-exclusive framework."""
    for pattern in VISIONOS_EXCLUSIVE_PATTERNS:
        if pattern in dylib_name:
            return True
    return False


def patch_macho(data, target_platform=PLATFORM_IOS, target_version=None, weak_link=True):
    """
    Patch LC_BUILD_VERSION and optionally weak-link visionOS frameworks.

    Returns (patched_data, changes_list) or (None, error_string).
    """
    if target_version is None:
        target_version = encode_version(15, 0, 0)

    changes = []

    # Check magic
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == MH_MAGIC_64:
        endian = "<"
    elif magic == MH_CIGAM_64:
        endian = ">"
    else:
        return None, f"Not a 64-bit Mach-O (magic: 0x{magic:08x})"

    ncmds = struct.unpack_from(f"{endian}I", data, 16)[0]

    offset = 32  # sizeof(mach_header_64)
    found_build_version = False

    patched = bytearray(data)

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(f"{endian}II", patched, offset)

        if cmd == LC_BUILD_VERSION:
            platform, minos, sdk, ntools = struct.unpack_from(
                f"{endian}IIII", patched, offset + 8
            )

            old_platform_name = PLATFORM_NAMES.get(platform, f"UNKNOWN({platform})")
            new_platform_name = PLATFORM_NAMES.get(target_platform, f"UNKNOWN({target_platform})")

            changes.append(
                f"  platform: {platform} ({old_platform_name}) → {target_platform} ({new_platform_name})"
            )
            changes.append(
                f"  minos:    {version_str(minos)} (0x{minos:08x}) → {version_str(target_version)} (0x{target_version:08x})"
            )
            changes.append(
                f"  sdk:      {version_str(sdk)} (0x{sdk:08x}) → {version_str(target_version)} (0x{target_version:08x})"
            )

            # Patch platform
            struct.pack_into(f"{endian}I", patched, offset + 8, target_platform)
            # Patch minos
            struct.pack_into(f"{endian}I", patched, offset + 12, target_version)
            # Patch sdk
            struct.pack_into(f"{endian}I", patched, offset + 16, target_version)

            found_build_version = True

        elif cmd == LC_LOAD_DYLIB and weak_link:
            dylib_name = _extract_dylib_name(patched, endian, offset, cmdsize)
            if _is_visionos_exclusive(dylib_name):
                # Patch LC_LOAD_DYLIB → LC_LOAD_WEAK_DYLIB
                struct.pack_into(f"{endian}I", patched, offset, LC_LOAD_WEAK_DYLIB)
                short_name = dylib_name.split("/")[-1]
                changes.append(f"  weak-linked: {short_name}")

        offset += cmdsize

    if not found_build_version:
        return None, "LC_BUILD_VERSION not found in Mach-O"

    return bytes(patched), changes


def patch_binary_file(binary_path, target_platform=PLATFORM_IOS, target_version=None):
    """
    Patch a Mach-O binary file (handles both thin and FAT binaries).

    Returns list of change descriptions, or raises on error.
    """
    with open(binary_path, "rb") as f:
        data = f.read()

    magic = struct.unpack_from("<I", data, 0)[0]
    all_changes = []

    if magic in (FAT_MAGIC, FAT_CIGAM):
        # FAT binary — need to patch each arm64 slice
        fat_endian = ">" if magic == FAT_MAGIC else "<"
        nfat_arch = struct.unpack_from(f"{fat_endian}I", data, 4)[0]
        all_changes.append(f"FAT binary with {nfat_arch} architecture(s)")

        patched = bytearray(data)
        arch_offset = 8  # sizeof(fat_header)

        for i in range(nfat_arch):
            cputype, cpusubtype, offset, size, align = struct.unpack_from(
                f"{fat_endian}IIIII", data, arch_offset
            )

            slice_data = data[offset : offset + size]
            result, info = patch_macho(slice_data, target_platform, target_version)

            if result is not None:
                all_changes.append(f"Slice {i} (cputype=0x{cputype:08x}):")
                all_changes.extend(info)
                patched[offset : offset + size] = result
            else:
                all_changes.append(f"Slice {i} (cputype=0x{cputype:08x}): skipped — {info}")

            arch_offset += 20  # sizeof(fat_arch)

        with open(binary_path, "wb") as f:
            f.write(bytes(patched))

    elif magic in (MH_MAGIC_64, MH_CIGAM_64):
        # Thin binary
        all_changes.append("Thin Mach-O 64-bit binary")
        result, info = patch_macho(data, target_platform, target_version)
        if result is None:
            raise RuntimeError(f"Failed to patch binary: {info}")
        all_changes.extend(info)

        with open(binary_path, "wb") as f:
            f.write(result)
    else:
        raise RuntimeError(f"Unknown binary format (magic: 0x{magic:08x})")

    return all_changes


# --- Info.plist Patching ---

PLIST_PATCHES = {
    "CFBundleSupportedPlatforms": ["iPhoneOS"],
    "DTPlatformName": "iphoneos",
    "UIDeviceFamily": [1],
}

VERSION_PLIST_KEYS = ["DTPlatformVersion", "MinimumOSVersion"]


def patch_info_plist(plist_path, ios_version_str="15.0"):
    """
    Patch an Info.plist to change visionOS identifiers to iOS.

    Returns list of change descriptions.
    """
    with open(plist_path, "rb") as f:
        plist = plistlib.load(f)

    changes = []

    # Fixed key patches
    for key, new_value in PLIST_PATCHES.items():
        old_value = plist.get(key)
        if old_value != new_value:
            changes.append(f"  {key}: {old_value!r} → {new_value!r}")
            plist[key] = new_value

    # Version patches
    for key in VERSION_PLIST_KEYS:
        old_value = plist.get(key)
        if old_value is not None and old_value != ios_version_str:
            changes.append(f"  {key}: {old_value!r} → {ios_version_str!r}")
            plist[key] = ios_version_str

    # DTSDKName: e.g. "xros26.2" → "iphoneos15.0"
    old_sdk_name = plist.get("DTSDKName", "")
    if old_sdk_name and ("xros" in old_sdk_name.lower() or "visionos" in old_sdk_name.lower()):
        new_sdk_name = f"iphoneos{ios_version_str}"
        changes.append(f"  DTSDKName: {old_sdk_name!r} → {new_sdk_name!r}")
        plist["DTSDKName"] = new_sdk_name

    if changes:
        with open(plist_path, "wb") as f:
            plistlib.dump(plist, f)

    return changes


# --- .app Bundle Patching ---

def find_executable_in_app(app_path):
    """Find the main executable inside a .app bundle via Info.plist."""
    plist_path = os.path.join(app_path, "Info.plist")
    if not os.path.exists(plist_path):
        raise FileNotFoundError(f"Info.plist not found in {app_path}")

    with open(plist_path, "rb") as f:
        plist = plistlib.load(f)

    exe_name = plist.get("CFBundleExecutable")
    if not exe_name:
        raise RuntimeError("CFBundleExecutable not found in Info.plist")

    exe_path = os.path.join(app_path, exe_name)
    if not os.path.exists(exe_path):
        raise FileNotFoundError(f"Executable not found: {exe_path}")

    return exe_path


def patch_app(app_path, ios_version_str="15.0"):
    """
    Patch an entire .app bundle: binary + Info.plist + embedded frameworks.

    Returns (binary_changes, plist_changes).
    """
    target_version = parse_version_string(ios_version_str)

    # Find and patch the main executable
    exe_path = find_executable_in_app(app_path)
    print(f"Binary: {exe_path}")
    binary_changes = patch_binary_file(exe_path, PLATFORM_IOS, target_version)

    # Patch embedded frameworks
    frameworks_dir = os.path.join(app_path, "Frameworks")
    if os.path.isdir(frameworks_dir):
        for item in os.listdir(frameworks_dir):
            if item.endswith(".framework"):
                fw_path = os.path.join(frameworks_dir, item)
                # Framework binary has same name as framework (minus .framework)
                fw_bin_name = item[:-len(".framework")]
                fw_bin_path = os.path.join(fw_path, fw_bin_name)
                if os.path.isfile(fw_bin_path):
                    print(f"Framework: {fw_bin_path}")
                    try:
                        fw_changes = patch_binary_file(fw_bin_path, PLATFORM_IOS, target_version)
                        binary_changes.append(f"  --- {item} ---")
                        binary_changes.extend(fw_changes)
                    except RuntimeError as e:
                        binary_changes.append(f"  --- {item}: skipped ({e}) ---")

    # Patch Info.plist
    plist_path = os.path.join(app_path, "Info.plist")
    print(f"Plist:  {plist_path}")
    plist_changes = patch_info_plist(plist_path, ios_version_str)

    return binary_changes, plist_changes


def parse_version_string(version_str):
    """Parse '15.0' or '15.0.1' into packed Mach-O version."""
    parts = version_str.split(".")
    major = int(parts[0])
    minor = int(parts[1]) if len(parts) > 1 else 0
    patch = int(parts[2]) if len(parts) > 2 else 0
    return encode_version(major, minor, patch)


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Patch visionOS (XROS) binaries/apps to appear as iOS apps."
    )
    parser.add_argument(
        "path",
        help="Path to a .app bundle or a Mach-O binary",
    )
    parser.add_argument(
        "--ios-version",
        default="15.0",
        help="Target iOS version (default: 15.0)",
    )
    args = parser.parse_args()

    path = os.path.abspath(args.path)

    if not os.path.exists(path):
        print(f"Error: {path} does not exist", file=sys.stderr)
        sys.exit(1)

    target_version = parse_version_string(args.ios_version)
    ios_ver = args.ios_version

    print(f"=== visionOS → iOS Patcher ===")
    print(f"Target: {path}")
    print(f"iOS version: {ios_ver}")
    print()

    if path.endswith(".app") and os.path.isdir(path):
        # Patch entire .app bundle
        binary_changes, plist_changes = patch_app(path, ios_ver)

        print()
        print("Binary changes (LC_BUILD_VERSION):")
        for c in binary_changes:
            print(c)

        print()
        print("Info.plist changes:")
        if plist_changes:
            for c in plist_changes:
                print(c)
        else:
            print("  (no changes needed)")
    else:
        # Patch bare binary
        print(f"Patching binary: {path}")
        changes = patch_binary_file(path, PLATFORM_IOS, target_version)
        print()
        print("Binary changes (LC_BUILD_VERSION):")
        for c in changes:
            print(c)

    print()
    print("Done. Verify with: otool -l <binary> | grep -A5 LC_BUILD_VERSION")


if __name__ == "__main__":
    main()
