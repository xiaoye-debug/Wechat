#!/usr/bin/env python3
"""Validate real macOS build output; emit dependency evidence and checksums."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from verify_source_contract import bundle_filter, verify as verify_source


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def verify(out, scheme):
    source_contract = verify_source()
    dylib = out / "WeChatEnvBypass.dylib"
    deb = out / f"WeChatEnvBypass-{scheme}.deb"
    archs = run("lipo", "-archs", str(dylib)).split()
    if archs != ["arm64"]:
        raise RuntimeError(f"Expected standalone arm64 app library, got {archs}")
    versions = run("otool", "-l", str(dylib))
    id_command = re.search(r"cmd LC_ID_DYLIB\s+cmdsize \d+\s+name (.*?) \(offset", versions)
    if not id_command:
        raise RuntimeError("LC_ID_DYLIB load command missing")
    identity = id_command.group(1)
    linked = run("otool", "-L", str(dylib))
    deps = [line.strip().split(" (compatibility version", 1)[0]
            for line in linked.splitlines()[1:] if line.strip()]
    external = [dep for dep in deps if dep != identity and not
                dep.startswith(("/usr/lib/", "/System/Library/"))]
    if external or any(re.search(r"substrate|hooker|ellekit|substitute", dep, re.I) for dep in deps):
        raise RuntimeError(f"Non-system hook dependency: {deps}")
    undefined = run("nm", "-u", str(dylib))
    if re.search(r"MSHook|LHHook|EKHook", undefined):
        raise RuntimeError("External hook symbols remain undefined")
    package_info = run("dpkg-deb", "--info", str(deb))
    control = run("dpkg-deb", "--field", str(deb))
    package_version = run("dpkg-deb", "--field", str(deb), "Version")
    if package_version != source_contract["version"]:
        raise RuntimeError("DEB version does not match source")
    if re.search(r"^Depends:.*(?:substrate|hooker|ellekit)", control, re.M | re.I):
        raise RuntimeError("Standalone package incorrectly requires a jailbreak hook runtime")
    architecture = run("dpkg-deb", "--field", str(deb), "Architecture")
    expected_arch = "iphoneos-arm64" if scheme == "rootless" else "iphoneos-arm"
    if architecture != expected_arch:
        raise RuntimeError(f"Wrong Debian architecture: {architecture} != {expected_arch}")
    prefix = "var/jb/" if scheme == "rootless" else ""
    relative = prefix + "Library/MobileSubstrate/DynamicLibraries/WeChatEnvBypass.dylib"
    with tempfile.TemporaryDirectory() as temporary:
        run("dpkg-deb", "--extract", str(deb), temporary)
        packed = Path(temporary) / relative
        if not packed.is_file() or packed.read_bytes() != dylib.read_bytes():
            raise RuntimeError(f"DEB payload differs from exported dylib: {relative}")
        if not packed.with_suffix(".plist").is_file():
            raise RuntimeError("DEB loader filter missing")
        if bundle_filter(packed.with_suffix(".plist")) != source_contract["bundle_ids"]:
            raise RuntimeError("Packaged bundle IDs do not match the supported bundle filter")
    if not re.search(r"\bminos\s+15\.0\b", versions):
        raise RuntimeError("Expected iOS 15.0 minimum deployment target")
    evidence = {
        "scheme": scheme, "architectures": archs, "install_name": identity, "dependencies": deps,
        "package_architecture": architecture, "deb_payload": relative,
        "minimum_ios": "15.0", "hook_generator": "internal",
        "version": package_version, "bundle_ids": source_contract["bundle_ids"],
        "migrated_default_enabled": source_contract["migrated_default_enabled"],
        "default_enabled_candidates": source_contract["default_enabled_candidates"],
        "ios27_device_tested": False, "certificate_signed_ipa_tested": False,
        "package_info": package_info,
    }
    (out / "build-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    (out / "dependencies.txt").write_text(linked + "\n", encoding="utf-8")
    files = sorted(p for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (out / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    verify(Path(sys.argv[1]), sys.argv[2])
