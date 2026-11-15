#!/usr/bin/env python3
"""
Forensic APK Static Auditor (forensic_apk_auditor.py)
=====================================================
Standalone, zero-dependency Python 3 static analysis and forensic auditing tool
for Android APK binaries (standard library only: zipfile, re, struct, json,
argparse, hashlib).

Capabilities:
  1. Container & ELF Architecture Inventory:
     Categorizes DEX bytecode files, native ELF (.so) shared libraries (extracting
     CPU ABIs and inspecting ELF headers via struct), META-INF cryptographic
     signatures, and AXML resources.
  2. Binary AndroidManifest.xml (AXML) String Pool Parser:
     Parses binary AXML chunks (RES_STRING_POOL_TYPE 0x0001) via struct alongside
     UTF-8 and UTF-16LE string extraction to recover all declared permissions
     (android.permission.*), highlighting high-risk capabilities:
       - RECEIVE_BOOT_COMPLETED
       - BIND_VPN_SERVICE
       - SYSTEM_ALERT_WINDOW
       - BIND_ACCESSIBILITY_SERVICE
       - READ_EXTERNAL_STORAGE / WRITE_EXTERNAL_STORAGE / REQUEST_INSTALL_PACKAGES
     Extracts declared Services, BroadcastReceivers (e.g. BootReceiver), and Activities.
  3. Multi-DEX Bytecode Forensic Scanner (classes*.dex):
     Scans all DEX files for hardcoded http:// and https:// endpoints/URLs and
     sensitive system/reflection/tunneling API calls (Runtime.getRuntime, exec,
     DexClassLoader, loadLibrary, VpnService, ProcessBuilder, Cipher).
  4. Educational Smali Neutralization Guide:
     Generates a step-by-step surgical patching guide demonstrating how to
     neutralize unwanted boot receivers, telemetry hooks, or VPN hijackers in
     Smali using 'return-void'.

License: MIT
"""

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

# High-risk permissions that warrant forensic scrutiny on Android TV / STB devices
HIGH_RISK_PERMISSIONS: Dict[str, str] = {
    "android.permission.RECEIVE_BOOT_COMPLETED": "Allows persistent daemon/service auto-start at system boot before user interaction.",
    "android.permission.BIND_VPN_SERVICE": "Allows intercepting/routing all device network traffic (used by residential proxy botnets like SkyLive/MagisTV).",
    "android.permission.SYSTEM_ALERT_WINDOW": "Allows drawing persistent full-screen lock overlays over other apps (used by ISP provisioning locks).",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Allows observing UI events, intercepting keystrokes, and automating clicks.",
    "android.permission.READ_EXTERNAL_STORAGE": "Allows reading shared external storage and media files.",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Allows writing/modifying files on shared external storage.",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Allows silent or prompted sideloading of secondary APK payloads.",
    "android.permission.PACKAGE_USAGE_STATS": "Allows profiling foreground app activity and user behavior.",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE": "Allows accepting all multicast packets on the local Wi-Fi LAN (mDNS/SSDP discovery).",
    "android.permission.WAKE_LOCK": "Prevents the Amlogic SoC from entering deep suspend states.",
}

# Sensitive API / class signatures scanned inside classes*.dex
SENSITIVE_API_SIGNATURES: Dict[str, Tuple[bytes, str]] = {
    "Runtime.getRuntime": (
        b"Ljava/lang/Runtime;",
        "Spawns native OS shell processes via Runtime.getRuntime().",
    ),
    "exec": (
        b"exec",
        "Executes external shell binaries or system commands.",
    ),
    "DexClassLoader": (
        b"Ldalvik/system/DexClassLoader;",
        "Dynamically loads external/encrypted DEX bytecode payloads at runtime.",
    ),
    "loadLibrary": (
        b"loadLibrary",
        "Loads native C/C++ ELF (.so) shared libraries via JNI.",
    ),
    "VpnService": (
        b"Landroid/net/VpnService;",
        "Creates a virtual network interface (TUN) to tunnel or proxy device traffic.",
    ),
    "ProcessBuilder": (
        b"Ljava/lang/ProcessBuilder;",
        "Constructs and spawns native operating system processes.",
    ),
    "System.setProperty": (
        b"setProperty",
        "Modifies JVM/Android system properties (often used for proxy overrides).",
    ),
}


def compute_sha256(file_path: Path) -> str:
    """Calculate the SHA-256 digest of the target APK file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_elf_header(raw_bytes: bytes) -> str:
    """
    Use struct to inspect the first 20 bytes of an ELF binary (.so) and return
    a human-readable architecture descriptor.
    """
    if len(raw_bytes) < 20 or raw_bytes[:4] != b"\x7fELF":
        return "Non-ELF or truncated binary"
    ei_class = raw_bytes[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = raw_bytes[5]   # 1 = Little Endian, 2 = Big Endian
    bits = "64-bit" if ei_class == 2 else "32-bit"
    endian_fmt = "<" if ei_data == 1 else ">"
    try:
        _, e_machine = struct.unpack(f"{endian_fmt}HH", raw_bytes[16:20])
    except struct.error:
        return f"ELF {bits}"

    machine_map = {
        0x28: "ARM (armeabi-v7a)",
        0xB7: "AArch64 (arm64-v8a)",
        0x03: "x86 (IA-32)",
        0x3E: "x86_64 (AMD64)",
    }
    arch_str = machine_map.get(e_machine, f"Machine 0x{e_machine:02x}")
    return f"ELF {bits} {arch_str}"


def parse_axml_string_pool(data: bytes) -> List[str]:
    """
    Extract strings from a compiled Android Binary XML (AXML) file using:
      1. Binary struct parsing of the RES_STRING_POOL_TYPE (0x0001) chunk header.
      2. Full-buffer UTF-8 and UTF-16LE regex scanning to ensure resilience
         against obfuscated or non-standard AXML headers.
    """
    extracted: Set[str] = set()

    # 1. Binary struct parser for AXML String Pool (Chunk Type 0x0001)
    if len(data) >= 36:
        try:
            xml_type, xml_header_size, xml_total_size = struct.unpack("<HHI", data[0:8])
            if xml_type == 0x0003:  # RES_XML_TYPE
                sp_offset = xml_header_size
                if sp_offset + 28 <= len(data):
                    (
                        sp_type,
                        sp_header_size,
                        sp_chunk_size,
                        string_count,
                        style_count,
                        flags,
                        strings_start,
                        styles_start,
                    ) = struct.unpack("<HHIIIIII", data[sp_offset : sp_offset + 28])

                    if sp_type == 0x0001 and string_count < 200000:
                        is_utf8 = bool(flags & (1 << 8))
                        offsets_base = sp_offset + sp_header_size
                        pool_base = sp_offset + strings_start

                        for idx in range(string_count):
                            off_pos = offsets_base + idx * 4
                            if off_pos + 4 > len(data):
                                break
                            (str_rel_off,) = struct.unpack("<I", data[off_pos : off_pos + 4])
                            pos = pool_base + str_rel_off
                            if pos >= len(data):
                                continue

                            if is_utf8:
                                # UTF-8 length encoding (1 or 2 bytes for char len, then 1 or 2 bytes for byte len)
                                if pos + 2 <= len(data):
                                    u16_len = data[pos]
                                    pos += 2 if (u16_len & 0x80) else 1
                                    if pos < len(data):
                                        byte_len = data[pos]
                                        if byte_len & 0x80 and pos + 1 < len(data):
                                            byte_len = ((byte_len & 0x7F) << 8) | data[pos + 1]
                                            pos += 2
                                        else:
                                            pos += 1
                                        raw_s = data[pos : pos + byte_len]
                                        s = raw_s.decode("utf-8", errors="ignore").strip()
                                        if len(s) >= 3:
                                            extracted.add(s)
                            else:
                                # UTF-16LE length encoding
                                if pos + 2 <= len(data):
                                    (u16_len,) = struct.unpack("<H", data[pos : pos + 2])
                                    pos += 2
                                    if u16_len & 0x8000 and pos + 2 <= len(data):
                                        (low,) = struct.unpack("<H", data[pos : pos + 2])
                                        u16_len = ((u16_len & 0x7FFF) << 16) | low
                                        pos += 2
                                    byte_len = u16_len * 2
                                    raw_s = data[pos : pos + byte_len]
                                    s = raw_s.decode("utf-16le", errors="ignore").strip()
                                    if len(s) >= 3:
                                        extracted.add(s)
        except struct.error:
            pass

    # 2. Regex fallback for UTF-8 and UTF-16LE strings across the AXML buffer
    for m in re.findall(rb"[\x20-\x7E]{3,}", data):
        extracted.add(m.decode("utf-8", errors="ignore").strip())

    for m in re.findall(rb"(?:[\x20-\x7E]\x00){3,}", data):
        extracted.add(m.decode("utf-16le", errors="ignore").strip())

    return sorted(extracted)


def classify_manifest_strings(strings: List[str]) -> Dict[str, Any]:
    """
    Classify AXML string pool entries into permissions, high-risk permissions,
    Services, BroadcastReceivers, and Activities.
    """
    permissions: Set[str] = set()
    services: Set[str] = set()
    receivers: Set[str] = set()
    activities: Set[str] = set()
    intent_actions: Set[str] = set()
    package_candidates: List[str] = []

    java_ident_re = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z0-9_$]+)+$")

    for s in strings:
        # Permissions (including custom *_PERMISSION constants)
        if (
            "android.permission." in s
            or s.endswith(".permission.C2D_MESSAGE")
            or ".permission." in s
            or s.endswith("_PERMISSION")
        ):
            if java_ident_re.match(s):
                permissions.add(s)
            else:
                perm_match = re.search(r"(android\.permission\.[A-Z0-9_]+)", s)
                if perm_match:
                    permissions.add(perm_match.group(1))
            continue

        # Intent actions
        if s.startswith("android.intent.action.") or s.startswith("android.net.conn."):
            intent_actions.add(s)
            continue

        if not java_ident_re.match(s):
            continue

        lower_s = s.lower()
        # Filter out standard resource/attr identifiers
        if s.startswith(("android.support.", "androidx.core.app.CoreComponentFactory")):
            continue

        if "service" in lower_s and not lower_s.startswith("android."):
            services.add(s)
        elif ("receiver" in lower_s or "boot" in lower_s) and not lower_s.startswith("android."):
            receivers.add(s)
        elif "activity" in lower_s and not lower_s.startswith("android."):
            activities.add(s)
        elif s.count(".") >= 1 and lower_s == s and not s.startswith(("android.", "androidx.", "com.google.", "kotlin.", "kotlinx.")):
            package_candidates.append(s)

    sorted_perms = sorted(permissions)
    high_risk_found = []
    for p in sorted_perms:
        short_name = p.split(".")[-1]
        if p in HIGH_RISK_PERMISSIONS:
            high_risk_found.append({
                "permission": p,
                "short_name": short_name,
                "risk_explanation": HIGH_RISK_PERMISSIONS[p],
            })
        elif short_name in ("RECEIVE_BOOT_COMPLETED", "BIND_VPN_SERVICE", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "READ_EXTERNAL_STORAGE"):
            high_risk_found.append({
                "permission": p,
                "short_name": short_name,
                "risk_explanation": HIGH_RISK_PERMISSIONS.get(f"android.permission.{short_name}", "High-privilege capability"),
            })

    return {
        "inferred_package": package_candidates[0] if package_candidates else "Unknown",
        "permissions": sorted_perms,
        "high_risk_permissions": high_risk_found,
        "services": sorted(services),
        "receivers": sorted(receivers),
        "activities": sorted(activities),
        "intent_actions": sorted(intent_actions),
    }


def scan_dex_payload(dex_name: str, dex_bytes: bytes) -> Dict[str, Any]:
    """
    Scan a classes*.dex binary for:
      - Hardcoded http:// and https:// URLs
      - Sensitive system calls (Runtime.getRuntime, exec, DexClassLoader, loadLibrary, VpnService)
    """
    # Verify DEX magic header ('dex\n035\x00' etc.)
    dex_version = "Unknown"
    if len(dex_bytes) >= 8 and dex_bytes[:4] == b"dex\n":
        dex_version = dex_bytes[4:7].decode("ascii", errors="ignore")

    url_matches = re.findall(rb"https?://[a-zA-Z0-9\.\-_/~:%?#=&+]+", dex_bytes)
    cleaned_urls: Set[str] = set()
    for raw_u in url_matches:
        u = raw_u.decode("utf-8", errors="ignore").rstrip(".,;)'\"")
        # Exclude noisy XML schema namespaces unless they are real endpoints
        if u not in ("http://schemas.android.com/apk/res/android", "http://www.w3.org/2001/XMLSchema"):
            cleaned_urls.add(u)

    detected_apis = []
    for api_name, (pattern_bytes, explanation) in SENSITIVE_API_SIGNATURES.items():
        if pattern_bytes in dex_bytes or api_name.encode("utf-8") in dex_bytes:
            detected_apis.append({
                "call": api_name,
                "description": explanation,
            })

    return {
        "dex_file": dex_name,
        "size_bytes": len(dex_bytes),
        "dex_version": dex_version,
        "urls": sorted(cleaned_urls),
        "sensitive_calls": detected_apis,
    }


def analyze_apk(apk_path: Path) -> Dict[str, Any]:
    """Run full static forensic analysis on an APK file and return a structured dictionary."""
    if not apk_path.exists():
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    sha256_hash = compute_sha256(apk_path)
    file_size = apk_path.stat().st_size

    categories: Dict[str, List[str]] = {
        "dex_bytecode": [],
        "native_elf_libraries": [],
        "meta_inf_signatures": [],
        "manifest_and_resources": [],
        "assets_and_other": [],
    }
    native_architectures: Set[str] = set()
    elf_details: List[Dict[str, str]] = []
    manifest_analysis: Dict[str, Any] = {}
    dex_reports: List[Dict[str, Any]] = []

    with zipfile.ZipFile(apk_path, "r") as zf:
        for member in zf.namelist():
            if member.endswith(".dex"):
                categories["dex_bytecode"].append(member)
            elif member.endswith(".so"):
                categories["native_elf_libraries"].append(member)
                parts = member.split("/")
                if len(parts) >= 2 and parts[0] == "lib":
                    native_architectures.add(parts[1])
                try:
                    with zf.open(member) as so_f:
                        header_bytes = so_f.read(64)
                    elf_details.append({
                        "path": member,
                        "elf_header": parse_elf_header(header_bytes),
                    })
                except Exception:
                    pass
            elif member.startswith("META-INF/"):
                categories["meta_inf_signatures"].append(member)
            elif member in ("AndroidManifest.xml", "resources.arsc") or member.startswith("res/"):
                categories["manifest_and_resources"].append(member)
            else:
                categories["assets_and_other"].append(member)

        # Parse AndroidManifest.xml
        if "AndroidManifest.xml" in zf.namelist():
            manifest_bytes = zf.read("AndroidManifest.xml")
            axml_strings = parse_axml_string_pool(manifest_bytes)
            manifest_analysis = classify_manifest_strings(axml_strings)

        # Scan all classes*.dex files
        for dex_name in sorted(categories["dex_bytecode"]):
            dex_bytes = zf.read(dex_name)
            dex_reports.append(scan_dex_payload(dex_name, dex_bytes))

    # Aggregate URLs and sensitive calls across all DEX files
    all_urls: Set[str] = set()
    all_calls: Dict[str, str] = {}
    for rep in dex_reports:
        all_urls.update(rep["urls"])
        for c in rep["sensitive_calls"]:
            all_calls[c["call"]] = c["description"]

    return {
        "apk_file": str(apk_path.resolve()),
        "apk_name": apk_path.name,
        "size_bytes": file_size,
        "size_mb": round(file_size / (1024 * 1024), 2),
        "sha256": sha256_hash,
        "inventory": {
            "total_files": sum(len(v) for v in categories.values()),
            "counts": {k: len(v) for k, v in categories.items()},
            "dex_files": categories["dex_bytecode"],
            "native_libraries": categories["native_elf_libraries"],
            "native_abis": sorted(native_architectures),
            "elf_headers": elf_details[:15],
            "meta_inf_files": categories["meta_inf_signatures"],
        },
        "manifest": manifest_analysis,
        "dex_analysis": {
            "per_dex": dex_reports,
            "aggregated_urls": sorted(all_urls),
            "aggregated_sensitive_calls": [
                {"call": k, "description": v} for k, v in sorted(all_calls.items())
            ],
        },
    }


def render_markdown_report(report: Dict[str, Any]) -> str:
    """Format the forensic analysis into a rich, human-readable Markdown report."""
    inv = report["inventory"]
    man = report.get("manifest", {})
    dex = report.get("dex_analysis", {})

    lines: List[str] = []
    lines.append(f"# Forensic APK Static Analysis Report: `{report['apk_name']}`")
    lines.append("")
    lines.append("## 1. Binary Identification & Container Inventory")
    lines.append(f"- **File Path**: `{report['apk_file']}`")
    lines.append(f"- **File Size**: `{report['size_mb']} MB` (`{report['size_bytes']:,} bytes`)")
    lines.append(f"- **SHA-256 Digest**: `{report['sha256']}`")
    lines.append(f"- **Inferred Package ID**: `{man.get('inferred_package', 'Unknown')}`")
    lines.append(f"- **Total Internal Files**: `{inv['total_files']}`")
    lines.append("")
    lines.append("| Category | Count | Key Artifacts / Notes |")
    lines.append("| :--- | :---: | :--- |")
    lines.append(f"| **DEX Bytecode (`.dex`)** | {inv['counts']['dex_bytecode']} | `{', '.join(inv['dex_files']) or 'None'}` |")
    abi_str = ", ".join(inv["native_abis"]) if inv["native_abis"] else "None (Pure Java/Kotlin DEX)"
    lines.append(f"| **Native ELF Libraries (`.so`)** | {inv['counts']['native_elf_libraries']} | ABIs: `{abi_str}` |")
    lines.append(f"| **Signatures (`META-INF/`)** | {inv['counts']['meta_inf_signatures']} | `{', '.join(inv['meta_inf_files'][:4])}` |")
    lines.append(f"| **Manifest & Resources** | {inv['counts']['manifest_and_resources']} | `AndroidManifest.xml`, `resources.arsc`, `res/*` |")
    lines.append(f"| **Assets & Misc** | {inv['counts']['assets_and_other']} | Internal assets & Kotlin metadata |")
    lines.append("")

    if inv["elf_headers"]:
        lines.append("### Native ELF Shared Libraries (`.so`)")
        for elf in inv["elf_headers"]:
            lines.append(f"- `{elf['path']}` — **{elf['elf_header']}**")
        lines.append("")

    # Section 2: Manifest & Permissions
    lines.append("## 2. Binary `AndroidManifest.xml` (AXML) Attack Surface")
    high_risk = man.get("high_risk_permissions", [])
    if high_risk:
        lines.append("### [!] High-Risk Permissions Highlighted")
        for hr in high_risk:
            lines.append(f"- **`{hr['permission']}`** (`{hr['short_name']}`): {hr['risk_explanation']}")
    else:
        lines.append("### [+] High-Risk Permissions: None Detected")
    lines.append("")

    all_perms = man.get("permissions", [])
    lines.append(f"### All Declared Permissions ({len(all_perms)})")
    if all_perms:
        for p in all_perms:
            lines.append(f"- `{p}`")
    else:
        lines.append("- *No standard `android.permission.*` entries found.*")
    lines.append("")

    # Components
    lines.append("### Declared Background Services, Receivers & Activities")
    services = man.get("services", [])
    receivers = man.get("receivers", [])
    activities = man.get("activities", [])

    lines.append(f"- **Services ({len(services)})**:")
    if services:
        for s in services[:15]:
            lines.append(f"  - `{s}`")
    else:
        lines.append("  - *None detected*")

    lines.append(f"- **BroadcastReceivers ({len(receivers)})**:")
    if receivers:
        for r in receivers[:15]:
            highlight = " **(BOOT PERSISTENCE TRIGGER)**" if "boot" in r.lower() else ""
            lines.append(f"  - `{r}`{highlight}")
    else:
        lines.append("  - *None detected*")

    lines.append(f"- **Activities ({len(activities)})**:")
    if activities:
        for a in activities[:15]:
            lines.append(f"  - `{a}`")
    else:
        lines.append("  - *None detected*")
    lines.append("")

    # Section 3: DEX Bytecode Endpoints & System Calls
    lines.append("## 3. Multi-DEX Bytecode Forensic Scan (`classes*.dex`)")
    calls = dex.get("aggregated_sensitive_calls", [])
    lines.append(f"### Sensitive System, Reflection & Tunneling Calls ({len(calls)})")
    if calls:
        for c in calls:
            lines.append(f"- **`{c['call']}`**: {c['description']}")
    else:
        lines.append("- *No high-risk native execution or dynamic classloading calls found.*")
    lines.append("")

    urls = dex.get("aggregated_urls", [])
    lines.append(f"### Hardcoded HTTP/HTTPS Endpoints & URLs ({len(urls)})")
    if urls:
        for u in urls[:25]:
            lines.append(f"- `{u}`")
        if len(urls) > 25:
            lines.append(f"- *... (+{len(urls) - 25} additional URLs omitted for brevity)*")
    else:
        lines.append("- *No hardcoded HTTP/HTTPS URLs detected.*")
    lines.append("")

    # Section 4: Educational Smali Neutralization Guide
    lines.append("## 4. Educational Guide: Surgical Method Neutralization in Smali (`return-void`)")
    lines.append(
        "When auditing third-party Android TV APKs that include unwanted boot persistence "
        "(`BootReceiver`), intrusive telemetry initializers, or forced update dialogs, you can "
        "neutralize the specific method in Dalvik bytecode without breaking the rest of the application:"
    )
    lines.append("")
    lines.append("### Step 1 — Decompile the APK to Smali with `apktool`")
    lines.append("```bash")
    lines.append(f"apktool d \"{report['apk_name']}\" -o decompiled_apk")
    lines.append("```")
    lines.append("")
    lines.append("### Step 2 — Replace the Target Method Body with `return-void`")
    lines.append(
        "Locate the target class inside `decompiled_apk/smali/` (for example, `BootReceiver.smali` "
        "or a telemetry initializer) and short-circuit `onReceive` so it exits immediately:"
    )
    lines.append("```smali")
    lines.append("# BEFORE (Original Dalvik Smali bytecode spawning a background daemon on boot):")
    lines.append(".method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V")
    lines.append("    .locals 3")
    lines.append("    invoke-static {p1}, Lcom/example/app/TelemetryService;->start(Landroid/content/Context;)V")
    lines.append("    return-void")
    lines.append(".end method")
    lines.append("")
    lines.append("# AFTER (Neutralized zero-RAM no-op via immediate return-void):")
    lines.append(".method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V")
    lines.append("    .locals 0")
    lines.append("    return-void")
    lines.append(".end method")
    lines.append("```")
    lines.append("")
    lines.append("### Step 3 — Rebuild, 4-Byte `zipalign`, and Sign with `apksigner` (V2/V3 Scheme)")
    lines.append("```bash")
    lines.append("apktool b decompiled_apk -o patched_unsigned.apk")
    lines.append("zipalign -p -f -v 4 patched_unsigned.apk patched_aligned.apk")
    lines.append("apksigner sign --ks release-key.jks --out patched_signed.apk patched_aligned.apk")
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic_apk_auditor.py",
        description="Standalone Python 3 Forensic APK Static Analyzer (AXML String Pool, DEX Endpoints, High-Risk Permissions & Smali Guide).",
    )
    parser.add_argument(
        "apk_path",
        metavar="APK_PATH",
        help="Path to the target .apk file to analyze.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Emit the complete forensic report as structured JSON instead of Markdown.",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        default=None,
        help="Optional file path to save the generated report (Markdown or JSON).",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    apk_path = Path(args.apk_path)
    if not apk_path.exists():
        print(f"[!] ERROR: Target APK file does not exist: {apk_path}", file=sys.stderr)
        return 1

    try:
        report = analyze_apk(apk_path)
    except zipfile.BadZipFile:
        print(f"[!] ERROR: '{apk_path}' is not a valid ZIP/APK archive.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[!] ERROR analyzing APK: {exc}", file=sys.stderr)
        return 1

    if args.output_json:
        rendered = json.dumps(report, indent=2, ensure_ascii=False)
    else:
        rendered = render_markdown_report(report)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
        print(f"[+] Forensic report written to: {out_path}")
    else:
        # Ensure UTF-8 safe printing on Windows consoles
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())
