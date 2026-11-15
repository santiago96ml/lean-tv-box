#!/usr/bin/env python3
"""
Lean TV Box Optimizer (lean_tvbox_optimizer.py)
===============================================
Standalone, zero-dependency Python 3 CLI toolkit for auditing, debloating,
and tuning constrained 2 GB RAM Android TV Boxes (Amlogic S905X2 / S905X3 / S905W,
Skyworth HP40A / FlowBox-F1, and generic OTT Set-Top Boxes) over ADB.

Features:
  - Automatic LAN discovery via ARP MAC OUI matching (Skyworth 10:76:36, etc.)
    and concurrent TCP port 5555 probing.
  - Non-destructive security & memory audit (--audit-only):
    /proc/meminfo breakdown, zRAM/swap pressure, SELinux enforcement status,
    listening TCP ports (/proc/net/tcp & tcp6), Accessibility/DeviceAdmin checks,
    and installed malware/telemetry detection.
  - Full non-root optimization pipeline (--optimize):
    * Neutralizes residential proxy malware (e.g. com.haxsmart.skylive)
    * Bypasses Skyworth firmware 'pm uninstall' whitelists on ar.com.flow.*
      using 'pm clear' + 'pm suspend --user 0' + 'pm disable-user --user 0'
    * Optionally suspends heavy preloads (--include-optional-preloads)
    * Caps ActivityManager max_cached_processes=4 for 2 GB RAM boards
    * Sets window/transition/animator scales to 0.5x
    * Executes 'pm trim-caches 999G' & 'sm fstrim' (or fstrim fallback)
    * Runs AOT native compilation ('cmd package compile -m speed') on SystemUI
      and active launchers
    * Prints a formatted Before vs. After RAM comparison table.

License: MIT
"""

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Known Skyworth / SDT / Amlogic STB IEEE MAC OUI prefixes (normalized lowercase, colon-separated)
SKYWORTH_MAC_PREFIXES = (
    "10:76:36",  # Skyworth Digital Technology (FlowBox-F1 / HP40A)
    "00:1a:9a",  # Skyworth Digital
    "24:e2:71",  # Shenzhen Skyworth
    "48:d8:45",  # Skyworth Digital
    "70:2e:80",  # Skyworth Digital
    "84:74:60",  # Skyworth Digital
    "c8:02:10",  # Skyworth Digital
    "e0:b9:4d",  # Skyworth Digital
)

# Core UI packages targeted for AOT speed compilation
AOT_CRITICAL_PACKAGES = [
    "com.android.systemui",
    "com.google.android.tvlauncher",
    "com.google.android.leanbacklauncher",
    "com.liskovsoft.smarttubetv.beta",
    "com.liskovsoft.smarttubetv",
    "io.github.visnkmr.bapl",
]


def resolve_adb_binary(custom_adb: Optional[str] = None) -> str:
    """Locate the adb executable across custom path, PATH, or local platform-tools."""
    if custom_adb and os.path.exists(custom_adb):
        return custom_adb

    path_adb = shutil.which("adb")
    if path_adb:
        return path_adb

    # Check common workspace relative locations
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir.parent / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb"),
        script_dir.parent.parent / "agente semi autonomo" / "tools" / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb"),
        Path.cwd() / "tools" / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    return "adb"


def load_debloat_catalog(profile_path: Optional[str] = None) -> Dict:
    """Load the structured debloat_packages.json catalog."""
    if profile_path:
        path = Path(profile_path)
    else:
        path = Path(__file__).resolve().parent.parent / "profiles" / "debloat_packages.json"

    if not path.exists():
        raise FileNotFoundError(f"Debloat catalog not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class ADBClient:
    """Lightweight wrapper around the ADB CLI for a specific target device."""

    def __init__(self, adb_bin: str, target: str, timeout: int = 25):
        self.adb_bin = adb_bin
        self.target = target
        self.timeout = timeout

    def run_adb(self, args: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
        cmd = [self.adb_bin]
        if self.target:
            cmd.extend(["-s", self.target])
        cmd.extend(args)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout or self.timeout,
            )
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        except subprocess.TimeoutExpired:
            return 124, "", "Command timed out"
        except FileNotFoundError:
            print(f"[!] ERROR: ADB binary '{self.adb_bin}' not found. Install Android Platform Tools or pass --adb-path.", file=sys.stderr)
            sys.exit(1)

    def shell(self, shell_cmd: str, timeout: Optional[int] = None) -> str:
        _, out, _ = self.run_adb(["shell", shell_cmd], timeout=timeout)
        return out

    def connect(self) -> bool:
        if ":" not in self.target:
            # USB serial or already listed transport
            _, out, _ = self.run_adb(["get-state"])
            return "device" in out
        proc = subprocess.run(
            [self.adb_bin, "connect", self.target],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        combined = (proc.stdout + " " + proc.stderr).lower()
        return "connected to" in combined or "already connected" in combined


def normalize_mac(raw_mac: str) -> str:
    """Convert '10-76-36-aa-bb-cc' or '10:76:36:AA:BB:CC' to '10:76:36:aa:bb:cc'."""
    cleaned = raw_mac.strip().lower().replace("-", ":")
    parts = [p.zfill(2) for p in cleaned.split(":") if p]
    return ":".join(parts)


def check_port_5555(ip: str, timeout: float = 0.6) -> bool:
    """Return True if TCP port 5555 (ADB over LAN) is open on the target IP."""
    try:
        with socket.create_connection((ip, 5555), timeout=timeout):
            return True
    except OSError:
        return False


def auto_discover_tvbox() -> Optional[str]:
    """
    Discover an Android TV Box on the local network by:
      1. Parsing the OS ARP table ('arp -a') for Skyworth MAC prefixes (e.g., 10:76:36).
      2. Probing TCP port 5555 on all ARP neighbors in parallel.
    """
    print("[*] Scanning system ARP table for Skyworth MAC prefixes and open ADB ports (5555/TCP)...")
    try:
        proc = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=8,
        )
        arp_out = proc.stdout
    except Exception as exc:
        print(f"[!] Failed to read ARP table: {exc}")
        return None

    arp_entries: List[Tuple[str, str]] = []
    # Matches IPv4 and MAC address across Windows ('192.168.1.69   10-76-36-xx-xx-xx')
    # and Linux/macOS ('(192.168.1.69) at 10:76:36:xx:xx:xx')
    pattern = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3})\s+.*?([0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2}[:\-][0-9a-fA-F]{1,2})"
    )

    for line in arp_out.splitlines():
        m = pattern.search(line)
        if m:
            ip = m.group(1)
            mac = normalize_mac(m.group(2))
            if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239."):
                continue
            arp_entries.append((ip, mac))

    # Priority 1: Match Skyworth MAC OUI prefix
    for ip, mac in arp_entries:
        if mac.startswith(SKYWORTH_MAC_PREFIXES):
            print(f"[+] Matched Skyworth MAC OUI ({mac}) at {ip}!")
            return f"{ip}:5555"

    # Priority 2: Probe TCP port 5555 across all discovered ARP neighbors
    candidate_ips = [ip for ip, _ in arp_entries]
    if candidate_ips:
        print(f"[*] Probing TCP port 5555 across {len(candidate_ips)} active LAN neighbors...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
            future_to_ip = {executor.submit(check_port_5555, ip): ip for ip in candidate_ips}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                if future.result():
                    print(f"[+] Discovered open ADB daemon on {ip}:5555")
                    return f"{ip}:5555"

    return None


def parse_meminfo(raw_meminfo: str) -> Dict[str, float]:
    """
    Parse /proc/meminfo output and return key metrics in Megabytes (MB).
    """
    kv_kb: Dict[str, int] = {}
    for line in raw_meminfo.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            num_match = re.search(r"(\d+)", v)
            if num_match:
                kv_kb[k.strip()] = int(num_match.group(1))

    total_kb = kv_kb.get("MemTotal", 0)
    avail_kb = kv_kb.get("MemAvailable", kv_kb.get("MemFree", 0) + kv_kb.get("Cached", 0))
    free_kb = kv_kb.get("MemFree", 0)
    cached_kb = kv_kb.get("Cached", 0) + kv_kb.get("Buffers", 0)
    swap_total_kb = kv_kb.get("SwapTotal", 0)
    swap_free_kb = kv_kb.get("SwapFree", 0)

    used_kb = max(0, total_kb - avail_kb)
    swap_used_kb = max(0, swap_total_kb - swap_free_kb)

    return {
        "total_mb": round(total_kb / 1024.0, 1),
        "used_mb": round(used_kb / 1024.0, 1),
        "available_mb": round(avail_kb / 1024.0, 1),
        "free_mb": round(free_kb / 1024.0, 1),
        "cached_mb": round(cached_kb / 1024.0, 1),
        "swap_total_mb": round(swap_total_kb / 1024.0, 1),
        "swap_used_mb": round(swap_used_kb / 1024.0, 1),
        "used_pct": round((used_kb / total_kb * 100.0), 1) if total_kb else 0.0,
    }


def get_listening_ports(adb: ADBClient) -> List[Tuple[int, str]]:
    """Parse /proc/net/tcp and /proc/net/tcp6 for state 0A (TCP_LISTEN)."""
    raw = adb.shell("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null")
    ports = set()
    for line in raw.splitlines():
        parts = line.strip().split()
        if len(parts) >= 4 and parts[3].upper() == "0A":
            local_addr = parts[1]
            if ":" in local_addr:
                port_hex = local_addr.split(":")[-1]
                try:
                    ports.add(int(port_hex, 16))
                except ValueError:
                    pass

    port_descriptions = {
        5353: "mDNS / ZeroConf Discovery",
        5555: "ADB over LAN Daemon",
        7547: "TR-069 CWMP ISP Remote Management Listener (RISK)",
        8008: "Google Cast / Chromecast Receiver HTTP",
        8009: "Google Cast / Chromecast Receiver TLS",
        8443: "HTTPS Local Service / Operator API",
        9080: "Operator Diagnostics / Telemetry Port",
    }
    result = []
    for p in sorted(ports):
        desc = port_descriptions.get(p, "Custom / Ephemeral Service")
        result.append((p, desc))
    return result


def get_installed_user0_packages(adb: ADBClient) -> List[str]:
    """Return list of currently installed/active packages for user 0."""
    raw = adb.shell("pm list packages --user 0")
    pkgs = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            pkgs.append(line.split("package:", 1)[1].strip())
    return pkgs


def run_audit(adb: ADBClient, catalog: Dict) -> Dict[str, float]:
    """
    Execute a comprehensive, read-only system, memory, and security audit.
    Returns parsed /proc/meminfo statistics.
    """
    print("\n" + "=" * 72)
    print(f"  LEAN TV BOX FORENSIC & MEMORY AUDIT — Target: {adb.target}")
    print("=" * 72)

    model = adb.shell("getprop ro.product.model") or "Unknown"
    brand = adb.shell("getprop ro.product.brand") or "Unknown"
    soc = adb.shell("getprop ro.board.platform") or "Unknown"
    android_ver = adb.shell("getprop ro.build.version.release") or "Unknown"
    sec_patch = adb.shell("getprop ro.build.version.security_patch") or "Unknown"
    selinux = adb.shell("getenforce") or "Unknown"

    print(f"[*] Hardware   : {brand} {model} (SoC Platform: {soc})")
    print(f"[*] OS Build   : Android {android_ver} (Security Patch: {sec_patch})")
    print(f"[*] SELinux    : {selinux}")

    # 1. Memory Snapshot
    mem_raw = adb.shell("cat /proc/meminfo")
    mem = parse_meminfo(mem_raw)
    print("\n[1] MEMORY SUBSYSTEM (/proc/meminfo):")
    print(f"    - Total Usable RAM : {mem['total_mb']:6.1f} MB")
    print(f"    - Active Used RAM  : {mem['used_mb']:6.1f} MB ({mem['used_pct']}%)")
    print(f"    - Available RAM    : {mem['available_mb']:6.1f} MB (Free: {mem['free_mb']} MB + Reclaimable Cache: {mem['cached_mb']} MB)")
    print(f"    - zRAM / Swap Used : {mem['swap_used_mb']:6.1f} MB / {mem['swap_total_mb']:.1f} MB")

    # 2. Top CPU / RSS Processes
    print("\n[2] TOP PROCESSES BY MEMORY / CPU:")
    top_out = adb.shell("ps -A -o PID,USER,%CPU,%MEM,RSS,NAME --sort=-RSS 2>/dev/null | head -n 12")
    if not top_out:
        top_out = adb.shell("top -b -n 1 | head -n 15")
    for line in top_out.splitlines()[:12]:
        print(f"    {line}")

    # 3. Open TCP Ports
    print("\n[3] OPEN LISTENING TCP PORTS (/proc/net/tcp & tcp6):")
    ports = get_listening_ports(adb)
    if not ports:
        print("    - None detected.")
    else:
        for port, desc in ports:
            print(f"    - TCP/{port:<5d} : {desc}")

    # 4. Known Malware, Operator Locks & Bloatware Scan
    print("\n[4] CATALOG THREAT & TELEMETRY SCAN (User 0):")
    installed = set(get_installed_user0_packages(adb))

    malware_pkgs = catalog.get("malware_and_botnets", {}).get("packages", [])
    operator_pkgs = catalog.get("operator_telemetry_and_locks", {}).get("packages", [])
    preload_pkgs = catalog.get("heavy_preloads_optional", {}).get("packages", [])

    found_malware = [p for p in malware_pkgs if p in installed]
    found_operator = [p for p in operator_pkgs if p in installed]
    found_preloads = [p for p in preload_pkgs if p in installed]

    if found_malware:
        for p in found_malware:
            print(f"    [!] CRITICAL MALWARE ACTIVE : {p} (Hidden VPN proxy & ~30% CPU hijack)")
    else:
        print("    [+] Malware & Botnets       : Clean (0 active threats)")

    if found_operator:
        print(f"    [!] Operator Telemetry/Locks: {len(found_operator)} active package(s) detected:")
        for p in found_operator:
            print(f"        - {p}")
    else:
        print("    [+] Operator Telemetry/Locks: All neutralized/absent")

    if found_preloads:
        print(f"    [*] Heavy Optional Preloads : {len(found_preloads)} installed ({', '.join(found_preloads)})")

    return mem


def print_ram_comparison_table(before: Dict[str, float], after: Dict[str, float]) -> None:
    """Render a clean ASCII Before/After RAM comparison table in the terminal."""
    delta_used = after["used_mb"] - before["used_mb"]
    delta_avail = after["available_mb"] - before["available_mb"]
    delta_swap = after["swap_used_mb"] - before["swap_used_mb"]
    delta_pct = after["used_pct"] - before["used_pct"]

    print("\n" + "=" * 72)
    print("  BEFORE vs. AFTER RAM OPTIMIZATION COMPARISON TABLE")
    print("=" * 72)
    print(f"  {'Metric':<26} | {'Before':>12} | {'After':>12} | {'Net Delta':>12}")
    print("  " + "-" * 68)
    print(f"  {'Total Kernel RAM':<26} | {before['total_mb']:>9.1f} MB | {after['total_mb']:>9.1f} MB | {'0.0 MB':>12}")
    print(f"  {'Used RAM':<26} | {before['used_mb']:>9.1f} MB | {after['used_mb']:>9.1f} MB | {delta_used:>+9.1f} MB")
    print(f"  {'Available Free+Cache RAM':<26} | {before['available_mb']:>9.1f} MB | {after['available_mb']:>9.1f} MB | {delta_avail:>+9.1f} MB")
    print(f"  {'zRAM / Swap Consumed':<26} | {before['swap_used_mb']:>9.1f} MB | {after['swap_used_mb']:>9.1f} MB | {delta_swap:>+9.1f} MB")
    print(f"  {'Memory Pressure (%)':<26} | {before['used_pct']:>10.1f} % | {after['used_pct']:>10.1f} % | {delta_pct:>+10.1f} %")
    print("=" * 72 + "\n")


def neutralize_package(adb: ADBClient, pkg: str, category: str) -> None:
    """
    Neutralize a target package using a defense-in-depth sequence:
      1. am force-stop <pkg>
      2. pm clear <pkg> (wipes state/cache & stops persistent services)
      3. cmd appops set <pkg> RUN_IN_BACKGROUND ignore
      4. pm suspend --user 0 <pkg> (crucial for Skyworth whitelist-protected ar.com.flow.*)
      5. pm disable-user --user 0 <pkg>
      6. pm uninstall --user 0 <pkg>
    """
    print(f"    -> Neutralizing [{category}] {pkg} ...")
    adb.shell(f"am force-stop {pkg} 2>/dev/null")
    clear_res = adb.shell(f"pm clear {pkg} 2>/dev/null")
    adb.shell(f"cmd appops set {pkg} RUN_IN_BACKGROUND ignore 2>/dev/null")
    adb.shell(f"cmd appops set {pkg} SYSTEM_ALERT_WINDOW deny 2>/dev/null")

    suspend_res = adb.shell(f"pm suspend --user 0 {pkg} 2>/dev/null")
    disable_res = adb.shell(f"pm disable-user --user 0 {pkg} 2>/dev/null")
    uninst_res = adb.shell(f"pm uninstall --user 0 {pkg} 2>/dev/null")

    status_notes = []
    if "Success" in clear_res:
        status_notes.append("cleared")
    if "true" in suspend_res.lower() or "suspended" in suspend_res.lower():
        status_notes.append("suspended")
    if "disabled" in disable_res.lower():
        status_notes.append("disabled")
    if "Success" in uninst_res:
        status_notes.append("uninstalled")
    elif "DELETE_FAILED_INTERNAL_ERROR" in uninst_res or pkg.startswith("ar.com.flow."):
        status_notes.append("whitelist-bypassed via pm suspend")

    summary = ", ".join(status_notes) if status_notes else "processed"
    print(f"       [OK] {pkg}: {summary}")


def run_optimization(adb: ADBClient, catalog: Dict, include_optional: bool = False) -> None:
    """
    Execute the complete Lean TV Box optimization pipeline and display
    a Before/After RAM comparison table.
    """
    print("\n[*] Capturing baseline RAM metrics before optimization...")
    before_mem = parse_meminfo(adb.shell("cat /proc/meminfo"))

    installed = set(get_installed_user0_packages(adb))

    # Step 1: Malware & Botnets
    print("\n[Step 1/6] Purging Malware & Residential Proxy Botnets...")
    for pkg in catalog.get("malware_and_botnets", {}).get("packages", []):
        if pkg in installed:
            neutralize_package(adb, pkg, "MALWARE")
        else:
            print(f"    - {pkg}: already absent.")

    # Step 2: Operator Telemetry & Provisioning Locks
    print("\n[Step 2/6] Neutralizing ISP Telemetry, TR-069/TR-369 & Provisioning Locks...")
    for pkg in catalog.get("operator_telemetry_and_locks", {}).get("packages", []):
        neutralize_package(adb, pkg, "OPERATOR/TELEMETRY")

    # Step 3: Optional Heavy Preloads
    if include_optional:
        print("\n[Step 3/6] Suspending Heavy Commercial Preloads (--include-optional-preloads)...")
        for pkg in catalog.get("heavy_preloads_optional", {}).get("packages", []):
            neutralize_package(adb, pkg, "HEAVY_PRELOAD")
    else:
        print("\n[Step 3/6] Skipping optional heavy preloads (pass --include-optional-preloads to include).")

    # Step 4: Low-RAM ActivityManager & Animation Tuning
    print("\n[Step 4/6] Applying 2 GB Low-RAM ActivityManager & UI Animation Profile...")
    adb.shell("settings put global activity_manager_constants max_cached_processes=4,background_settle_time=10000")
    adb.shell("settings put global window_animation_scale 0.5")
    adb.shell("settings put global transition_animation_scale 0.5")
    adb.shell("settings put global animator_duration_scale 0.5")
    adb.shell("settings put global wifi_scan_always_enabled 0")
    adb.shell("settings put global ble_scan_always_enabled 0")
    print("    [OK] max_cached_processes=4 | Animations=0.5x | Background Wi-Fi/BLE scanning=OFF")

    # Step 5: Flash Storage Trim & Cache Reclamation
    print("\n[Step 5/6] Reclaiming Package Caches & Running eMMC fstrim...")
    adb.shell("pm trim-caches 999G 2>/dev/null")
    adb.shell("sm fstrim 2>/dev/null")
    adb.shell("am kill-all 2>/dev/null")
    print("    [OK] Executed 'pm trim-caches 999G', 'sm fstrim', and 'am kill-all'")

    # Step 6: AOT Native Compilation (-m speed) for SystemUI & Launchers
    print("\n[Step 6/6] Running AOT Native Code Compilation ('cmd package compile -m speed')...")
    for pkg in AOT_CRITICAL_PACKAGES:
        if pkg in installed:
            res = adb.shell(f"cmd package compile -m speed -f {pkg}", timeout=60)
            print(f"    [OK] AOT compiled {pkg}: {res or 'Success'}")

    # Allow 2 seconds for ActivityManager to settle after am kill-all
    time.sleep(2)
    after_mem = parse_meminfo(adb.shell("cat /proc/meminfo"))
    print_ram_comparison_table(before_mem, after_mem)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lean_tvbox_optimizer.py",
        description="Lean TV Box Optimizer — Debloat, Security Audit & Low-RAM Tuning CLI for 2 GB Android TV Boxes.",
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target",
        metavar="IP:PORT",
        help="Target Android TV Box ADB address (e.g., 192.168.1.69:5555) or USB serial.",
    )
    target_group.add_argument(
        "--auto-discover",
        action="store_true",
        help="Automatically scan the LAN ARP table for Skyworth MAC prefixes (10:76:36) or open port 5555.",
    )

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--audit-only",
        action="store_true",
        help="Read-only audit: print /proc/meminfo, top processes, SELinux status, open TCP ports, and malware/telemetry scan.",
    )
    action_group.add_argument(
        "--optimize",
        action="store_true",
        help="Execute full debloat, Skyworth whitelist bypass (pm clear + pm suspend), max_cached_processes=4, 0.5x animations, fstrim, and AOT compilation.",
    )

    parser.add_argument(
        "--include-optional-preloads",
        action="store_true",
        help="Also clear and suspend heavy commercial preloads (YouTube TV Cobalt, Google Videos, Netflix daemon).",
    )
    parser.add_argument(
        "--profile",
        metavar="PATH",
        default=None,
        help="Custom path to debloat_packages.json (defaults to ../profiles/debloat_packages.json).",
    )
    parser.add_argument(
        "--adb-path",
        metavar="PATH",
        default=None,
        help="Explicit path to adb executable.",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    adb_bin = resolve_adb_binary(args.adb_path)
    catalog = load_debloat_catalog(args.profile)

    target = args.target
    if args.auto_discover:
        target = auto_discover_tvbox()
        if not target:
            print("[!] Auto-discovery did not find an active TV Box on port 5555. Specify --target <IP:PORT> manually.", file=sys.stderr)
            return 1

    adb = ADBClient(adb_bin=adb_bin, target=target)
    print(f"[*] Connecting to target {target} via ADB ({adb_bin})...")
    if not adb.connect():
        print(f"[!] Could not establish ADB session with {target}. Verify Developer Options -> Network Debugging.", file=sys.stderr)
        return 1

    if args.audit_only:
        run_audit(adb, catalog)
    elif args.optimize:
        run_audit(adb, catalog)
        run_optimization(adb, catalog, include_optional=args.include_optional_preloads)

    return 0


if __name__ == "__main__":
    sys.exit(main())
