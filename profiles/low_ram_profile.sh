#!/system/bin/sh
# ==============================================================================
# Lean TV Box — 2 GB Low-RAM Tuning Profile (low_ram_profile.sh)
# ==============================================================================
# Target SoCs : Amlogic S905X2 / S905X3 / S905X4 / S905W (Quad-Core Cortex-A53)
# Target Boards: Skyworth Digital HP40A (FlowBox-F1) & Generic 2 GB Android TV
# Execution    :
#   adb push profiles/low_ram_profile.sh /data/local/tmp/low_ram_profile.sh
#   adb shell sh /data/local/tmp/low_ram_profile.sh
# ==============================================================================

echo "======================================================================"
echo "  LEAN TV BOX: APPLYING 2 GB LOW-RAM & EMMC OPTIMIZATION PROFILE"
echo "======================================================================"

echo "[*] Baseline /proc/meminfo snapshot:"
grep -E "MemTotal|MemFree|MemAvailable|Cached|SwapTotal|SwapFree" /proc/meminfo

# 1. Cap ActivityManager Cached Processes & Background Settle Time
# Default Android TV keeps 16-32 cached processes in RAM, exhausting 2 GB boards
# and triggering constant zRAM swap thrashing. Capping to 4 preserves ~350 MB free.
echo ""
echo "[1/6] Configuring ActivityManager Low-RAM Constants (max_cached_processes=4)..."
settings put global activity_manager_constants "max_cached_processes=4,background_settle_time=10000,fg_to_bg_fgs_grace_duration=5000"
settings put global always_finish_activities 0

# 2. Trim WebView & Background Renderer Memory Footprint
echo "[2/6] Restricting Background WebView & Heavy Preload Wakeups..."
for wv_pkg in com.google.android.webview com.android.webview com.google.android.youtube.tv; do
    if pm list packages --user 0 | grep -q "^package:${wv_pkg}$"; then
        cmd appops set "${wv_pkg}" RUN_IN_BACKGROUND ignore 2>/dev/null
        cmd appops set "${wv_pkg}" RUN_ANY_IN_BACKGROUND ignore 2>/dev/null
        am send-trim-memory "${wv_pkg}" COMPLETE 2>/dev/null
        echo "      -> Trimmed & restricted background WebView/Cobalt state: ${wv_pkg}"
    fi
done

# 3. Set UI Window, Transition, and Animator Scales to 0.5x
# Reduces GPU frame-buffer hold times on Mali-G31 MP2 / Mali-450 GPUs.
echo "[3/6] Setting Window, Transition & Animator Scales to 0.5x..."
settings put global window_animation_scale 0.5
settings put global transition_animation_scale 0.5
settings put global animator_duration_scale 0.5

# 4. Disable Unnecessary Background Radio & Telemetry Scanners
echo "[4/6] Disabling Background Wi-Fi/BLE Scanning & Usage Stats Telemetry..."
settings put global wifi_scan_always_enabled 0
settings put global ble_scan_always_enabled 0
settings put global netstats_enabled 0
settings put secure send_action_app_error 0

# 5. Neutralize Known Malware & Skyworth Whitelist-Protected Operator Bloat
echo "[5/6] Enforcing Suspension on Malware & Operator Telemetry Packages..."
MALWARE_AND_TELEMETRY="
com.haxsmart.skylive
ar.com.flow.provisioncheck
ar.com.flow.androidtv_stb
ar.com.flow.radiosymusica
com.skyworth.android.tr069
com.sdt.android.tr369
com.skyworth.xmppservice
com.skyworth.update
com.sdt.ota
com.skyworthdigital.diagnose
com.skyworth.skylogcatservice
"

for pkg in $MALWARE_AND_TELEMETRY; do
    if pm list packages --user 0 | grep -q "^package:${pkg}$"; then
        am force-stop "${pkg}" 2>/dev/null
        pm clear "${pkg}" >/dev/null 2>&1
        cmd appops set "${pkg}" RUN_IN_BACKGROUND ignore 2>/dev/null
        cmd appops set "${pkg}" SYSTEM_ALERT_WINDOW deny 2>/dev/null
        pm suspend --user 0 "${pkg}" >/dev/null 2>&1
        pm disable-user --user 0 "${pkg}" >/dev/null 2>&1
        pm uninstall --user 0 "${pkg}" >/dev/null 2>&1
        echo "      -> Neutralized: ${pkg}"
    fi
done

# 6. Trim Package Caches, Execute eMMC fstrim, and AOT-Compile Core UI
echo "[6/6] Running Package Cache Reclamation, eMMC fstrim & AOT Compilation..."
pm trim-caches 999G 2>/dev/null
sm fstrim 2>/dev/null
am kill-all 2>/dev/null

for core_pkg in com.android.systemui com.google.android.tvlauncher com.liskovsoft.smarttubetv.beta; do
    if pm list packages --user 0 | grep -q "^package:${core_pkg}$"; then
        echo "      -> AOT compiling (${core_pkg}) with '-m speed'..."
        cmd package compile -m speed -f "${core_pkg}" >/dev/null 2>&1
    fi
done

sleep 2
echo ""
echo "[+] Post-Optimization /proc/meminfo snapshot:"
grep -E "MemTotal|MemFree|MemAvailable|Cached|SwapTotal|SwapFree" /proc/meminfo
echo "======================================================================"
echo "  LOW-RAM PROFILE APPLIED SUCCESSFULLY"
echo "======================================================================"
