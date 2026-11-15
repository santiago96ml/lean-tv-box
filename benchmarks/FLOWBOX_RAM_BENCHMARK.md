# Benchmark de Optimización de RAM y Telemetría — Flowbox F1 (Skyworth HP40A)

**Fecha de Ejecución:** 15 de noviembre de 2026  
**Dispositivo:** `FlowBox-F1` (OEM: Skyworth Digital / Modelo base: HP40A)  
**Sistema Operativo:** Android TV 12 (SDK 31)  
**Dirección ADB:** `192.168.1.69:5555`  
**RAM Total Instalada:** `1,984,460 kB` (`1,937.95 MB` / 2 GB nominales)

---

## 1. Resumen Ejecutivo

El dispositivo **Flowbox F1** presentaba un estado crítico de presión de memoria antes de la intervención:
- Solo **395.25 MB (`404,736 kB`)** de RAM disponible (`MemAvailable`, equivalente al **20.40%** del total).
- La partición **ZRAM (384.00 MB)** estaba **saturada al 99.999%** (`SwapFree: 4 kB`), forzando constante compresión/descompresión de páginas (*thrashing* de CPU) y degradando la fluidez de la interfaz.
- Un proceso huérfano de `com.google.android.webview:sandboxed_process0` retenía por sí solo **240.56 MB RSS (`266.78 MB PSS`)**, sumado a demonios persistentes de telemetría del operador/fabricante (`tr369`, `tr069`, `xmppservice`, `skylogcatservice`, `diagnose`, `sdt.ota`) y servicios en segundo plano de apps de streaming redundantes (`youtube.tv`, `netflix.ninja`, `google.android.videos`).

Tras ejecutar la neutralización de paquetes, limpieza de procesos huérfanos, recorte de cachés (`fstrim` / `trim-caches`), ajuste de constantes de `ActivityManager` para perfiles de 2 GB y compilación AOT (`speed`) de los componentes críticos de UI:

- **`MemAvailable` aumentó de `395.25 MB` a `973.50 MB` (+578.25 MB / +146.30%)**, liberando casi la mitad de la RAM total del equipo (**50.23%** de la RAM física ahora disponible).
- **`MemFree` aumentó de `119.61 MB` a `483.75 MB` (+364.14 MB / +304.44%)**.
- **`AnonPages` (memoria anónima/heap de procesos) cayó un 59.15%**, pasando de `910.32 MB` a `371.86 MB` (**-538.46 MB**).
- **`CmaFree` (memoria contigua para GPU y decodificación de video por hardware) subió de `52.21 MB` a `256.05 MB` (+203.84 MB / +390.45%)**.
- **`SwapFree` (ZRAM libre) pasó de `0.00 MB (4 kB)` a `108.65 MB (111,256 kB)`**, eliminando el cuello de botella de paginación.

---

## 2. Comparativa Exacta de `/proc/meminfo` (Antes vs. Después)

| Métrica (`/proc/meminfo`) | ANTES (kB) | ANTES (MB) | DESPUÉS (kB) | DESPUÉS (MB) | Delta (kB) | Delta (MB) | Variación (%) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **`MemTotal`** | 1,984,460 | 1,937.95 | 1,984,460 | 1,937.95 | 0 | 0.00 | 0.00% |
| **`MemAvailable`** | **404,736** | **395.25** | **996,864** | **973.50** | **+592,128** | **+578.25** | **+146.30%** |
| **`MemFree`** | **122,480** | **119.61** | **495,360** | **483.75** | **+372,880** | **+364.14** | **+304.44%** |
| **`Cached`** | 383,944 | 374.95 | 578,408 | 564.85 | +194,464 | +189.91 | +50.65% |
| **`Buffers`** | 14,436 | 14.10 | 36,072 | 35.23 | +21,636 | +21.13 | +149.88% |
| **`SwapTotal`** | 393,212 | 384.00 | 393,212 | 384.00 | 0 | 0.00 | 0.00% |
| **`SwapFree`** | **4** | **0.00** | **111,256** | **108.65** | **+111,252** | **+108.64** | **+2,781,300%** |
| **`SwapCached`** | 10,860 | 10.61 | 10,260 | 10.02 | -600 | -0.59 | -5.52% |
| **`AnonPages`** | **932,168** | **910.32** | **380,780** | **371.86** | **-551,388** | **-538.46** | **-59.15%** |
| **`Active(anon)`** | 623,860 | 609.24 | 293,980 | 287.09 | -329,880 | -322.15 | -52.88% |
| **`Inactive(anon)`** | 315,252 | 307.86 | 91,524 | 89.38 | -223,728 | -218.48 | -70.97% |
| **`CmaFree`** | **53,460** | **52.21** | **262,196** | **256.05** | **+208,736** | **+203.84** | **+390.45%** |
| **`Slab`** | 118,768 | 115.98 | 113,192 | 110.54 | -5,576 | -5.45 | -4.69% |
| **`KernelStack`** | 33,424 | 32.64 | 22,928 | 22.39 | -10,496 | -10.25 | -31.40% |
| **`PageTables`** | 46,888 | 45.79 | 27,788 | 27.14 | -19,100 | -18.65 | -40.74% |
| **`Committed_AS`** | 42,072,636 | 41,086.56 | 24,196,956 | 23,629.84 | -17,875,680 | -17,456.72 | -42.49% |

---

## 3. Resumen Global de `dumpsys meminfo` (Antes vs. Después)

| Indicador (`dumpsys meminfo`) | ANTES | DESPUÉS | Diferencia |
| :--- | :--- | :--- | :--- |
| **Estado general de RAM** | `1,984,460K (status normal)` | `1,984,460K (status normal)` | Sin alertas OOM |
| **Free RAM (Total reportado)** | `708,373K` (`691.77 MB`) | `906,864K` (`885.61 MB`) | **+198,491K (+193.84 MB)** |
| **Used RAM (Total reportado)** | `1,355,453K` (`1,323.68 MB`) | `1,043,823K` (`1,019.36 MB`) | **-311,630K (-304.33 MB)** |
| **Used PSS (Apps y Servicios)** | `1,158,429K` (`1,131.28 MB`) | `888,559K` (`867.73 MB`) | **-269,870K (-263.54 MB)** |
| **Kernel RAM** | `197,024K` (`192.41 MB`) | `155,264K` (`151.63 MB`) | **-41,760K (-40.78 MB)** |
| **Cached PSS** | `414,661K` (`404.94 MB`) | `0K` (`0.00 MB`) | **-414,661K (100% purgado)** |
| **ZRAM (Física / Swap)** | `105,812K` física para `393,208K` swap | `94,032K` física para `273,296K` swap | **-119,912K en swap (-117.10 MB)** |

---

## 4. Procesos en Segundo Plano Eliminados y Memoria Liberada

La siguiente tabla detalla los **20 procesos residentes en memoria** que fueron completamente erradicados de la RAM (`0 kB` tras la optimización) mediante la combinación de `pm clear`, `pm suspend --user 0`, `pm disable-user --user 0`, `am force-stop` y `am kill-all`:

| # | Proceso / Paquete | PID (Antes) | Categoría OOM (Antes) | RSS Antes (kB) | RSS Liberado (MB) | PSS Antes (kB) | PSS Liberado (MB) | Acción Aplicada |
| :-: | :--- | :-: | :--- | ---: | ---: | ---: | ---: | :--- |
| 1 | `com.google.android.webview:sandboxed_process0` | 22458 | Cached | 246,336 | **240.56 MB** | 273,185 | **266.78 MB** | `am force-stop` + `kill-all` |
| 2 | `com.lagradost.cloudstream3` | 22241 | Previous | 138,420 | **135.18 MB** | 113,463 | **110.80 MB** | `am kill-all` (proceso en caché) |
| 3 | `com.google.android.youtube.tv` | 24044 | Foreground | 101,972 | **99.58 MB** | 67,329 | **65.75 MB** | `clear` + `suspend` + `disable` + `force-stop` |
| 4 | `com.google.android.katniss:search` | 30864 | Cached | 78,512 | **76.67 MB** | 31,567 | **30.83 MB** | `am kill-all` |
| 5 | `com.android.vending` | 28493 | Cached | 75,884 | **74.11 MB** | 37,384 | **36.51 MB** | `am kill-all` |
| 6 | `com.sdt.android.tr369` | 4873 | Perceptible | 65,116 | **63.59 MB** | 30,534 | **29.82 MB** | `clear` + `suspend` + `force-stop` |
| 7 | `com.netflix.ninja` | 9317 | B Services | 64,812 | **63.29 MB** | 40,102 | **39.16 MB** | `clear` + `suspend` + `disable` + `force-stop` |
| 8 | `com.google.android.videos` | 30916 | Cached | 61,188 | **59.75 MB** | 24,037 | **23.47 MB** | `clear` + `suspend` + `disable` + `force-stop` |
| 9 | `com.google.android.gms:snet` | 30630 | Cached | 54,356 | **53.08 MB** | 14,969 | **14.62 MB** | `am kill-all` |
| 10 | `com.skyworth.xmppservice` | 5230 | Perceptible | 53,288 | **52.04 MB** | 31,975 | **31.23 MB** | `clear` + `suspend` + `force-stop` |
| 11 | `com.sdt.ota` | 6972 | Perceptible | 52,040 | **50.82 MB** | 17,475 | **17.07 MB** | `clear` + `suspend` + `force-stop` |
| 12 | `com.skyworthdigital.diagnose` | 4908 | Foreground | 49,416 | **48.26 MB** | 15,418 | **15.06 MB** | `clear` + `suspend` + `force-stop` |
| 13 | `com.skyworth.skylogcatservice` | 5207 | Perceptible | 48,164 | **47.04 MB** | 17,092 | **16.69 MB** | `clear` + `suspend` + `force-stop` |
| 14 | `com.google.android.packageinstaller` | 31046 | Cached | 43,824 | **42.80 MB** | 5,531 | **5.40 MB** | `am kill-all` |
| 15 | `com.google.android.tts` | 30835 | Cached | 43,472 | **42.45 MB** | 10,901 | **10.65 MB** | `am kill-all` |
| 16 | `com.google.android.permissioncontroller` | 30534 | Cached | 43,232 | **42.22 MB** | 6,279 | **6.13 MB** | `am kill-all` |
| 17 | `com.google.android.syncadapters.calendar` | 28810 | Cached | 36,596 | **35.74 MB** | 5,517 | **5.39 MB** | `am kill-all` |
| 18 | `com.skyworth.platform.skyplatformservice` | 5254 | Perceptible | 35,060 | **34.24 MB** | 19,538 | **19.08 MB** | Terminado junto a telemetría Skyworth |
| 19 | `com.google.process.gservices` | 21430 | Cached | 31,760 | **31.02 MB** | 5,291 | **5.17 MB** | `am kill-all` |
| 20 | `com.skyworth.android.tr069` | 4839 | Perceptible | 29,588 | **28.89 MB** | 7,216 | **7.05 MB** | `clear` + `suspend` + `force-stop` |
| — | **SUBTOTAL TELEMETRÍA + BLOATWARE + WEBVIEW** | *(11 procs)* | — | **806,980 kB** | **788.07 MB** | **543,901 kB** | **531.15 MB** | Neutralización directa |
| — | **TOTAL PROCESOS ELIMINADOS** | *(20 procs)* | — | **1,353,036 kB** | **1,321.32 MB** | **774,803 kB** | **756.64 MB** | Neutralización + `am kill-all` |

> **Nota sobre RSS vs. PSS:** `RSS` (*Resident Set Size*) incluye bibliotecas compartidas (`libc`, `libart`, framework de Android) mapeadas en cada proceso, mientras que `PSS` (*Proportional Set Size*) divide proporcionalmente las páginas compartidas y refleja el peso real atribuible a cada proceso en la RAM física. La reducción neta en `MemAvailable` (**+578.25 MB**) y `AnonPages` (**-538.46 MB**) guarda correlación directa con los **531.15 MB PSS** de telemetría/bloatware/WebView erradicados.

---

## 5. Estado de Neutralización de los 13 Paquetes Objetivo

| Paquete | Rol / Descripción | `pm clear` | `pm suspend --user 0` | `pm disable-user --user 0` | `am force-stop` |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `com.sdt.android.tr369` | Telemetría remota USP (TR-369) de Skyworth/SDT | `Success` | `suspended: true` | Bloqueado por whitelist OEM* | Ejecutado (`0 kB` en RAM) |
| `com.skyworth.xmppservice` | Demonio XMPP de control remoto del operador | `Success` | `suspended: true` | Bloqueado por whitelist OEM* | Ejecutado (`0 kB` en RAM) |
| `com.sdt.ota` | Servicio de actualización OTA propietario SDT | `Success` | `suspended: true` | Bloqueado por whitelist OEM* | Ejecutado (`0 kB` en RAM) |
| `com.skyworth.skylogcatservice` | Captura continua de `logcat` en segundo plano | `Success` | `suspended: true` | Bloqueado por whitelist OEM* | Ejecutado (`0 kB` en RAM) |
| `com.google.android.youtube.tv` | YouTube TV oficial (reemplazado por SmartTube) | `Success` | `suspended: true` | **`disabled-user`** | Ejecutado (`0 kB` en RAM) |
| `com.google.android.videos` | Google TV / Play Movies & TV | `Success` | `suspended: true` | **`disabled-user`** | Ejecutado (`0 kB` en RAM) |
| `com.netflix.ninja` | Cliente Netflix en segundo plano (`B Services`) | `Success` | `suspended: true` | **`disabled-user`** | Ejecutado (`0 kB` en RAM) |
| `ar.com.flow.androidtv_stb` | Launcher/Middleware pesado de Flow STB | `Success` | `suspended: true` | Bloqueado por whitelist OEM* | Ejecutado (`0 kB` en RAM) |
| `ar.com.flow.provisioncheck` | Verificador de aprovisionamiento Flow | `Success` | `suspended: true` | Bloqueado por whitelist OEM* | Ejecutado (`0 kB` en RAM) |
| `ar.com.flow.radiosymusica` | App de radios y música de Flow | `Success` | `suspended: true` | Bloqueado por whitelist OEM* | Ejecutado (`0 kB` en RAM) |
| `com.skyworth.android.tr069` | Telemetría remota CWMP (TR-069) | `Success` | `suspended: true` | Bloqueado por whitelist OEM* | Ejecutado (`0 kB` en RAM) |
| `com.skyworth.update` | Actualizador secundario Skyworth | `Success` | `suspended: true` | Bloqueado por whitelist OEM* | Ejecutado (`0 kB` en RAM) |
| `com.skyworthdigital.diagnose` | Servicio de diagnóstico y reporte de fallos | `Success` | `suspended: true` | Bloqueado por whitelist OEM* | Ejecutado (`0 kB` en RAM) |

*\*Nota técnica sobre la Whitelist OEM de Skyworth:* El firmware de Skyworth protege sus paquetes internos contra `pm disable-user` devolviendo `Info: <pkg> is in whitelist, there is no permission to excute`. Sin embargo, **`pm clear` + `pm suspend --user 0` + `am force-stop`** funcionan sin restricción, borrando sus datos de estado, suspendiéndolos a nivel de `PackageManager` y deteniendo por completo sus procesos y demonios en segundo plano (ninguno volvió a levantarse tras el `force-stop`).

---

## 6. Top 20 Procesos por RSS — Antes vs. Después

### 6.1 Top 20 Procesos ANTES de la Optimización
1. `246,336 K` (`240.56 MB`) — `com.google.android.webview:sandboxed_process0` (pid 22458) **[ELIMINADO]**
2. `142,320 K` (`138.98 MB`) — `system` (pid 3958)
3. `141,252 K` (`137.94 MB`) — `com.google.android.gms` (pid 26002)
4. `138,420 K` (`135.18 MB`) — `com.lagradost.cloudstream3` (pid 22241) **[ELIMINADO DE CACHÉ]**
5. `101,972 K` (`99.58 MB`) — `com.google.android.youtube.tv` (pid 24044) **[DESHABILITADO Y ELIMINADO]**
6. `79,332 K` (`77.47 MB`) — `com.google.android.tvlauncher` (pid 4823)
7. `78,512 K` (`76.67 MB`) — `com.google.android.katniss:search` (pid 30864) **[ELIMINADO DE CACHÉ]**
8. `75,884 K` (`74.11 MB`) — `com.android.vending` (pid 28493) **[ELIMINADO DE CACHÉ]**
9. `68,420 K` (`66.82 MB`) — `com.google.android.katniss:interactor` (pid 4707)
10. `67,960 K` (`66.37 MB`) — `com.google.android.apps.mediashell` (pid 5557)
11. `65,116 K` (`63.59 MB`) — `com.sdt.android.tr369` (pid 4873) **[SUSPENDIDO Y ELIMINADO]**
12. `64,812 K` (`63.29 MB`) — `com.netflix.ninja` (pid 9317) **[DESHABILITADO Y ELIMINADO]**
13. `64,696 K` (`63.18 MB`) — `com.homekey.tv` (pid 31151)
14. `61,188 K` (`59.75 MB`) — `com.google.android.videos` (pid 30916) **[DESHABILITADO Y ELIMINADO]**
15. `54,704 K` (`53.42 MB`) — `com.google.android.tvrecommendations` (pid 4809)
16. `54,356 K` (`53.08 MB`) — `com.google.android.gms:snet` (pid 30630) **[ELIMINADO DE CACHÉ]**
17. `53,288 K` (`52.04 MB`) — `com.skyworth.xmppservice` (pid 5230) **[SUSPENDIDO Y ELIMINADO]**
18. `52,040 K` (`50.82 MB`) — `com.sdt.ota` (pid 6972) **[SUSPENDIDO Y ELIMINADO]**
19. `49,416 K` (`48.26 MB`) — `com.skyworthdigital.diagnose` (pid 4908) **[SUSPENDIDO Y ELIMINADO]**
20. `48,164 K` (`47.04 MB`) — `com.skyworth.skylogcatservice` (pid 5207) **[SUSPENDIDO Y ELIMINADO]**

### 6.2 Top 20 Procesos DESPUÉS de la Optimización
1. `158,580 K` (`154.86 MB`) — `com.google.android.gms` (pid 26002)
2. `154,012 K` (`150.40 MB`) — `system` (pid 3958)
3. `94,640 K` (`92.42 MB`) — `com.google.android.tvlauncher` (pid 4823 / compilado con `-m speed`)
4. `75,304 K` (`73.54 MB`) — `com.google.android.katniss:interactor` (pid 4707)
5. `65,140 K` (`63.61 MB`) — `com.google.android.apps.mediashell` (pid 5557)
6. `62,412 K` (`60.95 MB`) — `com.homekey.tv` (pid 31151)
7. `58,472 K` (`57.10 MB`) — `com.android.systemui` (pid 4171 / compilado con `-m speed`)
8. `58,388 K` (`57.02 MB`) — `com.google.android.tvrecommendations` (pid 4809)
9. `49,584 K` (`48.42 MB`) — `com.android.providers.tv` (pid 7295)
10. `49,324 K` (`48.17 MB`) — `com.google.android.inputmethod.latin` (pid 4655)
11. `40,856 K` (`39.90 MB`) — `com.sdt.cert.manager` (pid 4760)
12. `39,980 K` (`39.04 MB`) — `com.weenas.castbay` (pid 7368)
13. `39,492 K` (`38.57 MB`) — `com.android.bluetooth` (pid 4150)
14. `39,332 K` (`38.41 MB`) — `com.droidlogic` (pid 4332)
15. `38,308 K` (`37.41 MB`) — `com.android.providers.media.module` (pid 4726)
16. `34,208 K` (`33.41 MB`) — `com.google.android.tv.remote.service` (pid 4483)
17. `34,156 K` (`33.36 MB`) — `com.sdt.frontpanelledsservice` (pid 6934)
18. `33,480 K` (`32.70 MB`) — `com.spotify.tv.android` (pid 7236)
19. `31,692 K` (`30.95 MB`) — `com.sdt.dialogservice` (pid 6912)
20. `31,156 K` (`30.43 MB`) — `com.sdt.rcupair` (pid 4388)

---

## 7. Ajustes de Sistema y Tuning Low-RAM Aplicados (2 GB Profile)

Todos los ajustes de bajo nivel para Android TV 12 fueron aplicados y verificados en vivo:

| Parámetro / Comando | Valor Aplicado | Estado Verificado | Impacto |
| :--- | :--- | :---: | :--- |
| `activity_manager_constants` | `max_cached_processes=4,background_settle_time=10000` | `OK` | Limita a 4 los procesos en caché y acorta a 10 s la liquidación de servicios en segundo plano. |
| `window_animation_scale` | `0.5` | `0.5` | Duplica la velocidad de apertura/cierre de ventanas. |
| `transition_animation_scale` | `0.5` | `0.5` | Duplica la velocidad de transiciones entre pantallas. |
| `animator_duration_scale` | `0.5` | `0.5` | Reduce un 50% el tiempo de animaciones en el launcher. |
| `sm fstrim` | TRIM de bloques flash eMMC | `PersistableBundle[{}]` (`OK`) | Optimiza la escritura en almacenamiento interno eMMC. |
| `pm trim-caches 999G` | Purga global de cachés de paquetes | `OK` | Libera espacio en `/data` y reduce presión en page cache. |
| `cmd package compile -m speed com.google.android.tvlauncher` | Compilación AOT completa (`speed`) | `Success` | Elimina el overhead JIT al navegar por la pantalla de inicio de Android TV. |
| `cmd package compile -m speed com.android.systemui` | Compilación AOT completa (`speed`) | `Success` | Acelera el renderizado de barra de volumen, notificaciones y ajustes rápidos. |
