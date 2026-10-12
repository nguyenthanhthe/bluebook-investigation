# Dịch ngược Bluebook 0.9.725 — Kết quả

Công cụ dùng: **REA** (`rea-agents@6.4.0`, CLI) cho artefact JS/ASAR và cấu trúc
PE, `pefile`, cùng các script trong `analysis/`. Phần lớn là phân tích **tĩnh**
trên artefact đã phát hành; các kết luận về hành vi runtime đều ghi rõ nguồn.

> REA có provider native (Ghidra/IDA/Hopper) nhưng **không provider nào được cấu
> hình** trên máy này (`provider_unavailable`: Ghidra cần `GHIDRA_INSTALL_DIR`,
> IDA cần `REA_IDA_MCP_CONFIG`, Hopper không hỗ trợ Windows). Vì vậy phần
> `Bluebook.exe` chỉ ở mức **cấu trúc + trích chuỗi + vài điểm mã quanh đường
> crash**, không dịch ngược từng hàm. Provider **JavaScript/ASAR của REA thì
> dùng được** và đã phân tích trọn `app.asar`.

---

## 1. Kiến trúc artefact

### 1.1 `Bluebook.exe` — file thực thi chính

| Trường | Giá trị |
|---|---|
| Định dạng | PE32 (32-bit), Subsystem GUI |
| Machine | `0x014C` (i386) |
| TimeDateStamp | `0x69F121AA` → 2026-04-28 21:07:54 UTC |
| Linker | 14.0 (MSVC VS2015+) |
| Số section | 11 |
| Sections | `.text .rdata .data .fptable .rodata .tls CPADinfo malloc_h prot .rsrc .reloc` |
| Entry point | RVA `0x03F2BF20` |
| ImageBase | `0x400000` |
| SizeOfImage | ~195 MB |
| DllCharacteristics | `0xC140` (DYNAMIC_BASE, NX_COMPAT, GUARD_CF, TERMINAL_SERVER_AWARE) |
| Ký số | **Có — EV Authenticode hợp lệ** |
| Chủ thể chứng thư | `CN=College Board, OU=bluebook, O=College Board, L=New York, S=New York, C=US` |
| Nhà phát hành | `DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1` |
| Hiệu lực | 2026-04-07 → 2027-04-07 |
| Import tĩnh | `VERSION`, `WINMM`, `WS2_32`, `KERNEL32`, `ntdll`, `CRYPT32`, `DWrite` |
| Delay-import | **52 DLL** (bộ Electron/Chromium) |

Delay-import gồm: `d3d11`, `d3d12`, `dxgi`, `dcomp`, `ffmpeg`, `COMCTL32`,
`UIAutomationCore`, `WINHTTP`, `urlmon`, `dwmapi`, `bcryptprimitives`,
`WINTRUST`, `SETUPAPI`, `PROPSYS`, `MMDevAPI`, `MF/MFPlat/MFReadWrite`,
`WTSAPI32`, `wevtapi`, `pdh`, `Secur32`, `ncrypt`, `ole32`, `SHELL32`, `SHLWAPI`,
`USER32`, `GDI32`, `ADVAPI32`, `COMDLG32`, `dbghelp`, `OLEAUT32`, `WINSPOOL.DRV`,
`USERENV`, `FONTSUB`, `dhcpcsvc`, `IPHLPAPI`, `RPCRT4`, `CFGMGR32`, `HID`,
`WINUSB`, `UxTheme`, `bthprops.cpl`, `OLEACC` và nhiều `api-ms-win-*`.

Các section `CPADinfo`, `malloc_h`, `prot`, `.fptable` là dấu hiệu layout của
Chromium/Electron 32-bit đóng gói. **Giả thuyết PyInstaller ban đầu là sai** —
Electron không dùng PyInstaller, và việc `pyinstaller` có mặt trên máy chỉ là
trùng hợp.

Chuỗi nhúng xác nhận có **đủ tầng GPU của Chromium**: ANGLE
(`ANGLE_SWIFTSHADER`, `:ANGLE_multi_draw:`, `third_party\angle\src`), Dawn/Vulkan
(`third_party\dawn\src\dawn\native\vulkan`), SwiftShader (`vk_swiftshader.dll`,
`enable-unsafe-swiftshader`), D3D11/12 (`media\gpu\windows\d3d12_*.cc`),
GLES2 (`gpu\command_buffer\service\gles2_cmd_decoder.cc`), Crashpad (169 lần
`crashpad`).

Ghi chú: chuỗi `sentry` (chữ thường) **không** có trong exe — SDK Sentry nằm ở
tầng JS, không phải trong binary.

### 1.2 `resources/app.asar`

| Mục | Giá trị |
|---|---|
| Kích thước | 65.786.417 bytes |
| SHA256 | `f22134015f2b06c6dda420d745831e71fb131c9834c33ff13bbe5bac36147984` |
| Số mục | **231** |
| Module phân tích được | **2.024** |
| Finding tĩnh | **5.172** |
| File JS parse thành công | **160** (0 lỗi parse) |
| Dung lượng text đọc | ~40 MB |

Cây file (bỏ `node_modules`):

```
main/index.js                     12.470.562 B   bundle chính (obfuscate)
main/index.js.LICENSE.txt                        thư viện bundled (xem §1.4)
main/0168fb5f428ae50416….node        449.024 B   native addon A
main/f44e2a3d05186f7633….node        527.360 B   native addon B
preload/index.js                      48.863 B   preload (obfuscate)
renderer/main.js                   3.958.044 B
renderer/vendor-private.js         1.358.672 B
renderer/vendor-public.js
renderer/integrity-worker.20346c2eec43b069.js   worker kiểm tra toàn vẹn
renderer/responses-worker.20346c2eec43b069.js
renderer/telemetry-worker.20346c2eec43b069.js
renderer/service-worker.js
renderer/workbox-261d7b79.js                    workbox precache
renderer/index.html
renderer/build.json                             {"buildTime":"2026-09-03 20:36"}
renderer/ckeditor/ckeditor.js
renderer/desmos/calculator.js
renderer/sre/**                                 MathJax Speech Rule Engine
renderer/*.svg (~hàng trăm), *.mp3
package.json
```

`renderer/build.json` cho `buildTime = 2026-09-03 20:36`, tức bản này build sau
timestamp của `Bluebook.exe` (`2026-04-28`) — phần renderer được cập nhật riêng,
không cùng nhịp với exe.

### 1.3 `node_modules` — chỉ 40 package

`base64-js, bindings, bl, buffer, chownr, decompress-response, deep-extend,
detect-libc, end-of-stream, expand-template, file-uri-to-path, fs-constants,
github-from-package, ieee754, inherits, ini, keytar, mimic-response, minimist,
mkdirp-classic, napi-build-utils, node-abi, node-addon-api, once,
prebuild-install, pump, rc, readable-stream, safe-buffer, semver, simple-concat,
simple-get, string_decoder, strip-json-comments, tar-fs, tar-stream,
tunnel-agent, util-deprecate, win-verify-signature, wrappy`

Tất cả đều là phụ thuộc của `keytar` / `win-verify-signature` /
`prebuild-install`. **Toàn bộ UI và logic ứng dụng nằm bundled trong
`main/index.js` + `renderer/`**, không nằm trong `node_modules`.

### 1.4 Thư viện bundled trong `main/index.js`

Từ `main/index.js.LICENSE.txt`: `localForage`, `hash-wasm`, `mime-db`,
`mime-types`, `@azure/msal-common` v14.16.1, `@azure/msal-node` v2.16.3,
`@noble/hashes`, `pako`, `lodash`, `React` (nhiều phiên bản, gồm 16.13.1 và
17.0.2), `URI.js`.

→ Xác nhận: UI là **React**, dùng **Azure MSAL** để xác thực, `hash-wasm` +
`@noble/hashes` để băm, `localForage` để lưu offline, `pako` để nén.

### 1.5 Hai native addon (N-API, 32-bit)

**Addon A — `0168fb5f428ae50416523bf915b82f49.node`** (449.024 B)
Export: `napi_register_module_v1`, `node_api_module_get_api_version_v1`.
Import: `ntdll`, `ole32`, `KERNEL32`, `USER32`, `ADVAPI32`, `OLEAUT32`,
`wlanapi`, `IPHLPAPI`, `api-ms-win-shcore-scaling-l1-1-1`.

Chuỗi nhận dạng → đây là **bộ thu thập dấu vết thiết bị / telemetry** của
College Board:

| Nhóm | Chuỗi |
|---|---|
| Firmware/BIOS | `BIOSVersion`, `SMBIOSBIOSVersion`, `EnumSystemFirmwareTables`, `biosInfo` |
| Màn hình | `EnumDisplayDevicesW`, `EnumDisplayMonitors`, `EnumDisplaySettingsW` |
| Mạng | `GetAdaptersAddresses`, `networkAdapters`, `adapterDesc`, `adapterDeviceId`, `qdAdapter` |
| WLAN | `WlanOpenHandle`, `WlanEnumInterfaces`, `WlanQueryInterface`, `WlanFreeMemory` |
| Đĩa | `GetDiskFreeSpaceExW`, `lowTotalDiskSpace`, `PROD_VIRTUAL_DISK` |
| Registry | `RegGetValueW`, `NtEnumerateKey`, `getRegistryRawData`, `registryKeys`, `virtualRegistry` |
| Locale | `EnumSystemLocalesEx/W`, `EnumSystemLocalesW` |
| Danh tính máy | `StringFromGUID2`, `computerSytemProduct` |
| **Chống gian lận** | `driverSignaturesEnforced`, `hypervisorSignatures`, `missingSignatures`, `signatureScanFirmware`, `signatureScanRSMB` |

Đáng chú ý: nó **kiểm tra chữ ký driver**, **phát hiện hypervisor** và có
`PROD_VIRTUAL_DISK` → app có khả năng nhận biết môi trường ảo hoá.

**Addon B — `f44e2a3d05186f76337879f7e48d7fdb.node`** (527.360 B)
Export: `_register_registryNativeModule_`. Import: `KERNEL32`, `ADVAPI32`.
Có đường dẫn build `D:\a\registry-js\registry-js\src\main.cc` → đây là
**`registry-js`** mã nguồn mở (đọc/ghi registry từ Node).

Cả hai được **giải nén ra `%TEMP%`** khi chạy, dưới tên `<guid>.tmp.node`. Trên
máy này `%TEMP%` = `D:\Temp`, nên có **417 file `*.tmp.node`** tồn đọng; cả 3
báo cáo WER đều ghi 3 module này nạp từ `D:\Temp`.

### 1.6 `package.json` và cấu hình cập nhật

```json
{ "name": "bluebook", "version": "0.9.725", "author": "College Board",
  "description": "The Blue Book App", "main": "main",
  "dependencies": { "keytar": "^7.9.0", "win-verify-signature": "1.7.0" } }
```

`resources/app-update.yml`:

```yaml
provider: generic
url: https://bluebook.app.collegeboard.org/downloads/
updaterCacheDirName: bluebook-updater
publisherName: [College Board]
```

- **`keytar`** — lưu credential vào Windows Credential Manager.
- **`win-verify-signature`** — **xác minh chữ ký Authenticode** của file. Đây là
  cơ sở để suy luận app **có** kiểm tra toàn vẹn file.

## 2. Cơ chế obfuscate

`main/index.js`, `preload/index.js` và các bundle `renderer/*.js` đều bị xử lý
bởi cùng một công cụ (kiểu `javascript-obfuscator`):

1. **Control-flow flattening** — thân hàm thành máy trạng thái:
   ```js
   var У2B = 4;
   for (; У2B !== 3;) { switch (У2B) { case 2: … У2B = 7; break; … } }
   ```
2. **Định danh homoglyph** — tên biến dùng ký tự Cyrillic/Greek (`У2B`, `Ζ9R`,
   `ρ`, `Κ3`, `Ν3НВ`) thay vì ASCII.
3. **Chuỗi literal escape** — `'\x64\u0065\x66\x69\x6e\x65…'` thay vì
   `'define…'`.
4. **Bảng chuỗi mã hoá** — phần lớn literal nằm trong mảng percent-encoded
   (`B3'$Kk_8%209%5B#T1%25%25U#%5E*h…`) rồi giải mã lúc chạy.

**Hệ quả thực tế:** `grep -c GPU` trên bundle gốc trả về **0**. Phải giải escape
trước mới thấy chữ.

Các script trong `analysis/` làm được bước 3:

| Script | Việc |
|---|---|
| `deescape.py` | giải `\xNN` / `\uNNNN` (không thực thi gì) |
| `collapse.py` | gộp chuỗi ghép từng ký tự `x += "C";` |
| `literals.py` | trích literal ASCII đọc được |
| `strdecode.py` | thử percent-decode + XOR/ADD đơn byte cho bảng chuỗi |

Bước 4 (giải bảng chuỗi) **chưa** hoàn tất: phép biến đổi không phải XOR/ADD đơn
byte thuần; cần thực thi hàm giải mã để lấy khoá. Vì vậy **không** kết luận nào
dưới đây dựa trên nội dung bảng chuỗi.

## 3. Đọc được từ bundle sau khi giải escape

| Literal | Ý nghĩa suy ra |
|---|---|
| `IntegrityManager` | lớp quản lý toàn vẹn file |
| `IntegrityEventFormatEnum` | enum sự kiện toàn vẹn |
| `isIntegritySyncComplete`, `integrityProcessedResponse`, `integrityPurgeSuccess` | vòng đời kiểm tra toàn vẹn |
| `integrityTransactionHash`, `responseIntegrityTransactionHash`, `integrityResponseTransactionHash` | hash giao dịch toàn vẹn |
| **`WIN_FAIL_FILE_INTEGRITY`** | mã lỗi khi kiểm tra toàn vẹn file thất bại |
| `win-verify-signature` | module xác minh chữ ký |
| `keytar` | lưu credential |
| `driverSignaturesEnforced`, `signatureScanFirmware`, `signatureScanRSMB`, `missingSignatures`, `hypervisorSignatures` | gọi sang addon A |
| `sandboxie` | **phát hiện Sandboxie** |
| `sandbox` | thuộc tính sandbox |
| `NoCryptoInitError`, `PostResponseCode` | luồng mã hoá / gửi bài |

Các chuỗi này cho thấy app có **ba lớp phòng vệ**: (a) kiểm tra toàn vẹn file
của chính nó, (b) xác minh chữ ký Authenticode, (c) phát hiện môi trường ảo
hoá/sandbox. Đây là lý do **không nên** vá nhị phân (xem `patch/README.md`).

## 4. Cấu hình runtime của Chromium do app tự đặt

Đọc trực tiếp dòng lệnh tiến trình con khi app chạy **thành công**:

```
--type=gpu-process
  --gpu-preferences=SAAAAAAAAADgAAAEAAAA…
  --use-gl=angle
  --use-angle=d3d11-warp-webgl          ← app TỰ ép backend ANGLE
  --enable-features=PdfUseShowSaveFilePicker
  --disable-features=DropInputEventsWhilePaintHolding,LocalNetworkAccessChecks,
                    NetworkServiceSandbox,ScreenAIOCREnabled,
                    SpareRendererForSitePerProcess,TraceSiteInstanceGetProcessCreation

--type=renderer
  --enable-sandbox --disable-gpu-compositing
  --js-flags=--max-old-space-size=3072
  --app-path="…\resources\app.asar"
  --standard-schemes=app --secure-schemes=app,sentry-ipc
  --service-worker-schemes=app

--type=utility (network.mojom.NetworkService)
  --service-sandbox-type=none
```

Đáng chú ý:

- App ép `--use-angle=d3d11-warp-webgl` — **WARP** là rasterizer phần mềm của
  Microsoft, tức app cố tình tránh GPU rời.
- Renderer có `--disable-gpu-compositing` và `--enable-sandbox`.
- `--js-flags=--max-old-space-size=3072` — heap V8 lớn cho bài thi.
- Trong exe có đúng **1** chuỗi `--type=relauncher`, và khi gỡ lỗi thấy tiến
  trình browser spawn thêm tiến trình browser → có **cơ chế relauncher** giám
  sát/khởi động lại.

**Ràng buộc quan trọng:** app **bỏ qua mọi tham số dòng lệnh truyền thêm**. Thử
`--no-sandbox`, `--disable-gpu-sandbox`, `--disable-gpu`,
`--use-angle=swiftshader`, `--in-process-gpu`, `--enable-logging`,
`--user-data-dir=…` — tất cả đều làm app thoát sau **~1,8 s với 1 tiến trình duy
nhất** (không spawn gì). Cùng cờ đó trên bản chạy được ở `D:\Temp\bbcopy` cũng
làm nó chết. Đây là hành vi lockdown có chủ đích, và nó chặn luôn cách chẩn đoán
bằng cờ — phải dùng **biến môi trường** để lấy log.

## 5. Content-Security-Policy của renderer

Từ `renderer/index.html`:

```
default-src 'self' 'unsafe-eval';
font-src   'self' data:;
style-src  'self' 'unsafe-inline';
media-src  'self' blob: data: https://*.collegeboard.org:*;
img-src    'self' data:;
worker-src 'self' blob:;
script-src-elem 'unsafe-inline' blob: 'self';
connect-src https://*.collegeboard.org:*
            https://o516766.ingest.sentry.io/api/5649233/
            https://agwtc.collegeboard.org/ 'self';
```

→ Telemetry qua **Sentry** (`o516766.ingest.sentry.io`, project 5649233); backend
`collegeboard.org`; custom scheme nội bộ là `app://dap-electron.collegeboard.org/`
(`renderer/build.json`, service worker workbox).

`meta` có `Cache-Control: no-cache, no-store, must-revalidate` và
`robots: noindex, nofollow`.

## 6. Giới hạn của phần dịch ngược này

- **Không** giải được bảng chuỗi obfuscate → nội dung logic nghiệp vụ chi tiết
  (luồng thi, luồng proctoring, định dạng giao dịch toàn vẹn) **chưa** đọc được.
- **Không** dịch ngược thân Chromium (~155 MB `.text`). Máy không có
  Ghidra/IDA/radare2, và điều đó cũng không cần cho câu hỏi nguyên nhân.
- Phần `Bluebook.exe` chỉ ở mức **cấu trúc + trích chuỗi + vài điểm mã cụ thể**
  quanh đường crash (`0x6455F47`, `0x056FFB5D`); **không** phải dịch ngược từng hàm.
- Mọi kết luận về hành vi runtime đến từ **quan sát thực thi** (log, dòng lệnh
  tiến trình, minidump), không phải suy diễn tĩnh. Phân tích tĩnh **không** nói
  được module nào thực sự chạy.

## 7. Phụ lục: điểm crash trong binary

| Địa chỉ | Nội dung | Ghi chú |
|---|---|---|
| RVA `0x6455F47` | `CC 0F 0B` (`int3; ud2`) | điểm browser tự sát; `IMMEDIATE_CRASH` |
| RVA `0x0A3A9119` | `"GPU process isn't usable. Goodbye."` | chuỗi trong `.rdata`, ASCII NUL-terminated |
| RVA `0x056FFB5D` | `push 0x0A7A9119` | lệnh duy nhất tham chiếu chuỗi trên |
| RVA `0x0A3A8C4A` | `..\..\content\browser\gpu\gpu_data_manager_impl_private.cc` | đường dẫn nguồn |
| RVA `0x0A3A9A6A` | `..\..\content\browser\gpu\gpu_process_host.cc` | đường dẫn nguồn |

Số lần xuất hiện `CC 0F 0B` trong `.text`: **147.615** — đây là macro **dùng
chung**, không phải dấu vân tay riêng của đường GPU. Chi tiết về chỗ hiểu sai
này: [root-cause.md §6](root-cause.md).
