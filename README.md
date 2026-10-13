# Bluebook 0.9.725 không khởi động — Điều tra, dịch ngược và bản vá

Báo cáo kỹ thuật về việc **Bluebook.exe** (ứng dụng thi College Board, bản
0.9.725) không bao giờ mở được cửa sổ trên máy này: nó luôn thoát sau khoảng
4–5 giây. Tài liệu trình bày cách tìm ra nguyên nhân, phần dịch ngược binary,
và một bản vá đã được kiểm chứng.

- Nguyên nhân: [docs/root-cause.md](docs/root-cause.md)
- **Cơ chế gốc (đã xác định):** [docs/mechanism.md](docs/mechanism.md)
- Dịch ngược: [docs/reverse-engineering.md](docs/reverse-engineering.md)
- Nhật ký thực nghiệm & cách tái lập: [docs/evidence.md](docs/evidence.md)
- Bản vá: [patch/README.md](patch/README.md)

---

## English TL;DR

Bluebook 0.9.725 is a **32-bit Electron 42 / Chromium 148** application
installed at `C:\Users\Admin\AppData\Local\Programs\bluebook`. It never shows a
window: the **GPU child process dies immediately** with Chromium's
`IMMEDIATE_CRASH` (exception `0x80000003`). After six retries the browser
process gives up, calls `LOG(FATAL)` at
`gpu_data_manager_impl_private.cc:417` ("GPU process isn't usable. Goodbye.")
and exits — WER records exception `0x4000001f` at RVA `0x6455F47`.

The trigger is **where the files physically live**: the app works when its
files sit outside the user profile and fails when they sit inside
`C:\Users\<user>\…`. This was isolated with a path matrix, and it is **not
caused by** the folder name, the path string (a `subst` drive still fails), the
owner, directory attributes, `%TEMP%`, Defender/ASR/CFA policy, IFEO, AppCompat
shims, or per-app GPU preference.

**The exact failure is now determined** (see [docs/mechanism.md](docs/mechanism.md)):
the sandboxed GPU child cannot open `icudtl.dat`. The crashing function records
`GetLastError = 5` (ACCESS_DENIED) and the attempted path in globals, which were
read directly from the suspended child. The decisive factor is the child's **Low
mandatory integrity level**: rebuilding a token with exactly the child's SID set
and running it twice — Medium IL versus Low IL — flips the result on the profile
path only. The denial boundary is the profile root `C:\Users\Admin` itself, and
the token is identical inside and outside the profile.

Critically, it is **not a College Board bug**: a stock 32-bit Electron binary
shows the same behaviour, and every other Electron app installed in the profile
on this machine is 64-bit and works. Bluebook is the only 32-bit Electron app
in the profile.

**Fix (verified):** relocate the install outside the profile and leave a
directory junction at the original path — `patch/fix_environment.ps1`. The
binary is untouched, so the College Board signature and the app's own integrity
checks stay valid. Patching the binary instead (`patch/patch_bluebook.py`) does
**not** work and is documented as a verified negative result.

---

## 1. Tóm tắt kết quả

| Mục | Kết quả |
|---|---|
| Ứng dụng | Bluebook 0.9.725, College Board |
| Kiến trúc | 32-bit (ia32), Electron 42.0.1, Chromium 148.0.7778.97 |
| Triệu chứng | Không hiện cửa sổ; thoát sau ~4–5 s; lặp 100% |
| Tiến trình chết đầu tiên | **GPU child process** — `IMMEDIATE_CRASH`, `0x80000003` |
| Nguyên nhân kết thúc | `LOG(FATAL)` — "GPU process isn't usable. Goodbye." |
| WER | exception `0x4000001f`, fault module `Bluebook.exe`, offset `0x06455f47` |
| **Biến quyết định** | **File nằm vật lý trong `C:\Users\<user>\…`** |
| Có phải bug của Bluebook? | **Không** — tái lập được với Electron 32-bit trần |
| Bản vá khuyến nghị | Di chuyển ra ngoài profile + junction — **đã kiểm chứng** |

## 2. Chuỗi sự kiện

Bật log của chính Chromium (qua **biến môi trường**, vì app từ chối tham số
dòng lệnh) thu được nguyên văn:

```
[15232:1013/024543.942:ERROR:content\browser\gpu\gpu_process_host.cc:999]
    GPU process exited unexpectedly: exit_code=-2147483645
… (6 lần, cách nhau ~70 ms)
[15232:1013/024544.287:WARNING:content\browser\gpu\gpu_process_host.cc:1441]
    The GPU process has crashed 6 time(s)
[15232:1013/024544.287:FATAL:content\browser\gpu\gpu_data_manager_impl_private.cc:417]
    GPU process isn't usable. Goodbye.
```

`-2147483645` = `0x80000003` = `STATUS_BREAKPOINT`, tức macro `IMMEDIATE_CRASH`
(`int3; ud2`) — tiến trình GPU **tự kết thúc**, không bị hệ thống giết. Sau 6
lần thử lại, Chromium hết đường fallback và tự sát.

Chuỗi này còn tìm thấy **nguyên văn trên stack** của tiến trình browser trong
minidump, kèm tiền tố `FATAL:…gpu_data_manager_impl_private.cc:417`.

## 3. Cách tìm ra nguyên nhân

### 3.1 Lỗi đi theo vị trí thư mục

| Vị trí | Kết quả |
|---|---|
| `C:\Users\Admin\AppData\Local\Programs\bluebook` | CHẾT |
| `C:\Users\Admin\AppData\Local\Programs\bluebook_test` | CHẾT |
| `C:\Users\Admin\bbt2` (gốc profile) | CHẾT |
| `C:\Users\Admin\Desktop\bbt2` | CHẾT |
| `C:\Users\Admin\Documents\bbt2` | CHẾT |
| `C:\Users\Public\bbt2` | **CHẠY** |
| `C:\ProgramData\bbt2` | **CHẠY** |
| `C:\TempBB\bluebook` | **CHẠY** |
| `C:\bbt2` | **CHẠY** |
| `D:\bluebook_test` | **CHẠY** |

→ Biến quyết định là **"nằm trong profile người dùng"**. Không phải tên thư mục
`bluebook`; không phải thư mục cha `Programs`.

### 3.2 Không phải chuỗi đường dẫn

| Phép thử | Kết quả |
|---|---|
| Truy cập thư mục lỗi qua ổ `subst` (`X:\bluebook`) | **CHẾT** → không phải chuỗi đường dẫn |
| Mô phỏng chuỗi tên ở nơi khác (`C:\TempBB\Users\Admin\bbt2`) | **CHẠY** |
| Truy cập thư mục lỗi qua tên ngắn 8.3 | **CHẾT** |

→ Gắn với **thư mục vật lý thật**.

### 3.3 Đã loại trừ (mỗi thứ đều có thí nghiệm)

ACL (cấp quyền đọc, từ chối quyền đọc sandbox SID, mô phỏng ACL profile),
chủ sở hữu, chặn kế thừa, thuộc tính Hidden/System, `%TEMP%`, Defender
Controlled Folder Access, ASR rules, Exploit Protection, IFEO, AppCompat
Layers, per-app GPU preference, Smart App Control/WDAC, HAGS, VBS/HVCI, driver
đồ họa 32-bit (đầy đủ), bản build OS.

Chi tiết và bảng kết quả: [docs/root-cause.md §3.3](docs/root-cause.md).

### 3.4 Bằng chứng then chốt: không phải bug của Bluebook

Dùng **cây Electron 32-bit trần** (`etest32.exe` — chính binary đó đã đổi tên,
kèm app tối giản; byte-identical):

| Vị trí | Kết quả |
|---|---|
| `C:\Users\Admin\etest_profile` | **CHẾT** (không có tiến trình GPU) |
| `C:\TempBB\etest_outside` | **CHẠY** (có đủ browser, gpu-process, renderer, utility) |

Quét `%LOCALAPPDATA%\Programs`:

| Ứng dụng | Kiến trúc | Trạng thái |
|---|---|---|
| ZCode, VS Code, Antigravity, LM Studio | x64 | chạy tốt |
| **Bluebook** | **i386 (32-bit)** | **CHẾT** |

→ Bluebook là ứng dụng **Electron 32-bit duy nhất** trong profile, và là ứng
dụng duy nhất lỗi. Đây là tương tác giữa **sandbox GPU của Chromium 32-bit** và
**đường dẫn nằm trong profile**, không phải lỗi trong code của College Board.

## 4. Kết luận

**Quan sát được:**

1. Khi file của một app **Electron 32-bit** nằm trong profile người dùng, tiến
   trình GPU của nó chết tức thì bằng `IMMEDIATE_CRASH` (`0x80000003`).
2. Browser thử lại 6 lần rồi gọi `LOG(FATAL)` và thoát → không có cửa sổ.
3. Cùng binary chạy tốt khi file nằm ngoài profile.
4. Tái lập được với Electron 32-bit trần → không phải bug của Bluebook.
5. App Electron 64-bit trong profile không bị.

**Suy luận:** tiến trình GPU bị hủy trong giai đoạn khởi tạo sandbox, **trước
khi** nạp bất kỳ DLL đồ họa nào. Củng cố: dump của tiến trình chết chỉ chứa DLL
hệ thống (`ntdll`, `kernel32`, `ole32`, `dwmapi`, `DWrite`, `wlanapi`…), **không
có** `d3d11.dll`, `libEGL.dll`, `libGLESv2.dll`, `dxgi.dll`.

**Đã xác định chính xác (xem [docs/mechanism.md](docs/mechanism.md)):** tiến
trình con sandbox không mở được `icudtl.dat`; `GetLastError = 5`
(ACCESS_DENIED) do chính nó ghi lại, đọc trực tiếp từ bộ nhớ tiến trình con đang
treo tại `int3` (RVA `0x19E0914`). **Yếu tố quyết định là mức toàn vẹn Low**:
dựng token trùng tập SID của tiến trình con rồi chạy ở Medium IL và Low IL, chỉ
đổi một biến — kết quả lật đúng trên đường dẫn profile. Biên giới bị từ chối là
thư mục profile `C:\Users\Admin`.

**Chưa xác định:** vì sao **chỉ runtime 32-bit** bị, còn Electron 64-bit trong
cùng profile thì không. Đây là câu hỏi mở duy nhất còn lại.

## 5. Bản vá

### 5.1 `patch/fix_environment.ps1` — khuyến nghị, đã kiểm chứng

Di chuyển file cài ra ngoài profile rồi để lại **directory junction** tại đường
dẫn cũ. File thật nằm ngoài profile → GPU process sống; đường dẫn cũ vẫn phân
giải → shortcut và updater vẫn hoạt động.

```powershell
powershell -ExecutionPolicy Bypass -File patch/fix_environment.ps1 -DryRun   # xem trước
powershell -ExecutionPolicy Bypass -File patch/fix_environment.ps1 -Apply    # áp dụng
powershell -ExecutionPolicy Bypass -File patch/fix_environment.ps1 -Revert   # hoàn tác
```

Đã kiểm chứng: `-Apply` → **cửa sổ mở**; `-Revert` → khôi phục nguyên trạng.
Script tự chạy thử 20 giây và **tự hoàn tác nếu thất bại**.

**Không sửa binary** → chữ ký EV của College Board còn nguyên và các kiểm tra
toàn vẹn của app (`win-verify-signature`, `IntegrityManager`) vẫn hợp lệ.

### 5.2 `patch/patch_bluebook.py` — kết quả âm đã kiểm chứng

Vá điểm crash `RVA 0x06455F47` (`CC 0F 0B` → `C3 90 90`) để hàm fatal **quay về**
thay vì giết tiến trình. **Không sửa được vấn đề:**

| | Bản gốc | Bản đã vá |
|---|---|---|
| Kết quả | chết ~4–5 s | **vẫn chết** ~5,4 s |
| Exception | `0x80000003` (`int3`) | **`0xC0000005` ACCESS_VIOLATION, EIP=`0x0`** |

Vì `LOG(FATAL)` là abort có chủ đích trên đường "không còn cách cứu"; chặn nó chỉ
khiến browser chạy tiếp trong trạng thái không hợp lệ rồi sập null-pointer. Bản
vá còn **phá chữ ký Authenticode**. Giữ lại như tài liệu về cơ chế.

## 6. Phần dịch ngược

Chi tiết đầy đủ: [docs/reverse-engineering.md](docs/reverse-engineering.md).

Điểm chính:

- `Bluebook.exe`: PE32 32-bit, 191,5 MB, **ký EV hợp lệ** (`CN=College Board`),
  11 section, có đủ tầng GPU của Chromium (ANGLE, Dawn/Vulkan, SwiftShader).
- `resources/app.asar`: 65,8 MB, **231 mục, 2.024 module**. UI nằm hết trong
  `main/index.js` (12,5 MB) + `renderer/`, chỉ có 40 package trong `node_modules`
  (đều là phụ thuộc của `keytar` / `win-verify-signature`).
- **Hai native addon N-API 32-bit:**
  - Addon A = **bộ thu thập dấu vết thiết bị** (BIOS/SMBIOS, đĩa, adapter mạng,
    WLAN, `driverSignaturesEnforced`, `hypervisorSignatures`, `PROD_VIRTUAL_DISK`).
  - Addon B = **`registry-js`** (mã nguồn mở).
- **Obfuscate:** control-flow flattening + định danh homoglyph Cyrillic/Greek +
  literal escape `\xNN`/`\uNNNN` + bảng chuỗi mã hoá. `grep -c GPU` trên bundle
  gốc trả về **0**.
- Đọc được sau khi giải escape: `IntegrityManager`, `WIN_FAIL_FILE_INTEGRITY`,
  `isIntegritySyncComplete`, `win-verify-signature`, `keytar`, `sandboxie`.
- App **tự ép** `--use-gl=angle --use-angle=d3d11-warp-webgl` cho GPU process.
- App **bỏ qua mọi tham số dòng lệnh truyền thêm** (mọi cờ đều làm nó thoát sau
  ~1,8 s với 1 tiến trình) — hành vi lockdown, và là lý do phải dùng biến môi
  trường để lấy log.

## 7. Nội dung repo

```
.
├── README.md                     ← file này
├── docs/
│   ├── root-cause.md             nguyên nhân, tách bạch quan sát/suy luận/chưa rõ
│   ├── mechanism.md              cơ chế gốc: tiến trình con không đọc được icudtl.dat
│   ├── reverse-engineering.md    kết quả dịch ngược binary + app.asar
│   └── evidence.md               nhật ký thực nghiệm & cách tái lập
├── analysis/                     script phân tích & thực nghiệm
│   ├── deescape.py collapse.py literals.py strdecode.py   (giải obfuscate JS)
│   ├── mdparse2.py mdstack.py mdmods.py                    (phân tích minidump)
│   ├── addon_strings.py archscan.py                        (native addon, kiến trúc)
│   ├── icuprobe.py childtoken.py dumpchild.py              (đọc biến ICU, token, dump con)
│   ├── tokenclone_test.py restricted_token_*.py            (thí nghiệm token hạn chế)
│   ├── dbwin.py dbgchild.py                                (bắt OutputDebugString, gỡ lỗi)
│   └── *.ps1                                               (ma trận vị trí, ACL, thuộc tính…)
└── patch/
    ├── README.md
    ├── fix_environment.ps1       bản vá khuyến nghị (đã kiểm chứng)
    └── patch_bluebook.py         bản vá nhị phân (kết quả âm đã kiểm chứng)
```

**Repo chỉ chứa phân tích.** Không có binary của College Board, không có JS đã
giải nén từ `app.asar`, không có dump bộ nhớ — xem `.gitignore`.

## 8. Cảnh báo

- Không có nội dung nào ở đây nhằm né tránh kiểm soát toàn vẹn thi cử,
  proctoring hay anti-cheat. Mục tiêu là khôi phục một ứng dụng đã mua bản
  quyền trên máy của chính người dùng.
- `patch/patch_bluebook.py` phá chữ ký số của ứng dụng.
- Nếu cần hỗ trợ chính thức, gửi College Board phần **English TL;DR** ở đầu tài
  liệu này kèm `docs/root-cause.md`.
