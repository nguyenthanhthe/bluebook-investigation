# BLUEBOOK không khởi động — Hồ sơ điều tra & Walkthrough

> **LƯU Ý:** Đây là hồ sơ của **phiên điều tra trước**, giữ lại để tham khảo lịch
> sử. Kết luận về cơ chế crash trong tài liệu này **không chính xác** — nó gán sai
> điểm crash `RVA 0x6455F47` cho `LOG(FATAL)` của GPU. Xem
> [root-cause.md §6](root-cause.md) để biết chỗ sai, và [root-cause.md](root-cause.md)
> cho phân tích đã hiệu chỉnh. Kết luận "lỗi theo đường dẫn cài đặt" thì đúng
> hướng, nhưng mô tả đúng hơn là "file nằm trong profile người dùng".

**Ngày:** 12–13/10/2026 · **Máy:** DESKTOP-GJJ8AO3 (Dell laptop, i7-13620H, 16 GB LPDDR5 hàn chết, RTX 4050 Laptop + Intel UHD, 2560x1600@120Hz)
**Hệ điều hành:** Windows 11 Pro 26H2, build 26300.9550 (enablement package KB5121794 đặt trên nền servicing 26100 = 24H2 base, LCU KB5124010)
**Bluebook:** phiên bản 0.9.725 (bản mới nhất, đã xác minh hash installer khớp chính xác `latest.yml` của College Board)

---

## English TL;DR (for College Board support)

Bluebook 0.9.725 (32-bit/ia32 Electron 42.0.1, Chromium 148) always terminates ~7–12 s after launch on this Windows 11 26H2 (26300.9550) machine. The browser process aborts with Chromium's `IMMEDIATE_CRASH` (bytes `CC 0F 0B` = `int3; ud2` at RVA `0x6455F47`) right after logging the fatal error
`content\browser\gpu\gpu_data_manager_impl_private.cc:417 — GPU process isn't usable. Goodbye.` (WER exception code `0x4000001f`, fault module Bluebook.exe).
**Key discovery:** an **SHA256-identical copy of the whole install folder** placed at `D:\Temp\bbcopy` runs perfectly on the same machine with the same user profile — window opens, GPU process stays alive (ANGLE D3D11 on the RTX 4050, `sandboxed: true`, WebGL/WebGPU enabled). The crash is therefore **tied to the installation path** `C:\Users\Admin\AppData\Local\Programs\bluebook` (or something path-dependent), **not** to the OS build, GPU drivers, WOW64, RAM, or the user profile. Verified driver components (incl. the 32-bit UMDs), registry policies (AppCompat, IFEO, SRP, GPU preferences), and ACLs are identical/normal. Precise mechanism still under investigation (see §7).

## 1. Tình huống hiện tại

1. **Bluebook không mở được** — 100% các lần chạy (~8/8 chạy đo + nhiều lần lặp) app chết sau 7–12 giây, **không bao giờ** hiện cửa sổ. Đây là vấn đề chính.
2. **"RAM đầy"** — có thật (14.8/15.7 GB = 94%) nhưng là do tải ứng dụng (SolidWorks ~4.5 GB, Brave, ZCode, node, svchost, Dell suite, NVIDIA overlay...), không phải lỗi; **không liên quan** tới việc Bluebook không mở (đã chứng minh: lúc crash vẫn còn ~9 GB commit headroom).
3. **"Xung nhịp GPU thấp"** — nhận định nhầm: GPU chạy **2595/3105 MHz (84% max, P0)**, số "2%" trong Task Manager là *utilization*, không phải clock. GPU bị giới hạn 70 W TGP (Dell thermal policy) — hoạt động bình thường.

**Hệ quả quan trọng nhất:** giả thuyết cũ "phải quay về Windows 24H2" đã bị **bác bỏ bằng thực nghiệm** (xem §5) — máy hiện tại đã vượt mọi yêu cầu của College Board, không cần (và không nên) hạ OS, dữ liệu không bị đụng vào.

## 2. Chữ ký crash của Bluebook (đã xác minh)

| Dấu hiệu | Giá trị | Ý nghĩa |
|---|---|---|
| WER event 1000 | exception `0x4000001f` tại offset `0x06455f47`, fault module `Bluebook.exe` | 3 lần, cùng offset → crash xác định (deterministic) |
| Minidump (Crashpad) | exception `0x80000003` tại **RVA `0x6455F47`** | trùng offset WER |
| Bytes tại RVA | `CC 0F 0B` = `int3; ud2` | **IMMEDIATE_CRASH** của Chromium — app *tự* kết thúc sau CHECK |
| Chuỗi lỗi trong dump | `FATAL:...gpu_data_manager_impl_private.cc:417] GPU process isn't usable. Goodbye.` | nguyên nhân tự sát: GPU process không dùng được |
| Sentry scope | `app.child-process-gone` `'GPU' process exited with 'crashed'` exitCode `-2147483645` (=`0x80000003`) | GPU process chết trước, browser chết theo |

Chuỗi sự kiện: GPU process con khởi động → chết ngay (~20 ms, chỉ load được DLL hệ thống, chưa kịp load DLL đồ họa nào) → Chromium thử lại hết giới hạn → browser process gọi `LOG(FATAL)` → tự crash (int3).

## 3. Những thứ đã loại trừ (qua kiểm tra thực tế)

- **OS build 26300 / WOW64 "hỏng"** — **BỊ BÁC BỎ**: DXDIAG 32-bit chạy tốt (D3D12/DDI 12, feature levels 12_1); Bluebook.exe chạy as Node (ia32) exit 0; và quan trọng nhất: chính binary 32-bit này tạo GPU process chạy **ngon lành** từ thư mục khác (xem §5). `wow64cpu.dll` 26100.9444 (khác các file WOW64 khác .9549) ban đầu là nghi phạm — hóa ra vô can (WinSxS chỉ có đúng 2 phiên bản đó, không phải file thiếu).
- **Thiếu driver đồ họa 32-bit** — tất cả UMD 32-bit đều hiện diện đúng nơi: `nvwgf2um.dll`, `nvldumd.dll`, `nvoglv32.dll` (DriverStore nvdmi), `igdumdim32.dll`, `igd10/12iumd32.dll` (iigd_dch); registry `UserModeDriverName/Wow` trỏ đúng.
- **Hỏng user profile** — chạy với `--user-data-dir` mới vẫn chết; rename `AppData\Roaming\bluebook` sang tên khác (profile mới toanh) vẫn chết.
- **RAM/commit** — còn ~9 GB headroom lúc crash.
- **GPU flags** — mọi tổ hợp (`--disable-gpu`, `--in-process-gpu`, `--no-sandbox`, `--use-angle=swiftshader`, `--disable-features=Vulkan,...`) đều không cho cửa sổ (quan sát thêm: process tồn tại ~45 s không hiện cửa sổ khi có flag; khả năng app tự relaunch và nuốt flag của chúng ta).
- **Path-specific settings** — không có mục nào cho Bluebook trong AppCompatFlags Layers (HKCU/HKLM/32), IFEO (3 nhánh), SRP/AppLocker policy keys, `UserGpuPreferences` (chỉ có Autodesk/eDrawings), Zone.Identifier/ADS, reparse point.
- **ACL lạ** — ACE `S-1-15-2-...` nhìn ban đầu khả nghi nhưng nó nằm trên **mọi** app trong `AppData\Local\Programs` (Arduino, ZCode, KiCad, Python...) và chúng chạy bình thường.
- **Các thứ từ phiên trước** — HAGS, VBS/HVCI (đang tắt), Defender exclusion, AppContainer, AppInit_DLLs, process mitigation, phần mềm chặn, UniKey (64-bit), PendingFileRenameOperations...

## 4. Bằng chứng quyết định — lỗi đi theo *đường dẫn cài đặt*

| Thí nghiệm | Kết quả |
|---|---|
| Chạy bản cài thật tại `C:\Users\Admin\AppData\Local\Programs\bluebook\Bluebook.exe` | **CHẾT ~11.5 s**, không cửa sổ |
| Copy **nguyên cả thư mục** ra `D:\Temp\bbcopy\` (SHA256 Bluebook.exe, app.asar, app-update.yml **giống nhau tuyệt đối**; 77/77 file giống hệt), chạy cùng profile | **CỬA SỔ HIỆN** ("Bluebook"), GPU process sống, renderer + utility + crashpad chạy đủ, app hoạt động |
| Đổi tên exe thành `etest32.exe` ở `D:\Temp\etest32` + app.asar thật của Bluebook | **Chạy tốt** — còn thấy log update "0.9.725 is not available (latest: 0.9.725)" |
| etest32 (binary gốc) với app tối giản | GPUFeatureStatus: `gpu_compositing/webgl/webgpu/video_decode = enabled`; GPUInfo: `ANGLE (NVIDIA GeForce RTX 4050 Laptop GPU) Direct3D11 vs_5_0 ps_5_0, D3D11-32.0.16.1742`, `sandboxed: true`, **0** child-process-gone |
| Cùng exe thật nhưng `--user-data-dir` mới | vẫn chết (2.9 s) |
| Cùng exe thật, profile đã rename sang tên khác | vẫn chết (11 s) |

→ Cùng OS, cùng binary, cùng profile, cùng driver: chỉ khác **thư mục chứa exe**. Lỗi nằm ở chính đường dẫn `C:\...\Programs\bluebook` (hoặc một thứ gắn với đường dẫn đó), chưa phải bản thân app hay Windows.

## 5. Vì sao KHÔNG nên hạ OS về 24H2

Vì bản copy byte-identical chạy ngon trên **cùng bản Windows 26H2 này**, lỗi không do OS build → hạ về 24H2 gần như chắc chắn **không sửa được** mà còn gây rủi ro dữ liệu (máy hiện **không có** `C:\Windows.old`, không có cửa sổ rollback 10 ngày → hạ OS chỉ còn đường cài sạch, rất đắt). Hướng đúng là xử lý yếu tố gắn với đường dẫn cài đặt (mục 7), chứ không phải thay OS.

## 6. Những gì đã làm (nhật ký tóm tắt)

**Phiên trước (12/10):** so sánh cấu hình máy với trang yêu cầu chính thức của College Board (máy vượt mọi yêu cầu); xác minh installer chính hãng (sha512 khớp `latest.yml`); xác định Bluebook là app Electron **32-bit duy nhất** trên máy; truy lùng GPU child process (`/tmp/gpudbg.py`, timeline, correlation 8 lần chạy); loạt loại trừ hệ thống (mục 3); xác minh 26H2 = bản phát hành chính thức qua enablement package (không phải build "lậu").

**Phiên này (13/10):**
1. Sửa lỗi đo đạc của phiên trước (script cũ theo dõi nhầm tiến trình launcher) → viết lại monitor chuẩn (`bbprobe.ps1`, `bbfinal.ps1`).
2. Mổ xẻ WER + minidump → tìm được chính xác địa chỉ tự sát `RVA 0x6455F47`, bytes `CC 0F 0B`, và message `GPU process isn't usable. Goodbye.` → xác nhận GPU process là nạn nhân đầu tiên.
3. Kiểm kê driver 32-bit (đầy đủ), iOS WOW64/WinSxS (đủ), xem CBS packages (EKB), WER queue, event log, PnP.
4. **Thí nghiệm chia tách:** dựng cây `D:\Temp\etest32` (cùng exe, app khác) → GPU process chạy tốt, `gpu_compositing: enabled`, 0 crash; thay app.asar thật vào → vẫn chạy tốt.
5. **Thí nghiệm quyết định:** copy nguyên thư mục cài → chạy ngon; bản cài thật vẫn chết; fresh profile vẫn chết → chốt "lỗi theo đường dẫn".
6. So sánh byte-by-byte (hash giống), ACL, AppCompat, IFEO, SRP, GPU preferences → đều sạch/vô can.
7. Đóng gói toàn bộ bằng chứng vào thư mục này (xem §8).

## 7. Điều còn mở & các bước tiếp theo

Cơ chế chính xác gây chết **chỉ khi chạy từ `C:\...\Programs\bluebook`** chưa tìm ra. Ứng viên còn lại, theo thứ tự nên làm:

1. **Ma trận vị trí** (chạy `scripts\discriminate.ps1` mở rộng): copy sang (a) `C:\Users\Admin\AppData\Local\Programs\bluebook_test2` (cùng cha, khác tên), (b) `C:\Temp\bbcopy2` (ổ C khác thư mục), (c) `D:\bluebook_test` — để tách biệt yếu tố "tên thư mục `bluebook`" vs "nằm trong `Programs`" vs "ổ C vs ổ D". Có thể chỉ sau 2–3 lần chạy là khoanh được.
2. **ProcMon (Sysinternals)** chạy với filter `Bluebook.exe`, bật trước khi launch bản cài thật → xem GPU process chết ở API/đường dẫn nào (so sánh nhánh chạy từ `bbcopy`). Cần quyền admin.
3. **Kiểm tra Defender real-time / ASR rule theo đường dẫn** (`Get-MpPreference` CỰC kỳ cần admin — lúc này không đọc được). Rất khả nghi vì nó là thứ điển hình "hành xử theo path".
4. **Xem dump của chính GPU process** (hiện dump bắt được là browser process): gắn debugger vào GPU child (dùng lại `scripts` dbg64/gpudbg) và bắt message CHECK của **nó** — sẽ nói chính xác nó chết vì sao.
5. Nếu để phục vụ **kỳ thi gấp**: chạy thẳng bản copy `D:\Temp\bbcopy\Bluebook.exe` (đã verify chạy được) và **làm 1 bài practice test** để xác nhận các tính năng lockdown/proctoring vẫn đầy đủ khi chạy từ đường dẫn lạ **trước khi tin dùng nó cho kỳ thi thật**.
6. Báo cho College Board support kèm thư mục này (có TL;DR tiếng Anh ở đầu file) và hỏi họ hướng dẫn hạ/đổi đường dẫn cài hoặc cho bản 64-bit.

## 8. Nội dung thư mục chứng cứ

```
D:\Temp\bluebook-investigation\
├── walkthrough.md          ← file này
├── exe\
│   ├── original\           Bluebook.exe (bản cài thật — phiên bản crash) + installer.exe (installer chính hãng đã hash-verify)
│   ├── bbcopy\             bản copy chạy ĐƯỢC (chứng cứ chính) — chạy bbcopy\Bluebook.exe là mở được
│   └── etest32\            cây thử nghiệm (exe đổi tên + app.asar thật) — dùng để chứng minh GPU process 32-bit khỏe mạnh
├── scripts\                toàn bộ script chẩn đoán (.ps1/.py) — xem mục 9
├── evidence\
│   ├── wer\                3 bản Report.wer chính thức của Windows Error Reporting (exception 0x4000001f)
│   ├── crashpad\           minidump mới nhất của browser process (mở bằng WinDbg/scripts\md.py)
│   ├── sentry\             scope_v3.json (telemetry của app) + bản chụp lại sau lần crash mới
│   ├── asar\               main/index.js + preload/index.js giải nén từ app.asar (mã đã obfuscate)
│   └── dx32.txt            báo cáo DXDIAG 32-bit (D3D12 OK trên Intel UHD)
└── results\gpu_prefs.txt   kiểm tra per-app GPU preferences (không có mục Bluebook)
```

## 9. Cách tái lập / chạy lại script

Chạy bằng PowerShell (có thể không cần admin cho hầu hết):

```powershell
# Thí nghiệm quyết định (real dies, copy works) — ~2 phút:
powershell -NoProfile -ExecutionPolicy Bypass -File D:\Temp\bluebook-investigation\scripts\discriminate.ps1

# Ma trận GPU flags — ~6 phút:
powershell -NoProfile -ExecutionPolicy Bypass -File D:\Temp\bluebook-investigation\scripts\bbfinal.ps1

# Mở minidump (tự viết, không cần WinDbg):
python D:\Temp\bluebook-investigation\scripts\md2.py D:\Temp\bluebook-investigation\evidence\crashpad\671127c2-40cc-4cac-b8f1-648375212d88.dmp

# Gom lại dump/evidence mới:
powershell -NoProfile -ExecutionPolicy Bypass -File D:\Temp\bluebook-investigation\scripts\build_evidence.ps1
```

Lưu ý bẫy kỹ thuật đã dính & đã sửa (đừng lặp lại): script cũ theo dõi **tiến trình launcher** (thoát exit 0 sau khi spawn con) nên báo "exit 0" sai — phải lọc theo `CommandLine -match '--type='` và đếm cả cây tiến trình; passing flag qua `Start-Process -ArgumentList` bằng chuỗi inline dễ mất flag (app relaunch) — nên viết monitor như `bbfinal.ps1`.