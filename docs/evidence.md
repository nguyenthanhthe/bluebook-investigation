# Nhật ký thực nghiệm & cách tái lập

Toàn bộ kết luận trong `docs/root-cause.md` đều tái lập được bằng các script
trong `analysis/`. Tài liệu này ghi lại từng thí nghiệm, lệnh chạy và kết quả.

## 0. Môi trường

| Mục | Giá trị |
|---|---|
| Máy | DESKTOP-GJJ8AO3 — Dell, i7-13620H, 16 GB, RTX 4050 Laptop + Intel UHD |
| OS | Windows 11 Pro, build 26300.9550 (26H2) |
| Quyền | **Không** có admin (UAC cần prompt tương tác) |
| `%TEMP%` | `D:\Temp` (không mặc định) |
| Cài đặt Bluebook | `C:\Users\Admin\AppData\Local\Programs\bluebook` |

Hệ quả của việc không có admin: **không** chạy được ProcMon (cần driver) hay
WinDbg. Các phương án thay thế đã dùng: `ELECTRON_ENABLE_LOGGING` qua biến môi
trường, trình gỡ lỗi `DEBUG_PROCESS` tự viết (`analysis/dbgchild.py`), listener
`OutputDebugString` qua shared memory DBWIN (`analysis/dbwin.py`), và bộ phân
tích minidump thuần Python (`analysis/mdparse2.py`).

## 1. Lấy log thật của ứng dụng

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/envlog.ps1 `
  -Exe "C:\Users\Admin\AppData\Local\Programs\bluebook\Bluebook.exe" -Tag real_envlog
```

Dùng **biến môi trường** (`ELECTRON_ENABLE_LOGGING=1`) chứ không dùng tham số
dòng lệnh, vì app từ chối tham số (xem mục 4). Kết quả: 6 dòng
`GPU process exited unexpectedly: exit_code=-2147483645` rồi
`FATAL:…gpu_data_manager_impl_private.cc:417] GPU process isn't usable. Goodbye.`

## 2. Ma trận vị trí

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/matrix.ps1   # tên thư mục vs cha vs ổ
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/matrix2.ps1  # Program / LocalAppData / Roaming / Profile / C:\Temp
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/matrix3.ps1  # Users\Admin vs Public vs ProgramData vs C:\
```

Kết quả chốt: chỉ **bên trong `C:\Users\Admin`** mới lỗi.

## 3. Tách biệt "chuỗi đường dẫn" và "thư mục thật"

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/substtest.ps1
```

| Phép thử | Kết quả |
|---|---|
| A. Bản cài thật | CHẾT |
| B. Cùng thư mục qua `subst X:` | **CHẾT** → không phải chuỗi đường dẫn |
| C. Chuỗi tên mô phỏng ở `C:\TempBB\Users\Admin\bbt2` | **CHẠY** |
| D. Qua tên ngắn 8.3 của thư mục thật | CHẾT |

## 4. App từ chối tham số dòng lệnh

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/sbtest2.ps1
```

Mọi cờ (`--no-sandbox`, `--disable-gpu`, `--use-angle=swiftshader`,
`--in-process-gpu`, `--enable-logging`, `--user-data-dir=…`) đều khiến app thoát
sau **~1,8 s với 1 tiến trình**. Cùng cờ đó trên bản chạy được ở `D:\Temp\bbcopy`
cũng làm nó chết. → Không thể chẩn đoán bằng cờ; phải dùng biến môi trường.

## 5. Loại trừ ACL / thuộc tính / TEMP / chính sách

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/acltest.ps1    # cấp quyền Users trong Programs
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/acl2.ps1       # từ chối sandbox SID nơi chạy được
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/appctest.ps1   # cấp RX cho AppContainer/pkg SID
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/aclmimic.ps1   # mô phỏng ACL profile
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/attrtest.ps1   # Hidden/System
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/temptest.ps1   # %TEMP% trong/ngoài profile
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/policy.ps1     # Defender CFA/ASR/IFEO/AppCompat/WDAC
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/dirprops.ps1   # ACL, owner, thuộc tính, reparse
```

Tất cả đều **không** thay đổi kết quả. Chi tiết trong `docs/root-cause.md` §3.3.

## 6. Bằng chứng "không phải bug của Bluebook"

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/etestcmp.ps1   # Electron 32-bit trần
python analysis/archscan.py "C:\Users\Admin\AppData\Local\Programs" 3       # kiến trúc mọi app trong profile
```

- `etest32.exe` (chính binary đó, đổi tên, app tối giản): CHẾT trong profile,
  CHẠY ngoài profile.
- Trong profile: ZCode / VS Code / Antigravity / LM Studio đều **x64** và chạy
  tốt; Bluebook là app Electron **32-bit duy nhất** → và là app duy nhất lỗi.

## 7. Thu thập dump

```powershell
# Dump của browser (luôn có):
python analysis/mdparse2.py "C:\Users\Admin\AppData\Roaming\bluebook\Crashpad\reports\<id>.dmp"
python analysis/mdstack.py  "…\<id>.dmp"     # stack thô + chuỗi

# Harvest nhanh để tìm dump của tiến trình GPU:
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/harvest2.ps1 `
  -Exe "C:\Users\Admin\AppData\Local\Programs\bluebook\Bluebook.exe" -Tag real_all -Secs 16
```

Kết quả: **chỉ** thu được dump của browser. Tiến trình GPU chết trước khi
Crashpad client của nó khởi tạo → không có dump GPU (giới hạn bằng chứng thật).

Chuỗi trên stack của dump browser (đọc bằng `mdstack.py`) — bằng chứng nguyên văn:

```
[8624:1013/023708.780:FATAL:content\browser\gpu\gpu_data_manager_impl_private.cc:417]
    GPU process isn't usable. Goodbye.
```

## 8. Dòng lệnh tiến trình con

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/cmdl.ps1 `
  -Exe "D:\Temp\bbcopy\Bluebook.exe" -Tag WORKING
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/cmdl.ps1 `
  -Exe "C:\Users\Admin\AppData\Local\Programs\bluebook\Bluebook.exe" -Tag CRASHING
```

Cho thấy `--use-gl=angle --use-angle=d3d11-warp-webgl` ở GPU process (bản chạy
được) và việc bản lỗi **không bao giờ** có dòng `--type=gpu-process` tồn tại đủ
lâu để đọc.

## 9. Bản vá & kiểm chứng bản vá

```powershell
# Thiết kế bản vá: junction trong profile -> file thật ở ngoài
powershell -NoProfile -ExecutionPolicy Bypass -File analysis/junctest.ps1
```

| Phép thử | Kết quả |
|---|---|
| J1. Junction trong profile → file thật ngoài profile | **CHẠY** |
| J2. Junction ngoài profile → file thật trong profile | **CHẾT** |
| Đối chứng. Chạy trực tiếp từ file thật ngoài profile | **CHẠY** |

→ Xác nhận: **vị trí vật lý** của file là biến quyết định, và **di chuyển file
ra ngoài profile** là cách sửa đúng.

```powershell
# Bản vá môi trường (đã kiểm chứng cả -Apply và -Revert):
powershell -NoProfile -ExecutionPolicy Bypass -File patch/fix_environment.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File patch/fix_environment.ps1 -Apply
powershell -NoProfile -ExecutionPolicy Bypass -File patch/fix_environment.ps1 -Revert

# Bản vá nhị phân (đã kiểm chứng là KHÔNG sửa được — xem patch/README.md):
python patch/patch_bluebook.py <input.exe> <output.exe>
```

## 10. Mục lục script

| Script | Việc |
|---|---|
| `run1.ps1` | chạy một exe, poll cửa sổ, báo CHẠY/CHẾT — harness cơ bản |
| `observe.ps1` | như trên, thêm dòng lệnh tiến trình con + mốc thời gian |
| `envlog.ps1` | chạy với `ELECTRON_ENABLE_LOGGING` qua **biến môi trường**, bắt stderr |
| `cmdl.ps1` | in **đầy đủ** dòng lệnh mọi tiến trình trong cây |
| `matrix.ps1` `matrix2.ps1` `matrix3.ps1` | ma trận vị trí cài đặt |
| `substtest.ps1` | tách "chuỗi đường dẫn" vs "thư mục thật" (subst, tên 8.3, mô phỏng chuỗi) |
| `sbtest2.ps1` | thử cờ sandbox/GPU → chứng minh app bỏ qua tham số |
| `acltest.ps1` `acl2.ps1` `aclmimic.ps1` `appctest.ps1` | loại trừ ACL / chủ sở hữu / sandbox SID |
| `attrtest.ps1` | loại trừ thuộc tính Hidden/System |
| `temptest.ps1` | loại trừ `%TEMP%` |
| `policy.ps1` `dirprops.ps1` | đọc chính sách bảo mật & thuộc tính thư mục |
| `etestcmp.ps1` `archscan.py` | chứng minh không phải bug của Bluebook (Electron 32-bit trần; quét kiến trúc) |
| `harvest2.ps1` | harvest Crashpad dump ở 10 ms/lần |
| `mdparse2.py` `mdstack.py` `mdmods.py` | phân tích minidump (exception, RVA, stack, chuỗi, module) |
| `dbwin.py` | bắt `OutputDebugString` toàn hệ thống qua shared memory DBWIN |
| `dbgchild.py` | gỡ lỗi cả cây tiến trình bằng `DEBUG_PROCESS` |
| `procmon_cap.ps1` | thử chạy ProcMon (cần admin — không dùng được trên máy này) |
| `deescape.py` `collapse.py` `literals.py` `strdecode.py` | giải obfuscate bundle JS |
| `addon_strings.py` | nhận dạng hai native addon |
| `junctest.ps1` | kiểm chứng thiết kế bản vá (junction) |

## 11. Lưu ý tái lập

- Phải **đóng** Bluebook trước mỗi lần thử (script đã tự kill).
- Mỗi lần chạy để lại file `<guid>.tmp.node` trong `%TEMP%` (ở đây `D:\Temp`);
  sau nhiều lần thử đã có 417 file. Có thể dọn an toàn.
- `%LOCALAPPDATA%\Programs` có thể chứa thư mục test do các thí nghiệm tạo ra
  (`bb_*`, `bbt*`, `bluebook_test`, `etest_*`) — nên dọn sau khi thử.
- Bản cài thật **không** bị thay đổi: SHA256 vẫn là `e87f9a29…2d0393`.
