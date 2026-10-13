# Nguyên nhân gốc — Bluebook.exe không khởi động

Tài liệu này trình bày chuỗi bằng chứng dẫn tới nguyên nhân, tách bạch rõ
**quan sát được (observation)**, **suy luận (inference)** và **chưa xác định
(unknown)**.

---

## 1. Triệu chứng

| Mục | Giá trị |
|---|---|
| Ứng dụng | Bluebook 0.9.725 (College Board) |
| Kiến trúc | **32-bit (ia32)**, PE32, ImageBase `0x400000` |
| Runtime | Electron 42.0.1 · Chromium 148.0.7778.97 · Node 24.15.0 |
| Kích thước exe | 191.469.256 bytes (SHA256 `e87f9a29…2d0393`) |
| Đường dẫn cài | `C:\Users\Admin\AppData\Local\Programs\bluebook\Bluebook.exe` |
| Hành vi | Không bao giờ hiện cửa sổ; thoát sau ~4–5 giây |
| WER | exception `0x4000001f`, fault module `Bluebook.exe`, offset `0x06455f47` |
| Crashpad | exception `0x80000003` tại RVA `0x6455F47` |

## 2. Chuỗi sự kiện (đã xác minh bằng log của chính ứng dụng)

Bật `ELECTRON_ENABLE_LOGGING=1` (qua biến môi trường, vì app **từ chối mọi
tham số dòng lệnh truyền thêm**) thu được stderr nguyên văn:

```
[15232:1013/024543.942:ERROR:content\browser\gpu\gpu_process_host.cc:999]
    GPU process exited unexpectedly: exit_code=-2147483645
... (lặp lại 6 lần, cách nhau ~70 ms)
[15232:1013/024544.287:WARNING:content\browser\gpu\gpu_process_host.cc:1441]
    The GPU process has crashed 6 time(s)
[15232:1013/024544.287:FATAL:content\browser\gpu\gpu_data_manager_impl_private.cc:417]
    GPU process isn't usable. Goodbye.
```

`-2147483645` = `0x80000003` = `STATUS_BREAKPOINT`, tức `IMMEDIATE_CRASH`
(`int3; ud2`) — tiến trình GPU **tự kết thúc**, không phải bị hệ thống giết.

Diễn giải:

1. Tiến trình **browser** khởi động bình thường (nạp được app.asar, chạy
   được logic Node/Electron).
2. Nó spawn tiến trình con **GPU**.
3. Tiến trình GPU **chết ngay lập tức** với `IMMEDIATE_CRASH`.
4. Browser thử lại **6 lần**.
5. Hết đường fallback, Chromium gọi `LOG(FATAL)` và tự sát.

## 3. Bằng chứng quyết định: lỗi theo **vị trí thư mục vật lý**

### 3.1 Ma trận vị trí (mỗi vị trí chạy ≥ 2 lần)

| Vị trí cài đặt | Kết quả | Có tiến trình GPU? |
|---|---|---|
| `C:\Users\Admin\AppData\Local\Programs\bluebook` | **CHẾT** | không |
| `C:\Users\Admin\AppData\Local\Programs\bluebook_test` | **CHẾT** | không |
| `C:\Users\Admin\bbt2` | **CHẾT** | không |
| `C:\Users\Admin\Desktop\bbt2` | **CHẾT** | không |
| `C:\Users\Admin\Documents\bbt2` | **CHẾT** | không |
| `C:\Users\Admin\AppData\bbt2` | **CHẾT** | không |
| `C:\Users\Public\bbt2` | **CHẠY** | có |
| `C:\ProgramData\bbt2` | **CHẠY** | có |
| `C:\TempBB\bluebook` | **CHẠY** | có |
| `C:\bbt2` | **CHẠY** | có |
| `D:\bluebook_test` | **CHẠY** | có |

→ Biến quyết định là **"nằm trong `C:\Users\Admin`"**, không phải tên thư mục
`bluebook`, không phải thư mục cha `Programs`.

### 3.2 Loại trừ "chuỗi đường dẫn"

| Thí nghiệm | Kết quả | Kết luận |
|---|---|---|
| `subst X: C:\Users\Admin\AppData\Local\Programs` rồi chạy `X:\bluebook\Bluebook.exe` | **CHẾT** | không phải do chuỗi đường dẫn nhìn thấy |
| Copy vào `C:\TempBB\Users\Admin\bbt2` (mô phỏng chuỗi tên) | **CHẠY** | chuỗi tên không gây lỗi |
| Chạy qua tên ngắn 8.3 của thư mục thật | **CHẾT** | vẫn là thư mục thật |

→ Lỗi gắn với **thư mục vật lý thật**, không phải chuỗi ký tự đường dẫn.

### 3.3 Loại trừ ACL / thuộc tính / TEMP / chính sách

| Giả thuyết | Thí nghiệm | Kết quả |
|---|---|---|
| ACL thiếu quyền đọc | Cấp `BUILTIN\Users` + package SID + `Everyone` quyền RX trên thư mục cài đang lỗi | **vẫn CHẾT** |
| ACL là nguyên nhân | Tạo thư mục làm việc rồi **từ chối** quyền đọc của sandbox SID | **vẫn CHẠY** |
| Chủ sở hữu / chặn kế thừa | Sao chép nguyên mẫu ACL của `C:\Users\Admin` sang nơi chạy được | **vẫn CHẠY** |
| Thuộc tính Hidden/System | Xóa `-H -S` trên bản lỗi; thêm `+H +S` trên bản chạy được | **không đổi** |
| `%TEMP%` | Ép TEMP vào/ra profile cho cả hai phía | **không đổi** |
| Defender CFA / ASR / Exploit Protection | Đọc registry | **tất cả trống** |
| IFEO / AppCompat Layers / per-app GPU pref | Đọc registry (3 nhánh + HKCU) | **không có mục Bluebook** |
| Smart App Control / WDAC | Đọc `CI\Policy` | **không bật** |

> **Cập nhật:** hai dòng đầu (ACL) là **phủ định đúng nhưng không nhắm đúng cơ
> chế**. Bản cài trong profile vốn đã có `Everyone:(I)(RX)` trên `icudtl.dat`,
> nên thêm ACE không thể giúp; trở ngại thật là **mức toàn vẹn Low** của tiến
> trình con. Xem [mechanism.md §5](mechanism.md).

## 4. Bằng chứng quyết định thứ hai: **không phải lỗi riêng của Bluebook**

Dùng một cây Electron 32-bit "trần" (`etest32.exe` = chính `Bluebook.exe` đã
đổi tên, kèm một app tối giản — byte-identical, SHA256 giống hệt):

| Vị trí | `etest32` |
|---|---|
| `C:\Users\Admin\etest_profile` | **CHẾT** (browser, crashpad, utility — không có GPU) |
| `C:\TempBB\etest_outside` | **CHẠY** (browser, crashpad, **gpu-process**, renderer, utility) |

Và quét toàn bộ `%LOCALAPPDATA%\Programs`:

| Ứng dụng | Kiến trúc | Trạng thái |
|---|---|---|
| ZCode | x64 | chạy tốt |
| Microsoft VS Code | x64 | chạy tốt |
| Antigravity | x64 | chạy tốt |
| LM Studio | x64 | chạy tốt |
| **Bluebook** | **i386 (32-bit)** | **CHẾT** |

→ Bluebook là **ứng dụng Electron 32-bit duy nhất** cài trong profile. Mọi ứng
dụng Electron 64-bit cài cùng chỗ đều chạy bình thường.

## 5. Kết luận

**Quan sát được (chắc chắn):**

1. Khi các file của một ứng dụng **Electron 32-bit** nằm **vật lý bên trong
   thư mục profile người dùng** (`C:\Users\<user>\…`), tiến trình **GPU** của
   nó chết tức thì bằng `IMMEDIATE_CRASH` (`0x80000003`).
2. Browser thử lại 6 lần, hết fallback, gọi `LOG(FATAL)` tại
   `gpu_data_manager_impl_private.cc:417` và tự kết thúc → app không hiện cửa sổ.
3. Cùng binary đó chạy tốt khi file nằm **ngoài** profile.
4. Hiện tượng tái lập được với **Electron 32-bit trần**, không cần mã của
   Bluebook → **không phải bug trong code College Board**.
5. Ứng dụng Electron 64-bit trong profile **không** bị.

**Suy luận (có bằng chứng, chưa chứng minh trọn vẹn):**

- Đây là tương tác giữa **sandbox GPU của Chromium 32-bit** và **đường dẫn nằm
  trong profile người dùng** trên Windows 11 26H2 (build 26300). Tiến trình GPU
  bị kết thúc trong giai đoạn khởi tạo sandbox, **trước khi** nạp bất kỳ DLL đồ
  họa nào.
- Củng cố: dump của tiến trình chết chỉ chứa DLL hệ thống
  (`ntdll`, `kernel32`, `ole32`, `dwmapi`, `DWrite`, `wlanapi`…) — **không có**
  `d3d11.dll`, `libEGL.dll`, `libGLESv2.dll`, `dxgi.dll`. Tức nó chết trước khi
  chạm tới tầng đồ họa.

**Đã xác định (xem [mechanism.md](mechanism.md)):** tiến trình con sandbox không
mở được `icudtl.dat` — `GetLastError = 5` (ACCESS_DENIED) do chính nó ghi lại,
đọc trực tiếp từ bộ nhớ. Yếu tố quyết định là **mức toàn vẹn Low** của tiến trình
con: cùng tập SID, chạy ở Medium IL thì mở được, ở Low IL thì bị từ chối; biên
giới là thư mục profile `C:\Users\Admin`.

**Chưa xác định:** vì sao **chỉ runtime 32-bit** bị, còn Electron 64-bit trong
cùng profile thì không. Đây là câu hỏi mở duy nhất còn lại.

## 6. Ghi chú: chỉnh sửa file `walkthrough.md` trước đó

Hồ sơ điều tra cũ khẳng định browser chết "bằng chính `IMMEDIATE_CRASH` của
`LOG(FATAL)` GPU tại RVA `0x6455F47`". Kiểm tra ở mức byte cho thấy cách diễn
giải đó **không chính xác**:

- `CC 0F 0B` (`int3; ud2`) là macro `IMMEDIATE_CRASH` **dùng chung** của
  Chromium — xuất hiện **147.615 lần** trong `.text`, không phải dấu vân tay
  riêng của đường GPU.
- Chuỗi `GPU process isn't usable. Goodbye.` nằm tại RVA `0x0A3A9119`, được
  tham chiếu từ code tại RVA `0x056FFB5D` — **một hàm khác** với điểm crash.
- Điểm crash `0x6455F47` là nhánh nguội của kiểm tra
  `std::string_view::substr`; các chuỗi `.rdata` lân cận là
  `string_view::substr` và `out_of_range was thrown in -fno-exceptions mode`.
  Lệnh ngay trước nó là `__security_check_cookie`.

Kết luận cũ ("lỗi theo đường dẫn cài đặt") **đúng hướng**, nhưng cơ chế và
địa chỉ crash bị gán sai. Tài liệu này thay thế phần đó.

Điểm quan trọng: chuỗi `LOG_FATAL` GPU **có thật** và đúng là dấu hiệu cuối
cùng — nó được tìm thấy nguyên văn trên stack của tiến trình browser trong
dump, kèm tiền tố
`[<pid>:<date>:FATAL:content\browser\gpu\gpu_data_manager_impl_private.cc:417]`.
Cái sai chỉ là việc **gán nhãn** điểm `0x6455F47` là "chỗ GPU tự sát".
