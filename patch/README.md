# Bản vá

Hai hướng, với mức độ tin cậy rất khác nhau. **Đọc kỹ trước khi dùng.**

---

## 1. `fix_environment.ps1` — BẢN VÁ KHUYẾN NGHỊ (đã kiểm chứng)

**Ý tưởng:** lỗi phụ thuộc **vị trí vật lý** của file. Di chuyển file ra ngoài
profile người dùng, rồi để lại một **directory junction** tại đường dẫn cũ.

**Vì sao để lại junction:** app, shortcut và Squirrel updater vẫn thấy đường dẫn
cài đặt quen thuộc; nhưng file thật nằm ngoài profile nên tiến trình GPU sống
được.

**Không sửa binary** → chữ ký EV của College Board còn nguyên, và các kiểm tra
toàn vẹn của app (`win-verify-signature`, `IntegrityManager`) vẫn hợp lệ.

### Cách dùng

```powershell
# 1. Xem trước, không thay đổi gì (mặc định):
powershell -ExecutionPolicy Bypass -File patch/fix_environment.ps1 -DryRun

# 2. Áp dụng:
powershell -ExecutionPolicy Bypass -File patch/fix_environment.ps1 -Apply

# 3. Hoàn tác:
powershell -ExecutionPolicy Bypass -File patch/fix_environment.ps1 -Revert
```

Tham số tuỳ chọn:

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `-InstallPath` | `%LOCALAPPDATA%\Programs\bluebook` | thư mục cài hiện tại |
| `-TargetPath` | `C:\BluebookApp` | nơi đặt file thật (ngoài profile) |

Script tự kiểm tra: thư mục cài có nằm trong profile không, đủ dung lượng
không, app có đang chạy không; sau khi áp dụng thì **tự chạy thử 20 giây** và
**tự hoàn tác nếu không mở được cửa sổ**.

### Đã kiểm chứng

| Phép thử | Kết quả |
|---|---|
| `-DryRun` | không thay đổi gì, in đúng kế hoạch |
| `-Apply` trên bản copy trong profile | **SUCCESS — cửa sổ mở** |
| `-Revert` | junction gỡ, file gốc khôi phục, `exe exists: True` |

### Hạn chế

- Nếu Bluebook **tự cập nhật** và tạo lại thư mục trong profile, phải chạy lại
  script.
- Việc di chuyển file có thể ảnh hưởng tới những gì worker kiểm tra toàn vẹn
  băm theo đường dẫn. Nếu app báo lỗi toàn vẹn (`WIN_FAIL_FILE_INTEGRITY`),
  hãy `-Revert` rồi thay bằng cách đơn giản hơn: cài/copy hẳn ra thư mục ngoài
  profile và tạo shortcut trỏ tới đó (không cần junction).
- Cần dung lượng trống trên ổ đích (khoảng 350 MB).

---

## 2. `patch_bluebook.py` — BẢN VÁ NHỊ PHÂN (đã kiểm chứng là **KHÔNG sửa được**)

**Ý tưởng:** vô hiệu hoá đúng chỗ browser tự sát. Điểm crash là đuôi của khối
nguội phát ra `LOG(FATAL)`:

```
RVA 0x06455F47    CC 0F 0B      ; int3 ; ud2   (IMMEDIATE_CRASH)
```

Script ghi đè 3 byte này thành `C3 90 90` (`ret; nop; nop`) để hàm `[[noreturn]]`
**quay về** thay vì giết tiến trình.

### Cách dùng

```bash
python patch/patch_bluebook.py <input.exe> [output.exe]
python patch/patch_bluebook.py --revert <patched.exe> [output.exe]
```

Script kiểm tra SHA256 của input khớp bản 0.9.725 đã biết
(`e87f9a29…2d0393`), kiểm tra đúng byte tại điểm vá, và **từ chối vá** nếu không
khớp.

### Kết quả thực nghiệm (quan trọng)

Đã vá một bản copy, đặt vào trong profile, và chạy:

| | Bản gốc | Bản đã vá |
|---|---|---|
| Kết quả | chết sau ~4–5 s | **vẫn chết** sau ~5,4 s |
| Exception trong dump | `0x80000003` (`int3`) | **`0xC0000005` ACCESS_VIOLATION, EIP=`0x0`** |
| Log | `GPU process isn't usable. Goodbye.` | vẫn y hệt |

**Vì sao thất bại:** `LOG(FATAL)` là **abort có chủ đích** — nó nằm trên đường
"không còn cách nào cứu". Chặn nó không làm GPU process sống lại; nó chỉ khiến
browser **tiếp tục chạy trong trạng thái không hợp lệ** rồi sập bằng
null-pointer. Tức bản vá **biến một abort có kiểm soát thành một crash không
xác định** — tệ hơn.

### Cảnh báo

- Phá **chữ ký Authenticode** của College Board. App có `win-verify-signature`
  và worker toàn vẹn → rất có thể bị phát hiện và từ chối chạy.
- **Không** dùng để né tránh kiểm soát toàn vẹn thi cử, proctoring, hay
  anti-cheat. Script tồn tại để **ghi lại cơ chế crash**, không phải để dùng
  thay bản vá môi trường.

---

## 3. Kết luận

Dùng **`fix_environment.ps1`**. Bản vá nhị phân được giữ lại như tài liệu về
cơ chế, và như một kết quả âm đã kiểm chứng: sửa triệu chứng ở tầng binary
không giải quyết được nguyên nhân nằm ở tầng môi trường.
