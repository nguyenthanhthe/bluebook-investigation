# Cơ chế gốc — vì sao tiến trình GPU chết khi file nằm trong profile

Tài liệu này khép lại câu hỏi còn để mở ở `docs/root-cause.md §5`: **chính xác
cái gì thất bại**. Câu trả lời đọc được trực tiếp từ bộ nhớ của tiến trình con
đang chết, và tái lập được bằng thí nghiệm có kiểm soát (chỉ đổi **một** biến).

---

## 1. Tóm tắt một dòng

Tiến trình con sandbox (GPU, renderer) của Bluebook **không mở được
`icudtl.dat`** — `GetLastError` trong chính nó ghi **5 = ERROR_ACCESS_DENIED** —
nên hàm nạp dữ liệu ICU của Chromium (`base/i18n/icu_util.cc`, RVA `0x19E0680`)
gọi `IMMEDIATE_CRASH` tại RVA `0x19E0914`; sau 6 lần thử lại, browser gọi
`LOG(FATAL)` và thoát.

Nguyên nhân là **mức toàn vẹn (integrity level)**: tiến trình con chạy ở mức
**Low** (`S-1-16-4096`). Trên đường dẫn nằm trong profile người dùng, quyền đọc
`icudtl.dat` bị từ chối với token Low, nhưng **được chấp nhận với chính token đó
ở mức Medium**. Ngoài profile (`C:\TempBB`, `D:\`, `C:\Users\Public`) thì Low
cũng đọc được.

## 2. Vì sao trước đây "chưa xác định được"

Ba rào cản nêu trong `docs/root-cause.md §5` đều gỡ được, mỗi cái cần một cách
tiếp cận khác:

| Rào cản cũ | Cách gỡ |
|---|---|
| "Không có admin → không chạy được WinDbg" | Không cần elevation. `DEBUG_PROCESS` gắn vào cây tiến trình và **giữ handle đầy đủ tới tiến trình con**, đủ để đọc bộ nhớ và token. |
| "Tiến trình GPU chết trước khi Crashpad kịp tạo dump" | Không cần dump. Chặn ngay tại `int3` trong ảnh, tiến trình bị treo, đọc thẳng biến toàn cục mà hàm crash đã ghi lại. |
| "Không rõ lời gọi sandbox nào thất bại" | Không phải lời gọi sandbox nào cả. Đây là **một lần mở file bị từ chối**, và nó tự ghi lại lý do. |

## 3. Hàm crash làm gì (dịch ngược)

Hàm tại RVA `0x19E0680` là đường khởi tạo dữ liệu ICU của Chromium. Đường thất
bại của nó (trích mã giả, `D:\rea-tools\decomp_child.c`):

```c
cVar5 = func_0x03c20640();          // nạp icudtl.dat
if (cVar5 == '\0') {                // THẤT BẠI
    _DAT_0b5a1004 = GetLastError();               // <- ghi lại mã lỗi Win32
    _DAT_0b5a1008 = aiStack_440[5];
    func_0x04350fd0(&DAT_0b5a100c, 0x104, iVar8); // <- ghi lại đường dẫn đã thử
    ...
}
```

rồi ở cuối hàm:

```c
if (bVar2) {                 // dữ liệu ICU không dùng được
    func_0x01e231d0(9);
    ...
}
pcVar3 = (code *)swi(3);     // <- RVA 0x19E0914 : int3  (IMMEDIATE_CRASH)
```

Mã lỗi và đường dẫn được lưu lại **trước khi** tiến trình tự sát. Đó là toàn bộ
bằng chứng cần thiết, và nó nằm trong bộ nhớ của chính tiến trình con.

Nhãn `_DAT_...` của Ghidra là địa chỉ tuyệt đối giả định ImageBase `0x400000`,
nên RVA thật = `nhãn − 0x400000` (ví dụ `_DAT_0b5a1004` → RVA `0x0B1A1004`,
trong `.data`).

## 4. Bằng chứng

### E1 — bản cài trong profile (bản đang lỗi)

```
[!!] pid=25332 (gpu-process) hit the ICU int3 at RVA 0x19e0914
  --- ICU globals in pid=25332 (gpu-process) (image base 0xde0000) ---
    icu_data_ptr     = 0xffffffff  -> -1 = ICU data NOT loaded
    GetLastError     = 0x00000005 (5)  -> ERROR_ACCESS_DENIED
    path_buf (utf16) = 'C:\Users\Admin\AppData\Local\Programs\bluebook\icudtl.dat'
```

Lỗi lặp lại y hệt ở tiến trình **renderer** — mọi tiến trình con sandbox đều
không đọc được dữ liệu ICU, không riêng GPU.

### E2 — bản cài ĐANG CHẠY TỐT, copy vào trong profile

Copy nguyên `D:\Temp\bbcopy` (chạy tốt) vào `C:\Users\Admin\zztest`:

```
[!!] pid=19084 (gpu-process) hit the ICU int3 at RVA 0x19e0914
    icu_data_ptr     = 0xffffffff  -> -1 = ICU data NOT loaded
    GetLastError     = 0x00000005 (5)  -> ERROR_ACCESS_DENIED
    path_buf (utf16) = 'C:\Users\Admin\zztest\icudtl.dat'
```

→ Cùng binary, cùng file: chỉ **đổi vị trí** là đổi kết quả. Loại bỏ khả năng
"bản cài hỏng" hay "file hỏng".

### E3 — chính bản cài đó, ngoài profile

```
ICU PROBE  exe=D:\Temp\bbcopy\Bluebook.exe
[+] CREATE pid=28620 tag=gpu-process base=0xea0000
[ok] no process hit the ICU int3 within the budget
```

### E4 — token thật của tiến trình GPU

```
TokenUser: S-1-5-21-...-1001
TokenIsRestricted: 1
TokenIsAppContainer: 0
TokenGroups (15):
  S-1-5-21-...-513            DENY-ONLY      <- nhóm chính của người dùng
  S-1-1-0        Everyone     MANDATORY|ENABLED|DEFAULT
  S-1-5-32-544   Administrators  DENY-ONLY
  S-1-5-32-545   Users        MANDATORY|ENABLED|DEFAULT
  S-1-5-4        INTERACTIVE  MANDATORY|ENABLED|DEFAULT
  S-1-5-11       Authenticated Users  DENY-ONLY
  S-1-5-5-0-...  (logon)      MANDATORY|ENABLED|DEFAULT|LOGON
  S-1-16-4096    Low IL                       <-- mức toàn vẹn Low
TokenRestrictedSids (5):   Users, Everyone, RESTRICTED(S-1-5-12), <capability>, <logon>
TokenPrivileges (1):       SeChangeNotifyPrivilege  ENABLED
```

Token này **giống hệt nhau** dù chạy trong hay ngoài profile (đã đối chiếu): yếu
tố thay đổi không phải token, mà là **đường dẫn**.

### E5 — thí nghiệm có kiểm soát: chỉ đổi mức toàn vẹn

Dựng token **trùng đúng** tập SID của tiến trình con
(`Everyone`+`Users`+`INTERACTIVE` được bật, SID người dùng bị disable), rồi chạy
**hai lần**: một lần ở Medium IL, một lần ở Low IL. Chỉ **một** biến thay đổi.

```
token                                                       PROFILE         TempBB      rea-tools    Public-bbt2
-----------------------------------------------------------------------------------------------------------------
  Everyone+Users+INTERACTIVE, Medium IL                             0              0              0              0
  Everyone+Users+INTERACTIVE, LOW IL  <-- child                     5              0              0              0
```

→ **Low IL là yếu tố quyết định.** Cùng tập SID, cùng quyền: ở Medium thì mở
được `icudtl.dat` trong profile; ở Low thì bị từ chối — và cột kết quả khớp
chính xác với hành vi thật của ứng dụng (profile chết; `C:\TempBB`, `D:\`,
`C:\Users\Public\bbt2` đều chạy).

### E6 — biên giới nằm ở gốc profile

Tạo một file tại từng mức của đường dẫn (file thừa hưởng nhãn của thư mục cha),
rồi cho token Low IL đọc:

```
    C:\Users\Admin                          err=5   <-- từ đây trở xuống bị từ chối
    ...\Admin\AppData                       err=5
    ...\AppData\Local                       err=5
    ...\Local\Programs                      err=5
    ...\Programs\bluebook                   err=5
```

→ Biên giới chính là **thư mục profile `C:\Users\Admin`**. File tạo trực tiếp
trong đó chỉ thừa hưởng ACE cho package SID / SYSTEM / Administrators / chủ sở
hữu — không có `Everyone`/`Users`.

### E7 — thí nghiệm nhân quả theo chiều ngược

Đặt `DENY Everyone` lên `icudtl.dat` trong `D:\Temp\aclmimic\app` (đường dẫn
ngoài profile, vốn chạy tốt):

```
SDDL: ...D:AI(D;;CCSWWPLORC;;;WD)(A;ID;FA;;;SY)(A;ID;FA;;;S-1-5-21-...-1001)
[!!] pid=27188 hit the ICU int3 at RVA 0x19e0914
    GetLastError     = 0x00000005 (5)  -> ERROR_ACCESS_DENIED
    path_buf (utf16) = 'D:\Temp\aclmimic\app\icudtl.dat'
```

→ Từ chối quyền đọc file ICU cũng tái hiện đúng lỗi ở nơi bình thường. Nghĩa là
**triệu chứng** (ACCESS_DENIED + int3) là hệ quả trực tiếp của việc không đọc
được file, bất kể nguyên nhân từ chối là gì.

## 5. Vì sao "cấp ACL" trong phiên trước không sửa được

`docs/root-cause.md §3.3` ghi: *"Cấp `BUILTIN\Users` + package SID + `Everyone`
quyền RX trên thư mục cài đang lỗi → vẫn CHẾT"*. Kết quả đó **đúng**, và giờ
giải thích được: **cấp thêm ACE không sửa được một trở ngại về mức toàn vẹn.**

Bằng chứng trực tiếp: bản cài trong profile **đã có** `Everyone:(I)(RX)` trên
`icudtl.dat`; thêm nữa cũng vô ích, vì `Everyone` là SID *được bật* trong token
con nhưng mức Low vẫn bị chặn trên cây thư mục profile. Nói cách khác, thí nghiệm
cũ là một **phủ định đúng nhưng không nhắm đúng cơ chế** — nó loại trừ DACL, mà
DACL đúng là không phải nguyên nhân.

## 6. Trạng thái phân loại

**Quan sát được (chắc chắn):**

1. Tiến trình con sandbox (GPU, renderer) chết bằng `IMMEDIATE_CRASH` tại RVA
   `0x19E0914` sau khi `icudtl.dat` không nạp được.
2. Chính tiến trình con ghi lại `GetLastError = 5` (ACCESS_DENIED) và đường dẫn
   đã thử — đọc trực tiếp từ bộ nhớ của nó.
3. Cùng binary + cùng file: trong profile → chết, ngoài → chạy.
4. Token con là restricted, **Low IL**, với SID người dùng và `Authenticated
   Users` ở trạng thái DENY-ONLY; token **không đổi** giữa hai vị trí.
5. Giữ nguyên tập SID, chỉ hạ mức toàn vẹn xuống Low → tái hiện đúng kết quả của
   ứng dụng (profile bị từ chối; `C:\TempBB`, `D:\`, `C:\Users\Public` thì không).
6. Biên giới bị từ chối là thư mục profile `C:\Users\Admin`.

**Suy luận (có bằng chứng, chưa đọc được từng nhãn SACL):**

- Cây thư mục profile mang một **nhãn toàn vẹn** khiến token Low IL không đọc
  được, dù DACL có `Everyone:(RX)`. Đọc chính xác nhãn đó cần
  `SeSecurityPrivilege` (máy không có), nên đây là suy luận từ hành vi chứ không
  phải từ đọc trực tiếp SACL.

**Chưa xác định:**

- Vì sao **chỉ kiến trúc 32-bit** bị, còn Electron 64-bit trong cùng profile thì
  không. Đây là câu hỏi mở duy nhất còn lại. Giả thuyết hợp lý: đường sandbox
  32-bit (WOW64) hạ token xuống Low IL, còn đường 64-bit thì không — nhưng chưa
  đo được sự khác biệt đó trên một app 64-bit.

## 7. Cách tái lập

```bash
# E1/E2/E3 — đọc thẳng biến toàn cục của tiến trình con
python analysis/icuprobe.py "C:\Users\Admin\AppData\Local\Programs\bluebook\Bluebook.exe" 30
python analysis/icuprobe.py "D:\Temp\bbcopy\Bluebook.exe" 30

# E4 — token thật của tiến trình GPU
python analysis/childtoken.py "C:\Users\Admin\AppData\Local\Programs\bluebook\Bluebook.exe" 30

# E5/E6 — mức toàn vẹn là yếu tố quyết định, và biên giới
python analysis/low_il_test.py

# Xác nhận tiến trình nào chết + ghi dump tiến trình con
python analysis/dumpchild.py "C:\Users\Admin\AppData\Local\Programs\bluebook\Bluebook.exe" 45
```

Không script nào cần quyền admin. `analysis/dumpchild.py` ghi được dump đầy đủ
của tiến trình con (~237 MB) — lần đầu tiên lấy được, phủ định ghi chú cũ rằng
"không bao giờ sinh dump cho tiến trình GPU".

---

## English summary

The GPU (and renderer) child processes die because they **cannot read
`icudtl.dat`**: the crashing function (`base/i18n/icu_util.cc`, RVA `0x19E0680`)
records `GetLastError = 5 (ACCESS_DENIED)` and the attempted path in globals
before hitting `IMMEDIATE_CRASH` at RVA `0x19E0914`. Those globals are readable
straight out of the suspended child, which is how this was determined without a
dump or elevation.

The decisive factor is the child's **Low mandatory integrity level**. The child
runs under a restricted, Low-IL token in which `Everyone`, `Users` and
`INTERACTIVE` stay enabled while the user SID and `Authenticated Users` are
DENY-ONLY. Rebuilding a token with exactly that SID set and running it twice —
once at Medium IL, once at Low IL — changes only one variable, and the result
flips precisely on the profile path: Medium opens `icudtl.dat`, Low is denied.
The denial boundary is the profile root `C:\Users\Admin` itself. The token is
identical inside and outside the profile; only the path differs.

This also explains why the earlier session's ACL experiment appeared to be a
false negative: the in-profile install **already** carries `Everyone:(I)(RX)` on
`icudtl.dat`, so adding ACEs could not help — the obstacle is the integrity
level, not the DACL.

The only remaining unknown is why this affects the **32-bit** runtime but not
64-bit Electron apps in the same profile.
