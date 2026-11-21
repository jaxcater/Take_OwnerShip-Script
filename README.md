# TakeOwnership & Admin Control

Công cụ gọn nhẹ cho Windows (Batch + PowerShell WinForms) giúp quản lý quyền quản trị (`Administrator`) và chiếm quyền sở hữu (`Take Ownership`) cho tệp tin hoặc thư mục thông qua cơ chế **UAC hợp lệ** của Windows.

## Tính năng chính

1. **Cấp quyền Administrator cho tài khoản hiện tại**
   - Thêm tài khoản Windows đang đăng nhập vào nhóm `Administrators` cục bộ (phân giải tự động theo SID `S-1-5-32-544`, hoạt động trên mọi ngôn ngữ Windows).
2. **Bật / Tắt tài khoản Built-in Administrator**
   - Bật hoặc tắt tài khoản `Administrator` mặc định của hệ thống (SID `-500`).
3. **Take Ownership cho File hoặc Thư mục**
   - Chiếm quyền sở hữu bằng `takeown.exe /a` và cấp toàn quyền kiểm soát (`Full Control`) cho nhóm `Administrators` bằng `icacls.exe /grant *S-1-5-32-544:F`.
4. **Cài / Gỡ "Take Ownership" vào Menu Chuột Phải**
   - Thêm tùy chọn **Take Ownership** (kèm biểu tượng khiên UAC) khi nhấp chuột phải vào tệp hoặc thư mục trong File Explorer (`HKEY_CLASSES_ROOT\*\shell\TakeOwnership` và `Directory\shell\TakeOwnership`).
   - Có thể gỡ bỏ sạch sẽ chỉ với một lần bấm.
5. **Truy cập nhanh công cụ quản trị**
   - Mở nhanh **PowerShell (Admin)** hoặc cửa sổ **Cài đặt UAC** (`UserAccountControlSettings.exe`).

## Yêu cầu hệ thống

- Windows 10 / Windows 11 (tích hợp sẵn Windows PowerShell 5.1+ và .NET WinForms).
- Tài khoản có quyền phê duyệt hộp thoại UAC (Administrator).

## Cách sử dụng

1. Tải hoặc clone repository về máy:
   ```powershell
   git clone https://github.com/jaxcater/Take_OwnerShip-Script.git
   ```
2. Mở thư mục dự án và nhấn đúp vào **`TakeOwnership_Admin.bat`**.
3. Chọn **Yes** khi Windows hiện hộp thoại **User Account Control (UAC)**.
4. Nhấn chọn chức năng bạn cần trên giao diện.

> **Lưu ý:** Bạn không cần mở trực tiếp tệp `TakeOwnership_Admin.ps1` — tệp `.bat` sẽ tự động xin quyền Administrator và khởi chạy giao diện `.ps1`.

## Cấu trúc tệp

| Tệp | Vai trò |
| --- | --- |
| `TakeOwnership_Admin.bat` | Trình khởi chạy chính, kiểm tra và yêu cầu nâng quyền UAC rồi chạy script PowerShell. |
| `TakeOwnership_Admin.ps1` | Script PowerShell tạo giao diện WinForms và thực thi các thao tác quản trị / Take Ownership. |
| `README.md` | Tài liệu hướng dẫn sử dụng. |

## Lưu ý an toàn

- Công cụ **không vượt mặt (bypass) UAC**: mọi tác vụ quản trị đều đi qua xác nhận UAC chính thức của Windows.
- Công cụ **chặn** thao tác Take Ownership trực tiếp lên ổ đĩa gốc (`C:\`, `D:\`, ...) và các thư mục gốc hệ thống (`C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`, `C:\Users`) nhằm tránh làm hỏng quyền mặc định của Windows Update / ứng dụng hệ thống.
- Với các đường dẫn con nằm trong `C:\Windows`, công cụ sẽ hiện hộp thoại cảnh báo xác nhận trước khi thực thi.
