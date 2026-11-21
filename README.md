# TakeOwnership & Windows Server Control Suite

Bộ công cụ quản trị chuyên sâu cho **Windows Server** và **Windows 10/11** (Batch + PowerShell WinForms), giúp quản trị viên hệ thống kiểm soát toàn diện quyền sở hữu tệp/thư mục/ổ đĩa (`C:`, `D:`, ...), gỡ bỏ bloatware, tắt dịch vụ/telemetry không cần thiết và dọn dẹp hệ thống thông qua cơ chế **UAC hợp lệ** của Windows.

## Tính năng chính

### 1. Quyền Admin & Take Ownership (Ổ C:, D:, Thư mục, Tệp)
- **Thêm tài khoản hiện tại vào nhóm `Administrators`**: Tự phân giải tên nhóm theo SID `S-1-5-32-544` (tương thích mọi ngôn ngữ Windows).
- **Bật / Tắt tài khoản Built-in `Administrator`**: Bật hoặc tắt tài khoản quản trị mặc định (SID `-500`).
- **Take Ownership & Full Control**:
  - Hỗ trợ chọn nhanh **tất cả các ổ đĩa cục bộ** (`C:\`, `D:\`, ...), thư mục, tệp tin hoặc dán đường dẫn trực tiếp.
  - Tùy chọn đệ quy (`/r /t`), gỡ thuộc tính `Read-Only / Hidden / System` (`attrib -r -s -h`), hoặc reset ACL kế thừa (`icacls /reset`).
  - Có **Xóa cưỡng bức (Force Delete)** để gỡ bỏ tệp/thư mục bị khóa quyền.
- **Menu Chuột Phải File Explorer**: Cài/gỡ nhanh tùy chọn **Take Ownership** (kèm khiên UAC) cho **File (`*`)**, **Thư mục (`Directory`)** và **Ổ đĩa (`Drive`)**.
- **Mở nhanh công cụ quản trị**: PowerShell (Admin), CMD (Admin), `lusrmgr.msc`, Cài đặt UAC.

### 2. Gỡ Bloatware & Tính năng dư thừa
- **Quét & gỡ Appx + Provisioned Packages**: Lọc và gỡ bỏ hoàn toàn (`Remove-AppxPackage -AllUsers` và `Remove-AppxProvisionedPackage -Online`) các gói bloatware phổ biến (Xbox, Bing, Cortana, Solitaire, Feedback Hub, GetHelp, Clipchamp, Copilot, Teams...).
- **Quét & gỡ Windows Capabilities**: Liệt kê các thành phần cài sẵn (`Get-WindowsCapability -Online`) để gỡ tính năng không cần thiết trên Server.
- **Gỡ Microsoft OneDrive hoàn toàn**: Dừng tiến trình và chạy `OneDriveSetup.exe /uninstall`.

### 3. Services & Server Hardening
- **Quản lý Services phổ biến**: Kiểm tra trạng thái thực tế và chuyển nhanh sang `Disabled + Stop`, `Manual`, hoặc `Automatic + Start` đối với `DiagTrack`, `dmwappushservice`, `SysMain`, `MapsBroker`, `WerSvc`, `WSearch`, `Spooler`, `RemoteRegistry`, `RetailDemo`, `Fax`, nhóm dịch vụ Xbox, `wisvc`.
- **Chính sách Server / Privacy (HKLM Policies)**: Áp dụng hoặc khôi phục các policy tắt Telemetry (`AllowTelemetry=0`), Consumer Features, Advertising ID, Cortana, Bing Web Search và Widgets.
- **Scheduled Tasks Telemetry**: Tắt các tác vụ nền thu thập dữ liệu (`Compatibility Appraiser`, `CEIP`, `Feedback\Siuf`, `Autochk\Proxy`).

### 4. Dọn dẹp Ổ C: / D: & Công cụ Server
- Dọn `C:\Windows\Temp`, `%TEMP%`, `Prefetch`, cache Windows Update (`SoftwareDistribution\Download`), Thùng rác tất cả ổ đĩa và dọn WinSxS (`DISM /StartComponentCleanup`).
- Mở nhanh `services.msc`, `diskmgmt.msc`, `eventvwr.msc`, `compmgmt.msc`, `gpedit.msc`, `secpol.msc`, `taskschd.msc`, `resmon.exe`.
- Nhật ký thao tác chi tiết kèm nút **Xuất Log (`.txt`)**.

## Yêu cầu hệ thống

- Windows Server 2016 / 2019 / 2022 / 2025 hoặc Windows 10 / 11.
- Windows PowerShell 5.1+ (tích hợp sẵn) và quyền Administrator (UAC).

## Cách sử dụng

1. Clone hoặc tải repository:
   ```powershell
   git clone https://github.com/jaxcater/Take_OwnerShip-Script.git
   ```
2. Nhấn đúp vào **`TakeOwnership_Admin.bat`**.
3. Chọn **Yes** ở hộp thoại **User Account Control (UAC)**.
4. Sử dụng 4 tab chức năng tùy theo nhu cầu quản trị Server / gỡ bloatware.

## Lưu ý an toàn

- Công cụ **không vượt mặt (bypass) UAC**; mọi thao tác quản trị đều đi qua xác nhận UAC chính thức của Windows.
- Đối với **ổ đĩa dữ liệu (`D:\`, `E:\`, ...)** và thư mục con: cho phép Take Ownership trực tiếp sau hộp thoại xác nhận nhanh.
- Đối với **gốc hệ điều hành (`C:\`, `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`, `C:\Users`)**: yêu cầu gõ chính xác `CONFIRM` (và chặn Force Delete trên các thư mục gốc này) để tránh tai nạn làm hỏng Windows Server.
