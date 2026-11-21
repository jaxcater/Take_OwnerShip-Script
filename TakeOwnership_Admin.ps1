Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

# Ensure script is running as Administrator
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-STA',
        '-WindowStyle', 'Hidden',
        '-File', "`"$PSCommandPath`""
    )
    exit
}

# Helper: Resolve localized built-in Administrators group name via SID S-1-5-32-544
function Get-AdminsGroupName {
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        return $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    } catch {
        return 'Administrators'
    }
}

# Helper: Find built-in Administrator account (SID ending with -500)
function Get-BuiltInAdminAccount {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        return Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1
    }
    return $null
}

# Helper: Check if current user is in local Administrators group
function Test-UserInAdminsGroup {
    $currentUserName = [Environment]::UserName
    try {
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            $members = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop
            foreach ($m in $members) {
                if ($m.Name -eq $currentUserName -or $m.Name.EndsWith("\$currentUserName", [System.StringComparison]::OrdinalIgnoreCase)) {
                    return $true
                }
            }
            return $false
        }
        return $isAdmin
    } catch {
        return $isAdmin
    }
}

# Helper: Guard against dangerous system root paths
function Test-ProtectedRootPath {
    param([string]$Path)
    $normalized = $Path.TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($normalized)) { return $true }
    if ($normalized -match '^[A-Za-z]:$') { return $true }

    $protected = @(
        $env:SystemRoot,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        (Join-Path $env:SystemDrive 'Users')
    ) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }

    return $protected -contains $normalized
}

# Embedded helper script installed for Explorer right-click Take Ownership
$HelperScriptContent = @'
param([Parameter(Position = 0)][string]$Target)

Add-Type -AssemblyName System.Windows.Forms

if ([string]::IsNullOrWhiteSpace($Target)) {
    [System.Windows.Forms.MessageBox]::Show('Không có đường dẫn mục tiêu.', 'Take Ownership', 'OK', 'Warning') | Out-Null
    exit 1
}

$Target = $Target.Trim().Trim('"')
if (-not (Test-Path -LiteralPath $Target)) {
    [System.Windows.Forms.MessageBox]::Show("Không tìm thấy đường dẫn:`n$Target", 'Take Ownership', 'OK', 'Error') | Out-Null
    exit 1
}

# Self-elevate if needed
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-WindowStyle', 'Hidden',
        '-File', "`"$PSCommandPath`"",
        "`"$Target`""
    )
    exit
}

$normalized = $Target.TrimEnd('\')
$protected = @(
    $env:SystemRoot,
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)},
    $env:ProgramData,
    (Join-Path $env:SystemDrive 'Users')
) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }

if ($normalized -match '^[A-Za-z]:$' -or ($protected -contains $normalized)) {
    [System.Windows.Forms.MessageBox]::Show(
        "Đã chặn thao tác trên thư mục gốc hệ thống để tránh hỏng Windows:`n$Target",
        'Take Ownership - Cảnh báo an toàn',
        'OK',
        'Warning'
    ) | Out-Null
    exit 1
}

$sysRoot = $env:SystemRoot.TrimEnd('\')
if ($normalized.StartsWith("$sysRoot\", [System.StringComparison]::OrdinalIgnoreCase)) {
    $ans = [System.Windows.Forms.MessageBox]::Show(
        "Mục tiêu nằm trong thư mục Windows ($Target).`nThay đổi quyền sở hữu file hệ thống có thể ảnh hưởng đến Windows Update hoặc ứng dụng hệ thống.`n`nBạn có chắc chắn muốn tiếp tục?",
        'Xác nhận Take Ownership',
        'YesNo',
        'Warning'
    )
    if ($ans -ne 'Yes') { exit 0 }
}

$isContainer = Test-Path -LiteralPath $Target -PathType Container
if ($isContainer) {
    & takeown.exe /f "$Target" /a /r /d y | Out-Null
    $takeownCode = $LASTEXITCODE
    & icacls.exe "$Target" /grant "*S-1-5-32-544:F" /t /c /q | Out-Null
    $icaclsCode = $LASTEXITCODE
} else {
    & takeown.exe /f "$Target" /a | Out-Null
    $takeownCode = $LASTEXITCODE
    & icacls.exe "$Target" /grant "*S-1-5-32-544:F" /c /q | Out-Null
    $icaclsCode = $LASTEXITCODE
}

if ($takeownCode -eq 0 -and $icaclsCode -eq 0) {
    [System.Windows.Forms.MessageBox]::Show(
        "Đã cấp toàn quyền sở hữu (Take Ownership) cho:`n$Target",
        'Take Ownership',
        'OK',
        'Information'
    ) | Out-Null
} else {
    [System.Windows.Forms.MessageBox]::Show(
        "Thao tác hoàn tất với cảnh báo/lỗi (takeown=$takeownCode, icacls=$icaclsCode) trên:`n$Target",
        'Take Ownership',
        'OK',
        'Warning'
    ) | Out-Null
}
'@

$HelperDir     = Join-Path $env:ProgramData 'MAGIAO_TakeOwnership'
$HelperPath    = Join-Path $HelperDir 'TakeOwnHelper.ps1'
$RegSubKeys    = @(
    '*\shell\TakeOwnership',
    'Directory\shell\TakeOwnership'
)

function Test-ContextMenuInstalled {
    foreach ($subKey in $RegSubKeys) {
        $k = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($subKey, $false)
        if ($null -eq $k) { return $false }
        $k.Close()
    }
    return $true
}

# Build WinForms UI
$form = New-Object System.Windows.Forms.Form
$form.Text = 'TakeOwnership & Admin Control'
$form.Size = New-Object System.Drawing.Size(520, 520)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9.5)
$form.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)

$lblHeader = New-Object System.Windows.Forms.Label
$lblHeader.Text = 'Quản lý Quyền Admin & Take Ownership'
$lblHeader.Font = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
$lblHeader.ForeColor = [System.Drawing.Color]::FromArgb(24, 34, 52)
$lblHeader.Location = New-Object System.Drawing.Point(20, 15)
$lblHeader.AutoSize = $true
$form.Controls.Add($lblHeader)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(20, 48)
$lblStatus.Size = New-Object System.Drawing.Size(465, 48)
$lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(55, 65, 81)
$form.Controls.Add($lblStatus)

$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Multiline = $true
$logBox.ReadOnly = $true
$logBox.ScrollBars = 'Vertical'
$logBox.BackColor = [System.Drawing.Color]::White
$logBox.Font = New-Object System.Drawing.Font('Consolas', 9)
$logBox.Location = New-Object System.Drawing.Point(20, 340)
$logBox.Size = New-Object System.Drawing.Size(465, 125)
$form.Controls.Add($logBox)

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'HH:mm:ss'
    $logBox.AppendText("[$ts] $Message`r`n")
}

function New-ActionButton {
    param([int]$Y, [string]$Text, [System.Drawing.Color]$BackColor)
    $btn = New-Object System.Windows.Forms.Button
    $btn.Location = New-Object System.Drawing.Point(20, $Y)
    $btn.Size = New-Object System.Drawing.Size(465, 38)
    $btn.Text = $Text
    $btn.FlatStyle = 'Flat'
    $btn.FlatAppearance.BorderSize = 0
    $btn.BackColor = $BackColor
    $btn.ForeColor = [System.Drawing.Color]::White
    $btn.Font = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    return $btn
}

$btnGrantAdmin = New-ActionButton 105 '1. Cấp quyền Administrator cho tài khoản hiện tại' ([System.Drawing.Color]::FromArgb(37, 99, 235))
$btnToggleBuiltIn = New-ActionButton 150 '2. Bật / Tắt tài khoản Built-in Administrator' ([System.Drawing.Color]::FromArgb(79, 70, 229))
$btnTakeOwnFile = New-ActionButton 195 '3. Take Ownership (File hoặc Thư mục...)' ([System.Drawing.Color]::FromArgb(5, 150, 105))
$btnContextMenu = New-ActionButton 240 '4. Cài / Gỡ "Take Ownership" vào Menu Chuột Phải' ([System.Drawing.Color]::FromArgb(217, 119, 6))

$btnOpenAdminShell = New-Object System.Windows.Forms.Button
$btnOpenAdminShell.Location = New-Object System.Drawing.Point(20, 288)
$btnOpenAdminShell.Size = New-Object System.Drawing.Size(228, 36)
$btnOpenAdminShell.Text = 'Mở PowerShell (Admin)'
$btnOpenAdminShell.FlatStyle = 'Flat'
$btnOpenAdminShell.BackColor = [System.Drawing.Color]::FromArgb(55, 65, 81)
$btnOpenAdminShell.ForeColor = [System.Drawing.Color]::White
$btnOpenAdminShell.FlatAppearance.BorderSize = 0
$btnOpenAdminShell.Cursor = [System.Windows.Forms.Cursors]::Hand

$btnOpenUAC = New-Object System.Windows.Forms.Button
$btnOpenUAC.Location = New-Object System.Drawing.Point(257, 288)
$btnOpenUAC.Size = New-Object System.Drawing.Size(228, 36)
$btnOpenUAC.Text = 'Mở Cài đặt UAC'
$btnOpenUAC.FlatStyle = 'Flat'
$btnOpenUAC.BackColor = [System.Drawing.Color]::FromArgb(75, 85, 99)
$btnOpenUAC.ForeColor = [System.Drawing.Color]::White
$btnOpenUAC.FlatAppearance.BorderSize = 0
$btnOpenUAC.Cursor = [System.Windows.Forms.Cursors]::Hand

$form.Controls.AddRange(@($btnGrantAdmin, $btnToggleBuiltIn, $btnTakeOwnFile, $btnContextMenu, $btnOpenAdminShell, $btnOpenUAC))

function Update-UIState {
    $user = "$([Environment]::UserDomainName)\$([Environment]::UserName)"
    $inGroup = Test-UserInAdminsGroup
    $builtIn = Get-BuiltInAdminAccount
    $builtInState = if ($builtIn) { if ($builtIn.Enabled) { 'Đang BẬT' } else { 'Đang TẮT' } } else { 'Không rõ' }
    $ctxState = if (Test-ContextMenuInstalled) { 'Đã cài' } else { 'Chưa cài' }

    $lblStatus.Text = "User: $user | Nhóm Admin: $(if ($inGroup) { 'Có' } else { 'Không' })`r`nBuilt-in Administrator: $builtInState | Menu chuột phải: $ctxState"

    if ($builtIn -and $builtIn.Enabled) {
        $btnToggleBuiltIn.Text = '2. Tắt tài khoản Built-in Administrator (Đang BẬT)'
    } else {
        $btnToggleBuiltIn.Text = '2. Bật tài khoản Built-in Administrator (Đang TẮT)'
    }

    if (Test-ContextMenuInstalled) {
        $btnContextMenu.Text = '4. Gỡ "Take Ownership" khỏi Menu Chuột Phải'
        $btnContextMenu.BackColor = [System.Drawing.Color]::FromArgb(185, 28, 28)
    } else {
        $btnContextMenu.Text = '4. Cài "Take Ownership" vào Menu Chuột Phải'
        $btnContextMenu.BackColor = [System.Drawing.Color]::FromArgb(217, 119, 6)
    }
}

# Action 1: Grant current user Administrators group membership
$btnGrantAdmin.Add_Click({
    $adminsGroup = Get-AdminsGroupName
    $currentUser = [Environment]::UserName
    if (Test-UserInAdminsGroup) {
        Write-Log "Tài khoản '$currentUser' đã thuộc nhóm '$adminsGroup'."
        [System.Windows.Forms.MessageBox]::Show("Tài khoản '$currentUser' đã có quyền $adminsGroup.", 'Thông báo', 'OK', 'Information') | Out-Null
        return
    }
    try {
        $out = & net.exe localgroup "$adminsGroup" "$currentUser" /add 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Đã thêm '$currentUser' vào nhóm '$adminsGroup'."
            [System.Windows.Forms.MessageBox]::Show(
                "Đã thêm '$currentUser' vào nhóm '$adminsGroup'.`nHãy đăng xuất (Sign out) và đăng nhập lại để Windows áp dụng đầy đủ quyền.",
                'Thành công', 'OK', 'Information'
            ) | Out-Null
        } else {
            Write-Log "Lỗi thêm vào nhóm Admin: $out"
        }
    } catch {
        Write-Log "Lỗi: $($_.Exception.Message)"
    }
    Update-UIState
})

# Action 2: Toggle Built-in Administrator account
$btnToggleBuiltIn.Add_Click({
    $builtIn = Get-BuiltInAdminAccount
    if (-not $builtIn) {
        Write-Log 'Không tìm thấy tài khoản Built-in Administrator (SID -500).'
        return
    }
    try {
        if ($builtIn.Enabled) {
            Disable-LocalUser -Name $builtIn.Name
            Write-Log "Đã TẮT tài khoản Built-in Administrator ($($builtIn.Name))."
        } else {
            Enable-LocalUser -Name $builtIn.Name
            Write-Log "Đã BẬT tài khoản Built-in Administrator ($($builtIn.Name))."
        }
    } catch {
        Write-Log "Lỗi thay đổi trạng thái Built-in Administrator: $($_.Exception.Message)"
    }
    Update-UIState
})

# Action 3: Take Ownership of a specific File or Folder
$btnTakeOwnFile.Add_Click({
    $choice = [System.Windows.Forms.MessageBox]::Show(
        "Chọn YES để chọn THƯ MỤC (Folder).`nChọn NO để chọn TỆP TIN (File).",
        'Chọn loại đối tượng Take Ownership',
        'YesNoCancel',
        'Question'
    )
    if ($choice -eq 'Cancel') { return }

    $targetPath = $null
    $isFolder = ($choice -eq 'Yes')

    if ($isFolder) {
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Chọn thư mục muốn Take Ownership'
        if ($dlg.ShowDialog() -eq 'OK') { $targetPath = $dlg.SelectedPath }
    } else {
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Title = 'Chọn tệp tin muốn Take Ownership'
        if ($dlg.ShowDialog() -eq 'OK') { $targetPath = $dlg.FileName }
    }

    if (-not $targetPath) { return }

    if (Test-ProtectedRootPath $targetPath) {
        Write-Log "BỊ CHẶN: Không thể Take Ownership toàn bộ thư mục gốc hệ thống ($targetPath)."
        [System.Windows.Forms.MessageBox]::Show(
            "Không cho phép Take Ownership trực tiếp trên ổ đĩa gốc hoặc thư mục gốc hệ thống ($targetPath) vì sẽ làm hỏng Windows.",
            'Cảnh báo an toàn', 'OK', 'Warning'
        ) | Out-Null
        return
    }

    $sysRoot = $env:SystemRoot.TrimEnd('\')
    if ($targetPath.TrimEnd('\').StartsWith("$sysRoot\", [System.StringComparison]::OrdinalIgnoreCase)) {
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Đường dẫn nằm trong Windows ($targetPath).`nThay đổi quyền file hệ thống có thể ảnh hưởng Windows Update/Store.`nTiếp tục?",
            'Xác nhận', 'YesNo', 'Warning'
        )
        if ($confirm -ne 'Yes') { return }
    }

    Write-Log "Đang Take Ownership: $targetPath ..."
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        if ($isFolder) {
            & takeown.exe /f "$targetPath" /a /r /d y | Out-Null
            $tCode = $LASTEXITCODE
            & icacls.exe "$targetPath" /grant "*S-1-5-32-544:F" /t /c /q | Out-Null
            $iCode = $LASTEXITCODE
        } else {
            & takeown.exe /f "$targetPath" /a | Out-Null
            $tCode = $LASTEXITCODE
            & icacls.exe "$targetPath" /grant "*S-1-5-32-544:F" /c /q | Out-Null
            $iCode = $LASTEXITCODE
        }
        Write-Log "Hoàn tất Take Ownership (takeown=$tCode, icacls=$iCode): $targetPath"
    } catch {
        Write-Log "Lỗi Take Ownership: $($_.Exception.Message)"
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

# Action 4: Install / Uninstall Explorer Context Menu
$btnContextMenu.Add_Click({
    if (Test-ContextMenuInstalled) {
        try {
            foreach ($subKey in $RegSubKeys) {
                [Microsoft.Win32.Registry]::ClassesRoot.DeleteSubKeyTree($subKey, $false)
            }
            if (Test-Path -LiteralPath $HelperDir) { Remove-Item -LiteralPath $HelperDir -Recurse -Force }
            Write-Log 'Đã gỡ "Take Ownership" khỏi menu chuột phải.'
        } catch {
            Write-Log "Lỗi khi gỡ menu chuột phải: $($_.Exception.Message)"
        }
    } else {
        try {
            if (-not (Test-Path -LiteralPath $HelperDir)) {
                New-Item -Path $HelperDir -ItemType Directory -Force | Out-Null
            }
            $utf8Bom = New-Object System.Text.UTF8Encoding($true)
            [System.IO.File]::WriteAllText($HelperPath, $HelperScriptContent, $utf8Bom)

            $cmdValue = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$HelperPath`" `"%1`""
            foreach ($subKey in $RegSubKeys) {
                $k = [Microsoft.Win32.Registry]::ClassesRoot.CreateSubKey($subKey)
                $k.SetValue('', 'Take Ownership')
                $k.SetValue('HasLUAShield', '')
                $k.SetValue('NoWorkingDirectory', '')
                $cmdKey = $k.CreateSubKey('command')
                $cmdKey.SetValue('', $cmdValue)
                $cmdKey.SetValue('IsolatedCommand', $cmdValue)
                $cmdKey.Close()
                $k.Close()
            }
            Write-Log 'Đã cài "Take Ownership" vào menu chuột phải (File & Thư mục).'
        } catch {
            Write-Log "Lỗi khi cài menu chuột phải: $($_.Exception.Message)"
        }
    }
    Update-UIState
})

# Action 5: Open Admin PowerShell & UAC Settings
$btnOpenAdminShell.Add_Click({
    Start-Process -FilePath 'powershell.exe' -Verb RunAs
    Write-Log 'Đã mở cửa sổ PowerShell với quyền Administrator.'
})

$btnOpenUAC.Add_Click({
    Start-Process -FilePath 'UserAccountControlSettings.exe'
    Write-Log 'Đã mở Cài đặt User Account Control (UAC).'
})

Update-UIState
Write-Log 'Sẵn sàng. Đang chạy với quyền Administrator.'
[void]$form.ShowDialog()
