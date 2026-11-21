Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic

[System.Windows.Forms.Application]::EnableVisualStyles()

# Ensure script is running as Administrator via official Windows UAC
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

#region Core Helpers

function Get-AdminsGroupName {
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        return $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    } catch {
        return 'Administrators'
    }
}

function Get-BuiltInAdminAccount {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        return Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1
    }
    return $null
}

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

function Get-OSInfoSummary {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        return "$($os.Caption) (Build $($os.BuildNumber))"
    } catch {
        return [Environment]::OSVersion.VersionString
    }
}

function Test-IsSystemDriveRoot {
    param([string]$Path)
    $norm = $Path.Trim().TrimEnd('\')
    $sysDrive = $env:SystemDrive.TrimEnd('\')
    return ($norm -ieq $sysDrive)
}

function Test-IsCriticalOSFolder {
    param([string]$Path)
    $norm = $Path.Trim().TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($norm)) { return $false }

    $critical = @(
        $env:SystemDrive,
        $env:SystemRoot,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        (Join-Path $env:SystemDrive 'Users')
    ) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }

    return ($critical -contains $norm)
}

function Test-IsUnderWindowsFolder {
    param([string]$Path)
    $norm = $Path.Trim().TrimEnd('\')
    $sysRoot = $env:SystemRoot.TrimEnd('\')
    return $norm.StartsWith("$sysRoot\", [System.StringComparison]::OrdinalIgnoreCase)
}

function Confirm-CriticalTarget {
    param([string]$Path, [string]$ActionName)

    if (Test-IsCriticalOSFolder $Path) {
        $typed = [Microsoft.VisualBasic.Interaction]::InputBox(
            "CẢNH BÁO CẤP SERVER!`n`nBạn đang yêu cầu [$ActionName] trực tiếp trên thư mục gốc hệ điều hành:`n$Path`n`nThao tác đệ quy trên đường dẫn này có thể ảnh hưởng nghiêm trọng tới Windows / Boot / Windows Update.`nNếu bạn hiểu rõ rủi ro và muốn tiếp tục, hãy gõ chính xác: CONFIRM",
            'Xác nhận thao tác hệ thống',
            ''
        )
        return ($typed -ceq 'CONFIRM')
    }

    if (Test-IsUnderWindowsFolder $Path) {
        $ans = [System.Windows.Forms.MessageBox]::Show(
            "Đường dẫn nằm trong thư mục Windows:`n$Path`n`nBạn có chắc chắn muốn thực hiện [$ActionName]?",
            'Xác nhận thao tác trong Windows',
            'YesNo',
            'Warning'
        )
        return ($ans -eq 'Yes')
    }

    if ($Path.Trim().TrimEnd('\') -match '^[A-Za-z]:$') {
        $ans = [System.Windows.Forms.MessageBox]::Show(
            "Bạn sắp thực hiện [$ActionName] cho toàn bộ ổ đĩa:`n$Path`n`nTiếp tục?",
            'Xác nhận thao tác ổ đĩa',
            'YesNo',
            'Question'
        )
        return ($ans -eq 'Yes')
    }

    return $true
}

function Invoke-TakeOwnership {
    param(
        [string]$TargetPath,
        [bool]$Recursive = $true,
        [bool]$ClearAttributes = $false,
        [bool]$ResetAcl = $false
    )

    $isContainer = Test-Path -LiteralPath $TargetPath -PathType Container
    $tCode = 0
    $iCode = 0

    if ($isContainer) {
        if ($Recursive) {
            & takeown.exe /f "$TargetPath" /a /r /d y | Out-Null
            $tCode = $LASTEXITCODE
            if ($ResetAcl) {
                & icacls.exe "$TargetPath" /reset /t /c /q | Out-Null
            }
            & icacls.exe "$TargetPath" /grant "*S-1-5-32-544:F" /t /c /q | Out-Null
            $iCode = $LASTEXITCODE
            if ($ClearAttributes) {
                & attrib.exe -r -s -h "$TargetPath\*" /s /d 2>$null | Out-Null
            }
        } else {
            & takeown.exe /f "$TargetPath" /a | Out-Null
            $tCode = $LASTEXITCODE
            if ($ResetAcl) {
                & icacls.exe "$TargetPath" /reset /c /q | Out-Null
            }
            & icacls.exe "$TargetPath" /grant "*S-1-5-32-544:F" /c /q | Out-Null
            $iCode = $LASTEXITCODE
            if ($ClearAttributes) {
                & attrib.exe -r -s -h "$TargetPath" 2>$null | Out-Null
            }
        }
    } else {
        & takeown.exe /f "$TargetPath" /a | Out-Null
        $tCode = $LASTEXITCODE
        if ($ResetAcl) {
            & icacls.exe "$TargetPath" /reset /c /q | Out-Null
        }
        & icacls.exe "$TargetPath" /grant "*S-1-5-32-544:F" /c /q | Out-Null
        $iCode = $LASTEXITCODE
        if ($ClearAttributes) {
            & attrib.exe -r -s -h "$TargetPath" 2>$null | Out-Null
        }
    }

    return @{ TakeownCode = $tCode; IcaclsCode = $iCode }
}

#endregion

#region Context Menu Helper Script (Embedded)

$HelperScriptContent = @'
param([Parameter(Position = 0)][string]$Target)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic

if ([string]::IsNullOrWhiteSpace($Target)) {
    [System.Windows.Forms.MessageBox]::Show('Không có đường dẫn mục tiêu.', 'Take Ownership', 'OK', 'Warning') | Out-Null
    exit 1
}

$Target = $Target.Trim().Trim('"')
try {
    if ($Target -match '^[A-Za-z]:\.$') {
        $Target = [System.IO.Path]::GetFullPath($Target)
    }
} catch {}

if (-not (Test-Path -LiteralPath $Target)) {
    [System.Windows.Forms.MessageBox]::Show("Không tìm thấy đường dẫn:`n$Target", 'Take Ownership', 'OK', 'Error') | Out-Null
    exit 1
}

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argTarget = if ($Target -match '^[A-Za-z]:\\$') { "$($Target)." } else { $Target }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-WindowStyle', 'Hidden',
        '-File', "`"$PSCommandPath`"",
        "`"$argTarget`""
    )
    exit
}

$norm = $Target.TrimEnd('\')
$critical = @(
    $env:SystemDrive,
    $env:SystemRoot,
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)},
    $env:ProgramData,
    (Join-Path $env:SystemDrive 'Users')
) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }

if ($critical -contains $norm) {
    $typed = [Microsoft.VisualBasic.Interaction]::InputBox(
        "CẢNH BÁO HỆ THỐNG!`nĐường dẫn là thư mục gốc OS: $Target`nThao tác đệ quy có thể làm hỏng quyền hệ thống.`nGõ CONFIRM để tiếp tục:",
        'Take Ownership - Xác nhận nâng cao',
        ''
    )
    if ($typed -cne 'CONFIRM') { exit 0 }
} elseif ($norm.StartsWith("$($env:SystemRoot.TrimEnd('\'))\", [System.StringComparison]::OrdinalIgnoreCase)) {
    $ans = [System.Windows.Forms.MessageBox]::Show(
        "Mục tiêu nằm trong thư mục Windows:`n$Target`n`nTiếp tục Take Ownership?",
        'Xác nhận Take Ownership',
        'YesNo',
        'Warning'
    )
    if ($ans -ne 'Yes') { exit 0 }
} elseif ($norm -match '^[A-Za-z]:$') {
    $ans = [System.Windows.Forms.MessageBox]::Show(
        "Take Ownership toàn bộ ổ đĩa $Target ?",
        'Xác nhận Take Ownership Ổ đĩa',
        'YesNo',
        'Question'
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
        "Hoàn tất với cảnh báo/lỗi (takeown=$takeownCode, icacls=$icaclsCode) trên:`n$Target",
        'Take Ownership',
        'OK',
        'Warning'
    ) | Out-Null
}
'@

$HelperDir  = Join-Path $env:ProgramData 'MAGIAO_TakeOwnership'
$HelperPath = Join-Path $HelperDir 'TakeOwnHelper.ps1'
$RegSubKeys = @(
    '*\shell\TakeOwnership',
    'Directory\shell\TakeOwnership',
    'Drive\shell\TakeOwnership'
)

function Test-ContextMenuInstalled {
    foreach ($subKey in $RegSubKeys) {
        $k = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($subKey, $false)
        if ($null -eq $k) { return $false }
        $k.Close()
    }
    return $true
}

#endregion

#region Data Tables for Bloatware, Services, Policies, Telemetry

$KnownBloatwarePatterns = @(
    'Microsoft.3DBuilder',
    'Microsoft.549981C3F5F10', # Cortana
    'Microsoft.BingFinance',
    'Microsoft.BingNews',
    'Microsoft.BingSports',
    'Microsoft.BingWeather',
    'Microsoft.BingSearch',
    'Clipchamp.Clipchamp',
    'Microsoft.Copilot',
    'Microsoft.GetHelp',
    'Microsoft.Getstarted',
    'Microsoft.Messaging',
    'Microsoft.Microsoft3DViewer',
    'Microsoft.MicrosoftOfficeHub',
    'Microsoft.MicrosoftSolitaireCollection',
    'Microsoft.MixedReality.Portal',
    'Microsoft.News',
    'Microsoft.Office.OneNote',
    'Microsoft.OneConnect',
    'Microsoft.People',
    'Microsoft.PowerAutomateDesktop',
    'Microsoft.Print3D',
    'Microsoft.SkypeApp',
    'Microsoft.Todos',
    'Microsoft.Wallet',
    'Microsoft.WindowsAlarms',
    'Microsoft.WindowsFeedbackHub',
    'Microsoft.WindowsMaps',
    'Microsoft.WindowsSoundRecorder',
    'Microsoft.XboxApp',
    'Microsoft.XboxGameOverlay',
    'Microsoft.XboxGamingOverlay',
    'Microsoft.XboxIdentityProvider',
    'Microsoft.XboxSpeechToTextOverlay',
    'Microsoft.Xbox.TCUI',
    'Microsoft.GamingApp',
    'Microsoft.YourPhone',
    'Microsoft.ZuneMusic',
    'Microsoft.ZuneVideo',
    'MicrosoftCorporationII.QuickAssist',
    'MSTeams',
    'Microsoft.Teams'
)

$ManagedServiceSpecs = @(
    @{ Name = 'DiagTrack';        Label = 'Connected User Experiences & Telemetry (DiagTrack)' },
    @{ Name = 'dmwappushservice'; Label = 'WAP Push Message Routing Service' },
    @{ Name = 'SysMain';          Label = 'SysMain (Superfetch)' },
    @{ Name = 'MapsBroker';       Label = 'Downloaded Maps Manager' },
    @{ Name = 'WerSvc';           Label = 'Windows Error Reporting Service' },
    @{ Name = 'WSearch';          Label = 'Windows Search Indexer' },
    @{ Name = 'Spooler';          Label = 'Print Spooler (Server hardening)' },
    @{ Name = 'RemoteRegistry';   Label = 'Remote Registry (Server hardening)' },
    @{ Name = 'RetailDemo';       Label = 'Retail Demo Service' },
    @{ Name = 'Fax';              Label = 'Fax Service' },
    @{ Name = 'XblAuthManager';   Label = 'Xbox Live Auth Manager' },
    @{ Name = 'XblGameSave';      Label = 'Xbox Live Game Save' },
    @{ Name = 'XboxGipSvc';       Label = 'Xbox Accessory Management' },
    @{ Name = 'XboxNetApiSvc';    Label = 'Xbox Live Networking Service' },
    @{ Name = 'wisvc';            Label = 'Windows Insider Service' }
)

$TelemetryTasks = @(
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
    '\Microsoft\Windows\Application Experience\StartupAppTask',
    '\Microsoft\Windows\Autochk\Proxy',
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
    '\Microsoft\Windows\Feedback\Siuf\DmClient',
    '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload'
)

$HardeningPolicies = @(
    @{
        Name = 'Disable Telemetry (AllowTelemetry = 0)'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        Prop = 'AllowTelemetry'
        Type = 'DWord'
        Val  = 0
    },
    @{
        Name = 'Disable Consumer Features / Suggested Apps'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Prop = 'DisableWindowsConsumerFeatures'
        Type = 'DWord'
        Val  = 1
    },
    @{
        Name = 'Disable Advertising ID'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
        Prop = 'DisabledByGroupPolicy'
        Type = 'DWord'
        Val  = 1
    },
    @{
        Name = 'Disable Cortana'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Prop = 'AllowCortana'
        Type = 'DWord'
        Val  = 0
    },
    @{
        Name = 'Disable Bing Web Search in Start'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Prop = 'DisableSearchBoxSuggestions'
        Type = 'DWord'
        Val  = 1
    },
    @{
        Name = 'Disable News and Interests / Widgets'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'
        Prop = 'AllowNewsAndInterests'
        Type = 'DWord'
        Val  = 0
    }
)

#endregion

#region Build WinForms Suite

$form = New-Object System.Windows.Forms.Form
$form.Text = 'TakeOwnership & Windows Server Control Suite'
$form.Size = New-Object System.Drawing.Size(760, 650)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9.5)
$form.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)

# Header Banner
$pnlTop = New-Object System.Windows.Forms.Panel
$pnlTop.Location = New-Object System.Drawing.Point(0, 0)
$pnlTop.Size = New-Object System.Drawing.Size(760, 74)
$pnlTop.BackColor = [System.Drawing.Color]::FromArgb(20, 30, 48)
$form.Controls.Add($pnlTop)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = 'TakeOwnership & Windows Server Control Suite'
$lblTitle.Font = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = [System.Drawing.Color]::White
$lblTitle.Location = New-Object System.Drawing.Point(16, 10)
$lblTitle.AutoSize = $true
$pnlTop.Controls.Add($lblTitle)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(16, 36)
$lblStatus.Size = New-Object System.Drawing.Size(720, 34)
$lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(203, 213, 225)
$lblStatus.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)
$pnlTop.Controls.Add($lblStatus)

# TabControl
$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Location = New-Object System.Drawing.Point(12, 82)
$tabs.Size = New-Object System.Drawing.Size(720, 390)
$form.Controls.Add($tabs)

$tabAcl      = New-Object System.Windows.Forms.TabPage('1. Quyền & Take Ownership (C: / D:)')
$tabBloat    = New-Object System.Windows.Forms.TabPage('2. Gỡ Bloatware & Tính năng')
$tabServices = New-Object System.Windows.Forms.TabPage('3. Services & Server Hardening')
$tabCleanup  = New-Object System.Windows.Forms.TabPage('4. Dọn dẹp Ổ C/D & Công cụ')
foreach ($tp in @($tabAcl, $tabBloat, $tabServices, $tabCleanup)) {
    $tp.BackColor = [System.Drawing.Color]::FromArgb(248, 250, 252)
    $tabs.TabPages.Add($tp)
}

# Shared Log Box at bottom
$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Multiline = $true
$logBox.ReadOnly = $true
$logBox.ScrollBars = 'Vertical'
$logBox.BackColor = [System.Drawing.Color]::FromArgb(15, 23, 42)
$logBox.ForeColor = [System.Drawing.Color]::FromArgb(226, 232, 240)
$logBox.Font = New-Object System.Drawing.Font('Consolas', 8.5)
$logBox.Location = New-Object System.Drawing.Point(12, 478)
$logBox.Size = New-Object System.Drawing.Size(610, 122)
$form.Controls.Add($logBox)

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'HH:mm:ss'
    $logBox.AppendText("[$ts] $Message`r`n")
}

function New-StyledButton {
    param([int]$X, [int]$Y, [int]$W, [int]$H, [string]$Text, [System.Drawing.Color]$Bg)
    $b = New-Object System.Windows.Forms.Button
    $b.Location = New-Object System.Drawing.Point($X, $Y)
    $b.Size = New-Object System.Drawing.Size($W, $H)
    $b.Text = $Text
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $Bg
    $b.ForeColor = [System.Drawing.Color]::White
    $b.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $b.Cursor = [System.Windows.Forms.Cursors]::Hand
    return $b
}

$btnExportLog = New-StyledButton 630 478 102 58 'Xuất Log' ([System.Drawing.Color]::FromArgb(51, 65, 85))
$btnClearLog  = New-StyledButton 630 542 102 58 'Xóa Log'  ([System.Drawing.Color]::FromArgb(100, 116, 139))
$form.Controls.AddRange(@($btnExportLog, $btnClearLog))

#region Tab 1: ACL & Take Ownership

$btnGrantAdmin    = New-StyledButton 16 14 332 36 'Thêm User hiện tại vào Administrators' ([System.Drawing.Color]::FromArgb(37, 99, 235))
$btnToggleBuiltIn = New-StyledButton 360 14 336 36 'Bật / Tắt Built-in Administrator' ([System.Drawing.Color]::FromArgb(79, 70, 229))
$btnContextMenu   = New-StyledButton 16 58 680 34 'Cài / Gỡ "Take Ownership" Menu Chuột Phải (File, Folder, Drive)' ([System.Drawing.Color]::FromArgb(217, 119, 6))
$tabAcl.Controls.AddRange(@($btnGrantAdmin, $btnToggleBuiltIn, $btnContextMenu))

$grpTarget = New-Object System.Windows.Forms.GroupBox
$grpTarget.Text = 'Chiếm quyền sở hữu & Kiểm soát tệp/thư mục/ổ đĩa (C:, D:, ...)'
$grpTarget.Location = New-Object System.Drawing.Point(16, 102)
$grpTarget.Size = New-Object System.Drawing.Size(680, 198)
$tabAcl.Controls.Add($grpTarget)

$lblDrive = New-Object System.Windows.Forms.Label
$lblDrive.Text = 'Chọn nhanh ổ đĩa:'
$lblDrive.Location = New-Object System.Drawing.Point(14, 28)
$lblDrive.AutoSize = $true
$grpTarget.Controls.Add($lblDrive)

$cmbDrives = New-Object System.Windows.Forms.ComboBox
$cmbDrives.DropDownStyle = 'DropDownList'
$cmbDrives.Location = New-Object System.Drawing.Point(130, 24)
$cmbDrives.Size = New-Object System.Drawing.Size(260, 24)
$grpTarget.Controls.Add($cmbDrives)

$btnUseDrive    = New-StyledButton 398 23 115 26 'Nạp ổ này' ([System.Drawing.Color]::FromArgb(15, 118, 110))
$btnPickFolder  = New-StyledButton 518 23 76 26 'Thư mục' ([System.Drawing.Color]::FromArgb(51, 65, 85))
$btnPickFile    = New-StyledButton 598 23 68 26 'Tệp...' ([System.Drawing.Color]::FromArgb(71, 85, 105))
$grpTarget.Controls.AddRange(@($btnUseDrive, $btnPickFolder, $btnPickFile))

$lblPath = New-Object System.Windows.Forms.Label
$lblPath.Text = 'Đường dẫn:'
$lblPath.Location = New-Object System.Drawing.Point(14, 64)
$lblPath.AutoSize = $true
$grpTarget.Controls.Add($lblPath)

$txtTargetPath = New-Object System.Windows.Forms.TextBox
$txtTargetPath.Location = New-Object System.Drawing.Point(130, 61)
$txtTargetPath.Size = New-Object System.Drawing.Size(536, 24)
$grpTarget.Controls.Add($txtTargetPath)

$chkRecursive = New-Object System.Windows.Forms.CheckBox
$chkRecursive.Text = 'Đệ quy toàn bộ thư mục con (/r /t)'
$chkRecursive.Checked = $true
$chkRecursive.Location = New-Object System.Drawing.Point(16, 98)
$chkRecursive.AutoSize = $true

$chkClearAttr = New-Object System.Windows.Forms.CheckBox
$chkClearAttr.Text = 'Gỡ thuộc tính Read-Only / Hidden / System (attrib -r -s -h)'
$chkClearAttr.Checked = $true
$chkClearAttr.Location = New-Object System.Drawing.Point(270, 98)
$chkClearAttr.AutoSize = $true

$chkResetAcl = New-Object System.Windows.Forms.CheckBox
$chkResetAcl.Text = 'Reset ACL kế thừa trước khi cấp quyền (icacls /reset)'
$chkResetAcl.Checked = $false
$chkResetAcl.Location = New-Object System.Drawing.Point(16, 122)
$chkResetAcl.AutoSize = $true

$grpTarget.Controls.AddRange(@($chkRecursive, $chkClearAttr, $chkResetAcl))

$btnRunTakeOwn = New-StyledButton 16 150 322 36 'TAKE OWNERSHIP + FULL CONTROL' ([System.Drawing.Color]::FromArgb(5, 150, 105))
$btnForceDel   = New-StyledButton 348 150 318 36 'XÓA CƯỠNG BỨC (Force Delete)' ([System.Drawing.Color]::FromArgb(185, 28, 28))
$grpTarget.Controls.AddRange(@($btnRunTakeOwn, $btnForceDel))

# Quick Admin Shells row
$btnAdminPS    = New-StyledButton 16 312 164 36 'PowerShell (Admin)' ([System.Drawing.Color]::FromArgb(30, 41, 59))
$btnAdminCMD   = New-StyledButton 188 312 164 36 'CMD (Admin)' ([System.Drawing.Color]::FromArgb(51, 65, 85))
$btnLusrmgr    = New-StyledButton 360 312 164 36 'Users & Groups' ([System.Drawing.Color]::FromArgb(71, 85, 105))
$btnUAC        = New-StyledButton 532 312 164 36 'Cài đặt UAC' ([System.Drawing.Color]::FromArgb(100, 116, 139))
$tabAcl.Controls.AddRange(@($btnAdminPS, $btnAdminCMD, $btnLusrmgr, $btnUAC))

#endregion

#region Tab 2: Bloatware & Optional Features

$lblBloatSearch = New-Object System.Windows.Forms.Label
$lblBloatSearch.Text = 'Lọc tên:'
$lblBloatSearch.Location = New-Object System.Drawing.Point(14, 16)
$lblBloatSearch.AutoSize = $true

$txtBloatFilter = New-Object System.Windows.Forms.TextBox
$txtBloatFilter.Location = New-Object System.Drawing.Point(68, 13)
$txtBloatFilter.Size = New-Object System.Drawing.Size(170, 24)

$btnScanAppx     = New-StyledButton 246 11 120 28 'Quét Appx' ([System.Drawing.Color]::FromArgb(37, 99, 235))
$btnSelectBloat  = New-StyledButton 372 11 154 28 'Chọn Bloatware' ([System.Drawing.Color]::FromArgb(217, 119, 6))
$btnRemoveAppx   = New-StyledButton 532 11 168 28 'Gỡ Appx đã chọn' ([System.Drawing.Color]::FromArgb(185, 28, 28))

$chkAppxList = New-Object System.Windows.Forms.CheckedListBox
$chkAppxList.Location = New-Object System.Drawing.Point(14, 46)
$chkAppxList.Size = New-Object System.Drawing.Size(686, 244)
$chkAppxList.CheckOnClick = $true

$btnScanCap     = New-StyledButton 14 300 170 40 'Quét Capabilities' ([System.Drawing.Color]::FromArgb(15, 118, 110))
$btnRemoveCap   = New-StyledButton 192 300 175 40 'Gỡ Capabilities chọn' ([System.Drawing.Color]::FromArgb(190, 18, 60))
$btnUninstOneDrive = New-StyledButton 375 300 175 40 'Gỡ OneDrive hoàn toàn' ([System.Drawing.Color]::FromArgb(124, 45, 18))
$btnClearSel    = New-StyledButton 558 300 142 40 'Bỏ chọn tất cả' ([System.Drawing.Color]::FromArgb(71, 85, 105))

$tabBloat.Controls.AddRange(@(
    $lblBloatSearch, $txtBloatFilter, $btnScanAppx, $btnSelectBloat, $btnRemoveAppx,
    $chkAppxList, $btnScanCap, $btnRemoveCap, $btnUninstOneDrive, $btnClearSel
))

$script:LoadedBloatMode = 'Appx' # 'Appx' or 'Capability'
$script:AppxCache = @()
$script:CapCache  = @()

#endregion

#region Tab 3: Services & Server Hardening

$btnScanServices    = New-StyledButton 14 12 130 30 'Làm mới' ([System.Drawing.Color]::FromArgb(37, 99, 235))
$btnSelectAllSvc    = New-StyledButton 150 12 120 30 'Chọn tất cả' ([System.Drawing.Color]::FromArgb(71, 85, 105))
$btnDisableServices = New-StyledButton 276 12 140 30 'Stop & Disable' ([System.Drawing.Color]::FromArgb(185, 28, 28))
$btnManualServices  = New-StyledButton 422 12 134 30 'Đặt Manual' ([System.Drawing.Color]::FromArgb(217, 119, 6))
$btnAutoServices    = New-StyledButton 562 12 138 30 'Auto & Start' ([System.Drawing.Color]::FromArgb(5, 150, 105))

$chkSvcList = New-Object System.Windows.Forms.CheckedListBox
$chkSvcList.Location = New-Object System.Drawing.Point(14, 48)
$chkSvcList.Size = New-Object System.Drawing.Size(686, 178)
$chkSvcList.CheckOnClick = $true

$grpHardening = New-Object System.Windows.Forms.GroupBox
$grpHardening.Text = 'Server Telemetry, Consumer Features & Privacy Policies'
$grpHardening.Location = New-Object System.Drawing.Point(14, 232)
$grpHardening.Size = New-Object System.Drawing.Size(686, 120)

$btnApplyHardening = New-StyledButton 14 26 210 38 'Áp dụng Policy Chặn Bloat/Telemetry' ([System.Drawing.Color]::FromArgb(15, 118, 110))
$btnDisableTasks   = New-StyledButton 234 26 216 38 'Tắt Scheduled Tasks Telemetry' ([System.Drawing.Color]::FromArgb(180, 83, 9))
$btnRevertPolicy   = New-StyledButton 460 26 212 38 'Khôi phục Policy Mặc định' ([System.Drawing.Color]::FromArgb(71, 85, 105))

$lblPolicyHint = New-Object System.Windows.Forms.Label
$lblPolicyHint.Text = 'Bao gồm: AllowTelemetry=0, DisableWindowsConsumerFeatures=1, AdvertisingInfo=1, AllowCortana=0, DisableSearchBoxSuggestions=1, AllowNewsAndInterests=0.'
$lblPolicyHint.Location = New-Object System.Drawing.Point(14, 72)
$lblPolicyHint.Size = New-Object System.Drawing.Size(658, 38)
$lblPolicyHint.ForeColor = [System.Drawing.Color]::FromArgb(71, 85, 105)

$grpHardening.Controls.AddRange(@($btnApplyHardening, $btnDisableTasks, $btnRevertPolicy, $lblPolicyHint))
$tabServices.Controls.AddRange(@($btnScanServices, $btnSelectAllSvc, $btnDisableServices, $btnManualServices, $btnAutoServices, $chkSvcList, $grpHardening))

#endregion

#region Tab 4: Disk Cleanup & Server Tools

$grpClean = New-Object System.Windows.Forms.GroupBox
$grpClean.Text = 'Dọn dẹp sâu ổ C: / D: & Bộ nhớ đệm hệ thống'
$grpClean.Location = New-Object System.Drawing.Point(16, 14)
$grpClean.Size = New-Object System.Drawing.Size(680, 178)
$tabCleanup.Controls.Add($grpClean)

$chkCleanTemp     = New-Object System.Windows.Forms.CheckBox
$chkCleanTemp.Text = 'Dọn C:\Windows\Temp, %TEMP%, Prefetch'
$chkCleanTemp.Checked = $true
$chkCleanTemp.Location = New-Object System.Drawing.Point(16, 28)
$chkCleanTemp.AutoSize = $true

$chkCleanWU       = New-Object System.Windows.Forms.CheckBox
$chkCleanWU.Text = 'Dọn cache Windows Update (SoftwareDistribution\Download)'
$chkCleanWU.Checked = $true
$chkCleanWU.Location = New-Object System.Drawing.Point(16, 54)
$chkCleanWU.AutoSize = $true

$chkCleanRecycle  = New-Object System.Windows.Forms.CheckBox
$chkCleanRecycle.Text = 'Dọn sạch Thùng rác (Recycle Bin) tất cả ổ đĩa (C:, D:, ...)'
$chkCleanRecycle.Checked = $true
$chkCleanRecycle.Location = New-Object System.Drawing.Point(16, 80)
$chkCleanRecycle.AutoSize = $true

$chkCleanWinSxS   = New-Object System.Windows.Forms.CheckBox
$chkCleanWinSxS.Text = 'Dọn Component Store bằng DISM (/StartComponentCleanup - có thể mất vài phút)'
$chkCleanWinSxS.Checked = $false
$chkCleanWinSxS.Location = New-Object System.Drawing.Point(16, 106)
$chkCleanWinSxS.AutoSize = $true

$btnRunCleanup = New-StyledButton 16 134 320 34 'CHẠY DỌN DẸP NGAY' ([System.Drawing.Color]::FromArgb(5, 150, 105))
$btnDiskCleanMgr = New-StyledButton 348 134 316 34 'Mở Disk Cleanup (cleanmgr.exe)' ([System.Drawing.Color]::FromArgb(37, 99, 235))
$grpClean.Controls.AddRange(@($chkCleanTemp, $chkCleanWU, $chkCleanRecycle, $chkCleanWinSxS, $btnRunCleanup, $btnDiskCleanMgr))

$grpServerTools = New-Object System.Windows.Forms.GroupBox
$grpServerTools.Text = 'Công cụ quản trị Windows Server nhanh'
$grpServerTools.Location = New-Object System.Drawing.Point(16, 202)
$grpServerTools.Size = New-Object System.Drawing.Size(680, 146)
$tabCleanup.Controls.Add($grpServerTools)

$ServerTools = @(
    @{ Label = 'Services (services.msc)';      Cmd = 'services.msc';   X = 16;  Y = 28 },
    @{ Label = 'Disk Mgmt (diskmgmt.msc)';     Cmd = 'diskmgmt.msc';   X = 180; Y = 28 },
    @{ Label = 'Event Viewer (eventvwr.msc)';  Cmd = 'eventvwr.msc';   X = 344; Y = 28 },
    @{ Label = 'Computer Mgmt (compmgmt.msc)'; Cmd = 'compmgmt.msc';   X = 508; Y = 28 },
    @{ Label = 'Group Policy (gpedit.msc)';    Cmd = 'gpedit.msc';     X = 16;  Y = 78 },
    @{ Label = 'Security Policy (secpol.msc)'; Cmd = 'secpol.msc';     X = 180; Y = 78 },
    @{ Label = 'Task Scheduler (taskschd)';    Cmd = 'taskschd.msc';   X = 344; Y = 78 },
    @{ Label = 'Resource Monitor (resmon)';    Cmd = 'resmon.exe';     X = 508; Y = 78 }
)
foreach ($tool in $ServerTools) {
    $tb = New-StyledButton $tool.X $tool.Y 156 38 $tool.Label ([System.Drawing.Color]::FromArgb(51, 65, 85))
    $cmdName = $tool.Cmd
    $tb.Tag = $cmdName
    $tb.Add_Click({
        param($s, $e)
        try {
            Start-Process -FilePath $s.Tag
            Write-Log "Đã mở $($s.Tag)"
        } catch {
            Write-Log "Không thể mở $($s.Tag): $($_.Exception.Message)"
        }
    })
    $grpServerTools.Controls.Add($tb)
}

#endregion

#region State & Event Handlers

$script:OSBanner = Get-OSInfoSummary

function Refresh-DrivesList {
    $cmbDrives.Items.Clear()
    try {
        $drives = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -in @('Fixed', 'Removable') -and $_.IsReady }
        foreach ($d in $drives) {
            $freeGB  = [math]::Round($d.AvailableFreeSpace / 1GB, 1)
            $totalGB = [math]::Round($d.TotalSize / 1GB, 1)
            $label   = if ($d.VolumeLabel) { $d.VolumeLabel } else { 'Local Disk' }
            [void]$cmbDrives.Items.Add("$($d.Name) [$label - trống $freeGB/$totalGB GB]")
        }
        if ($cmbDrives.Items.Count -gt 0) { $cmbDrives.SelectedIndex = 0 }
    } catch {
        [void]$cmbDrives.Items.Add("$env:SystemDrive\")
        $cmbDrives.SelectedIndex = 0
    }
}

function Update-UIState {
    $user = "$([Environment]::UserDomainName)\$([Environment]::UserName)"
    $inGroup = Test-UserInAdminsGroup
    $builtIn = Get-BuiltInAdminAccount
    $builtInState = if ($builtIn) { if ($builtIn.Enabled) { 'Đang BẬT' } else { 'Đang TẮT' } } else { 'Không rõ' }
    $ctxState = if (Test-ContextMenuInstalled) { 'Đã cài' } else { 'Chưa cài' }

    $lblStatus.Text = "OS: $script:OSBanner | Host: $env:COMPUTERNAME`r`nUser: $user (Admin Group: $(if ($inGroup) { 'Có' } else { 'Không' })) | Built-in Admin: $builtInState | Chuột phải: $ctxState"

    if ($builtIn -and $builtIn.Enabled) {
        $btnToggleBuiltIn.Text = 'Tắt Built-in Administrator (Đang BẬT)'
    } else {
        $btnToggleBuiltIn.Text = 'Bật Built-in Administrator (Đang TẮT)'
    }

    if (Test-ContextMenuInstalled) {
        $btnContextMenu.Text = 'Gỡ "Take Ownership" khỏi Menu Chuột Phải (File / Folder / Drive)'
        $btnContextMenu.BackColor = [System.Drawing.Color]::FromArgb(185, 28, 28)
    } else {
        $btnContextMenu.Text = 'Cài "Take Ownership" vào Menu Chuột Phải (File / Folder / Drive)'
        $btnContextMenu.BackColor = [System.Drawing.Color]::FromArgb(217, 119, 6)
    }
}

# Log Controls
$btnClearLog.Add_Click({ $logBox.Clear() })
$btnExportLog.Add_Click({
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'Text Files (*.txt)|*.txt'
    $dlg.FileName = "MAGIAO_ServerLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    if ($dlg.ShowDialog() -eq 'OK') {
        [IO.File]::WriteAllText($dlg.FileName, $logBox.Text, (New-Object System.Text.UTF8Encoding($true)))
        Write-Log "Đã xuất log ra: $($dlg.FileName)"
    }
})

# Tab 1 Events
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
            [System.Windows.Forms.MessageBox]::Show("Đã thêm '$currentUser' vào nhóm '$adminsGroup'. Hãy đăng xuất và đăng nhập lại.", 'Thành công', 'OK', 'Information') | Out-Null
        } else {
            Write-Log "Lỗi thêm Admin: $out"
        }
    } catch {
        Write-Log "Lỗi: $($_.Exception.Message)"
    }
    Update-UIState
})

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
        Write-Log "Lỗi Built-in Administrator: $($_.Exception.Message)"
    }
    Update-UIState
})

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

            foreach ($subKey in $RegSubKeys) {
                $argPattern = if ($subKey -like 'Drive*') { '"%1."' } else { '"%1"' }
                $cmdValue = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$HelperPath`" $argPattern"
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
            Write-Log 'Đã cài "Take Ownership" vào menu chuột phải (File, Folder & Drive).'
        } catch {
            Write-Log "Lỗi khi cài menu chuột phải: $($_.Exception.Message)"
        }
    }
    Update-UIState
})

$btnUseDrive.Add_Click({
    if ($cmbDrives.SelectedItem) {
        $driveRoot = $cmbDrives.SelectedItem.ToString().Split(' ')[0]
        $txtTargetPath.Text = $driveRoot
    }
})

$btnPickFolder.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Chọn thư mục muốn xử lý'
    if ($dlg.ShowDialog() -eq 'OK') { $txtTargetPath.Text = $dlg.SelectedPath }
})

$btnPickFile.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = 'Chọn tệp tin muốn xử lý'
    if ($dlg.ShowDialog() -eq 'OK') { $txtTargetPath.Text = $dlg.FileName }
})

$btnRunTakeOwn.Add_Click({
    $targetPath = $txtTargetPath.Text.Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($targetPath) -or -not (Test-Path -LiteralPath $targetPath)) {
        [System.Windows.Forms.MessageBox]::Show('Đường dẫn không tồn tại hoặc đang trống.', 'Thông báo', 'OK', 'Warning') | Out-Null
        return
    }
    if (-not (Confirm-CriticalTarget -Path $targetPath -ActionName 'Take Ownership + Full Control')) {
        Write-Log "Đã hủy Take Ownership: $targetPath"
        return
    }

    Write-Log "Đang thực thi Take Ownership: $targetPath (Đệ quy=$($chkRecursive.Checked), Gỡ thuộc tính=$($chkClearAttr.Checked), ResetACL=$($chkResetAcl.Checked))..."
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()
    try {
        $res = Invoke-TakeOwnership -TargetPath $targetPath -Recursive $chkRecursive.Checked -ClearAttributes $chkClearAttr.Checked -ResetAcl $chkResetAcl.Checked
        Write-Log "Hoàn tất Take Ownership (takeown=$($res.TakeownCode), icacls=$($res.IcaclsCode)): $targetPath"
    } catch {
        Write-Log "Lỗi Take Ownership: $($_.Exception.Message)"
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

$btnForceDel.Add_Click({
    $targetPath = $txtTargetPath.Text.Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($targetPath) -or -not (Test-Path -LiteralPath $targetPath)) {
        [System.Windows.Forms.MessageBox]::Show('Đường dẫn không tồn tại hoặc đang trống.', 'Thông báo', 'OK', 'Warning') | Out-Null
        return
    }
    if (Test-IsCriticalOSFolder $targetPath -or ($targetPath.TrimEnd('\') -match '^[A-Za-z]:$')) {
        [System.Windows.Forms.MessageBox]::Show("Bị chặn: Không thể dùng Force Delete lên ổ đĩa gốc hoặc thư mục gốc hệ thống ($targetPath).", 'An toàn hệ thống', 'OK', 'Error') | Out-Null
        return
    }
    $ans = [System.Windows.Forms.MessageBox]::Show(
        "CẢNH BÁO: Thao tác này sẽ Take Ownership và XÓA VĨNH VIỄN (không vào Thùng rác):`n$targetPath`n`nBạn chắc chắn muốn xóa?",
        'Xác nhận Xóa Cưỡng Bức',
        'YesNo',
        'Warning'
    )
    if ($ans -ne 'Yes') { return }

    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()
    try {
        [void](Invoke-TakeOwnership -TargetPath $targetPath -Recursive $true -ClearAttributes $true -ResetAcl $false)
        Remove-Item -LiteralPath $targetPath -Recurse -Force -ErrorAction Stop
        Write-Log "ĐÃ XÓA CƯỠNG BỨC thành công: $targetPath"
        $txtTargetPath.Clear()
    } catch {
        Write-Log "Lỗi khi xóa cưỡng bức ($targetPath): $($_.Exception.Message)"
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

$btnAdminPS.Add_Click({ Start-Process 'powershell.exe' -Verb RunAs; Write-Log 'Đã mở PowerShell (Admin).' })
$btnAdminCMD.Add_Click({ Start-Process 'cmd.exe' -Verb RunAs; Write-Log 'Đã mở CMD (Admin).' })
$btnLusrmgr.Add_Click({ try { Start-Process 'lusrmgr.msc' } catch { Write-Log $_.Exception.Message } })
$btnUAC.Add_Click({ Start-Process 'UserAccountControlSettings.exe'; Write-Log 'Đã mở Cài đặt UAC.' })

# Tab 2 Events (Bloatware)
function Render-BloatList {
    $filter = $txtBloatFilter.Text.Trim()
    $chkAppxList.Items.Clear()
    if ($script:LoadedBloatMode -eq 'Appx') {
        foreach ($pkg in $script:AppxCache) {
            if ($filter -and $pkg.Name -notlike "*$filter*") { continue }
            $tag = if ($pkg.IsProvisioned) { '[Appx+Prov]' } else { '[Appx]' }
            [void]$chkAppxList.Items.Add("$tag $($pkg.Name) ($($pkg.Version))")
        }
    } else {
        foreach ($cap in $script:CapCache) {
            if ($filter -and $cap.Name -notlike "*$filter*") { continue }
            [void]$chkAppxList.Items.Add("[Capability] $($cap.Name)")
        }
    }
}

$txtBloatFilter.Add_TextChanged({ Render-BloatList })
$btnClearSel.Add_Click({
    for ($i = 0; $i -lt $chkAppxList.Items.Count; $i++) { $chkAppxList.SetItemChecked($i, $false) }
})

$btnScanAppx.Add_Click({
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    Write-Log 'Đang quét Appx & Provisioned Packages...'
    [System.Windows.Forms.Application]::DoEvents()
    try {
        $script:LoadedBloatMode = 'Appx'
        $provSet = @{}
        foreach ($p in (Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue)) {
            $provSet[$p.DisplayName] = $p
        }
        $apps = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
            Where-Object { -not $_.NonRemovable -and -not $_.IsFramework } |
            Sort-Object Name -Unique
        $script:AppxCache = foreach ($a in $apps) {
            [PSCustomObject]@{
                Name          = $a.Name
                Version       = $a.Version
                PackageFull   = $a.PackageFullName
                IsProvisioned = $provSet.ContainsKey($a.Name)
                ProvPkgName   = if ($provSet.ContainsKey($a.Name)) { $provSet[$a.Name].PackageName } else { $null }
            }
        }
        Render-BloatList
        Write-Log "Tìm thấy $($script:AppxCache.Count) gói Appx có thể gỡ."
    } catch {
        Write-Log "Lỗi quét Appx: $($_.Exception.Message)"
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

$btnSelectBloat.Add_Click({
    if ($script:LoadedBloatMode -ne 'Appx' -or $chkAppxList.Items.Count -eq 0) {
        Write-Log 'Hãy bấm "Quét Appx" trước khi chọn nhanh Bloatware.'
        return
    }
    $count = 0
    for ($i = 0; $i -lt $chkAppxList.Items.Count; $i++) {
        $text = $chkAppxList.Items[$i].ToString()
        $matched = $false
        foreach ($pat in $KnownBloatwarePatterns) {
            if ($text -like "*$pat*") { $matched = $true; break }
        }
        $chkAppxList.SetItemChecked($i, $matched)
        if ($matched) { $count++ }
    }
    Write-Log "Đã chọn tự động $count gói Bloatware phổ biến."
})

$btnRemoveAppx.Add_Click({
    if ($script:LoadedBloatMode -ne 'Appx' -or $chkAppxList.CheckedItems.Count -eq 0) {
        Write-Log 'Chưa có gói Appx nào được chọn.'
        return
    }
    $selectedNames = @()
    foreach ($item in $chkAppxList.CheckedItems) {
        if ($item.ToString() -match '^\[Appx(?:\+Prov)?\]\s+([^\s]+)\s+\(') {
            $selectedNames += $matches[1]
        }
    }
    $ans = [System.Windows.Forms.MessageBox]::Show("Gỡ bỏ $($selectedNames.Count) gói Appx (AllUsers + Provisioned)?", 'Xác nhận gỡ Appx', 'YesNo', 'Warning')
    if ($ans -ne 'Yes') { return }

    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()
    try {
        foreach ($name in $selectedNames) {
            Write-Log "Đang gỡ Appx: $name..."
            Get-AppxPackage -AllUsers -Name $name -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -eq $name } |
                ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue | Out-Null }
        }
        Write-Log "Đã hoàn tất gỡ $($selectedNames.Count) gói Appx."
        $btnScanAppx.PerformClick()
    } catch {
        Write-Log "Lỗi khi gỡ Appx: $($_.Exception.Message)"
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

$btnScanCap.Add_Click({
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    Write-Log 'Đang quét Windows Capabilities đang cài (Installed)...'
    [System.Windows.Forms.Application]::DoEvents()
    try {
        $script:LoadedBloatMode = 'Capability'
        $script:CapCache = Get-WindowsCapability -Online -ErrorAction Stop |
            Where-Object { $_.State -eq 'Installed' } |
            Sort-Object Name
        Render-BloatList
        Write-Log "Tìm thấy $($script:CapCache.Count) Windows Capabilities đang cài."
    } catch {
        Write-Log "Lỗi quét Capabilities: $($_.Exception.Message)"
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

$btnRemoveCap.Add_Click({
    if ($script:LoadedBloatMode -ne 'Capability' -or $chkAppxList.CheckedItems.Count -eq 0) {
        Write-Log 'Hãy quét Capabilities và chọn mục cần gỡ.'
        return
    }
    $caps = @()
    foreach ($item in $chkAppxList.CheckedItems) {
        $caps += ($item.ToString() -replace '^\[Capability\]\s+', '')
    }
    $ans = [System.Windows.Forms.MessageBox]::Show("Gỡ bỏ $($caps.Count) Windows Capabilities đã chọn?", 'Xác nhận gỡ Capabilities', 'YesNo', 'Warning')
    if ($ans -ne 'Yes') { return }

    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()
    try {
        foreach ($c in $caps) {
            Write-Log "Đang gỡ Capability: $c..."
            Remove-WindowsCapability -Online -Name $c -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Log 'Hoàn tất gỡ Capabilities.'
        $btnScanCap.PerformClick()
    } catch {
        Write-Log "Lỗi gỡ Capability: $($_.Exception.Message)"
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

$btnUninstOneDrive.Add_Click({
    $ans = [System.Windows.Forms.MessageBox]::Show('Dừng và gỡ Microsoft OneDrive khỏi hệ thống?', 'Xác nhận gỡ OneDrive', 'YesNo', 'Warning')
    if ($ans -ne 'Yes') { return }

    Write-Log 'Đang dừng và gỡ Microsoft OneDrive...'
    try {
        Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        $setupPaths = @(
            (Join-Path $env:SystemRoot 'System32\OneDriveSetup.exe'),
            (Join-Path $env:SystemRoot 'SysWOW64\OneDriveSetup.exe')
        )
        $ran = $false
        foreach ($sp in $setupPaths) {
            if (Test-Path -LiteralPath $sp) {
                Start-Process -FilePath $sp -ArgumentList '/uninstall' -Wait
                $ran = $true
                break
            }
        }
        if ($ran) {
            Write-Log 'Đã chạy trình gỡ OneDriveSetup.exe /uninstall.'
        } else {
            Write-Log 'Không tìm thấy OneDriveSetup.exe trên máy này.'
        }
    } catch {
        Write-Log "Lỗi gỡ OneDrive: $($_.Exception.Message)"
    }
})

# Tab 3 Events (Services & Policies)
function Refresh-ServicesList {
    $chkSvcList.Items.Clear()
    $allSvcs = @{}
    foreach ($s in (Get-Service -ErrorAction SilentlyContinue)) {
        $allSvcs[$s.Name] = $s
    }
    foreach ($spec in $ManagedServiceSpecs) {
        if ($allSvcs.ContainsKey($spec.Name)) {
            $svc = $allSvcs[$spec.Name]
            [void]$chkSvcList.Items.Add("$($spec.Name) | [$($svc.Status) / $($svc.StartType)] - $($spec.Label)")
        } else {
            [void]$chkSvcList.Items.Add("$($spec.Name) | [Không cài đặt] - $($spec.Label)")
        }
    }
}

$btnScanServices.Add_Click({ Refresh-ServicesList; Write-Log 'Đã làm mới danh sách Services.' })
$btnSelectAllSvc.Add_Click({
    for ($i = 0; $i -lt $chkSvcList.Items.Count; $i++) { $chkSvcList.SetItemChecked($i, $true) }
})

function Set-SelectedServicesMode {
    param([string]$StartupType, [bool]$StopIt, [bool]$StartIt)
    if ($chkSvcList.CheckedItems.Count -eq 0) {
        Write-Log 'Chưa chọn service nào.'
        return
    }
    foreach ($item in $chkSvcList.CheckedItems) {
        $svcName = $item.ToString().Split('|')[0].Trim()
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        try {
            if ($StopIt -and $svc.Status -ne 'Stopped') {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $svcName -StartupType $StartupType -ErrorAction Stop
            if ($StartIt) {
                Start-Service -Name $svcName -ErrorAction SilentlyContinue
            }
            Write-Log "Service [$svcName] -> StartupType=$StartupType"
        } catch {
            Write-Log "Lỗi Service [$svcName]: $($_.Exception.Message)"
        }
    }
    Refresh-ServicesList
}

$btnDisableServices.Add_Click({ Set-SelectedServicesMode -StartupType 'Disabled'  -StopIt $true  -StartIt $false })
$btnManualServices.Add_Click({  Set-SelectedServicesMode -StartupType 'Manual'    -StopIt $false -StartIt $false })
$btnAutoServices.Add_Click({    Set-SelectedServicesMode -StartupType 'Automatic' -StopIt $false -StartIt $true  })

$btnApplyHardening.Add_Click({
    foreach ($pol in $HardeningPolicies) {
        try {
            if (-not (Test-Path -LiteralPath $pol.Path)) {
                New-Item -Path $pol.Path -Force | Out-Null
            }
            New-ItemProperty -Path $pol.Path -Name $pol.Prop -Value $pol.Val -PropertyType $pol.Type -Force | Out-Null
            Write-Log "Applied: $($pol.Name)"
        } catch {
            Write-Log "Lỗi Policy [$($pol.Name)]: $($_.Exception.Message)"
        }
    }
})

$btnRevertPolicy.Add_Click({
    foreach ($pol in $HardeningPolicies) {
        try {
            if (Test-Path -LiteralPath $pol.Path) {
                Remove-ItemProperty -Path $pol.Path -Name $pol.Prop -ErrorAction SilentlyContinue
            }
            Write-Log "Reverted: $($pol.Name)"
        } catch {
            Write-Log "Lỗi Revert [$($pol.Name)]: $($_.Exception.Message)"
        }
    }
})

$btnDisableTasks.Add_Click({
    foreach ($t in $TelemetryTasks) {
        try {
            & schtasks.exe /Change /TN "$t" /Disable 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Disabled Task: $t"
            }
        } catch {}
    }
    Write-Log 'Hoàn tất tắt Scheduled Tasks Telemetry (những task tồn tại trên máy).'
})

# Tab 4 Events (Disk Cleanup)
$btnDiskCleanMgr.Add_Click({ Start-Process 'cleanmgr.exe'; Write-Log 'Đã mở Disk Cleanup.' })

$btnRunCleanup.Add_Click({
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    [System.Windows.Forms.Application]::DoEvents()
    try {
        if ($chkCleanTemp.Checked) {
            $tempDirs = @(
                (Join-Path $env:SystemRoot 'Temp'),
                $env:TEMP,
                (Join-Path $env:SystemRoot 'Prefetch')
            ) | Select-Object -Unique
            foreach ($dir in $tempDirs) {
                if (Test-Path -LiteralPath $dir) {
                    Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "Đã dọn: $dir"
                }
            }
        }

        if ($chkCleanWU.Checked) {
            $wuDir = Join-Path $env:SystemRoot 'SoftwareDistribution\Download'
            if (Test-Path -LiteralPath $wuDir) {
                $wuSvc = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
                $wasRunning = ($wuSvc -and $wuSvc.Status -eq 'Running')
                if ($wasRunning) { Stop-Service -Name 'wuauserv' -Force -ErrorAction SilentlyContinue }
                Get-ChildItem -LiteralPath $wuDir -Force -ErrorAction SilentlyContinue |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                if ($wasRunning) { Start-Service -Name 'wuauserv' -ErrorAction SilentlyContinue }
                Write-Log "Đã dọn cache Windows Update: $wuDir"
            }
        }

        if ($chkCleanRecycle.Checked) {
            if (Get-Command Clear-RecycleBin -ErrorAction SilentlyContinue) {
                Clear-RecycleBin -Force -ErrorAction SilentlyContinue
                Write-Log 'Đã dọn sạch Thùng rác (C:, D:, ...).'
            }
        }

        if ($chkCleanWinSxS.Checked) {
            Write-Log 'Đang chạy DISM /StartComponentCleanup...'
            & dism.exe /Online /Cleanup-Image /StartComponentCleanup /Quiet | Out-Null
            Write-Log "DISM Cleanup hoàn tất (ExitCode=$LASTEXITCODE)."
        }
        Refresh-DrivesList
    } catch {
        Write-Log "Lỗi dọn dẹp: $($_.Exception.Message)"
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

#endregion

# Startup Initialization
Refresh-DrivesList
Refresh-ServicesList
Update-UIState
Write-Log "Sẵn sàng. Đang chạy với quyền Administrator trên $env:COMPUTERNAME."
[void]$form.ShowDialog()
