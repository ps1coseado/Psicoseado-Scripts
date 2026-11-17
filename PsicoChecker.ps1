$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

$script:Issues          = [Collections.Generic.List[object]]::new()
$script:LastEventCache  = @{}
$script:LogBatchCache   = @{}
$script:LogIdSets       = @{}
$script:PrefetchCache   = $null
$script:RecycleCache    = $null
$script:UsnCache        = $null
$script:ServiceEventCache = $null
$script:PrefetchPolicy  = $null
$script:NativeOk        = $false
$script:VtEnabled       = $false
$script:CimAvailable    = $null
$script:WmiAvailable    = $null

$script:TitleIndex   = '  '
$script:InfoIndex    = '    '
$script:FieldWidth   = 24
$script:RegNameWidth = 26
$script:PanelWidth   = 70
$script:PanelInner   = $script:PanelWidth - 2

$script:TitleColor   = 'Red'
$script:SubtColor    = 'DarkGray'
$script:TextColor    = 'White'
$script:SuccessColor = 'White'
$script:DangerColor  = 'Red'
# Yellow marks unusual or wrong findings; red is reserved for critical actions.
$script:WarnColor    = 'Yellow'
$script:FrameColor   = 'DarkRed'
$script:AccentColor  = 'Red'
$script:RunningColor = 'Green'
$script:FormatDate   = 'dd-MM-yyyy HH:mm:ss'

# Red theme: every gradient stays inside the red range. White is reserved for
# body text and positive results, so the interface keeps a clean contrast.
$script:BannerFrom  = @(120, 0, 0)
$script:BannerTo    = @(255, 70, 70)
$script:FrameFrom   = @(90, 0, 0)
$script:FrameTo     = @(225, 25, 25)
$script:SectionFrom = @(150, 0, 0)
$script:SectionTo   = @(255, 80, 80)

try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch {}
try { $Host.UI.RawUI.WindowTitle = 'Psico Checker :: by Psicoseado' } catch {}
try { Clear-Host } catch {}

function Test-IsAdmin {
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

if (-not (Test-IsAdmin)) {
    Write-Host ''
    Write-Host '  [ERROR] SE REQUIEREN PRIVILEGIOS DE ADMINISTRADOR' -ForegroundColor White -BackgroundColor Red
    Write-Host '          Abre PowerShell como administrador y vuelve a ejecutar el script.' -ForegroundColor $script:WarnColor
    Write-Host ''
    Start-Sleep -Seconds 5
    exit 1
}

if (-not ('PsicoNative' -as [type])) {
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Text;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

public static class PsicoNative
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll")]
    public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegOpenKeyEx(UIntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out SafeRegistryHandle phkResult);

    [DllImport("advapi32.dll")]
    private static extern int RegQueryInfoKey(
        SafeRegistryHandle hKey,
        StringBuilder lpClass,
        ref uint lpcClass,
        IntPtr lpReserved,
        out uint lpcSubKeys,
        out uint lpcbMaxSubKeyLen,
        out uint lpcbMaxClassLen,
        out uint lpcValues,
        out uint lpcbMaxValueNameLen,
        out uint lpcbMaxValueLen,
        out uint lpcbSecurityDescriptor,
        out long lpftLastWriteTime);

    [DllImport("kernel32.dll")]
    public static extern ulong GetTickCount64();

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, IntPtr buffer, int bufferSize, out int bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    public static int GetServiceProcessId(string serviceName)
    {
        IntPtr manager = OpenSCManager(null, null, 0x0001);
        if (manager == IntPtr.Zero)
        {
            return 0;
        }

        try
        {
            IntPtr service = OpenService(manager, serviceName, 0x0004);
            if (service == IntPtr.Zero)
            {
                return 0;
            }

            try
            {
                int size = Marshal.SizeOf(typeof(SERVICE_STATUS_PROCESS));
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    int needed;
                    if (!QueryServiceStatusEx(service, 0, buffer, size, out needed))
                    {
                        return 0;
                    }

                    SERVICE_STATUS_PROCESS status = (SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(buffer, typeof(SERVICE_STATUS_PROCESS));
                    return (int)status.dwProcessId;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModules(IntPtr process, IntPtr[] modules, int size, out int needed);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetModuleBaseName(IntPtr process, IntPtr module, StringBuilder name, int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int processId);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    // Returns the first loaded module that belongs to a screen-capture API.
    // explorer.exe is filtered by the caller because the shell loads the capture
    // DLL for normal window management, not because it is recording.
    public static string GetCaptureModule(int processId)
    {
        IntPtr process = OpenProcess(0x0410, false, processId);
        if (process == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            IntPtr[] modules = new IntPtr[2048];
            int needed;
            if (!EnumProcessModules(process, modules, modules.Length * IntPtr.Size, out needed))
            {
                return null;
            }

            int count = needed / IntPtr.Size;
            if (count > modules.Length)
            {
                count = modules.Length;
            }

            StringBuilder name = new StringBuilder(260);
            for (int i = 0; i < count; i++)
            {
                name.Length = 0;
                if (GetModuleBaseName(process, modules[i], name, name.Capacity) == 0)
                {
                    continue;
                }

                string text = name.ToString();
                if (text.Equals("Windows.Graphics.Capture.dll", StringComparison.OrdinalIgnoreCase) ||
                    text.IndexOf("graphicscapture", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("nvencodeapi", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("amdenc", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("amfrt", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return text;
                }
            }

            return null;
        }
        finally
        {
            CloseHandle(process);
        }
    }

    public static DateTime? GetKeyLastWriteTime(string hive, string subKey)
    {
        UIntPtr root = string.Equals(hive, "HKCU", StringComparison.OrdinalIgnoreCase)
            ? (UIntPtr)0x80000001u
            : (UIntPtr)0x80000002u;

        SafeRegistryHandle hKey;
        int result = RegOpenKeyEx(root, subKey, 0, 0x20019, out hKey);
        if (result != 0 || hKey == null || hKey.IsInvalid)
        {
            return null;
        }

        try
        {
            uint classLength = 0;
            uint subKeys;
            uint maxSubKeyLength;
            uint maxClassLength;
            uint values;
            uint maxValueNameLength;
            uint maxValueLength;
            uint securityDescriptor;
            long fileTime;

            result = RegQueryInfoKey(
                hKey,
                null,
                ref classLength,
                IntPtr.Zero,
                out subKeys,
                out maxSubKeyLength,
                out maxClassLength,
                out values,
                out maxValueNameLength,
                out maxValueLength,
                out securityDescriptor,
                out fileTime);

            if (result != 0 || fileTime <= 0)
            {
                return null;
            }

            return DateTime.FromFileTimeUtc(fileTime).ToLocalTime();
        }
        catch
        {
            return null;
        }
        finally
        {
            hKey.Dispose();
        }
    }
}
'@ -ErrorAction Stop
    } catch {}
}

$script:NativeOk = [bool]('PsicoNative' -as [type])

try {
    $stdOut = [PsicoNative]::GetStdHandle(-11)
    $vtMode = [uint32]0
    if ([PsicoNative]::GetConsoleMode($stdOut, [ref]$vtMode)) {
        $script:VtEnabled = [PsicoNative]::SetConsoleMode($stdOut, $vtMode -bor 0x0004)
    }
} catch {}

$script:RegView = [Microsoft.Win32.RegistryView]::Default
if ([Environment]::Is64BitOperatingSystem) { $script:RegView = [Microsoft.Win32.RegistryView]::Registry64 }

try {
    $script:RegLM = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $script:RegView)
} catch {
    try { $script:RegLM = [Microsoft.Win32.Registry]::LocalMachine } catch { $script:RegLM = $null }
}

try {
    $script:RegCU = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $script:RegView)
} catch {
    try { $script:RegCU = [Microsoft.Win32.Registry]::CurrentUser } catch { $script:RegCU = $null }
}

# --- Utilidades visuales ------------------------------------------------------
function Center-Inner {
    param([string]$Text, [int]$Width)
    if ($Text.Length -ge $Width) { return $Text.Substring(0, $Width) }
    $left = [int](($Width - $Text.Length) / 2)
    $right = $Width - $Text.Length - $left
    return (' ' * $left) + $Text + (' ' * $right)
}

function Write-Gradient {
    param([string]$Text, [int[]]$From, [int[]]$To)

    if (-not $script:VtEnabled) {
        Write-Host $Text -ForegroundColor $script:TitleColor
        return
    }

    $builder = [Text.StringBuilder]::new($Text.Length * 20)
    $last = [Math]::Max($Text.Length - 1, 1)

    for ($i = 0; $i -lt $Text.Length; $i++) {
        $character = $Text[$i]
        if ($character -eq ' ') {
            [void]$builder.Append(' ')
            continue
        }

        $t = $i / [double]$last
        $r = [int]($From[0] + ($To[0] - $From[0]) * $t)
        $g = [int]($From[1] + ($To[1] - $From[1]) * $t)
        $b = [int]($From[2] + ($To[2] - $From[2]) * $t)
        [void]$builder.Append("$([char]27)[38;2;$r;$g;${b}m").Append($character)
    }

    [void]$builder.Append("$([char]27)[0m")
    Write-Host $builder.ToString()
}

function Write-SectionHeader {
    param([string]$Title)

    $label = "  [ $Title ] "
    if ($label.Length -gt $script:PanelInner) { $label = $label.Substring(0, $script:PanelInner) }
    $fill = '═' * [Math]::Max(0, $script:PanelInner - $label.Length)

    Write-Host ''
    Write-Gradient ('╔' + ('═' * $script:PanelInner) + '╗') $script:SectionFrom $script:SectionTo
    Write-Host '║' -ForegroundColor $script:FrameColor -NoNewline
    Write-Host $label -ForegroundColor $script:TitleColor -NoNewline
    Write-Host $fill -ForegroundColor $script:FrameColor -NoNewline
    Write-Host '║' -ForegroundColor $script:FrameColor
    Write-Gradient ('╚' + ('═' * $script:PanelInner) + '╝') $script:SectionFrom $script:SectionTo
    Write-Host ''
}

function Write-SubSection {
    param([string]$Title)

    $lineLength = [Math]::Max(0, 60 - $Title.Length)
    Write-Host ($script:TitleIndex + '◆ ') -ForegroundColor $script:AccentColor -NoNewline
    Write-Host $Title -ForegroundColor $script:TitleColor -NoNewline
    Write-Host (' ' + ('─' * $lineLength)) -ForegroundColor $script:SubtColor
}

function Write-Field {
    param(
        [string]$Label,
        [AllowNull()][string]$Value,
        [int]$Width = $script:FieldWidth,
        [string]$LabelColor = $script:TextColor,
        [string]$ValueColor = $script:TextColor
    )

    if ($null -eq $Value) { $Value = '' }
    Write-Host ($script:InfoIndex + $Label.PadRight($Width)) -ForegroundColor $LabelColor -NoNewline
    Write-Host $Value -ForegroundColor $ValueColor
}

function Write-ThinSeparator {
    Write-Host ($script:InfoIndex + ('─' * 58)) -ForegroundColor $script:SubtColor
}

function Write-Int {
    param([string]$Indent, [string]$Symbol, [string]$Message)
    Write-Host ($Indent + ' [') -ForegroundColor $script:FrameColor -NoNewline
    Write-Host $Symbol -ForegroundColor $script:AccentColor -NoNewline
    Write-Host '] ' -ForegroundColor $script:FrameColor -NoNewline
    Write-Host $Message -ForegroundColor $script:WarnColor
}

function Write-UsageBar {
    param([string]$Label, [double]$Percent, [string]$Suffix = '')

    $barWidth = 20
    $value = [Math]::Max(0.0, [Math]::Min(100.0, [Math]::Round($Percent, 0)))
    $filled = [int][Math]::Round(($value / 100) * $barWidth)
    if ($filled -gt $barWidth) { $filled = $barWidth }
    if ($filled -lt 0) { $filled = 0 }
    $empty = $barWidth - $filled
    $color = if ($value -ge 85) { $script:DangerColor } elseif ($value -ge 60) { $script:WarnColor } else { $script:SuccessColor }

    Write-Host ($script:InfoIndex + $Label.PadRight($script:FieldWidth)) -ForegroundColor $script:TextColor -NoNewline
    Write-Host '[' -ForegroundColor $script:SubtColor -NoNewline
    Write-Host ('█' * $filled) -ForegroundColor $color -NoNewline
    Write-Host ('░' * $empty) -ForegroundColor $script:SubtColor -NoNewline
    Write-Host '] ' -ForegroundColor $script:SubtColor -NoNewline
    Write-Host ('{0,3}%' -f $value) -ForegroundColor $color -NoNewline
    if ($Suffix) { Write-Host ('  ' + $Suffix) -ForegroundColor $script:SubtColor } else { Write-Host '' }
}

function Format-Duration {
    param($Value)
    if ($null -eq $Value -or $Value -isnot [TimeSpan]) { return 'Unknown' }
    if ($Value.Ticks -lt 0) { $Value = [TimeSpan]::Zero }
    return ('{0}d {1}h {2}m {3}s' -f $Value.Days, $Value.Hours, $Value.Minutes, $Value.Seconds)
}

function Format-Bytes {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes / 1KB)) }
    return ('{0:N0} B' -f $Bytes)
}

function Format-Time {
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToString($script:FormatDate) }
    return 'Unknown'
}

function Format-RegTime {
    param($Value)
    if ($Value -is [datetime]) {
        if ($Value.Year -le 1601) { return '(never)' }
        return $Value.ToString('yyyy-MM-dd HH:mm')
    }
    return 'Unknown'
}

# Registry policy values are usually numbers, but a damaged or unusual build
# can store text. Returning $null keeps callers from throwing a cast error.
function ConvertTo-IntOrNull {
    param($Value)
    if ($null -eq $Value) { return $null }
    $number = 0
    if ([int]::TryParse([string]$Value, [ref]$number)) { return $number }
    return $null
}

function Add-Issue {
    param([string]$Area, [string]$Detail)
    if ([string]::IsNullOrWhiteSpace($Area)) { $Area = 'General' }
    if ([string]::IsNullOrWhiteSpace($Detail)) { $Detail = 'Error desconocido' }
    $script:Issues.Add([pscustomobject]@{ Area = $Area; Detail = $Detail })
}

function Get-PathStatus {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return 'Unknown' }

    try {
        if ([IO.File]::Exists($Path) -or [IO.Directory]::Exists($Path)) { return 'Present' }
    } catch {}

    try {
        $null = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return 'Present'
    } catch [System.UnauthorizedAccessException] {
        return 'Access denied'
    } catch [System.Security.SecurityException] {
        return 'Access denied'
    } catch [System.Management.Automation.ItemNotFoundException] {
        return 'Missing'
    } catch [System.IO.FileNotFoundException] {
        return 'Missing'
    } catch [System.IO.DirectoryNotFoundException] {
        return 'Missing'
    } catch [System.IO.DriveNotFoundException] {
        return 'Missing'
    } catch {
        return 'Error'
    }
}

# --- Registro -----------------------------------------------------------------
function Get-RegInfo {
    param([string]$Path, [string]$Name)

    $result = [pscustomobject]@{
        Status    = 'Read error'
        Value     = $null
        LastWrite = $null
        Error     = $null
    }

    $match = [regex]::Match($Path, '^(HKLM|HKCU):\\(.+)$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success) {
        $result.Error = "Ruta no valida: $Path"
        return $result
    }

    $hive = $match.Groups[1].Value.ToUpperInvariant()
    $subKey = $match.Groups[2].Value
    $root = if ($hive -eq 'HKCU') { $script:RegCU } else { $script:RegLM }

    if (-not $root) {
        $result.Error = 'Registry API unavailable'
        return $result
    }

    $key = $null
    try {
        $key = $root.OpenSubKey($subKey, $false)
    } catch [System.UnauthorizedAccessException] {
        $result.Status = 'Access denied'
        $result.Error = $_.Exception.Message
        return $result
    } catch [System.Security.SecurityException] {
        $result.Status = 'Access denied'
        $result.Error = $_.Exception.Message
        return $result
    } catch {
        $result.Status = 'Read error'
        $result.Error = $_.Exception.Message
        return $result
    }

    if ($null -eq $key) {
        $result.Status = 'Key missing'
        return $result
    }

    try {
        if ([string]::IsNullOrEmpty($Name)) {
            $result.Status = 'Present'
        } else {
            $value = $key.GetValue($Name, [DBNull]::Value)
            if ($value -is [DBNull]) {
                $result.Status = 'Value missing'
            } else {
                $result.Status = 'Present'
                $result.Value = $value
            }
        }
    } catch [System.UnauthorizedAccessException] {
        $result.Status = 'Access denied'
        $result.Error = $_.Exception.Message
        return $result
    } catch [System.Security.SecurityException] {
        $result.Status = 'Access denied'
        $result.Error = $_.Exception.Message
        return $result
    } catch {
        $result.Status = 'Read error'
        $result.Error = $_.Exception.Message
        return $result
    } finally {
        try { $key.Close() } catch {}
    }

    if ($script:NativeOk) {
        try { $result.LastWrite = [PsicoNative]::GetKeyLastWriteTime($hive, $subKey) } catch {}
    }

    return $result
}

function ConvertTo-StartModeName {
    param([string]$Value)
    switch ($Value) {
        'Automatic'      { return 'Auto' }
        'Automatic (Delayed Start)' { return 'Auto (delayed)' }
        'Auto'           { return 'Auto' }
        'Manual'         { return 'Manual' }
        'Disabled'       { return 'Disabled' }
        'Boot'           { return 'Boot' }
        'System'         { return 'System' }
        default          { return $Value }
    }
}

function ConvertTo-ServiceState {
    param([string]$Value)
    switch ($Value) {
        'StartPending'    { return 'Start Pending' }
        'StopPending'     { return 'Stop Pending' }
        'PausePending'    { return 'Pause Pending' }
        'ContinuePending' { return 'Continue Pending' }
        default           { return $Value }
    }
}

# Get-Service on older Windows builds does not expose StartType, so fall back to
# the service's Start value in the registry. Both paths end with the same labels
# as Win32_Service.StartMode (Auto/Manual/Disabled) to keep output consistent.
function Get-ServiceStartMode {
    param([string]$ServiceName, $Controller)

    $mode = ''
    if ($Controller) { $mode = [string]$Controller.StartType }

    if ([string]::IsNullOrWhiteSpace($mode)) {
        $start = Get-RegInfo -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name 'Start'
        $number = if ($start.Status -eq 'Present') { ConvertTo-IntOrNull $start.Value } else { $null }
        if ($null -ne $number) {
            $mode = switch ($number) {
                0 { 'Boot' }
                1 { 'System' }
                2 { 'Auto' }
                3 { 'Manual' }
                4 { 'Disabled' }
                default { 'Unknown' }
            }
        }
    }

    $mode = ConvertTo-StartModeName $mode
    if ([string]::IsNullOrWhiteSpace($mode)) { return 'Unknown' }
    return $mode
}

# Custom Windows builds sometimes remove the CIM cmdlets or stop the WMI
# service. Try CIM first, then classic WMI, and let the caller fall back to
# registry/native data when both are unavailable. A provider that throws once is
# not tried again, so a broken build pays that cost only once.
function Get-CimOrWmiData {
    param(
        [string]$ClassName,
        [string[]]$Property = @(),
        [string]$Filter
    )

    $items = @()

    if ($script:CimAvailable -ne $false) {
        try {
            $arguments = @{ ClassName = $ClassName; ErrorAction = 'SilentlyContinue' }
            if ($Property.Count -gt 0) { $arguments.Property = $Property }
            if ($Filter) { $arguments.Filter = $Filter }
            $items = @(Get-CimInstance @arguments)
            $script:CimAvailable = $true
        } catch {
            $script:CimAvailable = $false
            $items = @()
        }
    }

    if ($items.Count -eq 0 -and $script:WmiAvailable -ne $false) {
        try {
            $arguments = @{ Class = $ClassName; ErrorAction = 'SilentlyContinue' }
            if ($Property.Count -gt 0) { $arguments.Property = $Property }
            if ($Filter) { $arguments.Filter = $Filter }
            $items = @(Get-WmiObject @arguments)
            $script:WmiAvailable = $true
        } catch {
            $script:WmiAvailable = $false
            $items = @()
        }
    }

    return $items
}

# The .NET event reader has locale-independent errors: a missing channel and a
# denied log are real exceptions, while "no matching events" simply returns an
# empty list. This avoids false read errors on non-English Windows.
function Get-EventLogRecords {
    param(
        [string]$LogName,
        [string]$XPath = '*',
        [int]$MaxRecords = 1000,
        [bool]$IncludeValues = $true
    )

    $result = [pscustomobject]@{
        Status  = 'Readable'
        Records = @()
        Error   = $null
    }

    $reader = $null
    try {
        $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $XPath)
        $query.ReverseDirection = $true
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)

        $records = [Collections.Generic.List[object]]::new()
        while ($records.Count -lt $MaxRecords) {
            $record = $reader.ReadEvent()
            if ($null -eq $record) { break }

            try {
                $recordId = 0
                try { $recordId = [int]$record.Id } catch {}
                $created = $null
                try { $created = $record.TimeCreated } catch {}

                $values = [Collections.Generic.List[string]]::new()
                if ($IncludeValues) {
                    try { foreach ($property in $record.Properties) { $values.Add([string]$property.Value) } } catch {}
                }
                $records.Add([pscustomobject]@{
                    Id          = $recordId
                    TimeCreated = $created
                    Values      = $values.ToArray()
                })
            } catch {
            } finally {
                try { $record.Dispose() } catch {}
            }
        }

        $result.Records = $records.ToArray()
    } catch {
        $exception = $_.Exception.GetBaseException()

        if ($exception -is [System.UnauthorizedAccessException] -or $exception -is [System.Security.SecurityException]) {
            $result.Status = 'Access denied'
        } elseif ($exception -is [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] -or
                  $exception -is [System.Diagnostics.Eventing.Reader.EventLogDisabledException]) {
            $result.Status = 'Log missing'
        } else {
            $result.Status = 'Read error'
            $result.Error = $exception.Message
        }
    } finally {
        if ($reader) { try { $reader.Dispose() } catch {} }
    }

    return $result
}

function Get-OsInfoFallback {
    $caption = 'Windows'
    $product = Get-RegInfo -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'ProductName'
    if ($product.Status -eq 'Present' -and $product.Value) {
        $caption = ([string]$product.Value).Trim()
    }

    $build = 0
    $buildInfo = Get-RegInfo -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuildNumber'
    if ($buildInfo.Status -eq 'Present') { [void][int]::TryParse([string]$buildInfo.Value, [ref]$build) }
    if ($build -ge 22000 -and $caption -match '^Windows 10') {
        $caption = $caption -replace '^Windows 10', 'Windows 11'
    }

    $bootTime = $null
    if ($script:NativeOk) {
        try {
            $uptimeMs = [double][PsicoNative]::GetTickCount64()
            if ($uptimeMs -gt 0) { $bootTime = (Get-Date).AddMilliseconds(-$uptimeMs) }
        } catch {}
    }

    return [pscustomobject]@{
        Caption        = $caption
        LastBootUpTime = $bootTime
    }
}

function Get-PrefetchPolicyInfo {
    if ($null -eq $script:PrefetchPolicy) {
        $script:PrefetchPolicy = Get-RegInfo -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnablePrefetcher'
    }

    $policy = $script:PrefetchPolicy
    $info = [pscustomobject]@{
        Text     = 'Unreadable'
        Disabled = $false
        Color    = $script:WarnColor
    }

    if ($policy.Status -eq 'Present' -and $null -ne $policy.Value) {
        $number = ConvertTo-IntOrNull $policy.Value
        if ($null -eq $number) {
            $info.Text = 'Unexpected value'
            $info.Color = $script:WarnColor
        } else {
            switch ($number) {
                0 { $info.Text = 'Disabled (0)';    $info.Disabled = $true; $info.Color = $script:WarnColor }
                1 { $info.Text = 'Apps only (1)';   $info.Color = $script:TextColor }
                2 { $info.Text = 'Boot only (2)';   $info.Color = $script:TextColor }
                3 { $info.Text = 'Apps + boot (3)'; $info.Color = $script:TextColor }
                default { $info.Text = "Unexpected value ($number)"; $info.Color = $script:WarnColor }
            }
        }
    } elseif ($policy.Status -eq 'Present' -or $policy.Status -eq 'Value missing') {
        $info.Text = 'Not configured (default)'
        $info.Color = $script:TextColor
    } elseif ($policy.Status -eq 'Key missing') {
        $info.Text = 'Key missing (default)'
        $info.Color = $script:TextColor
    } elseif ($policy.Status -eq 'Access denied') {
        $info.Text = 'Unreadable (access denied)'
    }

    return $info
}

# --- Datos cacheados ----------------------------------------------------------
function Get-PrefetchData {
    if ($null -ne $script:PrefetchCache) { return $script:PrefetchCache }

    $path = Join-Path $env:SystemRoot 'Prefetch'
    $status = Get-PathStatus $path
    $files = @()
    $headers = [Collections.Generic.List[object]]::new()
    $folder = $null
    $readError = $null

    if ($status -eq 'Present') {
        try {
            $folder = [IO.DirectoryInfo]::new($path)
            $files = @($folder.GetFiles('*.pf'))
        } catch {
            $exception = $_.Exception.GetBaseException()
            $readError = $exception.Message
            if ($exception -is [System.UnauthorizedAccessException] -or $exception -is [System.Security.SecurityException]) {
                $status = 'Access denied'
            } else {
                $status = 'Error'
            }
        }

        $share = [IO.FileShare]([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        foreach ($file in $files) {
            $header = ''
            $readOk = $false
            try {
                $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
                try {
                    $buffer = New-Object byte[] 4
                    $bytesRead = $stream.Read($buffer, 0, 4)
                } finally {
                    $stream.Dispose()
                }
                $readOk = ($bytesRead -gt 0)
                if ($readOk) { $header = [Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead) }
            } catch {}

            $valid = $header.StartsWith('MAM', [StringComparison]::OrdinalIgnoreCase) -or
                     $header.StartsWith('SCCA', [StringComparison]::OrdinalIgnoreCase)

            $headers.Add([pscustomobject]@{
                Name     = $file.Name
                Header   = $header
                ReadOk   = $readOk
                Valid    = $valid
                Hidden   = (($file.Attributes -band [IO.FileAttributes]::Hidden) -ne 0)
                ReadOnly = $file.IsReadOnly
            })
        }
    }

    $newest = $null
    foreach ($file in $files) {
        if ($null -eq $newest -or $file.LastWriteTime -gt $newest) { $newest = $file.LastWriteTime }
    }

    $script:PrefetchCache = [pscustomobject]@{
        Path      = $path
        Status    = $status
        Files     = $files
        Headers   = $headers.ToArray()
        Folder    = $folder
        ReadError = $readError
        Newest    = $newest
    }
    return $script:PrefetchCache
}

function Get-RecycleOriginalPath {
    param([string]$Path)
    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -lt 28) { return $null }
        $nameLength = [BitConverter]::ToInt32($bytes, 24)
        if ($nameLength -lt 2 -or $nameLength -gt 65536 -or (28 + $nameLength) -gt $bytes.Length) { return $null }
        # A few stores contain an odd byte count. Decoding it produces a fake
        # replacement glyph at the end, so keep only complete UTF-16 units.
        if (($nameLength % 2) -ne 0) { $nameLength-- }
        $text = [Text.Encoding]::Unicode.GetString($bytes, 28, $nameLength)
        return $text.TrimEnd([char]0)
    } catch {
        return $null
    }
}

function Get-RecycleData {
    if ($null -ne $script:RecycleCache) { return $script:RecycleCache }

    $root = Join-Path $env:SystemDrive '$Recycle.bin'
    $result = [pscustomobject]@{
        Path     = $root
        Status   = 'Missing'
        Count    = 0
        LastPath = $null
        LastTime = $null
        Modified = $null
        Partial  = $false
    }

    $rootItem = $null
    try {
        $candidateRoot = [IO.DirectoryInfo]::new($root)
        if ($candidateRoot.Exists) { $rootItem = $candidateRoot }
    } catch {}
    if ($null -eq $rootItem) {
        $script:RecycleCache = $result
        return $result
    }

    $result.Status = 'Present'
    $result.Modified = $rootItem.LastWriteTime
    $all = [Collections.Generic.List[object]]::new()

    try {
        $sidFolders = @($rootItem.GetDirectories())
    } catch {
        $result.Partial = $true
        $sidFolders = @()
    }

    foreach ($sidFolder in $sidFolders) {
        if ($sidFolder.Name -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')) { continue }
        try {
            $items = @($sidFolder.GetFiles('$I*'))
            foreach ($item in $items) { $all.Add($item) }
        } catch {
            $result.Partial = $true
        }
    }

    $result.Count = $all.Count
    if ($all.Count -gt 0) {
        $latest = $null
        foreach ($item in $all) {
            if ($null -eq $latest -or $item.CreationTime -gt $latest.CreationTime) { $latest = $item }
        }
        $result.LastTime = $latest.CreationTime
        $original = Get-RecycleOriginalPath $latest.FullName
        $result.LastPath = if ($original) { $original } else { $latest.Name }
    }

    $script:RecycleCache = $result
    return $result
}

function Get-JavaLauncherExecutions {
    param([string]$Path)

    $map = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $lastDate = $null
    $dateRx1 = [regex]'\[(?<d>\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2})'
    $dateRx2 = [regex]'\[(?<d>\d{1,2}/\d{1,2}/\d{4}[ T]\d{1,2}:\d{2}:\d{2})'
    $jarRx = [regex]'(?i)-jar(?:\s+|=)(?:"(?<jar>[^"]+)"|(?<jar>[^\s]+))'
    $createRx = [regex]'(?i)CreateProcess\(\s*[^,]+,\s*"(?<command>.*)\)\s*succeeded'

    foreach ($line in [IO.File]::ReadLines($Path)) {
        $lineDate = $null
        $dateMatch = $dateRx1.Match($line)
        if (-not $dateMatch.Success) { $dateMatch = $dateRx2.Match($line) }

        if ($dateMatch.Success) {
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParse(
                    $dateMatch.Groups['d'].Value,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::None,
                    [ref]$parsed)) {
                $lineDate = $parsed
            }
        }

        if ($lineDate) { $lastDate = $lineDate }

        $jarMatch = $jarRx.Match($line)
        if (-not $jarMatch.Success) { continue }

        $jarPath = $jarMatch.Groups['jar'].Value.Trim('"', "'")
        $jarPath = $jarPath.TrimEnd([char[]]@(')', ']', '}', ',', ';'))
        if ($jarPath.StartsWith('\\')) {
            $jarPath = '\\' + ($jarPath.Substring(2) -replace '\\\\', '\')
        } else {
            $jarPath = $jarPath -replace '\\\\', '\'
        }
        if ([string]::IsNullOrWhiteSpace($jarPath)) { continue }

        $isJavaJar = [bool]($line -match '(?i)\bjava(?:w)?(?:\.exe)?\b.*\s-jar(?:\s|=)')
        $when = if ($lineDate) { $lineDate } elseif ($lastDate) { $lastDate } else { $null }

        # The log wraps the real launch inside CreateProcess(exe, "full command").
        # Keep that full command so the checker shows what actually ran, not only
        # the jar name.
        $command = $line.Trim()
        $createMatch = $createRx.Match($line)
        if ($createMatch.Success) {
            $command = '"' + $createMatch.Groups['command'].Value.Trim()
        }

        $map[$jarPath] = [pscustomobject]@{
            Jar     = $jarPath
            Command = $command
            Date    = $when
            JavaJar = $isJavaJar
        }
    }

    return @($map.Values | Sort-Object Date)
}

$script:LogIdSets['System'] = @(104, 6005)
$script:LogIdSets['Security'] = @(1102, 4616)
$script:LogIdSets['Microsoft-Windows-Ntfs/Operational'] = @(3079)
$script:LogIdSets['Microsoft-Windows-PowerShell/Operational'] = @(4103)

function Get-LogEvidenceMap {
    param([string]$LogName)

    if ($script:LogBatchCache.ContainsKey($LogName)) { return $script:LogBatchCache[$LogName] }

    $entry = [pscustomobject]@{
        Status = 'None'
        Times  = @{}
        Error  = $null
    }

    $ids = @()
    if ($script:LogIdSets.ContainsKey($LogName)) { $ids = @($script:LogIdSets[$LogName]) }

    $xpath = '*'
    if ($ids.Count -gt 0) {
        $clauses = @($ids | ForEach-Object { 'EventID=' + [int]$_ })
        $xpath = '*[System[(' + ($clauses -join ' or ') + ')]]'
    }

    $batch = Get-EventLogRecords -LogName $LogName -XPath $xpath -MaxRecords 1000 -IncludeValues:$false
    switch ($batch.Status) {
        'Readable' {
            $entry.Status = 'Readable'
            foreach ($record in $batch.Records) {
                $recordId = [int]$record.Id
                $created = $record.TimeCreated
                if (-not $entry.Times.ContainsKey($recordId)) {
                    $entry.Times[$recordId] = $created
                } elseif ($created -and (-not $entry.Times[$recordId] -or $created -gt $entry.Times[$recordId])) {
                    $entry.Times[$recordId] = $created
                }
            }
        }
        'Log missing' { $entry.Status = 'Log missing' }
        'Access denied' { $entry.Status = 'Access denied' }
        default {
            $entry.Status = 'Read error'
            $entry.Error = $batch.Error
        }
    }

    $script:LogBatchCache[$LogName] = $entry
    return $entry
}

function Get-LastEvent {
    param([string]$LogName, [int]$EventId)

    $cacheKey = "$LogName|$EventId"
    if ($script:LastEventCache.ContainsKey($cacheKey)) { return $script:LastEventCache[$cacheKey] }

    $result = [pscustomobject]@{
        Status = 'None'
        Time   = $null
        Error  = $null
    }

    $map = Get-LogEvidenceMap -LogName $LogName
    switch ($map.Status) {
        'Log missing'   { $result.Status = 'Log missing' }
        'Access denied' { $result.Status = 'Access denied' }
        'Read error'    { $result.Status = 'Read error'; $result.Error = $map.Error }
        default {
            if ($map.Times.ContainsKey([int]$EventId)) {
                $result.Status = 'Found'
                $result.Time = $map.Times[[int]$EventId]
            }
        }
    }

    $script:LastEventCache[$cacheKey] = $result
    return $result
}

function Get-ServiceEventItem {
    param($Data, [string]$Key)

    $normalized = $Key.ToLowerInvariant()
    if (-not $Data.Items.ContainsKey($normalized)) {
        $Data.Items[$normalized] = [Collections.Generic.List[datetime]]::new()
    }
    return $Data.Items[$normalized]
}

function Get-ServiceEventData {
    if ($null -ne $script:ServiceEventCache) { return $script:ServiceEventCache }

    $data = [pscustomobject]@{
        Items      = @{}
        ReadError  = $false
        LogCleared = $false
    }

    $since = if ($script:BootTime) { $script:BootTime.AddSeconds(-5) } else { (Get-Date).AddDays(-7) }
    $stamp = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture)
    # Filtering by time in XPath avoids walking months of service events when a
    # machine has a busy System log. The 5-second grace keeps boot-time events.
    $serviceXPath = "*[System[Provider[@Name='Service Control Manager'] and EventID=7036 and TimeCreated[@SystemTime>='$stamp']]]"
    $batch = Get-EventLogRecords -LogName 'System' -XPath $serviceXPath -MaxRecords 5000

    if ($batch.Status -ne 'Readable') {
        $data.ReadError = $true
        $script:ServiceEventCache = $data
        return $data
    }

    foreach ($eventRecord in $batch.Records) {
        if ($since -and $eventRecord.TimeCreated -and $eventRecord.TimeCreated -lt $since) { continue }

        $values = @($eventRecord.Values)
        if ($values.Count -eq 0) { continue }

        $key = [string]$values[0]
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        if ($script:DisplayToName.ContainsKey($key)) { $key = $script:DisplayToName[$key] }
        if (-not $script:ServiceByName.ContainsKey($key)) { continue }

        $item = Get-ServiceEventItem -Data $data -Key $key
        if ($eventRecord.TimeCreated) { $item.Add($eventRecord.TimeCreated) }
    }

    foreach ($item in $data.Items.Values) {
        if ($item.Count -gt 1) { $item.Sort() }
    }

    if ($script:BootTime) {
        $clear = Get-LastEvent -LogName 'System' -EventId 104
        if ($clear.Status -eq 'Found' -and $clear.Time -and $clear.Time -gt $script:BootTime) {
            $data.LogCleared = $true
        }
    }

    $script:ServiceEventCache = $data
    return $data
}

# --- Instantaneas del sistema ------------------------------------------------
$script:RunDate = Get-Date

$osItems = @(Get-CimOrWmiData -ClassName Win32_OperatingSystem -Property Caption, LastBootUpTime)
$script:OsInfo = $osItems | Select-Object -First 1
if (-not $script:OsInfo) { $script:OsInfo = Get-OsInfoFallback }
if (-not $script:OsInfo) { Add-Issue 'System' 'No se pudo consultar la información del sistema operativo' }

$script:BootTime = $null
if ($script:OsInfo -and $script:OsInfo.LastBootUpTime) {
    if ($script:OsInfo.LastBootUpTime -is [datetime]) {
        $script:BootTime = [datetime]$script:OsInfo.LastBootUpTime
    } else {
        try { $script:BootTime = [Management.ManagementDateTimeConverter]::ToDateTime([string]$script:OsInfo.LastBootUpTime) } catch {}
    }
}
$script:OsCaption = if ($script:OsInfo -and $script:OsInfo.Caption) { ([string]$script:OsInfo.Caption).Trim() } else { 'Windows' }

$script:Processes = @(Get-CimOrWmiData -ClassName Win32_Process -Property Name, ProcessId, ParentProcessId, CommandLine, CreationDate, ExecutablePath)
if ($script:Processes.Count -eq 0) {
    $processFallback = [Collections.Generic.List[object]]::new()
    foreach ($liveProcess in @(Get-Process -ErrorAction SilentlyContinue)) {
        $processPath = $null
        $processStart = $null
        try { $processPath = [string]$liveProcess.Path } catch {}
        try { $processStart = $liveProcess.StartTime } catch {}

        $processName = [string]$liveProcess.ProcessName
        if ($processName -and $processName -notmatch '(?i)\.exe$') { $processName += '.exe' }

        $processFallback.Add([pscustomobject]@{
            Name            = $processName
            ProcessId       = [int]$liveProcess.Id
            ParentProcessId = 0
            CommandLine     = $null
            CreationDate    = $processStart
            ExecutablePath  = $processPath
        })
    }
    $script:Processes = $processFallback.ToArray()
}
if ($script:Processes.Count -eq 0) { Add-Issue 'Processes' 'No se pudo obtener la lista de procesos' }

# WMI returns CreationDate as a CIM_DATETIME string while CIM returns a real
# DateTime. Normalize once so uptime and start-time formatting never fail on a
# machine where only classic WMI is available.
$normalizedProcesses = [Collections.Generic.List[object]]::new()
foreach ($processEntry in $script:Processes) {
    $created = $processEntry.CreationDate
    if ($created -and $created -isnot [datetime]) {
        try { $created = [Management.ManagementDateTimeConverter]::ToDateTime([string]$created) } catch { $created = $null }
    }
    $normalizedProcesses.Add([pscustomobject]@{
        Name            = [string]$processEntry.Name
        ProcessId       = [int]$processEntry.ProcessId
        ParentProcessId = [int]$processEntry.ParentProcessId
        CommandLine     = [string]$processEntry.CommandLine
        CreationDate    = $created
        ExecutablePath  = [string]$processEntry.ExecutablePath
    })
}
$script:Processes = $normalizedProcesses.ToArray()

$script:ProcessById = @{}
foreach ($processEntry in $script:Processes) {
    try { $script:ProcessById[[int]$processEntry.ProcessId] = $processEntry } catch {}
}

$script:ServiceNames = @(
    'SysMain'
    'PcaSvc'
    'DPS'
    'EventLog'
    'Schedule'
    'DiagTrack'
    'DusmSvc'
    'Appinfo'
    'DcomLaunch'
    'WSearch'
    'BAM'
)

# Only these services are reported. Get-Service takes ~25 ms for the whole
# list, while enumerating Win32_Service costs several hundred milliseconds on a
# cold WMI provider and fails entirely when WMI is broken.
$script:Services = [Collections.Generic.List[object]]::new()
foreach ($serviceName in $script:ServiceNames) {
    $controller = $null
    try { $controller = Get-Service -Name $serviceName -ErrorAction Stop } catch { continue }
    if (-not $controller) { continue }

    $serviceType = [string]$controller.ServiceType
    $isDriver = ($serviceType -match 'Driver')
    $servicePid = 0
    if ($script:NativeOk) {
        try { $servicePid = [int][PsicoNative]::GetServiceProcessId($serviceName) } catch {}
    }

    $script:Services.Add([pscustomobject]@{
        Name        = [string]$controller.Name
        DisplayName = [string]$controller.DisplayName
        State       = ConvertTo-ServiceState ([string]$controller.Status)
        StartMode   = Get-ServiceStartMode -ServiceName $serviceName -Controller $controller
        ProcessId   = $servicePid
        IsDriver    = $isDriver
    })
}
$script:Services = $script:Services.ToArray()
if ($script:Services.Count -eq 0) { Add-Issue 'Services' 'No se pudo consultar el estado de los servicios' }

$script:ServiceByName = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
$script:DisplayToName = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)

foreach ($serviceEntry in $script:Services) {
    try {
        if ($serviceEntry.Name) { $script:ServiceByName[[string]$serviceEntry.Name] = $serviceEntry }
        if ($serviceEntry.DisplayName) { $script:DisplayToName[[string]$serviceEntry.DisplayName] = [string]$serviceEntry.Name }
        if ($serviceEntry.Name) { $script:DisplayToName[[string]$serviceEntry.Name] = [string]$serviceEntry.Name }
    } catch {}
}

$script:Drives = @()
$driveInfos = @()
try { $driveInfos = @([IO.DriveInfo]::GetDrives()) } catch {}
foreach ($drive in $driveInfos) {
    try {
        $driveType = $drive.DriveType
        # Check the type before IsReady: probing a disconnected network drive
        # here can block for seconds for data that is then discarded.
        if ($driveType -ne [IO.DriveType]::Fixed -and $driveType -ne [IO.DriveType]::Removable) { continue }
        if (-not $drive.IsReady) { continue }

        $driveLabel = [string]$drive.VolumeLabel
        if ([string]::IsNullOrWhiteSpace($driveLabel)) { $driveLabel = '(no label)' }
        $driveFormat = [string]$drive.DriveFormat
        if ([string]::IsNullOrWhiteSpace($driveFormat)) { $driveFormat = 'Unknown' }

        $script:Drives += [pscustomobject]@{
            Name   = [string]$drive.Name
            Format = $driveFormat
            Label  = $driveLabel
            Type   = [string]$driveType
            Total  = [double]$drive.TotalSize
            Free   = [double]$drive.AvailableFreeSpace
        }
    } catch {}
}

function Split-CommandLine {
    param([string]$CommandLine)

    $tokens = [Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $tokens.ToArray() }

    $builder = [Text.StringBuilder]::new()
    $inQuotes = $false

    for ($i = 0; $i -lt $CommandLine.Length; $i++) {
        $character = $CommandLine[$i]

        if ($character -eq '"') {
            if ($inQuotes -and ($i + 1) -lt $CommandLine.Length -and $CommandLine[$i + 1] -eq '"') {
                [void]$builder.Append('"')
                $i++
            } else {
                $inQuotes = -not $inQuotes
            }
        } elseif ([char]::IsWhiteSpace($character) -and -not $inQuotes) {
            if ($builder.Length -gt 0) {
                $tokens.Add($builder.ToString())
                [void]$builder.Clear()
            }
        } else {
            [void]$builder.Append($character)
        }
    }

    if ($builder.Length -gt 0) { $tokens.Add($builder.ToString()) }
    return $tokens.ToArray()
}

function Get-LaunchInfo {
    param([string]$CommandLine)

    $info = [pscustomobject]@{
        IsMinecraft = $false
        GameDir     = $null
        Arguments   = [Collections.Generic.List[object]]::new()
    }

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $info }

    if ($CommandLine -match '(?i)(net\.minecraft|--gameDir|-Dminecraft|--assetIndex|fabric-loader|net\.fabricmc|cpw\.mods|theseus|lunarclient|badlion)') {
        $info.IsMinecraft = $true
    }

    $tokens = @(Split-CommandLine -CommandLine $CommandLine)
    $valueSwitches = @(
        'Dloader.addMods',
        'Dloader.modsFolder',
        'Dloader.modsDir',
        'Dfabric.addMods',
        'Dfabric.modsFolder',
        'Dfabric.modsDir',
        'javaagent',
        'workdir',
        'gameDir',
        'DgameDir'
    )

    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $token = $tokens[$i]
        if (-not $token.StartsWith('-')) { continue }

        $raw = $token.TrimStart('-')
        $name = $raw
        $value = $null
        $separator = $raw.IndexOfAny([char[]]@('=', ':'))

        if ($separator -ge 0) {
            $name = $raw.Substring(0, $separator)
            $value = $raw.Substring($separator + 1).Trim('"')
        } elseif (($i + 1) -lt $tokens.Count -and -not $tokens[$i + 1].StartsWith('-') -and ($valueSwitches -contains $name)) {
            $value = $tokens[$i + 1].Trim('"')
            $i++
        }

        if ($name -match '^(?:D)?gameDir$') {
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $info.GameDir = $value
                $info.IsMinecraft = $true
            }
            continue
        }

        if ($name -match '^(?:Dloader\.(?:addMods|modsFolder|modsDir)|Dfabric\.(?:addMods|modsFolder|modsDir)|javaagent|workdir)$') {
            $info.Arguments.Add([pscustomobject]@{
                Name  = $name
                Value = if ($null -ne $value) { $value } else { '(no value)' }
            })
            if ($name -match '^(?:Dloader|Dfabric)\.') { $info.IsMinecraft = $true }
        }
    }

    return $info
}

# --- Banner -------------------------------------------------------------------
$psicoBanner = @(
    '██████╗  ███████╗ ██╗  ██████╗  ██████╗',
    '██╔══██╗ ██╔════╝ ██║ ██╔════╝ ██╔═══██╗',
    '██████╔╝ ███████╗ ██║ ██║      ██║   ██║',
    '██╔═══╝  ╚════██║ ██║ ██║      ██║   ██║',
    '██║      ███████║ ██║ ╚██████╗ ╚██████╔╝',
    '╚═╝      ╚══════╝ ╚═╝  ╚═════╝  ╚═════╝'
)

$checkerBanner = @(
    ' ██████╗ ██╗  ██╗ ███████╗  ██████╗ ██╗  ██╗ ███████╗ ██████╗',
    '██╔════╝ ██║  ██║ ██╔════╝ ██╔════╝ ██║ ██╔╝ ██╔════╝ ██╔══██╗',
    '██║      ███████║ █████╗   ██║      █████╔╝  █████╗   ██████╔╝',
    '██║      ██╔══██║ ██╔══╝   ██║      ██╔═██╗  ██╔══╝   ██╔══██╗',
    '╚██████╗ ██║  ██║ ███████╗ ╚██████╗ ██║  ██╗ ███████╗ ██║  ██║',
    ' ╚═════╝ ╚═╝  ╚═╝ ╚══════╝  ╚═════╝ ╚═╝  ╚═╝ ╚══════╝ ╚═╝  ╚═╝'
)

Write-Gradient ('╔' + ('═' * $script:PanelInner) + '╗') $script:FrameFrom $script:FrameTo
Write-Gradient ('║' + (' ' * $script:PanelInner) + '║') $script:FrameFrom $script:FrameTo
foreach ($row in $psicoBanner) {
    Write-Gradient ('║' + (Center-Inner $row $script:PanelInner) + '║') $script:BannerFrom $script:BannerTo
}
Write-Gradient ('║' + (' ' * $script:PanelInner) + '║') $script:FrameFrom $script:FrameTo
foreach ($row in $checkerBanner) {
    Write-Gradient ('║' + (Center-Inner $row $script:PanelInner) + '║') $script:BannerFrom $script:BannerTo
}
Write-Gradient ('║' + (' ' * $script:PanelInner) + '║') $script:FrameFrom $script:FrameTo
Write-Gradient ('║' + (Center-Inner '»» @psicoseado ««' $script:PanelInner) + '║') $script:FrameFrom $script:FrameTo
Write-Gradient ('║' + (' ' * $script:PanelInner) + '║') $script:FrameFrom $script:FrameTo
Write-Gradient ('╚' + ('═' * $script:PanelInner) + '╝') $script:FrameFrom $script:FrameTo
Write-Host ''

$infoLine1 = '  EQUIPO   : ' + $env:COMPUTERNAME.PadRight(24) + 'USUARIO : ' + $env:USERNAME
$infoLine2 = '  SISTEMA  : ' + $script:OsCaption
$infoLine3 = '  FECHA    : ' + $script:RunDate.ToString('dd-MM-yyyy HH:mm:ss')

Write-Gradient ('╔' + ('═' * $script:PanelInner) + '╗') $script:FrameFrom $script:FrameTo
foreach ($line in @($infoLine1, $infoLine2, $infoLine3)) {
    if ($line.Length -gt $script:PanelInner) { $line = $line.Substring(0, $script:PanelInner) }
    Write-Host '║' -ForegroundColor $script:FrameColor -NoNewline
    Write-Host $line.PadRight($script:PanelInner) -ForegroundColor $script:TextColor -NoNewline
    Write-Host '║' -ForegroundColor $script:FrameColor
}
Write-Gradient ('╚' + ('═' * $script:PanelInner) + '╝') $script:FrameFrom $script:FrameTo
Write-Host ''

# --- INFORMACION GENERAL ------------------------------------------------------
Write-SectionHeader 'GENERAL INFORMATION'

Write-SubSection 'System boot time'
if ($script:BootTime) {
    $upTime = $script:RunDate - $script:BootTime
    Write-Host ($script:InfoIndex + 'Last Boot:'.PadRight($script:FieldWidth)) -ForegroundColor $script:TextColor -NoNewline
    Write-Host ($script:BootTime.ToString($script:FormatDate) + ' ') -ForegroundColor $script:SuccessColor -NoNewline
    Write-Host ('(' + (Format-Duration $upTime) + ')') -ForegroundColor $script:TextColor
} else {
    Write-Field 'Last Boot:' 'Unknown' $script:FieldWidth $script:TextColor $script:WarnColor
}

Write-Host ''
Write-SubSection 'Connected drives'
if ($script:Drives.Count -gt 0) {
    $firstDrive = $true
    foreach ($drive in $script:Drives) {
        if (-not $firstDrive) {
            Write-Host ''
            Write-ThinSeparator
        }
        $firstDrive = $false

        Write-Host ($script:InfoIndex + $drive.Name + '  ' + $drive.Format + '  ' + $drive.Label + '  [' + $drive.Type + ']') -ForegroundColor $script:TitleColor

        $used = [Math]::Max(0.0, $drive.Total - $drive.Free)

        Write-Field 'Capacity:' (Format-Bytes $drive.Total) $script:FieldWidth $script:TextColor $script:SubtColor
        Write-Field 'Free:' (Format-Bytes $drive.Free) $script:FieldWidth $script:TextColor $script:SubtColor
        if ($drive.Total -gt 0) {
            Write-UsageBar 'Used:' (($used / $drive.Total) * 100) ((Format-Bytes $used) + ' used')
        }
    }
} else {
    Write-Host ($script:InfoIndex + 'No fixed or removable drives found.') -ForegroundColor $script:SubtColor
}

Write-Host ''
Write-SubSection 'Minecraft Information'
$javaProcesses = @($script:Processes | Where-Object { $_.Name -and $_.Name -match '^(?i)java(w)?\.exe$' })
$foundAnyMc = $false

foreach ($processEntry in $javaProcesses) {
    $launchInfo = Get-LaunchInfo -CommandLine ([string]$processEntry.CommandLine)
    if (-not $launchInfo.IsMinecraft) { continue }

    $foundAnyMc = $true
    $processId = [int]$processEntry.ProcessId
    $liveProcess = Get-Process -Id $processId -ErrorAction SilentlyContinue
    $startTime = $processEntry.CreationDate
    if (-not $startTime -and $liveProcess) { $startTime = $liveProcess.StartTime }
    $processUpTime = if ($startTime) { $script:RunDate - $startTime } else { $null }
    $processName = if ($liveProcess -and $liveProcess.MainWindowTitle) { $liveProcess.MainWindowTitle } else { [string]$processEntry.Name }
    $gameDir = if ($launchInfo.GameDir) { $launchInfo.GameDir } else { 'Unknown' }

    Write-Host ($script:InfoIndex + "MC process found '$processName' ($processId) ") -ForegroundColor $script:TextColor -NoNewline
    Write-Host (Format-Duration $processUpTime) -ForegroundColor $script:TextColor
    Write-Field 'Folder:' $gameDir $script:FieldWidth $script:TextColor $script:SubtColor

    if ($launchInfo.Arguments.Count -gt 0) {
        Write-Host ($script:InfoIndex + 'Arguments:') -ForegroundColor $script:TextColor
        foreach ($argument in $launchInfo.Arguments) {
            Write-Host ($script:InfoIndex + '  - ' + $argument.Name + ': ') -ForegroundColor $script:SubtColor -NoNewline
            Write-Host $argument.Value -ForegroundColor $script:TextColor
        }
    }
    Write-Host ''
}

if (-not $foundAnyMc) {
    Write-Host ($script:InfoIndex + 'No Minecraft processes found.') -ForegroundColor $script:SubtColor
}

Write-Host ''
Write-SubSection 'Finding java -jar strings in this instance'
$jarLaunches = [Collections.Generic.List[object]]::new()

foreach ($processEntry in $script:Processes) {
    $commandLine = [string]$processEntry.CommandLine
    if ([string]::IsNullOrWhiteSpace($commandLine)) { continue }

    # Only java.exe/javaw.exe really launch a jar. Without this check a shell
    # whose command line mentions "java ... -jar ..." is reported as a launch.
    $processName = [string]$processEntry.Name
    $executableName = ''
    try { $executableName = [IO.Path]::GetFileName([string]$processEntry.ExecutablePath) } catch {}
    if ($processName -notmatch '(?i)^javaw?\.exe$' -and $executableName -notmatch '(?i)^javaw?\.exe$') { continue }

    if ($commandLine -notmatch '(?i)\bjava(?:w)?(?:\.exe)?\b.*?\s-jar(?:\s+|=)') { continue }

    $jarPath = ''
    $jarMatch = [regex]::Match($commandLine, '(?i)-jar(?:\s+|=)(?:"(?<jar>[^"]+)"|(?<jar>[^\s]+))')
    if ($jarMatch.Success) {
        $jarPath = $jarMatch.Groups['jar'].Value.Trim('"', "'")
        $jarPath = $jarPath.TrimEnd([char[]]@(')', ']', '}', ',', ';'))
    }

    $parentPid = [int]$processEntry.ParentProcessId
    $parentName = 'Unknown'
    $shellChain = $false
    $cursor = $parentPid
    $guard = 0

    while ($cursor -and $guard -lt 10) {
        $guard++
        $parentEntry = $script:ProcessById[$cursor]
        if (-not $parentEntry) { break }
        if ($parentName -eq 'Unknown') { $parentName = [string]$parentEntry.Name }
        if ([string]$parentEntry.Name -match '^(?i)explorer\.exe$') { $shellChain = $true }
        $next = [int]$parentEntry.ParentProcessId
        if ($next -eq $cursor) { break }
        $cursor = $next
    }

    $jarLaunches.Add([pscustomobject]@{
        ProcessId  = [int]$processEntry.ProcessId
        Name       = [string]$processEntry.Name
        Created    = $processEntry.CreationDate
        ParentName = $parentName
        ParentPid  = $parentPid
        ShellChain = $shellChain
        Jar        = $jarPath
    })
}

if ($jarLaunches.Count -eq 0) {
    Write-Host ($script:InfoIndex + 'No java -jar strings found.') -ForegroundColor $script:SubtColor
} else {
    Write-Field 'Found:' ([string]$jarLaunches.Count) $script:FieldWidth $script:TextColor $script:SubtColor
    $counter = 0
    foreach ($launch in $jarLaunches) {
        $counter++
        $launchDate = Format-Time $launch.Created
        $jarText = if ($launch.Jar) { $launch.Jar } else { 'Unknown' }
        Write-Host ($script:InfoIndex + "  $counter. $launchDate  PID $($launch.ProcessId)  $($launch.Name)") -ForegroundColor $script:TitleColor
        Write-Host ($script:InfoIndex + '     |- Jar:    ') -ForegroundColor $script:SubtColor -NoNewline
        Write-Host $jarText -ForegroundColor $script:TextColor
        Write-Host ($script:InfoIndex + '     |- Parent: ') -ForegroundColor $script:SubtColor -NoNewline
        Write-Host ("$($launch.ParentName) ($($launch.ParentPid))") -ForegroundColor $script:TextColor
        Write-Host ($script:InfoIndex + '     |- Shell:  ') -ForegroundColor $script:SubtColor -NoNewline
        Write-Host $(if ($launch.ShellChain) { 'Explorer chain' } else { 'No Explorer chain' }) -ForegroundColor $script:SubtColor
    }
}

# --- ESTADO DE SERVICIOS ------------------------------------------------------
Write-SectionHeader 'SERVICE STATUS'

$serviceNames = $script:ServiceNames
$serviceEventData = Get-ServiceEventData
$now = Get-Date
$bar = [char]0x2502

Write-Host ($script:InfoIndex + 'SERVICE'.PadRight(15) + ' ' + 'DISPLAY NAME'.PadRight(46) + [string]$bar + ' ' + 'STATE'.PadRight(17) + 'SINCE / ACTIVE FOR') -ForegroundColor $script:SubtColor
Write-ThinSeparator

foreach ($serviceName in $serviceNames) {
    $info = $script:ServiceByName[$serviceName]
    if (-not $info) {
        Write-Host ($script:InfoIndex + $serviceName.PadRight(15) + ' ' + '-'.PadRight(46) + [string]$bar + ' ') -ForegroundColor $script:WarnColor -NoNewline
        Write-Host ('Not found'.PadRight(17)) -ForegroundColor $script:WarnColor -NoNewline
        Write-Host '-' -ForegroundColor $script:SubtColor
        continue
    }

    $isDriver = [bool]$info.IsDriver
    $state = [string]$info.State
    if ([string]$info.StartMode -eq 'Disabled') { $state = 'Disabled' }

    $eventInfo = $null
    if ($serviceEventData.Items.ContainsKey($serviceName.ToLowerInvariant())) {
        $eventInfo = $serviceEventData.Items[$serviceName.ToLowerInvariant()]
    }

    $stateSince = $null
    $estimated = $false
    $eventCount = if ($eventInfo) { $eventInfo.Count } else { 0 }
    $parityMatches = (($state -eq 'Running' -and ($eventCount % 2) -eq 1) -or
                      (($state -eq 'Stopped' -or $state -eq 'Disabled') -and ($eventCount % 2) -eq 0))

    # A 7036 start/stop pair gives the exact per-service time. Without events,
    # the process start is the best value available, but a shared process starts
    # once for several services, so it is marked with a tilde.
    if (-not $serviceEventData.ReadError -and -not $serviceEventData.LogCleared -and $eventCount -gt 0 -and $parityMatches) {
        $stateSince = $eventInfo[$eventCount - 1]
    } elseif ($isDriver -and $script:BootTime) {
        $stateSince = $script:BootTime
        $estimated = $true
    } else {
        $processId = 0
        if (-not $isDriver -and [int]$info.ProcessId -gt 0) { $processId = [int]$info.ProcessId }
        if ($state -eq 'Running' -and $processId -gt 0 -and $script:ProcessById.ContainsKey($processId)) {
            $stateSince = $script:ProcessById[$processId].CreationDate
            $estimated = $true
        }
    }

    $timeText = 'Unknown'
    $durationText = 'Unknown'
    $mark = ''
    if ($state -eq 'Disabled') {
        $timeText = '-'
        $durationText = '-'
    } elseif ($stateSince) {
        $span = $now - $stateSince
        if ($span.Ticks -lt 0) { $span = [TimeSpan]::Zero }
        $mark = if ($estimated) { '~' } else { '' }
        $timeText = $mark + $stateSince.ToString('HH:mm:ss')
        $durationText = $mark + (Format-Duration $span)
    }

    $displayName = [string]$info.DisplayName
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $serviceName }
    if ($displayName.Length -gt 46) { $displayName = $displayName.Substring(0, 43) + '...' }

    $stateColor = switch ($state) {
        'Running'  { $script:RunningColor }
        'Stopped'  { $script:WarnColor }
        'Disabled' { $script:WarnColor }
        default    { $script:WarnColor }
    }

    Write-Host ($script:InfoIndex + $serviceName.PadRight(15) + ' ') -ForegroundColor $script:TitleColor -NoNewline
    Write-Host ($displayName.PadRight(46)) -ForegroundColor $script:TextColor -NoNewline
    Write-Host ([string]$bar + ' ') -ForegroundColor $script:SubtColor -NoNewline
    Write-Host ($state.PadRight(17)) -ForegroundColor $stateColor -NoNewline
    $tail = if ($state -eq 'Disabled' -or -not $stateSince) {
        $durationText
    } else {
        "$timeText ($durationText)"
    }
    Write-Host $tail -ForegroundColor $script:SubtColor
}

if ($serviceEventData.ReadError) {
    Write-Host ''
    Write-Host ($script:InfoIndex + 'System log unreadable; times are process or boot estimates.') -ForegroundColor $script:WarnColor
} elseif ($serviceEventData.LogCleared) {
    Write-Host ''
    Write-Host ($script:InfoIndex + 'System log cleared after boot; times are process or boot estimates.') -ForegroundColor $script:WarnColor
}

# --- EVIDENCIA DE EVENTOS -----------------------------------------------------
Write-SectionHeader 'EVENT LOG EVIDENCE'

$eventLogItems = @(
    @{
        Message  = 'USN Journal Cleared'
        Log      = '(Ntfs/Operational 3079)'
        LogName  = 'Microsoft-Windows-Ntfs/Operational'
        Registry = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Ntfs/Operational'
        EventId  = 3079
        Alert    = $true
    },
    @{
        Message  = 'Event Logs Cleared'
        Log      = '(System 104)'
        LogName  = 'System'
        Registry = 'SYSTEM\CurrentControlSet\Services\EventLog\System'
        EventId  = 104
        Alert    = $true
    },
    @{
        Message  = 'Security Log Cleared'
        Log      = '(Security 1102)'
        LogName  = 'Security'
        Registry = 'SYSTEM\CurrentControlSet\Services\EventLog\Security'
        EventId  = 1102
        Alert    = $true
    },
    @{
        Message  = 'EventLog Started'
        Log      = '(System 6005)'
        LogName  = 'System'
        Registry = 'SYSTEM\CurrentControlSet\Services\EventLog\System'
        EventId  = 6005
    },
    @{
        Message  = 'System time changed'
        Log      = '(Security 4616)'
        LogName  = 'Security'
        Registry = 'SYSTEM\CurrentControlSet\Services\EventLog\Security'
        EventId  = 4616
        Alert    = $true
    },
    @{
        Message  = 'Last executed pipeline'
        Log      = '(PowerShell/Operational 4103)'
        LogName  = 'Microsoft-Windows-PowerShell/Operational'
        Registry = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational'
        EventId  = 4103
    }
)

foreach ($item in $eventLogItems) {
    $lastEvent = Get-LastEvent -LogName $item.LogName -EventId $item.EventId

    $eventText = 'Unknown'
    $eventColor = $script:SubtColor
    switch ($lastEvent.Status) {
        'Found' {
            $eventText = Format-Time $lastEvent.Time
            $eventColor = if ($item.Alert) { $script:WarnColor } else { $script:TextColor }
        }
        'None' {
            $eventText = 'No records found'
            $eventColor = $script:SubtColor
        }
        'Log missing' {
            $eventText = 'Log not found'
            $eventColor = $script:SubtColor
        }
        'Access denied' {
            $eventText = 'Access denied'
            $eventColor = $script:WarnColor
            Add-Issue 'Event logs' "Acceso denegado a $($item.LogName) (ID $($item.EventId))"
        }
        'Read error' {
            $eventText = 'Unreadable'
            $eventColor = $script:WarnColor
            Add-Issue 'Event logs' "No se pudo leer $($item.LogName) (ID $($item.EventId)): $($lastEvent.Error)"
        }
        default {
            $eventText = 'Unreadable'
            $eventColor = $script:WarnColor
            Add-Issue 'Event logs' "No se pudo leer $($item.LogName) (ID $($item.EventId))"
        }
    }

    $regInfo = Get-RegInfo -Path ("HKLM:\" + $item.Registry)
    $lastWriteText = if ($regInfo.LastWrite) { Format-Time $regInfo.LastWrite } else { 'Unknown' }

    Write-Host ($script:TitleIndex + $item.Message.PadRight(24) + ': ') -ForegroundColor $script:TextColor -NoNewline
    Write-Host ($eventText.PadRight(20) + ' ') -ForegroundColor $eventColor -NoNewline
    Write-Host $item.Log -ForegroundColor $script:SubtColor
    $lastWriteColor = if ($item.Alert -and $lastEvent.Status -eq 'Found') { $script:WarnColor } else { $script:SubtColor }
    Write-Field 'Last modified:' $lastWriteText $script:FieldWidth $script:TextColor $lastWriteColor
    Write-Host ''
}

# --- ARCHIVOS COMUNES ---------------------------------------------------------
Write-SectionHeader 'COMMON FILES'

Write-SubSection 'Recycle Bin'
$recycle = Get-RecycleData
if ($recycle.Status -eq 'Present') {
    $countText = [string]$recycle.Count
    if ($recycle.Partial) { $countText += ' (partial)' }
    $lastText = if ($recycle.Count -gt 0) { $recycle.LastPath } else { 'No deleted items' }
    $lastTimeText = if ($recycle.LastTime) { Format-Time $recycle.LastTime } else { 'N/A' }
    $modifiedText = if ($recycle.Modified) { Format-Time $recycle.Modified } else { 'Unknown' }

    Write-Field 'Total Items:' $countText $script:FieldWidth $script:TextColor $script:SubtColor
    Write-Field 'Last Deleted Item:' $lastText $script:FieldWidth $script:TextColor $script:SubtColor
    Write-Field 'Deleted At:' $lastTimeText $script:FieldWidth $script:TextColor $script:SubtColor
    Write-Field 'Modified Time:' $modifiedText $script:FieldWidth $script:TextColor $script:SubtColor
} else {
    Write-Host ($script:InfoIndex + "$($recycle.Path) not found.") -ForegroundColor $script:SubtColor
}

Write-Host ''
Write-SubSection 'Console Host History'
$historyPath = $null
try {
    if (Get-Command Get-PSReadLineOption -ErrorAction SilentlyContinue) {
        $historyPath = (Get-PSReadLineOption).HistorySavePath
    }
} catch {}
if ([string]::IsNullOrWhiteSpace($historyPath)) {
    $historyPath = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
}

if ((Get-PathStatus $historyPath) -ne 'Missing') {
    $historyItem = Get-Item -LiteralPath $historyPath -Force -ErrorAction SilentlyContinue
    if ($historyItem) {
        $lastLine = $null
        $historyError = $null
        try {
            $lastLine = Get-Content -LiteralPath $historyPath -Tail 1 -ErrorAction Stop
        } catch {
            $historyError = $_.Exception.Message
            Add-Issue 'Console history' "No se pudo leer $historyPath : $($_.Exception.Message)"
        }

        if ($historyError) {
            $lastCommand = 'Unreadable'
        } elseif ($lastLine) {
            $lastLine = ([string]$lastLine).Trim()
            if ($lastLine -eq '}') {
                $lastCommand = 'ScriptBlock'
            } elseif ($lastLine) {
                $lastCommand = $lastLine
            } else {
                $lastCommand = '(empty)'
            }
        } else {
            $lastCommand = '(empty)'
        }

        Write-Field 'Last Command:' $lastCommand $script:FieldWidth $script:TextColor $(if ($historyError) { $script:WarnColor } else { $script:SubtColor })
        Write-Field 'File Attributes:' $historyItem.Attributes.ToString() $script:FieldWidth $script:TextColor $script:SubtColor
        Write-Field 'Modified Time:' (Format-Time $historyItem.LastWriteTime) $script:FieldWidth $script:TextColor $script:SubtColor
    } else {
        Write-Host ($script:InfoIndex + 'History file not accessible.') -ForegroundColor $script:WarnColor
    }
} else {
    Write-Host ($script:InfoIndex + 'History file not found.') -ForegroundColor $script:SubtColor
}

function Get-HostsEntryType {
    param([string]$Line)

    $clean = $Line
    $commentIndex = $clean.IndexOf('#')
    if ($commentIndex -ge 0) { $clean = $clean.Substring(0, $commentIndex) }
    $clean = $clean.Trim()
    if ([string]::IsNullOrWhiteSpace($clean)) { return 'Empty' }

    $parts = @($clean -split '\s+' | Where-Object { $_ -ne '' })
    if ($parts.Count -lt 2) { return 'Malformed' }

    $localNames = @(
        'localhost', 'localhost.localdomain', 'local', 'broadcasthost',
        'ip6-localhost', 'ip6-loopback', 'ip6-localnet', 'ip6-mcastprefix',
        'ip6-allnodes', 'ip6-allrouters', 'ip6-allhosts'
    )

    $hostNames = @($parts[1..($parts.Count - 1)] | ForEach-Object { $_.ToLowerInvariant() })
    $allLocal = $true
    foreach ($hostName in $hostNames) {
        if ($localNames -notcontains $hostName) { $allLocal = $false; break }
    }

    $ip = $null
    $parsed = [Net.IPAddress]::TryParse($parts[0], [ref]$ip)
    if (-not $parsed) {
        if ($allLocal -and $parts[0] -match '^(?i)(::1|127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.255|fe80:[0-9a-f:]+%[^\s]+)$') { return 'Local' }
        return 'Malformed'
    }

    $bytes = $ip.GetAddressBytes()
    $isLoopback = $false
    $isUnspecified = $false
    $isBroadcast = $false
    $isPrivate = $false

    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        $isLoopback = ($bytes[0] -eq 127)
        $isUnspecified = ($bytes[0] -eq 0 -and $bytes[1] -eq 0 -and $bytes[2] -eq 0 -and $bytes[3] -eq 0)
        $isBroadcast = ($bytes[0] -eq 255 -and $bytes[1] -eq 255 -and $bytes[2] -eq 255 -and $bytes[3] -eq 255)
        $isPrivate = ($bytes[0] -eq 10) -or
                     ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
                     ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
                     ($bytes[0] -eq 169 -and $bytes[1] -eq 254)
    } else {
        $isLoopback = [Net.IPAddress]::IsLoopback($ip)
        $isUnspecified = $ip.Equals([Net.IPAddress]::IPv6Any)
        $isPrivate = $ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal
    }

    if ($allLocal -and ($isLoopback -or $isUnspecified -or $isBroadcast)) { return 'Local' }
    if ($isLoopback -or $isUnspecified) { return 'Blocklist' }
    if ($isPrivate) { return 'LAN' }
    return 'Public'
}

Write-Host ''
Write-SubSection 'Hosts'
$hostsPath = Join-Path $env:SystemRoot 'System32\Drivers\etc\hosts'
$hostsStatus = Get-PathStatus $hostsPath

if ($hostsStatus -eq 'Present') {
    $hostsItem = Get-Item -LiteralPath $hostsPath -Force -ErrorAction SilentlyContinue
    $hostsLines = @()
    $hostsError = $null
    try {
        $hostsLines = [IO.File]::ReadAllLines($hostsPath)
    } catch {
        $hostsError = $_.Exception.Message
        Add-Issue 'Hosts file' "No se pudo leer $hostsPath : $($_.Exception.Message)"
    }

    $activeCount = 0
    $localCount = 0
    $blocklistCount = 0
    $lanCount = 0
    $publicCount = 0
    $malformedCount = 0
    $publicEntries = [Collections.Generic.List[string]]::new()
    $malformedEntries = [Collections.Generic.List[string]]::new()

    foreach ($line in $hostsLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith('#')) { continue }

        $activeCount++
        switch (Get-HostsEntryType -Line $trimmed) {
            'Local'     { $localCount++ }
            'Blocklist' { $blocklistCount++ }
            'LAN'       { $lanCount++ }
            'Public'    { $publicCount++; $publicEntries.Add($trimmed) }
            'Malformed' { $malformedCount++; $malformedEntries.Add($trimmed) }
        }
    }

    if ($hostsItem) {
        Write-Field 'File Attributes:' $hostsItem.Attributes.ToString() $script:FieldWidth $script:TextColor $script:SubtColor
        Write-Field 'Modified Time:' (Format-Time $hostsItem.LastWriteTime) $script:FieldWidth $script:TextColor $script:SubtColor
    }

    Write-Host ($script:InfoIndex + 'Active entries:'.PadRight($script:FieldWidth)) -ForegroundColor $script:TextColor -NoNewline
    if ($hostsError) {
        Write-Host 'Unreadable' -ForegroundColor $script:WarnColor
    } elseif ($activeCount -eq 0) {
        Write-Host 'None (default hosts file)' -ForegroundColor $script:SuccessColor
    } else {
        $parts = @("$activeCount total")
        if ($localCount -gt 0) { $parts += "$localCount local/default" }
        if ($blocklistCount -gt 0) { $parts += "$blocklistCount blocked" }
        if ($lanCount -gt 0) { $parts += "$lanCount LAN" }
        if ($publicCount -gt 0) { $parts += "$publicCount public" }
        if ($malformedCount -gt 0) { $parts += "$malformedCount malformed" }
        Write-Host ($parts -join ', ') -ForegroundColor $script:TextColor
    }

    if ($publicEntries.Count -gt 0) {
        for ($i = 0; $i -lt [Math]::Min(5, $publicEntries.Count); $i++) {
            Write-Host ($script:InfoIndex + '  |- Public mapping: ') -ForegroundColor $script:SubtColor -NoNewline
            Write-Host $publicEntries[$i] -ForegroundColor $script:WarnColor
        }
        if ($publicEntries.Count -gt 5) {
            Write-Host ($script:InfoIndex + "  |- And $($publicEntries.Count - 5) more...") -ForegroundColor $script:SubtColor
        }
    }

    if ($malformedEntries.Count -gt 0) {
        for ($i = 0; $i -lt [Math]::Min(3, $malformedEntries.Count); $i++) {
            Write-Host ($script:InfoIndex + '  |- Malformed: ') -ForegroundColor $script:SubtColor -NoNewline
            Write-Host $malformedEntries[$i] -ForegroundColor $script:WarnColor
        }
    }
} else {
    Write-Host ($script:InfoIndex + "Hosts not found in '$hostsPath'") -ForegroundColor $script:SubtColor
}

function Get-UsnInfo {
    if ($null -ne $script:UsnCache) { return $script:UsnCache }

    $result = [pscustomobject]@{
        Status = 'Unavailable'
        Error  = $null
    }

    $fsutil = Join-Path $env:SystemRoot 'System32\fsutil.exe'
    if (-not [IO.File]::Exists($fsutil)) {
        $result.Error = 'fsutil.exe not found'
        $script:UsnCache = $result
        return $result
    }

    try {
        $output = @(& $fsutil usn queryjournal $env:SystemDrive 2>&1)
        $exitCode = $LASTEXITCODE
        $text = (($output | ForEach-Object { [string]$_ }) -join "`n").Trim()

        if ($exitCode -eq 0) {
            $result.Status = 'OK'
        } else {
            $result.Error = $text
        }
    } catch {
        $result.Error = $_.Exception.Message
    }

    $script:UsnCache = $result
    return $result
}

Write-Host ''
Write-SubSection 'USNJournal ($UsnJrnl:$J)'
$usn = Get-UsnInfo
$usnPath = $env:SystemDrive + '\' + '$Extend\$UsnJrnl:$J'
$usnBasePath = $env:SystemDrive + '\' + '$Extend\$UsnJrnl'

# Creation time comes from the journal file itself. It needs the same access
# the journal has, so an unreadable value is shown as Unknown, not as evidence.
$usnFile = Get-Item -LiteralPath $usnBasePath -Force -ErrorAction SilentlyContinue
if (-not $usnFile) {
    $usnFile = Get-Item -LiteralPath $usnPath -Force -ErrorAction SilentlyContinue
}
$usnCreated = if ($usnFile) { Format-Time $usnFile.CreationTime } else { 'Unknown' }

Write-Field 'File Path:' $usnPath $script:FieldWidth $script:TextColor $script:SubtColor
Write-Field 'Created:' $usnCreated $script:FieldWidth $script:TextColor $script:SubtColor

if ($usn.Status -eq 'OK') {
    Write-Field 'State:' '$UsnJrnl:$J Intact!' $script:FieldWidth $script:TextColor $script:TextColor
} else {
    Write-Field 'State:' '$UsnJrnl:$J Missing or unreadable' $script:FieldWidth $script:TextColor $script:WarnColor
    if ($usn.Error) {
        $shortError = $usn.Error
        if ($shortError.Length -gt 160) { $shortError = $shortError.Substring(0, 160) + '...' }
        Write-Host ($script:InfoIndex + '  |- ' + $shortError) -ForegroundColor $script:WarnColor
    }
}

Write-Host ''
Write-SubSection 'TEMP'
$tmp = ''
try { $tmp = [IO.Path]::GetTempPath() } catch {}
if ([string]::IsNullOrWhiteSpace($tmp)) { $tmp = $env:TEMP }

if ($tmp -and ((Get-PathStatus $tmp) -ne 'Missing')) {
    $javaLauncherPath = Join-Path $tmp 'JavaLauncher.log'
    $javaLauncherStatus = Get-PathStatus $javaLauncherPath

    Write-Host ($script:InfoIndex + 'JavaLauncher:'.PadRight($script:FieldWidth)) -ForegroundColor $script:TextColor -NoNewline
    if ($javaLauncherStatus -eq 'Present') {
        Write-Host 'Found' -ForegroundColor $script:TextColor
        $javaLauncherItem = Get-Item -LiteralPath $javaLauncherPath -Force -ErrorAction SilentlyContinue

        if ($javaLauncherItem) {
            Write-Field 'File Attributes:' $javaLauncherItem.Attributes.ToString() $script:FieldWidth $script:TextColor $script:SubtColor
        }

        $executions = @()
        $launcherError = $null
        try {
            $executions = @(Get-JavaLauncherExecutions -Path $javaLauncherPath)
        } catch {
            $launcherError = $_.Exception.Message
            Add-Issue 'TEMP' "No se pudo leer $javaLauncherPath : $($_.Exception.Message)"
        }

        if ($launcherError) {
            Write-Field 'java -jar:' 'Unreadable' $script:FieldWidth $script:TextColor $script:WarnColor
        } elseif ($executions.Count -eq 0) {
            Write-Field 'java -jar:' 'No entries' $script:FieldWidth $script:TextColor $script:SubtColor
        } else {
            $javaJarCount = @($executions | Where-Object { $_.JavaJar }).Count
            $javaJarText = if ($javaJarCount -gt 0) { "Yes ($javaJarCount)" } else { 'Not detected' }
            $javaJarColor = if ($javaJarCount -gt 0) { $script:SuccessColor } else { $script:SubtColor }
            Write-Field 'java -jar:' $javaJarText $script:FieldWidth $script:TextColor $javaJarColor

            Write-Host ($script:InfoIndex + 'Execution(s):') -ForegroundColor $script:TextColor
            $counter = 0
            foreach ($execution in $executions) {
                $counter++
                if ($counter -gt 30) {
                    Write-Host ($script:InfoIndex + "  ... and $($executions.Count - 30) more") -ForegroundColor $script:SubtColor
                    break
                }
                $dateText = Format-Time $execution.Date
                $commandText = if ($execution.Command) { $execution.Command } else { $execution.Jar }
                Write-Host ($script:InfoIndex + "  $counter. $dateText : ") -ForegroundColor $script:SubtColor -NoNewline
                Write-Host $commandText -ForegroundColor $script:TextColor
            }
        }
    } elseif ($javaLauncherStatus -eq 'Access denied') {
        Write-Host 'Access denied' -ForegroundColor $script:WarnColor
        Add-Issue 'TEMP' "Acceso denegado a $javaLauncherPath"
    } else {
        Write-Host 'Not found' -ForegroundColor $script:SubtColor
    }

    Write-Host ''
    $jNativeHook = @()
    $jNativeError = $null
    try {
        $jNativeHook = @(Get-ChildItem -LiteralPath $tmp -Filter 'JNativeHook*' -Force -File -ErrorAction Stop | Sort-Object LastWriteTime)
    } catch {
        $jNativeError = $_.Exception.Message
        Add-Issue 'TEMP' "No se pudo enumerar JNativeHook en $tmp : $($_.Exception.Message)"
    }

    Write-Host ($script:InfoIndex + 'JNativeHook:'.PadRight($script:FieldWidth)) -ForegroundColor $script:TextColor -NoNewline
    if ($jNativeError) {
        Write-Host 'Unreadable' -ForegroundColor $script:WarnColor
    } elseif ($jNativeHook.Count -eq 0) {
        Write-Host 'None' -ForegroundColor $script:SuccessColor
    } else {
        Write-Host "$($jNativeHook.Count) file(s)" -ForegroundColor $script:TextColor
        $counter = 0
        foreach ($file in $jNativeHook) {
            $counter++
            if ($counter -gt 10) {
                Write-Host ($script:InfoIndex + "  ... and $($jNativeHook.Count - 10) more") -ForegroundColor $script:SubtColor
                break
            }
            Write-Host ($script:InfoIndex + "  $counter. $(Format-Time $file.LastWriteTime) : ") -ForegroundColor $script:SubtColor -NoNewline
            Write-Host $file.FullName -ForegroundColor $script:TextColor
        }
    }
} else {
    Write-Host ($script:InfoIndex + "$tmp not found.") -ForegroundColor $script:SubtColor
}

# --- INTEGRIDAD DE PREFETCH ---------------------------------------------------
Write-SectionHeader 'PREFETCH INTEGRITY'

$prefetch = Get-PrefetchData
$prefetchPolicy = Get-PrefetchPolicyInfo
$invalidHeaders = @($prefetch.Headers | Where-Object { $_.ReadOk -and -not $_.Valid })
$readFailures = @($prefetch.Headers | Where-Object { -not $_.ReadOk })
$validHeaders = @($prefetch.Headers | Where-Object { $_.Valid }).Count
$readOnlyCount = @($prefetch.Headers | Where-Object { $_.ReadOnly }).Count
$hiddenCount = @($prefetch.Headers | Where-Object { $_.Hidden }).Count
$readOnlyColor = if ($readOnlyCount -gt 0) { $script:WarnColor } else { $script:SubtColor }
$hiddenColor = if ($hiddenCount -gt 0) { $script:WarnColor } else { $script:SubtColor }

$prefetchStatus = 'Not found'
$prefetchColor = $script:SubtColor

if ($prefetch.Status -eq 'Present') {
    if ($prefetch.ReadError) {
        $prefetchStatus = 'Unreadable'
        $prefetchColor = $script:WarnColor
        Add-Issue 'Prefetch' "No se pudo enumerar $($prefetch.Path): $($prefetch.ReadError)"
    } elseif ($prefetch.Files.Count -eq 0) {
        $prefetchStatus = 'Empty'
        $prefetchColor = $script:SubtColor
    } elseif ($invalidHeaders.Count -gt 0) {
        $prefetchStatus = "$($invalidHeaders.Count) unexpected header(s)"
        $prefetchColor = $script:WarnColor
    } elseif ($readFailures.Count -gt 0) {
        $prefetchStatus = "$($readFailures.Count) unreadable file(s)"
        $prefetchColor = $script:WarnColor
    } else {
        $prefetchStatus = "Headers valid ($($prefetch.Files.Count) files)"
        $prefetchColor = $script:SuccessColor
    }
} elseif ($prefetch.Status -eq 'Access denied') {
    $prefetchStatus = 'Access denied'
    $prefetchColor = $script:WarnColor
    Add-Issue 'Prefetch' "Acceso denegado a $($prefetch.Path)"
} elseif ($prefetch.Status -eq 'Error') {
    $prefetchStatus = 'Unreadable'
    $prefetchColor = $script:WarnColor
    Add-Issue 'Prefetch' "No se pudo enumerar $($prefetch.Path): $($prefetch.ReadError)"
} else {
    $prefetchStatus = 'Not found'
    $prefetchColor = $script:SubtColor
}

Write-Host ($script:TitleIndex + 'Prefetch status:'.PadRight($script:FieldWidth) + $prefetchStatus) -ForegroundColor $prefetchColor
Write-Host ''

if ($prefetch.Status -eq 'Present') {
    Write-Field 'Path:' $prefetch.Path $script:FieldWidth $script:TextColor $script:SubtColor
    Write-Field 'Prefetch files:' ([string]$prefetch.Files.Count) $script:FieldWidth $script:TextColor $script:TextColor
    Write-Field 'Valid headers:' ([string]$validHeaders) $script:FieldWidth $script:TextColor $script:TextColor
    Write-Field 'Read-only:' ([string]$readOnlyCount) $script:FieldWidth $script:TextColor $readOnlyColor
    Write-Field 'Hidden:' ([string]$hiddenCount) $script:FieldWidth $script:TextColor $hiddenColor

    $newestText = if ($prefetch.Newest) { Format-Time $prefetch.Newest } else { 'N/A' }
    Write-Field 'Newest write:' $newestText $script:FieldWidth $script:TextColor $script:SubtColor

    $folderCreatedText = 'Unknown'
    $recreatedText = 'Unknown'
    $recreatedColor = $script:SubtColor
    if ($prefetch.Folder) {
        $folderCreatedText = Format-Time $prefetch.Folder.CreationTime
        if ($script:BootTime -and $prefetch.Folder.CreationTime -gt $script:BootTime) {
            $recreatedText = 'Yes (observation)'
            $recreatedColor = $script:WarnColor
        } else {
            $recreatedText = 'No'
        }
    }
    Write-Field 'Folder created:' $folderCreatedText $script:FieldWidth $script:TextColor $script:SubtColor
    Write-Field 'Created after boot:' $recreatedText $script:FieldWidth $script:TextColor $recreatedColor
    Write-Field 'Prefetch policy:' $prefetchPolicy.Text $script:FieldWidth $script:TextColor $prefetchPolicy.Color

    if ($invalidHeaders.Count -gt 0) {
        Write-Host ''
        for ($i = 0; $i -lt [Math]::Min(10, $invalidHeaders.Count); $i++) {
            $entry = $invalidHeaders[$i]
            $headerText = if ([string]::IsNullOrWhiteSpace($entry.Header)) { '(empty)' } else { $entry.Header.Trim([char[]]@([char]0)) }
            Write-Int $script:InfoIndex '-' "Header '$headerText' (expected MAM/SCCA)"
            Write-Host ($script:InfoIndex + '  |- File: ') -ForegroundColor $script:SubtColor -NoNewline
            Write-Host $entry.Name -ForegroundColor $script:TextColor
        }
        if ($invalidHeaders.Count -gt 10) {
            Write-Host ($script:InfoIndex + "  ... and $($invalidHeaders.Count - 10) more") -ForegroundColor $script:SubtColor
        }
    }

    if ($readFailures.Count -gt 0) {
        Write-Host ''
        for ($i = 0; $i -lt [Math]::Min(10, $readFailures.Count); $i++) {
            Write-Host ($script:InfoIndex + '  |- Unreadable: ' + $readFailures[$i].Name) -ForegroundColor $script:WarnColor
        }
    }

    Write-Host ''
    Write-Host ($script:InfoIndex + 'Attributes are observations, not proof of tampering.') -ForegroundColor $script:SubtColor
} else {
    Write-Host ($script:InfoIndex + "Path: $($prefetch.Path)") -ForegroundColor $script:SubtColor
}

# --- REGISTRO -----------------------------------------------------------------
Write-SectionHeader 'REGISTRY'

$registryItems = @(
    @{ Name = 'PowerShell Logging'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Key = 'EnableScriptBlockLogging'; Disabled = 0 }
    @{ Name = 'Activities Cache';    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';                 Key = 'EnableActivityFeed';         Disabled = 0 }
    @{ Name = 'Prefetch Enabled';    Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'; Key = 'EnablePrefetcher'; Disabled = 0 }
    @{ Name = 'PCA Client Enabled';  Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat';            Key = 'DisabledPCA';                Disabled = 1 }
    @{ Name = 'Command Prompt';      Path = 'HKCU:\Software\Policies\Microsoft\Windows\System';                Key = 'DisableCMD';                 Disabled = 1 }
)

foreach ($item in $registryItems) {
    $reg = Get-RegInfo -Path $item.Path -Name $item.Key
    $status = 'Unreadable'
    $statusColor = $script:WarnColor

    switch ($reg.Status) {
        'Present' {
            $value = ConvertTo-IntOrNull $reg.Value
            if ($null -eq $value) {
                $status = 'Not set'
                $statusColor = $script:SubtColor
            } elseif ($value -eq [int]$item.Disabled) {
                $status = 'Disabled'
                $statusColor = $script:WarnColor
            } else {
                $status = if ($item.Name -ne 'Command Prompt') { 'Enabled' } else { 'Available' }
                $statusColor = $script:SuccessColor
            }
        }
        'Value missing' {
            $status = 'Not configured'
            $statusColor = $script:SubtColor
        }
        'Key missing' {
            $status = 'Key missing'
            $statusColor = $script:SubtColor
        }
        'Access denied' {
            $status = 'Unreadable (access denied)'
            $statusColor = $script:WarnColor
            Add-Issue 'Registry' "Acceso denegado a $($item.Path) -> $($item.Key)"
        }
        default {
            $status = 'Unreadable'
            $statusColor = $script:WarnColor
            Add-Issue 'Registry' "No se pudo leer $($item.Path) -> $($item.Key): $($reg.Error)"
        }
    }

    $lastWriteText = if ($reg.LastWrite) { Format-RegTime $reg.LastWrite } else { 'Unknown' }
    Write-Host ($script:InfoIndex + $item.Name.PadRight($script:RegNameWidth) + ' ') -ForegroundColor $script:TextColor -NoNewline
    Write-Host ($status.PadRight(26)) -ForegroundColor $statusColor -NoNewline
    Write-Host $lastWriteText -ForegroundColor $script:SubtColor
}

function Get-DebuggerAssessment {
    param([string]$Debugger, [string]$KeyName)

    $result = [pscustomobject]@{
        Path      = $null
        Signature = 'Unknown'
        Signer    = $null
        Verdict   = 'Unknown'
        Color     = $script:SubtColor
    }

    if ([string]::IsNullOrWhiteSpace($Debugger)) {
        $result.Verdict = 'Not set'
        return $result
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($Debugger.Trim())
    $target = $expanded
    if ($target -match '^"([^"]+)"') {
        $target = $Matches[1]
    } elseif ($target -match '^(.+?\.(?:exe|com|bat|cmd|dll))(?:\s|$)') {
        $target = $Matches[1]
    } else {
        $target = ($target -split '\s+')[0]
    }

    # Path helpers throw on registry values with illegal characters, so reject
    # them before touching the file system instead of reporting a read error.
    $invalidChars = [IO.Path]::GetInvalidPathChars()
    if ([string]::IsNullOrWhiteSpace($target) -or $target.IndexOfAny($invalidChars) -ge 0) {
        $result.Verdict = 'Unreadable'
        $result.Color = $script:WarnColor
        return $result
    }

    $debuggerBase = ''
    $keyBase = ''
    try { $debuggerBase = [IO.Path]::GetFileNameWithoutExtension($target) } catch {}
    try { $keyBase = [IO.Path]::GetFileNameWithoutExtension($KeyName) } catch {}
    if ($debuggerBase -and $keyBase -and $debuggerBase -ieq $keyBase) {
        $result.Verdict = 'Self-reference (no hijack)'
        $result.Color = $script:TextColor
        return $result
    }

    if (-not [IO.Path]::IsPathRooted($target)) {
        $command = Get-Command $target -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command -and $command.Source) {
            $target = $command.Source
        } else {
            $candidates = @(
                (Join-Path $env:SystemRoot $target),
                (Join-Path $env:SystemRoot (Join-Path 'System32' $target)),
                (Join-Path $env:ProgramFiles $target)
            )
            foreach ($candidate in $candidates) {
                if ($candidate -and (Get-PathStatus $candidate) -eq 'Present') { $target = $candidate; break }
            }
        }
    }

    $result.Path = $target
    $evidence = Get-PathStatus $target
    if ($evidence -ne 'Present') {
        $result.Verdict = if ($evidence -eq 'Access denied') { 'Unreadable' } else { 'Target missing' }
        return $result
    }

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $target -ErrorAction Stop
        $result.Signature = [string]$signature.Status
        if ($signature.SignerCertificate) { $result.Signer = [string]$signature.SignerCertificate.Subject }
    } catch {}

    $extension = [IO.Path]::GetExtension($target).ToLowerInvariant()
    if ($result.Signature -eq 'Valid') {
        if ($result.Signer -match '(?i)Microsoft') {
            $result.Verdict = 'Microsoft-signed'
            $result.Color = $script:SuccessColor
        } else {
            $result.Verdict = 'Signed (third-party)'
            $result.Color = $script:WarnColor
        }
    } elseif ($extension -in @('.bat', '.cmd', '.ps1', '.vbs', '.js')) {
        $result.Verdict = 'Script (no Authenticode)'
        $result.Color = $script:WarnColor
    } elseif ($result.Signature -eq 'NotSigned') {
        $result.Verdict = 'Unsigned'
        $result.Color = $script:WarnColor
    } elseif ($result.Signature -eq 'Unknown' -or $result.Signature -eq 'Unavailable') {
        $result.Verdict = 'Signature unavailable'
        $result.Color = $script:WarnColor
    } else {
        $result.Verdict = "Signature: $($result.Signature)"
        $result.Color = $script:WarnColor
    }

    return $result
}

$ifeoSubKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$debuggers = [Collections.Generic.List[object]]::new()
$deniedKeys = [Collections.Generic.List[string]]::new()
$ifeoStatus = 'Missing'
$ifeoChecked = 0
$ifeoKey = $null

try {
    $ifeoKey = $script:RegLM.OpenSubKey($ifeoSubKey, $false)
    if ($ifeoKey) {
        $ifeoStatus = 'Present'
        try {
            $ifeoNames = @($ifeoKey.GetSubKeyNames())
            $ifeoChecked = $ifeoNames.Count
        } catch {
            $ifeoNames = @()
            Add-Issue 'IFEO' "No se pudo enumerar $ifeoSubKey : $($_.Exception.Message)"
        }

        foreach ($ifeoName in $ifeoNames) {
            $subKey = $null
            try {
                $subKey = $ifeoKey.OpenSubKey($ifeoName, $false)
                if ($subKey) {
                    $debuggerValue = $subKey.GetValue('Debugger')
                    if ($debuggerValue -and -not [string]::IsNullOrWhiteSpace([string]$debuggerValue)) {
                        $assessment = Get-DebuggerAssessment -Debugger ([string]$debuggerValue) -KeyName $ifeoName
                        $debuggers.Add([pscustomobject]@{
                            Key        = $ifeoName
                            Debugger   = [string]$debuggerValue
                            Assessment = $assessment
                        })
                    }
                }
            } catch {
                $exception = $_.Exception.GetBaseException()
                if ($exception -is [System.UnauthorizedAccessException] -or $exception -is [System.Security.SecurityException]) {
                    $deniedKeys.Add($ifeoName)
                } else {
                    Add-Issue 'IFEO' "No se pudo leer la clave $ifeoName : $($exception.Message)"
                }
            } finally {
                if ($subKey) { try { $subKey.Close() } catch {} }
            }
        }
    }
} catch {
    $exception = $_.Exception
    while ($exception.InnerException) { $exception = $exception.InnerException }
    if ($exception -is [System.UnauthorizedAccessException] -or $exception -is [System.Security.SecurityException]) {
        $ifeoStatus = 'Access denied'
        Add-Issue 'IFEO' "Acceso denegado a $ifeoSubKey"
    } else {
        $ifeoStatus = 'Error'
        Add-Issue 'IFEO' "No se pudo abrir $ifeoSubKey : $($exception.Message)"
    }
} finally {
    if ($ifeoKey) { try { $ifeoKey.Close() } catch {} }
}

$protectedIfeoPattern = '(?i)^(DefenderAgentScan|MpCmdRun|MsMpEng|NisSrv|MpUXSrv|MpSvc|MpDefenderCoreService)\.(exe|dll)$'
$notableDenied = @($deniedKeys | Where-Object { $_ -notmatch $protectedIfeoPattern })
$protectedDenied = @($deniedKeys | Where-Object { $_ -match $protectedIfeoPattern })

if ($notableDenied.Count -gt 0) {
    Add-Issue 'IFEO' "$($notableDenied.Count) clave(s) IFEO no se pudieron leer"
}

Write-Host ''
Write-Host ($script:InfoIndex + 'Debuggers (IFEO):'.PadRight($script:FieldWidth)) -ForegroundColor $script:TextColor -NoNewline

if ($ifeoStatus -eq 'Access denied') {
    Write-Host 'Unreadable (access denied)' -ForegroundColor $script:WarnColor
} elseif ($ifeoStatus -eq 'Error') {
    Write-Host 'Unreadable' -ForegroundColor $script:WarnColor
} elseif ($ifeoStatus -eq 'Missing') {
    Write-Host 'Not present' -ForegroundColor $script:SubtColor
} elseif ($debuggers.Count -eq 0) {
    Write-Host "None ($ifeoChecked keys checked)" -ForegroundColor $script:SuccessColor
} else {
    $allowlisted = @($debuggers | Where-Object { $_.Assessment.Verdict -in @('Microsoft-signed', 'Self-reference (no hijack)') })
    $notable = @($debuggers | Where-Object { $_.Assessment.Verdict -notin @('Microsoft-signed', 'Self-reference (no hijack)') })

    if ($notable.Count -eq 0) {
        Write-Host "None actionable ($($allowlisted.Count) allowlisted)" -ForegroundColor $script:SuccessColor
    } else {
        Write-Host "$($notable.Count) to inspect" -ForegroundColor $script:WarnColor

        $counter = 0
        foreach ($debugger in $notable) {
            $counter++
            Write-Int $script:InfoIndex $counter 'Debugger entry'
            Write-Host ($script:InfoIndex + '  |- Executable: ') -ForegroundColor $script:SubtColor -NoNewline
            Write-Host $debugger.Key -ForegroundColor $script:TextColor
            Write-Host ($script:InfoIndex + '  |- Debugger:   ') -ForegroundColor $script:SubtColor -NoNewline
            Write-Host $debugger.Debugger -ForegroundColor $debugger.Assessment.Color
            Write-Host ($script:InfoIndex + '  |- Target:     ') -ForegroundColor $script:SubtColor -NoNewline
            Write-Host $(if ($debugger.Assessment.Path) { $debugger.Assessment.Path } else { 'Unknown' }) -ForegroundColor $script:SubtColor
            Write-Host ($script:InfoIndex + '  |- Verdict:    ') -ForegroundColor $script:SubtColor -NoNewline
            Write-Host ("$($debugger.Assessment.Verdict) (signature: $($debugger.Assessment.Signature))") -ForegroundColor $debugger.Assessment.Color
        }
    }
}

if ($protectedDenied.Count -gt 0) {
    Write-Host ($script:InfoIndex + "  |- $($protectedDenied.Count) Windows-protected key(s) not readable") -ForegroundColor $script:SubtColor
}

if ($notableDenied.Count -gt 0) {
    Write-Int $script:InfoIndex '-' 'Some IFEO keys could not be read'
    for ($i = 0; $i -lt [Math]::Min(5, $notableDenied.Count); $i++) {
        Write-Host ($script:InfoIndex + '  |- ' + $notableDenied[$i]) -ForegroundColor $script:SubtColor
    }
}

# --- PROCESOS DE CAPTURA ------------------------------------------------------
Write-SectionHeader 'SCREEN CAPTURE PROCESSES'

function ConvertTo-LocalFilePath {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $path = $Value.Trim().Trim('"').Trim("'")

    if ($path -match '^(?i)file:///(.+)$') {
        $path = $Matches[1]
        try { $path = [Uri]::UnescapeDataString($path) } catch {}
        if ($path -match '^/[A-Za-z]:/') { $path = $path.Substring(1) }
    }

    $path = $path -replace '/', '\'
    if ($path -match '^[A-Za-z]:\\') { return $path }
    return $null
}

function Get-HtmlApiEvidence {
    param([string]$Path)

    $result = [pscustomobject]@{
        Strong     = $false
        Confidence = 'Low'
        Matches    = @()
    }

    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }
    if (-not [IO.File]::Exists($Path)) { return $result }

    $stream = $null
    try {
        $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($file.Length -le 0 -or $file.Length -gt 5MB) { return $result }

        $buffer = New-Object byte[] 262144
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { return $result }

        $text = [Text.Encoding]::UTF8.GetString($buffer, 0, $read)
        $screenRx  = [regex]'(?i)(getDisplayMedia|desktopCapturer|tabCapture|screencast|grabador de pantalla|grabaci[oó]n de pantalla|chromeMediaSource\s*[:=]\s*[''"]desktop)'
        $genericRx = [regex]'(?i)(MediaRecorder|canvas\.captureStream|RecordRTC)'

        $screenMatches  = @($screenRx.Matches($text)  | ForEach-Object { $_.Value.ToLowerInvariant() } | Sort-Object -Unique)
        $genericMatches = @($genericRx.Matches($text) | ForEach-Object { $_.Value.ToLowerInvariant() } | Sort-Object -Unique)
        $matches = @(@($screenMatches) + @($genericMatches) | Select-Object -Unique)

        $result.Matches = $matches
        if ($screenMatches.Count -ge 1) {
            $result.Strong = $true
            $result.Confidence = if ($screenMatches.Count -ge 2 -or $genericMatches.Count -ge 1) { 'Medium' } else { 'Low' }
        } elseif ($genericMatches.Count -ge 2) {
            $result.Strong = $true
            $result.Confidence = 'Low'
        }
    } catch {
    } finally {
        if ($stream) { $stream.Dispose() }
    }

    return $result
}

# Programs that can record, clip or capture the desktop. The key is the
# executable base name (lowercase, without extension).
$captureCatalog = @(
    @{ Key = 'obs';                Name = 'OBS Studio';                     Background = $false }
    @{ Key = 'obs32';              Name = 'OBS Studio (32-bit)';            Background = $false }
    @{ Key = 'obs64';              Name = 'OBS Studio';                     Background = $false }
    @{ Key = 'streamlabs';         Name = 'Streamlabs Desktop';             Background = $false }
    @{ Key = 'streamlabs desktop'; Name = 'Streamlabs Desktop';             Background = $false }
    @{ Key = 'streamlabs obs';     Name = 'Streamlabs OBS';                 Background = $false }
    @{ Key = 'xsplit';             Name = 'XSplit Broadcaster';             Background = $false }
    @{ Key = 'xsplit.core';        Name = 'XSplit Broadcaster';             Background = $false }
    @{ Key = 'xsplit.gamecaster';  Name = 'XSplit Gamecaster';              Background = $false }
    @{ Key = 'bandicam';           Name = 'Bandicam';                       Background = $false }
    @{ Key = 'bdcam';              Name = 'Bandicam';                       Background = $false }
    @{ Key = 'camtasia';           Name = 'Camtasia';                       Background = $false }
    @{ Key = 'camtasiastudio';     Name = 'Camtasia Studio';                Background = $false }
    @{ Key = 'camtasiarecorder';   Name = 'Camtasia Recorder';              Background = $false }
    @{ Key = 'fraps';              Name = 'Fraps';                          Background = $false }
    @{ Key = 'action';             Name = 'Mirillis Action!';               Background = $false }
    @{ Key = 'dxtory';             Name = 'Dxtory';                         Background = $false }
    @{ Key = 'flashback';          Name = 'Flashback Express';              Background = $false }
    @{ Key = 'flashbackrecorder';  Name = 'Flashback Recorder';             Background = $false }
    @{ Key = 'screenrec';          Name = 'ScreenRec';                      Background = $false }
    @{ Key = 'loom';               Name = 'Loom';                           Background = $false }
    @{ Key = 'playclaw';           Name = 'PlayClaw';                       Background = $false }
    @{ Key = 'icecreamscreenrecorder'; Name = 'Icecream Screen Recorder'; Background = $false }
    @{ Key = 'icecream screen recorder'; Name = 'Icecream Screen Recorder'; Background = $false }
    @{ Key = 'medal';              Name = 'Medal';                          Background = $false }
    @{ Key = 'outplayed';          Name = 'Outplayed';                      Background = $false }
    @{ Key = 'sharex';             Name = 'ShareX';                         Background = $false }
    @{ Key = 'snagit32';           Name = 'Snagit';                         Background = $false }
    @{ Key = 'snagitcapture';      Name = 'Snagit Capture';                 Background = $false }
    @{ Key = 'nvsphelper64';       Name = 'NVIDIA ShadowPlay/Share helper'; Background = $true }
    @{ Key = 'nvidia share';       Name = 'NVIDIA Share';                   Background = $false }
    @{ Key = 'gamebar';            Name = 'Xbox Game Bar';                  Background = $true }
    @{ Key = 'gamebarft';          Name = 'Xbox Game Bar';                  Background = $true }
    @{ Key = 'gamebarftserver';    Name = 'Xbox Game Bar';                  Background = $true }
    @{ Key = 'xboxgamebarwidgets'; Name = 'Xbox Game Bar widgets';          Background = $true }
    @{ Key = 'snippingtool';       Name = 'Snipping Tool';                  Background = $true }
    @{ Key = 'screenclippinghost'; Name = 'Snipping Tool overlay';          Background = $true }
)

$captureMap = @{}
foreach ($entry in $captureCatalog) { $captureMap[[string]$entry.Key] = $entry }

# Names from kill-screen-processes.ps1. A HashSet keeps the lookups fast and
# case-insensitive; explorer.exe is intentionally excluded because the shell
# loads the capture DLL for normal window management.
$forbiddenProcesses = @(
    'chrome', 'firefox', 'msedge', 'opera', 'opera_gx', 'brave', 'vivaldi',
    'browser', 'waterfox', 'librewolf', 'palemoon', 'tor', 'torbrowser',
    'chromium', 'ungoogled-chromium', 'epicbrowser', 'slimjet', 'comodo',
    'obs', 'obs32', 'obs64', 'streamlabs', 'camtasia', 'bandicam', 'xsplit',
    'fraps', 'action', 'dxtory', 'sharex', 'screenrec', 'flashback', 'bdcam',
    'gamebar', 'xboxgamebar', 'gamebarpresencewriter', 'broadcastdvr',
    'discord', 'discordcanary', 'discordptb', 'steam', 'steamwebhelper',
    'overwolf', 'teams', 'riotclientservices', 'epicgameslauncher',
    'nvcontainer', 'nvdisplay.container', 'nvidiashare', 'nvbackend',
    'nvsphelper64', 'nvstreamer', 'nvtray', 'nvtelemetry', 'nvfbc', 'nvifrex',
    'amdsoftware', 'radeonsoftware', 'amdxcapture', 'amdenc', 'amddvr'
)
$forbiddenSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($name in $forbiddenProcesses) { [void]$forbiddenSet.Add($name) }

$captureDetected = [Collections.Generic.List[object]]::new()
$seenCaptureNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($liveProcess in @(Get-Process -ErrorAction SilentlyContinue)) {
    $processName = [string]$liveProcess.ProcessName
    if ([string]::IsNullOrWhiteSpace($processName)) { continue }
    if ($processName -eq 'explorer') { continue }
    if ($seenCaptureNames.Contains($processName)) { continue }

    $isForbidden = $forbiddenSet.Contains($processName)
    $captureModule = $null
    if ($script:NativeOk) {
        try { $captureModule = [PsicoNative]::GetCaptureModule([int]$liveProcess.Id) } catch {}
    }
    if (-not $isForbidden -and -not $captureModule) { continue }

    $kind = if ($isForbidden -and $captureModule) {
        'Forbidden process + capture module'
    } elseif ($captureModule) {
        "Capture module: $captureModule"
    } else {
        'Forbidden process'
    }

    $processPath = ''
    try { $processPath = [string]$liveProcess.Path } catch {}

    [void]$seenCaptureNames.Add($processName)
    $captureDetected.Add([pscustomobject]@{
        Name    = $processName
        Process = $processName + '.exe'
        PID     = [int]$liveProcess.Id
        Kind    = $kind
        Path    = $processPath
    })
}

if ($captureDetected.Count -eq 0) {
    Write-Host ($script:InfoIndex + 'No forbidden or capture processes detected.') -ForegroundColor $script:SuccessColor
} else {
    Write-Host ($script:InfoIndex + 'Detected processes:') -ForegroundColor $script:WarnColor
    foreach ($item in $captureDetected) {
        Write-Host ($script:InfoIndex + ('  - {0}  [{1}, PID {2}]' -f $item.Process, $item.Kind, $item.PID)) -ForegroundColor $script:TitleColor
        if ($item.Path) {
            Write-Host ($script:InfoIndex + '      |- ' + $item.Path) -ForegroundColor $script:SubtColor
        }
    }

    $interactive = $false
    try { $interactive = (-not [Console]::IsInputRedirected) -and (-not [Console]::IsOutputRedirected) } catch {}

    if (-not $interactive) {
        Write-Host ''
        Write-Host ($script:InfoIndex + 'No console available: nothing was closed.') -ForegroundColor $script:SubtColor
    } else {
        $detectedNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($item in $captureDetected) { [void]$detectedNames.Add($item.Name) }

        Write-Host ''
        Write-Host ($script:InfoIndex + '[A] Close all detected processes') -ForegroundColor $script:TextColor
        Write-Host ($script:InfoIndex + '[B] Close one specific process') -ForegroundColor $script:TextColor
        Write-Host ($script:InfoIndex + '[C] Close all except one process') -ForegroundColor $script:TextColor
        Write-Host ($script:InfoIndex + '[Enter] Keep them running') -ForegroundColor $script:SubtColor
        $choice = ''
        try { $choice = [string](Read-Host ($script:InfoIndex + 'Select an option (A / B / C)')) } catch {}
        $choice = $choice.Trim().ToUpperInvariant()

        switch ($choice) {
            'A' {
                foreach ($item in $captureDetected) {
                    try {
                        Stop-Process -Name $item.Name -Force -ErrorAction Stop
                        Write-Host ($script:InfoIndex + "[Terminated] $($item.Process)") -ForegroundColor $script:DangerColor
                    } catch {
                        Write-Host ($script:InfoIndex + "[Error] $($item.Process): $($_.Exception.Message)") -ForegroundColor $script:WarnColor
                    }
                }
            }
            'B' {
                $target = ''
                try { $target = [string](Read-Host ($script:InfoIndex + 'Process name to close (example: chrome)')) } catch {}
                $target = $target.Trim().ToLowerInvariant().Replace('.exe', '')
                if ($detectedNames.Contains($target)) {
                    try {
                        Stop-Process -Name $target -Force -ErrorAction Stop
                        Write-Host ($script:InfoIndex + "[Terminated] $target.exe") -ForegroundColor $script:DangerColor
                    } catch {
                        Write-Host ($script:InfoIndex + "[Error] $target.exe: $($_.Exception.Message)") -ForegroundColor $script:WarnColor
                    }
                } else {
                    Write-Host ($script:InfoIndex + '[Error] Process not found in the detected list.') -ForegroundColor $script:WarnColor
                }
            }
            'C' {
                $exclude = ''
                try { $exclude = [string](Read-Host ($script:InfoIndex + 'Process name to keep (example: chrome)')) } catch {}
                $exclude = $exclude.Trim().ToLowerInvariant().Replace('.exe', '')
                if (-not $detectedNames.Contains($exclude)) {
                    Write-Host ($script:InfoIndex + '[Error] Process not found in the detected list.') -ForegroundColor $script:WarnColor
                } else {
                    foreach ($item in $captureDetected) {
                        if ($item.Name -eq $exclude) { continue }
                        try {
                            Stop-Process -Name $item.Name -Force -ErrorAction Stop
                            Write-Host ($script:InfoIndex + "[Terminated] $($item.Process)") -ForegroundColor $script:DangerColor
                        } catch {
                            Write-Host ($script:InfoIndex + "[Error] $($item.Process): $($_.Exception.Message)") -ForegroundColor $script:WarnColor
                        }
                    }
                    Write-Host ($script:InfoIndex + "[Kept] $exclude.exe") -ForegroundColor $script:SuccessColor
                }
            }
            default {
                Write-Host ($script:InfoIndex + 'No processes were closed.') -ForegroundColor $script:SubtColor
            }
        }
    }
}

# Command lines that show an active capture path even when the binary is renamed.
$commandFindings = [Collections.Generic.List[object]]::new()
$seenCommands = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$browserNames = @(
    'chrome', 'firefox', 'msedge', 'opera', 'opera_gx', 'brave', 'vivaldi',
    'browser', 'waterfox', 'librewolf', 'palemoon', 'tor', 'torbrowser',
    'chromium', 'epicbrowser', 'slimjet', 'comodo', 'msedgewebview2'
)
$appRx = [regex]'(?i)--app(?:=|\s+)(?:"(?<u>[^"]+)"|(?<u>\S+))'
$htmlRx = [regex]'(?i)(?<u>(?:[a-z]:\\|file:///)[^\s"'']+\.html?)'

foreach ($processEntry in $script:Processes) {
    if (-not $processEntry.Name) { continue }
    $processName = [string]$processEntry.Name
    $baseName = ''
    try { $baseName = [IO.Path]::GetFileNameWithoutExtension($processName).ToLowerInvariant() } catch {}
    if ([string]::IsNullOrWhiteSpace($baseName)) { continue }
    $commandLine = [string]$processEntry.CommandLine
    if ([string]::IsNullOrWhiteSpace($commandLine)) { continue }

    # FFmpeg capturing the desktop (common for scripted or disguised recorders).
    if ($baseName -eq 'ffmpeg' -and $commandLine -match '(?i)(?:^|\s)-f\s+(?:gdigrab|ddagrab)\b|(?:^|\s)-i\s+desktop\b') {
        $key = "ffmpeg|$($processEntry.ProcessId)"
        if ($seenCommands.Add($key)) {
            $commandFindings.Add([pscustomobject]@{
                Program    = 'FFmpeg desktop capture'
                ID         = "PID $($processEntry.ProcessId)"
                Detail     = $commandLine
                Confidence = 'High'
                Apis       = 'gdigrab/ddagrab'
            })
        }
        continue
    }

    # Screen-capture API used directly from a PowerShell command line.
    if ($baseName -match '^(?:powershell|pwsh|powershell_ise)$' -and $commandLine -match '(?i)CopyFromScreen') {
        $key = "powershell|$($processEntry.ProcessId)"
        if ($seenCommands.Add($key)) {
            $commandFindings.Add([pscustomobject]@{
                Program    = 'PowerShell screen capture'
                ID         = "PID $($processEntry.ProcessId)"
                Detail     = $commandLine
                Confidence = 'Medium'
                Apis       = 'Graphics.CopyFromScreen'
            })
        }
        continue
    }

    # Local HTML pages launched as browser "apps" with capture APIs.
    if ($browserNames -notcontains $baseName) { continue }

    $candidateUrl = ''
    $appMatch = $appRx.Match($commandLine)
    if ($appMatch.Success) { $candidateUrl = $appMatch.Groups['u'].Value.Trim() }

    if (-not $candidateUrl) {
        $htmlMatch = $htmlRx.Match($commandLine)
        if ($htmlMatch.Success) { $candidateUrl = $htmlMatch.Groups['u'].Value }
    }

    if (-not $candidateUrl) { continue }
    $candidatePath = ConvertTo-LocalFilePath $candidateUrl
    if (-not $candidatePath) { continue }

    $fileEvidence = Get-HtmlApiEvidence -Path $candidatePath
    if (-not $fileEvidence.Strong) { continue }

    $key = "$baseName|$candidatePath"
    if (-not $seenCommands.Add($key)) { continue }

    $commandFindings.Add([pscustomobject]@{
        Program    = "Browser page: $processName"
        ID         = "PID $($processEntry.ProcessId)"
        Detail     = $candidatePath
        Confidence = $fileEvidence.Confidence
        Apis       = ($fileEvidence.Matches -join ', ')
    })
}

# Prefetch keeps one record per executable that has run, including recorders that
# are no longer open. This is history, not proof of what was captured.
function Get-PrefetchExecutableBase {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $stem = [IO.Path]::GetFileNameWithoutExtension($Name)
    $dash = $stem.LastIndexOf('-')
    if ($dash -gt 0) { $stem = $stem.Substring(0, $dash) }
    $base = [IO.Path]::GetFileNameWithoutExtension($stem)
    if ([string]::IsNullOrWhiteSpace($base)) { return $null }
    return $base.ToLowerInvariant()
}

$prefetchHits = @()
$prefetchFiles = 0
$prefetchAvailable = $false
if ($prefetch) {
    $prefetchAvailable = ($prefetch.Status -eq 'Present')
    if ($prefetchAvailable) {
        $prefetchFiles = $prefetch.Files.Count
        $byProgram = @{}
        foreach ($file in $prefetch.Files) {
            $exeBase = Get-PrefetchExecutableBase -Name $file.Name
            if (-not $exeBase) { continue }
            $catalogEntry = $captureMap[$exeBase]
            if (-not $catalogEntry -or $catalogEntry.Background) { continue }
            if (-not $byProgram.ContainsKey($exeBase) -or $file.LastWriteTime -gt $byProgram[$exeBase].When) {
                $byProgram[$exeBase] = [pscustomobject]@{
                    Program = [string]$catalogEntry.Name
                    When    = $file.LastWriteTime
                }
            }
        }
        $prefetchHits = @($byProgram.Values | Sort-Object When -Descending)
    }
}

# Recorder configuration folders prove the program was installed and opened,
# even when no executable is running now.
$configEvidence = [Collections.Generic.List[object]]::new()
$configCandidates = @(
    @{ Path = (Join-Path $env:APPDATA 'obs-studio');   Name = 'OBS Studio' }
    @{ Path = (Join-Path $env:APPDATA 'slobs-client'); Name = 'Streamlabs Desktop' }
    @{ Path = (Join-Path $env:APPDATA 'Medal');        Name = 'Medal' }
)
foreach ($candidate in $configCandidates) {
    if (-not $candidate.Path) { continue }
    if ([IO.Directory]::Exists($candidate.Path)) {
        $configEvidence.Add([pscustomobject]@{
            Name     = $candidate.Name
            Path     = $candidate.Path
            Modified = (Get-Item -LiteralPath $candidate.Path -Force -ErrorAction SilentlyContinue).LastWriteTime
        })
    }
}

# Recorder output folders show that clips or recordings exist on disk.
$videosRoot = [Environment]::GetFolderPath('MyVideos')
if ([string]::IsNullOrWhiteSpace($videosRoot)) { $videosRoot = Join-Path $env:USERPROFILE 'Videos' }
$outputCandidates = @(
    @{ Path = (Join-Path $videosRoot 'Medal');    Name = 'Medal clips' }
    @{ Path = (Join-Path $videosRoot 'Captures'); Name = 'Xbox Game Bar/Snipping Tool captures' }
    @{ Path = (Join-Path $videosRoot 'NVIDIA');   Name = 'NVIDIA ShadowPlay clips' }
)
$outputEvidence = [Collections.Generic.List[object]]::new()
foreach ($candidate in $outputCandidates) {
    if ([string]::IsNullOrWhiteSpace($candidate.Path)) { continue }
    if (-not [IO.Directory]::Exists($candidate.Path)) { continue }

    $newestClip = $null
    try {
        $newestClip = Get-ChildItem -LiteralPath $candidate.Path -File -Recurse -Depth 3 -ErrorAction Stop |
            Where-Object { $_.Extension -match '^\.(mp4|mkv|flv|avi|mov|wmv|webm)$' } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
    } catch {}

    if ($newestClip) {
        $outputEvidence.Add([pscustomobject]@{
            Name  = $candidate.Name
            Path  = $newestClip.FullName
            When  = $newestClip.LastWriteTime
            Bytes = $newestClip.Length
        })
    }
}

if ($commandFindings.Count -gt 0 -or $prefetchHits.Count -gt 0 -or $configEvidence.Count -gt 0 -or $outputEvidence.Count -gt 0) {
    Write-Host ''
    Write-Host ($script:InfoIndex + 'Recorder evidence (history, not proof of recording):') -ForegroundColor $script:TextColor
}

if ($commandFindings.Count -gt 0) {
    Write-Host ($script:InfoIndex + 'Command-line capture evidence:') -ForegroundColor $script:TextColor
    foreach ($finding in $commandFindings) {
        Write-Host ($script:InfoIndex + ('  - {0}  [{1}]' -f $finding.Program, $finding.ID)) -ForegroundColor $script:TitleColor
        Write-Host ($script:InfoIndex + '      |- Detail:     ' + $finding.Detail) -ForegroundColor $script:SubtColor
        Write-Host ($script:InfoIndex + '      |- APIs:       ' + $finding.Apis) -ForegroundColor $script:SubtColor
        Write-Host ($script:InfoIndex + '      |- Confidence: ' + $finding.Confidence) -ForegroundColor $script:SubtColor
    }
}

if ($prefetchHits.Count -gt 0) {
    Write-Host ($script:InfoIndex + 'Recorder history in Prefetch (ran earlier, may not be running now):') -ForegroundColor $script:TextColor
    foreach ($hit in $prefetchHits) {
        Write-Host ($script:InfoIndex + ('  - {0}  [last run {1}]' -f $hit.Program, (Format-Time $hit.When))) -ForegroundColor $script:TitleColor
    }
}

if ($configEvidence.Count -gt 0) {
    Write-Host ($script:InfoIndex + 'Recorder configuration found (installed and opened at some point):') -ForegroundColor $script:TextColor
    foreach ($item in $configEvidence) {
        Write-Host ($script:InfoIndex + ('  - {0}  [last write {1}]' -f $item.Name, (Format-Time $item.Modified))) -ForegroundColor $script:TitleColor
        Write-Host ($script:InfoIndex + '      |- ' + $item.Path) -ForegroundColor $script:SubtColor
    }
}

if ($outputEvidence.Count -gt 0) {
    Write-Host ($script:InfoIndex + 'Capture output found (clips/recordings exist on disk):') -ForegroundColor $script:TextColor
    foreach ($item in $outputEvidence) {
        Write-Host ($script:InfoIndex + ('  - {0}  [newest {1}, {2}]' -f $item.Name, (Format-Time $item.When), (Format-Bytes ([double]$item.Bytes)))) -ForegroundColor $script:TitleColor
        Write-Host ($script:InfoIndex + '      |- ' + $item.Path) -ForegroundColor $script:SubtColor
    }
}

if (-not $prefetchAvailable) {
    Write-Host ''
    Write-Host ($script:InfoIndex + 'Prefetch history unavailable (disabled or unreadable), running processes were still checked.') -ForegroundColor $script:SubtColor
}

Write-Host ''
Write-Host ($script:InfoIndex + "Checked $($script:Processes.Count) processes and $prefetchFiles Prefetch records.") -ForegroundColor $script:SubtColor

# --- ERRORES DE LECTURA -------------------------------------------------------
Write-Host ''
Write-SectionHeader 'READ ERRORS'

$scanIssues = @($script:Issues | Sort-Object Area, Detail -Unique)
if ($scanIssues.Count -eq 0) {
    Write-Host ($script:InfoIndex + 'No read errors recorded.') -ForegroundColor $script:SuccessColor
} else {
    Write-Host ($script:InfoIndex + ("{0} check(s) could not be read:" -f $scanIssues.Count)) -ForegroundColor $script:WarnColor
    Write-Host ''
    foreach ($areaGroup in @($scanIssues | Group-Object Area | Sort-Object Name)) {
        Write-Host ($script:InfoIndex + '[' + $areaGroup.Name + ']') -ForegroundColor $script:TitleColor
        foreach ($issue in @($areaGroup.Group)) {
            Write-Host ($script:InfoIndex + '  |- ' + $issue.Detail) -ForegroundColor $script:WarnColor
        }
    }
    Write-Host ''
    Write-Host ($script:InfoIndex + 'Unreadable values are not proof of tampering.') -ForegroundColor $script:SubtColor
}

Write-Host ''
Write-Gradient ('╔' + ('═' * $script:PanelInner) + '╗') $script:FrameFrom $script:FrameTo
Write-Gradient ('║' + (Center-Inner 'ESCANEO COMPLETADO' $script:PanelInner) + '║') $script:FrameFrom $script:FrameTo
Write-Gradient ('╚' + ('═' * $script:PanelInner) + '╝') $script:FrameFrom $script:FrameTo
Write-Host ''
