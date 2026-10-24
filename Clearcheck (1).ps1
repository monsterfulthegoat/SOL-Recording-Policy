# SOL Recording Policy - Recording Policy (Hardened)
# All rights reserved - SOL Recording Policy

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:PSDefaultParameterValues = @{}
foreach ($__n in @(
    'Invoke-WebRequest','Invoke-RestMethod','Invoke-Expression','Test-Path','Get-Item',
    'Get-ChildItem','Get-ItemProperty','Get-ItemPropertyValue','Get-CimInstance','Get-WmiObject',
    'Get-Process','Start-Process','Get-Service','Get-WinEvent','Get-AuthenticodeSignature',
    'Get-Module','New-Item','Remove-Item','Add-Content'
)) {
    Microsoft.PowerShell.Management\Remove-Item -Path "Alias:\$__n"    -Force -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Management\Remove-Item -Path "Function:\$__n" -Force -ErrorAction SilentlyContinue
}

Clear-Host

$script:SOLVersion = '1.0.0'
$script:Brand = 'CLEARCHECK'   # <-- change this one word to rebrand everything on screen
try { $Host.UI.RawUI.WindowTitle = "$($script:Brand) v$($script:SOLVersion)" } catch {}

# ---- FAST ENTROPY ----
try {
    if (-not ('SOL.FastEntropy' -as [type])) {
        Add-Type -Namespace SOL -Name FastEntropy -MemberDefinition @'
public static double Compute(string filePath) {
    if (!System.IO.File.Exists(filePath)) return 0.0;
    try {
        using (var fs = new System.IO.FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite)) {
            int toRead = (int)System.Math.Min(fs.Length, 4194304L);
            if (toRead <= 0) return 0.0;
            byte[] buffer = new byte[toRead];
            int read = fs.Read(buffer, 0, toRead);
            if (read <= 0) return 0.0;
            int[] counts = new int[256];
            for (int i = 0; i < read; i++) counts[buffer[i]]++;
            double entropy = 0.0;
            double len = (double)read;
            for (int i = 0; i < 256; i++) {
                if (counts[i] > 0) { double p = counts[i] / len; entropy -= p * System.Math.Log(p, 2); }
            }
            return System.Math.Round(entropy, 3);
        }
    } catch { return -1.0; }
}
'@ -ErrorAction SilentlyContinue
    }
} catch {}

function Get-FileEntropy {
    param ([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return 0.0 }
    try {
        if ('SOL.FastEntropy' -as [type]) { return [SOL.FastEntropy]::Compute($FilePath) }
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -eq 0) { return 0.0 }
        $sampleLen = [Math]::Min($bytes.Length, 1048576)
        $byteCounts = @{}
        for ($i = 0; $i -lt $sampleLen; $i++) { $byteCounts[$bytes[$i]]++ }
        $entropy = 0.0; $len = [double]$sampleLen
        foreach ($count in $byteCounts.Values) { $p = $count / $len; $entropy -= $p * [Math]::Log($p, 2) }
        return [Math]::Round($entropy, 3)
    } catch { return -1.0 }
}

# ---- CONSOLE API ----
function Disable-ConsoleQuickEdit {
    try {
        if (-not ('SOL.ConsoleApi' -as [type])) {
            Add-Type -Namespace SOL -Name ConsoleApi -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
'@ -ErrorAction Stop
        }
        $stdin = [SOL.ConsoleApi]::GetStdHandle(-10)
        [uint32]$mode = 0
        if (-not [SOL.ConsoleApi]::GetConsoleMode($stdin, [ref]$mode)) { return }
        $mode = ($mode -bor 0x0080) -band (-bnot 0x0040) -band (-bnot 0x0020)
        [void][SOL.ConsoleApi]::SetConsoleMode($stdin, $mode)
    } catch {}
}

function Invoke-ConsoleRefresh {
    try { [Console]::Out.Flush() } catch {}
    try { [Console]::Error.Flush() } catch {}
}

Disable-ConsoleQuickEdit
Invoke-ConsoleRefresh

# ====================================================================
# v2.0 NEW: NATIVE PROCESS/THREAD/VM/PIPE SCAN API
# ====================================================================
function Initialize-NativeProcessScanApi {
    if ('SOL.NativePS' -as [type]) { return $true }
    try {
        Add-Type -Namespace SOL -Name NativePS -UsingNamespace System.Collections.Generic -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct PROCESSENTRY32 {
    public uint dwSize;
    public uint cntUsage;
    public uint th32ProcessID;
    public UIntPtr th32DefaultHeapID;
    public uint th32ModuleID;
    public uint cntThreads;
    public uint th32ParentProcessID;
    public int pcPriClassBase;
    public uint dwFlags;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string szExeFile;
}

[StructLayout(LayoutKind.Sequential)]
public struct THREADENTRY32 {
    public uint dwSize;
    public uint cntUsage;
    public uint th32ThreadID;
    public uint th32OwnerProcessID;
    public int tpBasePri;
    public int tpDeltaPri;
    public uint dwFlags;
}

[StructLayout(LayoutKind.Sequential)]
public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public IntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
}

[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(IntPtr hObject);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, ref MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);
[DllImport("ntdll.dll")]
public static extern int NtQueryInformationThread(IntPtr hThread, int ThreadInfoClass, ref IntPtr ThreadInfo, int InfoLength, out int ReturnLength);

public const uint TH32CS_SNAPPROCESS  = 0x00000002;
public const uint TH32CS_SNAPTHREAD   = 0x00000004;
public const uint THREAD_QUERY_INFORMATION = 0x0040;
public const uint PROCESS_QUERY_INFORMATION = 0x0400;
public const uint PROCESS_VM_READ     = 0x0010;
public const int  ThreadQuerySetWin32StartAddress = 9;
public const uint MEM_COMMIT   = 0x1000;
public const uint MEM_PRIVATE  = 0x20000;
public const uint PAGE_EXECUTE           = 0x10;
public const uint PAGE_EXECUTE_READ      = 0x20;
public const uint PAGE_EXECUTE_READWRITE = 0x40;
public const uint PAGE_EXECUTE_WRITECOPY = 0x80;

public static int[] GetAllPidsViaToolhelp() {
    var pids = new List<int>();
    IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == new IntPtr(-1)) return pids.ToArray();
    try {
        PROCESSENTRY32 e = new PROCESSENTRY32();
        e.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
        if (Process32First(snap, ref e)) {
            do { pids.Add((int)e.th32ProcessID); } while (Process32Next(snap, ref e));
        }
    } finally { CloseHandle(snap); }
    return pids.ToArray();
}

public static string[] GetInjectedThreadsForProcess(int targetPid) {
    var results = new List<string>();
    IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == new IntPtr(-1)) return results.ToArray();
    IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)targetPid);
    if (hProc == IntPtr.Zero) { CloseHandle(snap); return results.ToArray(); }
    try {
        THREADENTRY32 te = new THREADENTRY32();
        te.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));
        if (!Thread32First(snap, ref te)) return results.ToArray();
        do {
            if (te.th32OwnerProcessID != (uint)targetPid) continue;
            IntPtr hThread = OpenThread(THREAD_QUERY_INFORMATION, false, te.th32ThreadID);
            if (hThread == IntPtr.Zero) continue;
            try {
                IntPtr startAddr = IntPtr.Zero;
                int ret = 0;
                if (NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, ref startAddr, IntPtr.Size, out ret) == 0 && startAddr != IntPtr.Zero) {
                    MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
                    if (VirtualQueryEx(hProc, startAddr, ref mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) > 0) {
                        bool isExec    = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                        bool isPrivate = (mbi.Type == MEM_PRIVATE);
                        bool isCommit  = (mbi.State == MEM_COMMIT);
                        if (isExec && isPrivate && isCommit)
                            results.Add(string.Format("TID {0} -> start 0x{1:X} [private executable memory]", te.th32ThreadID, startAddr.ToInt64()));
                    }
                }
            } finally { CloseHandle(hThread); }
        } while (Thread32Next(snap, ref te));
    } finally { CloseHandle(snap); CloseHandle(hProc); }
    return results.ToArray();
}

'@ -ErrorAction Stop
        return $true
    } catch { return $false }
}

function Initialize-VmDetectionApi {
    if ('SOL.VmCheck' -as [type]) { return $true }
    try {
        Add-Type -Namespace SOL -Name VmCheck -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
    IntPtr lpSec, uint dwCreation, uint dwFlags, IntPtr hTemplate);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(IntPtr h);

public static string[] GetVmDeviceArtifacts() {
    var hits = new System.Collections.Generic.List<string>();
    string[] devs = {
        @"\\.\VMCIDev", @"\\.\vmci", @"\\.\hgfs", @"\\.\vmhgfs",
        @"\\.\VBoxGuest", @"\\.\VBoxTrayIPC", @"\\.\Hyper-V_VmbusRoot", @"\\.\balloon"
    };
    foreach (string d in devs) {
        IntPtr h = CreateFileW(d, 0xC0000000u, 0x3u, IntPtr.Zero, 3u, 0u, IntPtr.Zero);
        if (h != new IntPtr(-1)) { hits.Add(d); CloseHandle(h); }
    }
    return hits.ToArray();
}
'@ -ErrorAction Stop
        return $true
    } catch { return $false }
}

# ====================================================================
# ORIGINAL HELPER FUNCTIONS
# ====================================================================
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Open-LocalMachineRegistryKey {
    param([string]$SubKeyPath)
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        if ([string]::IsNullOrWhiteSpace($SubKeyPath)) { return $base }
        return $base.OpenSubKey($SubKeyPath)
    } catch { return $null }
}

function Add-RegistryKeyFingerprint {
    param([Microsoft.Win32.RegistryKey]$Key, [string]$Prefix, [System.Collections.Generic.List[string]]$Parts)
    foreach ($name in $Key.GetValueNames()) {
        $raw = $Key.GetValue($name)
        if ($null -eq $raw) { $Parts.Add("$Prefix|$name=") }
        elseif ($raw -is [byte[]]) { $Parts.Add("$Prefix|$name=0x$([BitConverter]::ToString($raw).Replace('-',''))") }
        else { $Parts.Add("$Prefix|$name=$raw") }
    }
    foreach ($subName in $Key.GetSubKeyNames()) {
        $subKey = $Key.OpenSubKey($subName)
        if ($subKey) { Add-RegistryKeyFingerprint -Key $subKey -Prefix "$Prefix\$subName" -Parts $Parts; $subKey.Close() }
        else { $Parts.Add("$Prefix\$subName=<missing>") }
    }
}

$script:MicrosoftCodeSigningRoots = @(
    '3B1EFD3A66EA28B16697394703A72CA340A05BD5','8F43288AD272F3103B6FB1428485EA3014C0BCFE',
    'CDD4EEAE6000AC7F40C3802C171E30148030C072','A43489159A520F0D93D032CCAF37E7FE20A8B419',
    '7F88CD7223F3C813818C994614A89C99FA3B5247','73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74',
    '999A64C37FF47D9FAB95F14769891460EEC4C3C5','06F1AA330B927B753A40E68CDF22E34BCBEF3352',
    'F40042E2E5F7E8EF8189FED15519AECE42C3BFA2'
)
$script:MicrosoftShippedRoots = $script:MicrosoftCodeSigningRoots + @(
    '31F9FC8BA3805986B721EA7295C65B3A44534274','0119E81BE9A14CD8E22F40AC118C687ECBA3F4D8',
    '92B46C76E13054E104F230517E6E504D43AB10B5','245C97DF7514E7CF2DF8BE72AE957B9E04741E85',
    'BE36A4562FB2EE05DBB3D32323ADF445084ED656','18F7C1FCC3090203FD5BAA2F861A754976C8DD25'
)
$script:AuthRootThumbprints = $null

function Get-AuthRootThumbprints {
    if ($null -ne $script:AuthRootThumbprints) { return $script:AuthRootThumbprints }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    try { Get-ChildItem 'Cert:\LocalMachine\AuthRoot' -ErrorAction Stop | ForEach-Object { [void]$set.Add($_.Thumbprint) } } catch {}
    foreach ($tp in $script:MicrosoftShippedRoots) { [void]$set.Add($tp) }
    $script:AuthRootThumbprints = $set
    return $set
}

function Test-UserInstalledRootThumbprint {
    param([string]$Thumbprint)
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $true }
    return -not (Get-AuthRootThumbprints).Contains($Thumbprint)
}

function Get-SignatureRootThumbprint {
    param($Certificate)
    if (-not $Certificate) { return $null }
    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        [void]$chain.Build($Certificate)
        if ($chain.ChainElements.Count -eq 0) { return $null }
        return $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint
    } catch { return $null }
}

function Test-SignedMicrosoftFile {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { return $false }
        if ($sig.SignerCertificate.Subject -notmatch '(?i)(Microsoft Corporation|Microsoft Windows)') { return $false }
        $root = Get-SignatureRootThumbprint -Certificate $sig.SignerCertificate
        return ($root -and ($script:MicrosoftCodeSigningRoots -contains $root))
    } catch { return $false }
}

function Test-SignedByShippedRoot {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try {
        $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { return $false }
        $root = Get-SignatureRootThumbprint -Certificate $sig.SignerCertificate
        if (-not $root) { return $false }
        return -not (Test-UserInstalledRootThumbprint -Thumbprint $root)
    } catch { return $false }
}

$script:HandleHolderTrustedPrefixes = @('\windows\system32\','\windows\syswow64\','\program files\','\program files (x86)\','\roblox\')

function Test-TrustedHandleHolder {
    param([string]$ExecutablePath)
    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) { return $false }
    $lower = $ExecutablePath.ToLower().Replace('/','\')
    $inTrustedDir = $false
    foreach ($prefix in $script:HandleHolderTrustedPrefixes) { if ($lower.Contains($prefix)) { $inTrustedDir = $true; break } }
    if (-not $inTrustedDir) { return $false }
    return (Test-SignedByShippedRoot -Path $ExecutablePath)
}

function Test-TrustedProcessPath {
    param([string]$ExecutablePath)
    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) { return $true }
    $path = $ExecutablePath.ToLower().Replace('/','\')
    $prefixes = @("$($env:SystemRoot.ToLower())\","$($env:ProgramFiles.ToLower())\")
    $pf86 = ${env:ProgramFiles(x86)}; if ($pf86) { $prefixes += "$($pf86.ToLower())\" }
    foreach ($prefix in $prefixes) { if ($path.StartsWith($prefix)) { return $true } }
    return $false
}

function Test-UserLandProcessPath {
    param([string]$ExecutablePath)
    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) { return $false }
    $path = $ExecutablePath.ToLower().Replace('/','\')
    foreach ($marker in @('\downloads\','\desktop\','\temp\')) { if ($path -like "*$marker*") { return $true } }
    return $false
}

$script:SignatureCache = @{}
function Get-CachedSignatureStatus {
    param([string]$Path)
    if (-not $Path) { return 'Unknown' }
    if ($script:SignatureCache.ContainsKey($Path)) { return $script:SignatureCache[$Path] }
    $status = 'Unknown'
    try { $status = [string](Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop).Status } catch {}
    if ($status -eq 'Valid' -and -not (Test-SignedByShippedRoot -Path $Path)) { $status = 'UntrustedRoot' }
    $script:SignatureCache[$Path] = $status
    return $status
}

# ====================================================================
# CHEAT KEYWORDS - v2.0 EXPANDED LIST
# ====================================================================
$script:CheatKeywords = @(
    # Original keywords
    'matcha','isabelle','severe','aegis','potassium','lattice','spectre','matrix','clarity',
    'loader','photon','valex','aimmy','keyauth','xeno','melatonin','evolve','serotonin',
    'ghostify','dx9ware','unicore','lumen','monolith','skript','ntfsdump','atlanta','eulen',
    'hammafia','redengine','susano','bypass','volt','fleasion',
    # v2.0 additions - executor names
    'krnl','solara','synapse','celery','hydrogen','oxygen','electron','fluxus','comet',
    'arceus','elysian','codex','sirhurt','vermillion','trigon','macsploit','acidware',
    'nihon','proxo','scriptblox','deluded','vega','krampus','wavepipe',
    # v2.0 - cheat function names (appear in pipes/processes/files)
    'getgenv','hookfunction','identifyexecutor','checkcaller','decompile','saveinstance',
    'readfile','writefile','getscripts','infiniteyield','infinite_yield',
    # v2.0 - cheat tool names
    'cheatengine','aimbot','wallhack','triggerbot','speedhack','autofarm','autoclick',
    'executor','injector','wearedevs','deltaexecutor','carbonexecutor'
)

$script:FolderOnlyKeywords = @('map')

function Test-KeywordTokenMatch {
    param([string]$Text, [string]$Keyword)
    if ([string]::IsNullOrWhiteSpace($Text) -or [string]::IsNullOrWhiteSpace($Keyword)) { return $false }
    $escaped = [regex]::Escape($Keyword)
    return [regex]::IsMatch($Text, "(?i)(^|[\\_\s\-\.])(($escaped))($|[\\_\s\-\.])")
}

function Get-MatchedCheatKeyword {
    param([string]$Text, [switch]$FolderName)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $lower = $Text.ToLower()
    if ($FolderName) {
        foreach ($kw in $script:CheatKeywords) {
            if ($kw -eq 'loader' -and $lower -match '(?i)\b[a-z0-9_-]*(download|upload|bootload|workload|dataload)er') { continue }
            if ($kw.Length -le 4) { if (Test-KeywordTokenMatch -Text $lower -Keyword $kw) { return $kw } }
            elseif ($lower -like "*$kw*") { return $kw }
        }
        foreach ($kw in $script:FolderOnlyKeywords) { if (Test-KeywordTokenMatch -Text $lower -Keyword $kw) { return $kw } }
        return $null
    }
    foreach ($kw in $script:CheatKeywords) {
        if ($kw -eq 'loader' -and $lower -match '(?i)\b[a-z0-9_-]*(download|upload|bootload|workload|dataload)er') { continue }
        if ($kw.Length -le 4) { if (Test-KeywordTokenMatch -Text $lower -Keyword $kw) { return $kw } }
        elseif ($lower -like "*$kw*") { return $kw }
    }
    return $null
}

# ====================================================================
# v2.0 NEW DETECTION: HIDDEN PROCESS (3-SOURCE COMPARISON)
# ====================================================================
function Get-HiddenProcessAlerts {
    $alerts = @()

    $wmiPids        = New-Object 'System.Collections.Generic.HashSet[int]'
    $psPids         = New-Object 'System.Collections.Generic.HashSet[int]'
    $toolhelpPids   = New-Object 'System.Collections.Generic.HashSet[int]'

    try { Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object { [void]$wmiPids.Add([int]$_.ProcessId) } }
    catch { $alerts += 'WARNING: WMI process enumeration failed for cross-check' }

    try { Get-Process -ErrorAction Stop | ForEach-Object { [void]$psPids.Add([int]$_.Id) } } catch {}

    if (Initialize-NativeProcessScanApi) {
        try {
            foreach ($p in [SOL.NativePS]::GetAllPidsViaToolhelp()) { [void]$toolhelpPids.Add($p) }
        } catch {}
    }

    $systemPids = @(0, 4)
    $normalMissingPattern = '(?i)^(Registry|Secure System|Memory Compression|Idle|System)$'

    # Toolhelp vs WMI - processes visible in one but not other
    if ($toolhelpPids.Count -gt 5 -and $wmiPids.Count -gt 5) {
        foreach ($pid in $toolhelpPids) {
            if ($pid -le 4 -or $systemPids -contains $pid) { continue }
            if (-not $wmiPids.Contains($pid)) {
                $name = 'unknown'
                try { $p = Get-Process -Id $pid -ErrorAction Stop; $name = $p.ProcessName } catch {}
                if ($name -notmatch $normalMissingPattern) {
                    $alerts += "FAILURE: Process hidden from WMI but visible in Toolhelp32 (PID $pid): $name"
                }
            }
        }
        foreach ($pid in $wmiPids) {
            if ($pid -le 4 -or $systemPids -contains $pid) { continue }
            if (-not $toolhelpPids.Contains($pid) -and -not $psPids.Contains($pid)) {
                try {
                    $info = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction Stop | Select-Object -First 1
                    $name = if ($info) { [string]$info.Name } else { 'unknown' }
                    if ($name -notmatch $normalMissingPattern) {
                        $alerts += "WARNING: Process in WMI/PS but not Toolhelp32 (PID $pid): $name - possible anomaly"
                    }
                } catch {}
            }
        }
    }

    # Sanity: if WMI and PS lists differ significantly it's suspicious
    if ($wmiPids.Count -gt 5 -and $psPids.Count -gt 5) {
        $wmiOnly = ($wmiPids | Where-Object { $_ -gt 4 -and -not $psPids.Contains($_) }).Count
        $psOnly  = ($psPids  | Where-Object { $_ -gt 4 -and -not $wmiPids.Contains($_) }).Count
        if ($wmiOnly -gt 5 -or $psOnly -gt 5) {
            $alerts += "WARNING: Large discrepancy between WMI ($($wmiPids.Count)) and Get-Process ($($psPids.Count)) - WMI-only:$wmiOnly PS-only:$psOnly"
        }
    }

    # PID gap analysis - rootkits sometimes leave large unexplained gaps when hiding PIDs
    if ($toolhelpPids.Count -gt 5) {
        $sorted = @($toolhelpPids | Sort-Object)
        $prev = 4; $bigGaps = 0
        foreach ($pid in $sorted) {
            if ($pid -le 4) { continue }
            if (($pid - $prev) -gt 0x8000 -and $prev -gt 4) { $bigGaps++ }
            $prev = $pid
        }
        if ($bigGaps -gt 5) { $alerts += "WARNING: Abnormal PID gap distribution ($bigGaps large gaps) - may indicate process hiding" }
    }

    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No hidden processes detected (3-source cross-check passed)' }
    return @($alerts | Select-Object -Unique)
}

# ====================================================================
# v2.0 NEW DETECTION: INJECTED THREADS
# ====================================================================
function Get-InjectedThreadAlerts {
    $alerts = @()
    if ([IntPtr]::Size -ne 8) { return @('WARNING: Thread injection scan skipped (run 64-bit PowerShell)') }
    if (-not (Initialize-NativeProcessScanApi)) { return @('WARNING: Thread injection scan unavailable') }

    $targets = New-Object 'System.Collections.Generic.List[System.Diagnostics.Process]'
    try {
        $targets.AddRange(@(Get-Process -Name 'RobloxPlayerBeta' -ErrorAction SilentlyContinue))
        $targets.AddRange(@(Get-Process -Name 'RobloxPlayerLauncher' -ErrorAction SilentlyContinue))
    } catch {}

    foreach ($proc in $targets) {
        try {
            $injected = [SOL.NativePS]::GetInjectedThreadsForProcess([int]$proc.Id)
            foreach ($info in $injected) {
                $alerts += "FAILURE: Injected thread detected in $($proc.ProcessName) (PID $($proc.Id)): $info"
            }
        } catch {
            $alerts += "WARNING: Could not scan threads for $($proc.ProcessName) (PID $($proc.Id))"
        }
    }

    if ($targets.Count -eq 0) { $alerts += 'INFO: Roblox not running - injected thread check skipped' }
    elseif ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No injected threads detected in Roblox' }
    return @($alerts | Select-Object -Unique)
}

# ====================================================================
# v2.0 NEW DETECTION: VIRTUAL MACHINE / HYPERVISOR
# ====================================================================
function Get-VirtualMachineAlerts {
    $alerts = @()
    $vmScore = 0
    $vmEvidence = @()

    # 1. Registry keys
    $vmRegChecks = @(
        @{ Path = 'HKLM:\SOFTWARE\VMware, Inc.\VMware Tools';            Label = 'VMware Tools installed' },
        @{ Path = 'HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions';   Label = 'VirtualBox Guest Additions' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'; Label = 'Hyper-V guest parameters' },
        @{ Path = 'HKLM:\HARDWARE\ACPI\DSDT\VBOX__';                   Label = 'VirtualBox ACPI table' },
        @{ Path = 'HKLM:\HARDWARE\ACPI\DSDT\BOCHS_';                   Label = 'BOCHS/QEMU ACPI table' },
        @{ Path = 'HKLM:\HARDWARE\ACPI\DSDT\BXPC___';                  Label = 'VirtualBox PC ACPI table' }
    )
    foreach ($r in $vmRegChecks) {
        if (Test-Path $r.Path -ErrorAction SilentlyContinue) { $vmScore += 3; $vmEvidence += $r.Label }
    }

    # 2. BIOS / system strings
    try {
        $bios = Get-ItemProperty 'HKLM:\HARDWARE\Description\System\BIOS' -ErrorAction Stop
        $biosStr = "$([string]$bios.SystemManufacturer) $([string]$bios.SystemProductName) $([string]$bios.BIOSVendor)"
        if ($biosStr -match '(?i)VMware|VirtualBox|QEMU|Bochs|Xen|KVM|Hyper-V|Virtual Machine|VBOX|innotek|Parallels') {
            $vmScore += 4; $vmEvidence += "BIOS/system string: $($biosStr.Trim())"
        }
    } catch {}

    # 3. WMI hardware
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $hw = "$([string]$cs.Manufacturer) $([string]$cs.Model)"
        if ($hw -match '(?i)VMware|VirtualBox|QEMU|KVM|Hyper-V|Virtual Machine|VBOX|innotek|Bochs|Parallels|Xen') {
            $vmScore += 4; $vmEvidence += "Hardware model: $($hw.Trim())"
        }
    } catch {}

    # 4. VM-specific processes
    $vmProcs = @(
        @{ Name = 'vmtoolsd';    Label = 'VMware Tools daemon' },
        @{ Name = 'VBoxService'; Label = 'VirtualBox Service' },
        @{ Name = 'VBoxTray';    Label = 'VirtualBox Tray' },
        @{ Name = 'vmsrvc';      Label = 'Virtual PC service' },
        @{ Name = 'xenservice';  Label = 'Xen service' },
        @{ Name = 'qemu-ga';     Label = 'QEMU guest agent' }
    )
    foreach ($p in $vmProcs) {
        if (Get-Process -Name $p.Name -ErrorAction SilentlyContinue) { $vmScore += 2; $vmEvidence += "VM process running: $($p.Label)" }
    }

    # 5. MAC address OUI check (VMware/VirtualBox use known OUIs)
    try {
        Get-CimInstance Win32_NetworkAdapter -ErrorAction SilentlyContinue | Where-Object { $_.MACAddress } | ForEach-Object {
            $oui = $_.MACAddress.Replace(':','').Replace('-','').Substring(0,6).ToUpper()
            $vmOUIs = @('000C29','000569','001C14','005056','525400','080027','0A0027')
            foreach ($v in $vmOUIs) {
                if ($oui -eq $v) { $vmScore += 3; $vmEvidence += "VM MAC OUI on '$($_.Name)': $($_.MACAddress)"; break }
            }
        }
    } catch {}

    # 6. Device artifacts (VMware VMCI, VirtualBox guest, etc.)
    if (Initialize-VmDetectionApi) {
        try {
            foreach ($dev in [SOL.VmCheck]::GetVmDeviceArtifacts()) {
                $vmScore += 3; $vmEvidence += "VM device accessible: $dev"
            }
        } catch {}
    }

    # 7. CPU name
    try {
        $cpu = (Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1).Name
        if ($cpu -match '(?i)Virtual|QEMU|KVM|VMware') { $vmScore += 2; $vmEvidence += "CPU name: $cpu" }
    } catch {}

    if ($vmScore -ge 4) {
        $level = if ($vmScore -ge 7) { 'FAILURE' } else { 'WARNING' }
        $alerts += "${level}: Virtual machine environment detected (confidence score: $vmScore/20)"
        foreach ($ev in $vmEvidence) { $alerts += "INFO: VM evidence -> $ev" }
        $alerts += 'INFO: A VM can conceal cheats running on the physical host from this check'
    } else {
        $alerts += 'SUCCESS: No virtual machine environment detected'
    }
    return @($alerts | Select-Object -Unique)
}

# ====================================================================
# v2.0 NEW DETECTION: CHEAT ENGINE
# ====================================================================
function Get-CheatEngineAlerts {
    $alerts = @()

    # Running processes
    foreach ($ceName in @('cheatengine-x86_64','cheatengine-x86_64-SSE4-AVX2','CheatEngine','cheatengine','CE_loader')) {
        $p = Get-Process -Name $ceName -ErrorAction SilentlyContinue
        if ($p) { $alerts += "FAILURE: Cheat Engine is running (PID $($p.Id)): $ceName" }
    }

    # Kernel driver files
    foreach ($drv in @('dbk64.sys','dbk32.sys','CE_driver.sys')) {
        if (Test-Path "$env:SystemRoot\System32\drivers\$drv") { $alerts += "FAILURE: Cheat Engine kernel driver present: $drv" }
    }

    # Registry
    foreach ($key in @('HKLM:\SOFTWARE\Cheat Engine','HKCU:\SOFTWARE\Cheat Engine')) {
        try { if (Test-Path $key) { $alerts += "WARNING: Cheat Engine registry key found: $key" } } catch {}
    }

    # Common install/download paths
    $cePaths = @(
        (Join-Path ${env:ProgramFiles}     'Cheat Engine*\Cheat*.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Cheat Engine*\Cheat*.exe'),
        (Join-Path $env:USERPROFILE        'Downloads\Cheat*.exe'),
        (Join-Path $env:USERPROFILE        'Desktop\Cheat*.exe'),
        (Join-Path $env:LOCALAPPDATA       'Programs\Cheat Engine*\Cheat*.exe')
    )
    foreach ($pattern in $cePaths) {
        $found = Resolve-Path $pattern -ErrorAction SilentlyContinue
        foreach ($f in $found) { $alerts += "WARNING: Cheat Engine binary found: $($f.Path)" }
    }

    # BAM/prefetch trace
    try {
        $bamEntries = Get-BamEntries -ErrorAction SilentlyContinue
        foreach ($e in $bamEntries) {
            if ($e.Leaf -match '(?i)cheatengine|CheatEngine') {
                $alerts += "FAILURE: Cheat Engine execution history: $($e.Raw) ($(if ($e.Time) { Get-Date $e.Time -Format 'HH:mm' } else { 'unknown time' }))"
            }
        }
    } catch {}

    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No Cheat Engine artifacts detected' }
    return @($alerts | Select-Object -Unique)
}

# ====================================================================
# v2.0 NEW DETECTION: ETW TAMPER
# ====================================================================
function Get-EtwTamperingAlerts {
    $alerts = @()

    # Check if ETW syscall stubs are hooked (EtwEventWrite is commonly patched)
    if ([IntPtr]::Size -eq 8 -and (Initialize-SOLIntegrityApi)) {
        foreach ($fn in @('EtwEventWrite','EtwpWriteUserEvent','NtTraceEvent','NtTraceControl')) {
            try {
                $hookDetails = [SOL.IntegrityScan]::GetSyscallHookDetails($fn)
                if ($hookDetails) { $alerts += "FAILURE: ETW function hooked: $fn -> $hookDetails" }
            } catch {}
        }
    }

    # Microsoft-Windows-Threat-Intelligence provider (cheats commonly patch/disable this)
    $tiProviderKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}'
    try {
        if (Test-Path $tiProviderKey) {
            $enabled = Get-ItemPropertyValue -Path $tiProviderKey -Name 'Enabled' -ErrorAction Stop
            if ([int]$enabled -eq 0) { $alerts += 'FAILURE: Microsoft-Windows-Threat-Intelligence ETW provider disabled (cheat evasion technique)' }
        }
    } catch {}

    # Security/System autologger sessions
    foreach ($session in @('EventLog-Security','EventLog-System','EventLog-Application')) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\$session"
        try {
            if (Test-Path $path) {
                $start = Get-ItemPropertyValue -Path $path -Name 'Start' -ErrorAction Stop
                if ([int]$start -eq 0) { $alerts += "FAILURE: ETW Autologger '$session' is disabled" }
            }
        } catch {}
    }

    # Check logman for expected sessions (logman is a signed Windows binary)
    try {
        $logmanOut = & "$env:SystemRoot\System32\logman.exe" query -ets 2>&1 | Out-String
        if ($logmanOut -notmatch '(?i)NT Kernel Logger') {
            $alerts += 'WARNING: NT Kernel Logger ETW session not found (may be stopped)'
        }
    } catch {}

    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: ETW session integrity verified' }
    return @($alerts | Select-Object -Unique)
}

# ====================================================================
# v2.0 NEW DETECTION: DEBUGGER / ANALYSIS TOOLS
# ====================================================================
function Get-DebuggerDetectionAlerts {
    $alerts = @()

    # .NET debugger attached?
    try {
        if ([System.Diagnostics.Debugger]::IsAttached) { $alerts += 'FAILURE: .NET debugger is attached to this PowerShell process' }
    } catch {}

    # Console output redirected (output capture for replay spoofing)
    try {
        if ([Console]::IsOutputRedirected) { $alerts += 'WARNING: Console output is redirected - output may be captured for spoofing' }
    } catch {}

    # Analysis/debugging tools
    $analysisTools = @(
        @{ Name = 'cheatengine-x86_64';  Label = 'Cheat Engine';           Level = 'FAILURE' },
        @{ Name = 'x64dbg';              Label = 'x64dbg debugger';        Level = 'FAILURE' },
        @{ Name = 'x32dbg';              Label = 'x32dbg debugger';        Level = 'FAILURE' },
        @{ Name = 'ollydbg';             Label = 'OllyDbg';                Level = 'FAILURE' },
        @{ Name = 'windbg';              Label = 'WinDbg';                  Level = 'WARNING' },
        @{ Name = 'ida64';               Label = 'IDA Pro 64-bit';          Level = 'FAILURE' },
        @{ Name = 'ida';                 Label = 'IDA Pro';                 Level = 'FAILURE' },
        @{ Name = 'ghidra';              Label = 'Ghidra';                  Level = 'WARNING' },
        @{ Name = 'dnspy';               Label = 'dnSpy .NET debugger';     Level = 'WARNING' },
        @{ Name = 'de4dot';              Label = 'de4dot .NET deobfuscator';Level = 'WARNING' },
        @{ Name = 'processhacker';       Label = 'Process Hacker';          Level = 'WARNING' },
        @{ Name = 'processhacker3';      Label = 'Process Hacker 3';        Level = 'WARNING' },
        @{ Name = 'api-monitor';         Label = 'API Monitor';             Level = 'WARNING' },
        @{ Name = 'wireshark';           Label = 'Wireshark (network tap)'; Level = 'WARNING' },
        @{ Name = 'fiddler';             Label = 'Fiddler (HTTP proxy)';    Level = 'WARNING' },
        @{ Name = 'charles';             Label = 'Charles Proxy';           Level = 'WARNING' },
        @{ Name = 'httpdebugger';        Label = 'HTTP Debugger';           Level = 'WARNING' }
    )
    foreach ($tool in $analysisTools) {
        if (Get-Process -Name $tool.Name -ErrorAction SilentlyContinue) {
            $alerts += "$($tool.Level): Analysis/debugging tool running: $($tool.Label)"
        }
    }

    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No analysis or debugging tools detected' }
    return @($alerts | Select-Object -Unique)
}

# ====================================================================
# v2.0 NEW DETECTION: AMSI INTEGRITY
# ====================================================================
function Get-AmsiIntegrityAlerts {
    $alerts = @()
    $amsiPath = "$env:SystemRoot\System32\amsi.dll"

    if (-not (Test-Path $amsiPath)) {
        $alerts += 'FAILURE: amsi.dll missing from System32'
        return $alerts
    }

    try {
        $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -FilePath $amsiPath -ErrorAction Stop
        if ($sig.Status -ne 'Valid') { $alerts += "FAILURE: amsi.dll signature is $($sig.Status)" }
        elseif ($sig.SignerCertificate.Subject -notmatch '(?i)Microsoft') { $alerts += 'FAILURE: amsi.dll not signed by Microsoft' }
        else { $alerts += 'SUCCESS: amsi.dll signature valid (Microsoft)' }
    } catch { $alerts += 'WARNING: Could not verify amsi.dll signature' }

    # AMSI providers
    $amsiProvKey = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
    try {
        if (-not (Test-Path $amsiProvKey)) { $alerts += 'FAILURE: AMSI providers registry key missing' }
        else {
            $providers = @(Get-ChildItem $amsiProvKey -ErrorAction SilentlyContinue)
            if ($providers.Count -eq 0) { $alerts += 'FAILURE: No AMSI providers registered (script scanning bypassed)' }
            else { $alerts += "SUCCESS: $($providers.Count) AMSI provider(s) registered" }
        }
    } catch {}

    # AMSI syscall hook (common: patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN)
    if ([IntPtr]::Size -eq 8 -and (Initialize-SOLIntegrityApi)) {
        try {
            $hook = [SOL.IntegrityScan]::GetSyscallHookDetails('AmsiScanBuffer')
            if ($hook) { $alerts += "FAILURE: AmsiScanBuffer is hooked (AMSI bypassed) -> $hook" }
        } catch {}
        try {
            $hook = [SOL.IntegrityScan]::GetSyscallHookDetails('AmsiOpenSession')
            if ($hook) { $alerts += "FAILURE: AmsiOpenSession is hooked -> $hook" }
        } catch {}
    }

    # Check if AMSI disabled via policy
    foreach ($policyPath in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell')) {
        try {
            if (Test-Path $policyPath) {
                $amsiDisabled = Get-ItemPropertyValue -Path $policyPath -Name 'EnableScriptBlockLogging' -ErrorAction Stop
                if ([int]$amsiDisabled -eq 0) { $alerts += "WARNING: PowerShell script block logging disabled by policy" }
            }
        } catch {}
    }

    if (-not ($alerts | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) {
        $alerts = @('SUCCESS: AMSI integrity verified') + $alerts
    }
    return @($alerts | Select-Object -Unique)
}

# ====================================================================
# v2.0 NEW DETECTION: SUSPICIOUS NETWORK CONNECTIONS
# ====================================================================
function Get-SuspiciousNetworkAlerts {
    $alerts = @()

    $cheatPortSignatures = @(4444, 4445, 31337, 1337, 6666, 9999, 12345, 54321, 7331, 8765)

    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction Stop
        $seen  = New-Object 'System.Collections.Generic.HashSet[string]'

        foreach ($c in $conns) {
            $remote = [string]$c.RemoteAddress
            $rPort  = [int]$c.RemotePort
            $pid    = [int]$c.OwningProcess

            if ($remote -match '^(0\.0\.0\.0|::|\*|127\.|::1$)') { continue }
            if ($rPort -in @(80, 443, 53, 8080, 8443)) { continue }

            if ($cheatPortSignatures -contains $rPort) {
                $pName = 'unknown'
                try { $pName = (Get-Process -Id $pid -ErrorAction Stop).ProcessName } catch {}
                $key = "$remote`:$rPort|$pid"
                if ($seen.Add($key)) {
                    $alerts += "WARNING: Suspicious outbound connection on port $rPort by $pName (PID $pid) -> $remote"
                }
            }
        }
    } catch {
        if ($_.Exception.Message -notmatch 'denied') {
            $alerts += "WARNING: TCP connection scan unavailable ($($_.Exception.Message))"
        }
    }

    # Enhanced HOSTS file check (full non-standard entries, not just Roblox)
    try {
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $hostsLines = @(Get-Content $hostsPath -ErrorAction SilentlyContinue | Where-Object {
            $_.Trim() -ne '' -and -not $_.Trim().StartsWith('#')
        })
        foreach ($line in $hostsLines) {
            if ($line -notmatch '(?i)^\s*127\.0\.0\.1\s+localhost\s*$|^\s*::1\s+localhost\s*$') {
                $kwHit = Get-MatchedCheatKeyword -Text $line
                $level = if ($kwHit) { 'FAILURE' } else { 'WARNING' }
                if ($kwHit) { $alerts += "FAILURE: HOSTS file entry [$kwHit]: $line" }
                elseif ($line -match '(?i)(roblox|rbxcdn|clientsettings)') { $alerts += "FAILURE: HOSTS file redirects Roblox: $line" }
                else { $alerts += "WARNING: Non-standard HOSTS entry: $line" }
            }
        }
    } catch {}

    # DNS cache check for cheat-related domains
    $cheatDomainPatterns = @('keyauth','luarmor','wearedevs','solara','krnl.vip','synapsex','getsynapse','comet-rblx')
    try {
        Get-DnsClientCache -ErrorAction Stop | ForEach-Object {
            $entry = [string]$_.Entry
            foreach ($pattern in $cheatDomainPatterns) {
                if ($entry -like "*$pattern*") {
                    $alerts += "WARNING: DNS cache entry matches cheat domain pattern [$pattern]: $entry"
                }
            }
        }
    } catch {}

    # Proxy enabled?
    try {
        $proxyKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $proxyOn = (Get-ItemProperty $proxyKey -ErrorAction Stop).ProxyEnable
        if ([int]$proxyOn -eq 1) {
            $server = (Get-ItemProperty $proxyKey).ProxyServer
            $alerts += "WARNING: System HTTP proxy enabled: $server"
        }
    } catch {}

    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: Network configuration clean, no suspicious connections' }
    return @($alerts | Select-Object -Unique)
}

# ====================================================================
# v2.0 NEW DETECTION: ENHANCED NAMED PIPE SCAN
# ====================================================================
function Get-EnhancedNamedPipeAlerts {
    $alerts = @()

    $executorPipeKeywords = @(
        'krnl','synapse','solara','celery','hydrogen','electron','fluxus','oxygen','arceus',
        'vega','elysian','codex','comet','trigon','carbon','macsploit','nihon','proxo',
        'executor','inject','cheat','hack','exploit','hookpipe','rbxcheat','aimbot',
        'krampus','wavepipe','wearedevs','memefish','readmemory','vmread',
        'getgenv','hookfunction','delta_pipe','robloxmgr','scriptrunner'
    )

    try {
        $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\')
        $flagged = @()

        foreach ($pipe in $pipes) {
            $leaf     = Split-Path -Leaf $pipe
            $leafLow  = $leaf.ToLower()

            foreach ($kw in $executorPipeKeywords) {
                if ($leafLow.Contains($kw)) { $flagged += @{ Pipe = $pipe; Kw = $kw }; break }
            }
            $kwHit = Get-MatchedCheatKeyword -Text $leaf
            if ($kwHit -and -not ($flagged | Where-Object { $_.Pipe -eq $pipe })) {
                $flagged += @{ Pipe = $pipe; Kw = $kwHit }
            }
        }

        foreach ($hit in $flagged) { $alerts += "FAILURE: Suspicious named pipe [$($hit.Kw)]: $($hit.Pipe)" }

        $anonCount = @($pipes | Where-Object { (Split-Path -Leaf $_) -match '^\d+$' }).Count
        $alerts += "INFO: $($pipes.Count) total named pipes ($anonCount anonymous)"

        if ($anonCount -gt 150) { $alerts += "WARNING: Unusually high anonymous pipe count: $anonCount (normal < 100)" }

    } catch { $alerts += "WARNING: Named pipe enumeration failed ($($_.Exception.Message))" }

    if (-not ($alerts | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) {
        $alerts = @('SUCCESS: No suspicious named pipes detected') + $alerts
    }
    return @($alerts | Select-Object -Unique)
}

# ====================================================================
# v2.0 NEW DETECTION: RECORDING AUTHENTICITY
# ====================================================================
function Get-RecordingAuthenticityAlerts {
    $alerts = @()

    # Virtual camera / screen capture tools (could feed fake footage)
    $virtualCapture = @(
        @{ Name = 'ManyCam';        Level = 'WARNING'; Label = 'ManyCam virtual camera' },
        @{ Name = 'SplitCam';       Level = 'WARNING'; Label = 'SplitCam virtual camera' },
        @{ Name = 'xsplit.core';    Level = 'WARNING'; Label = 'XSplit (screen share tool)' },
        @{ Name = 'NDIVirtualInput';Level = 'WARNING'; Label = 'NDI Virtual Input camera' },
        @{ Name = 'AnyDesk';        Level = 'WARNING'; Label = 'AnyDesk (remote desktop)' },
        @{ Name = 'TeamViewer';     Level = 'WARNING'; Label = 'TeamViewer (remote desktop)' },
        @{ Name = 'TeamViewer_Service'; Level = 'WARNING'; Label = 'TeamViewer service' },
        @{ Name = 'RustDesk';       Level = 'WARNING'; Label = 'RustDesk (remote desktop)' },
        @{ Name = 'parsec-core';    Level = 'WARNING'; Label = 'Parsec (remote desktop)' },
        @{ Name = 'vncserver';      Level = 'WARNING'; Label = 'VNC Server (remote access)' },
        @{ Name = 'tvnserver';      Level = 'WARNING'; Label = 'TightVNC server' }
    )
    foreach ($p in $virtualCapture) {
        if (Get-Process -Name $p.Name -ErrorAction SilentlyContinue) {
            $alerts += "$($p.Level): $($p.Label) is running (could feed fake video)"
        }
    }

    # Remote Desktop session detection
    try {
        $sessionName = $env:SESSIONNAME
        if ($sessionName -match '(?i)^RDP-') { $alerts += 'FAILURE: This session is an RDP remote desktop session' }
    } catch {}

    # Check for virtual monitor (no physical display)
    try {
        $monitors = @(Get-CimInstance Win32_DesktopMonitor -ErrorAction Stop | Where-Object { $_.PixelsPerXLogicalInch -gt 0 })
        if ($monitors.Count -eq 0) {
            $alerts += 'WARNING: No physical monitor detected - possible headless/virtual display'
        } else {
            foreach ($m in $monitors) {
                if ($m.Name -match '(?i)virtual|rdp|remote|citrix|spice') {
                    $alerts += "WARNING: Virtual/remote display in use: $($m.Name)"
                }
            }
        }
    } catch {}

    # Terminal server / multi-session check
    try {
        $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        if (Test-Path $tsKey) {
            $fDeny = Get-ItemPropertyValue $tsKey -Name 'fDenyTSConnections' -ErrorAction Stop
            if ([int]$fDeny -eq 0) { $alerts += 'WARNING: Remote Desktop connections are ENABLED on this machine' }
        }
    } catch {}

    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No recording authenticity concerns detected' }
    return @($alerts | Select-Object -Unique)
}

# ====================================================================
# ALL ORIGINAL DETECTION FUNCTIONS (preserved from base SOL)
# ====================================================================

function Get-SuspiciousHighEntropyFileAlerts {
    $alerts = @()
    $targetFolders = @((Join-Path $env:USERPROFILE 'Downloads'),(Join-Path $env:USERPROFILE 'Desktop'),$env:TEMP,"$env:SystemDrive\")
    $scannedFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($folder in $targetFolders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        $files = Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '(?i)^\.(exe|dll)$' -and $_.Length -gt 50KB -and $_.Length -lt 30MB } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 20
        foreach ($file in $files) {
            if (-not $scannedFiles.Add($file.FullName)) { continue }
            $entropy = Get-FileEntropy -FilePath $file.FullName
            if ($entropy -lt 7.20 -or $entropy -gt 7.95) { continue }
            if (Test-SignedByShippedRoot -Path $file.FullName) { continue }
            $kw = Get-MatchedCheatKeyword -Text $file.Name
            $kwTag = if ($kw) { " [$kw]" } else { "" }
            $alerts += "WARNING: High-entropy packed binary$kwTag [Entropy: $entropy] -> $($file.FullName)"
        }
    }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No high-entropy packed binaries detected' }
    return @($alerts | Select-Object -Unique)
}

# ---- MODULE INIT ----
$script:SOLModuleState = @{}
$script:DefenderAvailable = $false
$script:CorePowerShellModules = @(
    'Microsoft.PowerShell.Archive','Microsoft.PowerShell.Diagnostics','Microsoft.PowerShell.Host',
    'Microsoft.PowerShell.LocalAccounts','Microsoft.PowerShell.Management','Microsoft.PowerShell.Security',
    'Microsoft.PowerShell.Utility','Microsoft.PowerShell.Operation.Validation','PackageManagement','PowerShellGet','PSReadLine'
)

function Initialize-SOLModules {
    $results = @()
    $moduleSpecs = @(
        @{ Name = 'Microsoft.PowerShell.Management'; Required = $true;  Label = 'PowerShell Management' },
        @{ Name = 'Microsoft.PowerShell.Utility';   Required = $true;  Label = 'PowerShell Utility' },
        @{ Name = 'Microsoft.PowerShell.Security';  Required = $true;  Label = 'PowerShell Security' },
        @{ Name = 'CimCmdlets';                     Required = $true;  Label = 'CIM cmdlets' },
        @{ Name = 'ScheduledTasks';                 Required = $true;  Label = 'Scheduled Tasks' },
        @{ Name = 'Defender';                       Required = $true;  Label = 'Windows Defender' },
        @{ Name = 'PSReadLine';                     Required = $false; Label = 'PSReadLine' }
    )
    foreach ($spec in $moduleSpecs) {
        $name = $spec.Name; $required = [bool]$spec.Required; $label = $spec.Label
        $available = @()
        try { $available = @(Microsoft.PowerShell.Core\Get-Module -ListAvailable -Name $name -ErrorAction SilentlyContinue) } catch {}
        if ($available.Count -eq 0) {
            $script:SOLModuleState[$name] = $false
            $results += "$(if ($required) { 'FAILURE' } else { 'INFO' }): $(if ($required) { 'Required' } else { 'Optional' }) module unavailable -> $label ($name)"
            continue
        }
        try { Microsoft.PowerShell.Core\Import-Module -Name $name -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null } catch {
            $script:SOLModuleState[$name] = $false
            $results += "$(if ($required) { 'FAILURE' } else { 'WARNING' }): Module could not be imported -> $label"
            continue
        }
        if (Microsoft.PowerShell.Core\Get-Module -Name $name -ErrorAction SilentlyContinue) {
            $script:SOLModuleState[$name] = $true; $results += "SUCCESS: Module available -> $label"
        } else {
            $script:SOLModuleState[$name] = $false
            $results += "$(if ($required) { 'FAILURE' } else { 'WARNING' }): Module did not load -> $label"
        }
    }
    $script:DefenderAvailable = $false
    if ($script:SOLModuleState.ContainsKey('Defender') -and $script:SOLModuleState['Defender']) {
        $missing = @('Get-MpComputerStatus','Get-MpPreference','Get-MpThreat') |
            Where-Object { -not (Microsoft.PowerShell.Core\Get-Command -Name $_ -ErrorAction SilentlyContinue) }
        if ($missing.Count -eq 0) { $script:DefenderAvailable = $true; $results += 'SUCCESS: Windows Defender cmdlets available' }
        else { $results += "FAILURE: Defender module loaded but cmdlets unavailable -> $($missing -join ', ')" }
    }
    return $results
}

function Get-Exclusions {
    $list = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    try {
        $prefs = Defender\Get-MpPreference -ErrorAction Stop
        foreach ($item in @($prefs.ExclusionPath) + @($prefs.ExclusionProcess) + @($prefs.ExclusionExtension)) {
            if ($item) { [void]$list.Add([string]$item) }
        }
    } catch {}
    foreach ($root in @('SOFTWARE\Microsoft\Windows Defender\Exclusions','SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions')) {
        foreach ($type in @('Paths','Processes','Extensions')) {
            try {
                $key = Open-LocalMachineRegistryKey -SubKeyPath "$root\$type"
                if (-not $key) { continue }
                foreach ($name in $key.GetValueNames()) { if ($name) { [void]$list.Add($name) } }
                $key.Close()
            } catch {}
        }
    }
    return @($list)
}

$script:DefenderExclusionsRegRoots = @('SOFTWARE\Microsoft\Windows Defender\Exclusions','SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions')
$script:DefenderThreatsRegRoots    = @('SOFTWARE\Microsoft\Windows Defender\Threats','SOFTWARE\Policies\Microsoft\Windows Defender\Threats')
$script:DefenderThreatsSystemSubkeys = @('ThreatSeverityDefaultAction','ThreatIDDefaultAction','ThreatTypeDefaultAction')

function Get-RegistrySubtreeFingerprint {
    param([string]$RelativePath)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    try {
        $root = Open-LocalMachineRegistryKey -SubKeyPath $RelativePath
        if (-not $root) { return 'MISSING' }
        Add-RegistryKeyFingerprint -Key $root -Prefix $RelativePath -Parts $parts; $root.Close()
    } catch { return 'ERROR' }
    if ($parts.Count -eq 0) { return 'EMPTY' }
    return ($parts | Sort-Object) -join '|'
}

function Get-DefenderRegistryMonitorLabels {
    $labels = @{}
    foreach ($root in $script:DefenderExclusionsRegRoots) { $labels[$root] = "Defender Exclusions registry ($root)" }
    foreach ($root in $script:DefenderThreatsRegRoots)    { $labels[$root] = "Defender Threats registry ($root)" }
    return $labels
}
function Get-DefenderRegistryFingerprints {
    $fps = @{}
    foreach ($root in ($script:DefenderExclusionsRegRoots + $script:DefenderThreatsRegRoots)) {
        $fps[$root] = Get-RegistrySubtreeFingerprint -RelativePath $root
    }
    return $fps
}

function Get-AllowedDefenderThreats {
    $list = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($relPath in @('SOFTWARE\Microsoft\Windows Defender\Exclusions\Threats','SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Threats')) {
        try {
            $key = Open-LocalMachineRegistryKey -SubKeyPath $relPath
            if (-not $key) { continue }
            foreach ($name in $key.GetValueNames()) { if ($name) { [void]$list.Add("$relPath -> $name") } }
            foreach ($subName in $key.GetSubKeyNames()) { [void]$list.Add("$relPath\$subName") }
            $key.Close()
        } catch {}
    }
    foreach ($root in $script:DefenderThreatsRegRoots) {
        try {
            $key = Open-LocalMachineRegistryKey -SubKeyPath $root
            if (-not $key) { continue }
            foreach ($subName in $key.GetSubKeyNames()) {
                if ($script:DefenderThreatsSystemSubkeys -contains $subName) { continue }
                if ($subName -match '(?i)^\{?[0-9A-F-]{36}\}?$|^\d+$') { [void]$list.Add("$root\$subName") }
            }
            $key.Close()
        } catch {}
    }
    return @($list)
}

function Get-DefenderStatusAlerts {
    $alerts = @()
    if (-not $script:DefenderAvailable) { $alerts += 'WARNING: Windows Defender PowerShell module/cmdlets unavailable'; return $alerts }
    try {
        $def = Defender\Get-MpComputerStatus -ErrorAction Stop
        if (-not $def.RealTimeProtectionEnabled) { $alerts += 'FAILURE: Real-time protection disabled' }
        if (-not $def.IsTamperProtected)         { $alerts += 'WARNING: Tamper protection disabled' }
    } catch { $alerts += 'WARNING: Defender status unavailable' }
    foreach ($disableKey in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender','HKLM:\SOFTWARE\Microsoft\Windows Defender')) {
        try { $disabled = Get-ItemPropertyValue -Path $disableKey -Name 'DisableAntiSpyware' -ErrorAction Stop; if ($disabled -eq 1) { $alerts += 'FAILURE: DisableAntiSpyware active' } } catch {}
    }
    return $alerts
}

function Initialize-SOLIntegrityApi {
    if ('SOL.IntegrityScan' -as [type]) { return $true }
    try {
        Add-Type -Namespace SOL -Name IntegrityScan -UsingNamespace System.Text, System.Collections.Generic, System.Diagnostics -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
public static extern IntPtr GetModuleHandle(string lpModuleName);
[DllImport("user32.dll")]
public static extern int GetWindowLong(IntPtr hWnd, int nIndex);
[DllImport("user32.dll")]
public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
[DllImport("user32.dll")]
public static extern bool IsWindowVisible(IntPtr hWnd);
[DllImport("user32.dll", SetLastError = true)]
public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
[DllImport("user32.dll", CharSet = CharSet.Unicode)]
public static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
public const int GWL_EXSTYLE = -20;
public const int WS_EX_TOPMOST = 0x00000008;
public const int WS_EX_TRANSPARENT = 0x00000020;
public const int WS_EX_LAYERED = 0x00080000;

public static string GetSyscallHookDetails(string functionName) {
    IntPtr hMod = GetModuleHandle("ntdll.dll");
    if (hMod == IntPtr.Zero) {
        hMod = GetModuleHandle("amsi.dll");
        if (hMod == IntPtr.Zero) return null;
    }
    // Try ntdll first, then amsi.dll
    IntPtr pFunc = GetProcAddress(hMod, functionName);
    if (pFunc == IntPtr.Zero) {
        IntPtr hAmsi = GetModuleHandle("amsi.dll");
        if (hAmsi != IntPtr.Zero) pFunc = GetProcAddress(hAmsi, functionName);
    }
    if (pFunc == IntPtr.Zero) return null;

    byte[] b = new byte[32];
    System.Runtime.InteropServices.Marshal.Copy(pFunc, b, 0, 32);
    if (b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8) return null;

    long target = 0;
    if (b[0] == 0xE9) {
        int rel32 = BitConverter.ToInt32(b, 1);
        target = pFunc.ToInt64() + 5 + rel32;
    } else if (b[0] == 0xFF && b[1] == 0x25) {
        int disp32 = BitConverter.ToInt32(b, 2);
        long ptr = pFunc.ToInt64() + 6 + disp32;
        try { target = System.Runtime.InteropServices.Marshal.ReadInt64((IntPtr)ptr); } catch {}
    } else if (b[0] == 0x48 && b[1] == 0xB8) {
        target = BitConverter.ToInt64(b, 2);
    }

    if (target != 0) {
        try {
            foreach (ProcessModule pm in Process.GetCurrentProcess().Modules) {
                long start = pm.BaseAddress.ToInt64();
                long end = start + pm.ModuleMemorySize;
                if (target >= start && target < end)
                    return pm.FileName + " (Offset: +0x" + (target - start).ToString("X") + ")";
            }
        } catch {}
        return "Unbacked Memory at 0x" + target.ToString("X") + " (Injected Shellcode / Manual Map)";
    }
    return "Trampoline at 0x" + pFunc.ToInt64().ToString("X") + " (Raw: " + BitConverter.ToString(b, 0, 8) + ")";
}

public static bool IsSyscallHooked(string functionName) { return GetSyscallHookDetails(functionName) != null; }

private static List<string> _overlayHits;
private static bool OverlayEnumCallback(IntPtr hWnd, IntPtr lParam) {
    if (!IsWindowVisible(hWnd)) return true;
    int exStyle = GetWindowLong(hWnd, GWL_EXSTYLE);
    if ((exStyle & WS_EX_TOPMOST) != 0 && (exStyle & WS_EX_TRANSPARENT) != 0) {
        uint pid = 0; GetWindowThreadProcessId(hWnd, out pid);
        StringBuilder title = new StringBuilder(256);
        GetWindowTextW(hWnd, title, title.Capacity);
        _overlayHits.Add(pid.ToString() + "|" + exStyle.ToString("X") + "|" + title.ToString());
    }
    return true;
}
public static string[] FindTopmostOverlays() {
    _overlayHits = new List<string>();
    try { EnumWindows(new EnumWindowsProc(OverlayEnumCallback), IntPtr.Zero); } catch { return null; }
    return _overlayHits.ToArray();
}
'@ -ErrorAction Stop
        return $true
    } catch { return $false }
}

function Get-ClrHijackAlerts {
    $alerts = @()
    $vars = @('COR_ENABLE_PROFILING','COR_PROFILER','COR_PROFILER_PATH','CORECLR_ENABLE_PROFILING','CORECLR_PROFILER','CORECLR_PROFILER_PATH','COMPLUS_ENABLE_PROFILING')
    foreach ($v in $vars) {
        $m = [Environment]::GetEnvironmentVariable($v,'Machine')
        $u = [Environment]::GetEnvironmentVariable($v,'User')
        $p = [Environment]::GetEnvironmentVariable($v,'Process')
        if ($m -or $u -or $p) { $alerts += "FAILURE: .NET CLR profiler hijack in $v (Machine:'$m' User:'$u' Process:'$p')" }
    }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No CLR profiler hijacking detected' }
    return $alerts
}

function Get-NtdllSyscallIntegrityAlerts {
    $alerts = @()
    if ([IntPtr]::Size -ne 8) { return @('WARNING: 32-bit PowerShell - syscall integrity check skipped') }
    if (-not (Initialize-SOLIntegrityApi)) { return @('WARNING: Native integrity API could not be initialized') }
    foreach ($fn in @('NtQuerySystemInformation','NtOpenProcess','NtDuplicateObject','NtReadVirtualMemory','NtWriteVirtualMemory','NtProtectVirtualMemory')) {
        $hookDetails = [SOL.IntegrityScan]::GetSyscallHookDetails($fn)
        if ($hookDetails) { $alerts += "FAILURE: In-memory syscall hook on $fn -> $hookDetails" }
    }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: Native syscall stubs intact (no inline hooks)' }
    return $alerts
}

function Get-StreamingProcessIntegrityAlerts {
    $alerts = @()
    $targets = @('obs64','obs32','medal','Discord','chrome','msedge','brave','firefox','opera','operagx','vivaldi','spotify','fleasion')
    $scannedModules = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $sysRoot = $env:SystemRoot
    foreach ($name in $targets) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
            $proc = $_
            try {
                foreach ($mod in $proc.Modules) {
                    $path = [string]$mod.FileName
                    if ([string]::IsNullOrWhiteSpace($path)) { continue }
                    if ($path.StartsWith($sysRoot,[System.StringComparison]::OrdinalIgnoreCase)) { continue }
                    if (-not $scannedModules.Add($path)) { continue }
                    $isSigned = $false
                    try { $cert = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($path); if ($cert) { $isSigned = $true } } catch {
                        $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue
                        if ($sig -and $sig.Status -eq 'Valid') { $isSigned = $true }
                    }
                    if (-not $isSigned) {
                        $entropy = Get-FileEntropy -FilePath $path
                        $alerts += "FAILURE: Unsigned module in $($proc.Name) (PID $($proc.Id)) [Entropy: $entropy] -> $path"
                    } elseif (Test-UserLandProcessPath -ExecutablePath $path) {
                        $alerts += "WARNING: Userland module in $($proc.Name) (PID $($proc.Id)) -> $path"
                    }
                }
            } catch { $alerts += "WARNING: Could not inspect modules for $($proc.Name) (PID $($proc.Id))" }
        }
    }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: Monitored application module integrity verified' }
    return @($alerts | Select-Object -Unique)
}

function Get-TransparentOverlayAlerts {
    $alerts = @()
    if (-not (Initialize-SOLIntegrityApi)) { return @('WARNING: Overlay scan API unavailable') }
    $hits = [SOL.IntegrityScan]::FindTopmostOverlays()
    if ($null -eq $hits) { return @('WARNING: Failed to enumerate topmost overlays') }
    $trusted = @('dwm','explorer','taskmgr','applicationframehost','systemsettings','textinputhost',
        'robloxplayerbeta','discord','gameoverlayui','nvidia overlay','nvcontainer','gamebar','gamebarftserver',
        'obs64','medal','steamwebhelper','shellexperiencehost','procexp','procexp64','runtimebroker',
        'startmenuexperiencehost','searchhost','lockapp','widgets','ctfmon','searchui','sihost')
    foreach ($hit in $hits) {
        $parts = $hit -split '\|', 3
        $pidVal = 0; [void][int]::TryParse($parts[0],[ref]$pidVal)
        if ($pidVal -le 0 -or $pidVal -eq $PID) { continue }
        $pInfo = Resolve-ProcessIdentity -TargetPid $pidVal
        $nameLower = ($pInfo.Name -replace '\.exe$','').ToLower()
        if ($trusted -contains $nameLower -and $pInfo.Path -and (Test-SignedByShippedRoot -Path $pInfo.Path)) { continue }
        if ($pInfo.Path -and $pInfo.Path.StartsWith($env:SystemRoot,[System.StringComparison]::OrdinalIgnoreCase) -and (Test-SignedByShippedRoot -Path $pInfo.Path)) { continue }
        $style = $parts[1]; $title = if ($parts.Count -ge 3 -and $parts[2]) { " '$($parts[2])'" } else { '' }
        if ($pInfo.Path -and -not (Test-TrustedProcessPath -ExecutablePath $pInfo.Path)) {
            $alerts += "FAILURE: Transparent click-through overlay$title from untrusted path (PID $pidVal, ExStyle 0x$style) -> $($pInfo.Path)"
        } else {
            $alerts += "WARNING: Transparent click-through overlay$title detected (PID $pidVal, ExStyle 0x$style)"
        }
    }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No suspicious transparent overlay windows found' }
    return @($alerts | Select-Object -Unique)
}

# --- remaining original functions (stubs calling originals where large) ---

function Get-MemoryIntegrityAlerts {
    $alerts = @()
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
    try {
        $enabled = Get-ItemPropertyValue -Path $regPath -Name 'Enabled' -ErrorAction Stop
        if ($enabled -eq 1) { $alerts += 'SUCCESS: Memory Integrity (HVCI) enabled' }
        else { $alerts += 'WARNING: Memory Integrity (HVCI) disabled' }
    } catch { $alerts += 'WARNING: Memory Integrity (HVCI) status unavailable' }
    return $alerts
}

function Get-ActiveDefenderThreatAlerts {
    $alerts = @()
    if (-not $script:DefenderAvailable) { $alerts += 'WARNING: Windows Defender PowerShell module/cmdlets unavailable'; return $alerts }
    try {
        $threats = @(Defender\Get-MpThreat -ErrorAction Stop | Where-Object { $_.Status -eq 'Active' })
        if ($threats.Count -eq 0) { $alerts += 'SUCCESS: No active Microsoft Defender threats' }
        else {
            foreach ($threat in $threats) {
                $name = [string]$threat.ThreatName; $resources = [string]$threat.Resources
                if ($resources) { $alerts += "FAILURE: Active Defender threat -> $name | $resources" }
                else { $alerts += "FAILURE: Active Defender threat -> $name" }
            }
        }
    } catch { $alerts += 'WARNING: Unable to query active Microsoft Defender threats' }
    return $alerts
}

function Get-TestSigningAlerts {
    $alerts = @()
    try {
        $out = & "$env:SystemRoot\System32\bcdedit.exe" /enum '{current}' 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0 -and $out -match 'denied|privilege') { $alerts += 'WARNING: Could not read boot configuration (run as Administrator)' }
        else {
            if ($out -match '(?im)^\s*testsigning\s+Yes')       { $alerts += 'FAILURE: Test signing is ENABLED (unsigned drivers can load)' }
            if ($out -match '(?im)^\s*nointegritychecks\s+Yes') { $alerts += 'FAILURE: Driver integrity checks are DISABLED (nointegritychecks)' }
            if ($out -match '(?im)^\s*debug\s+Yes')             { $alerts += 'WARNING: Kernel debugging is enabled' }
            if ($out -match '(?im)^\s*hypervisorlaunchtype\s+Off') { $alerts += 'INFO: Hypervisor launch is Off (Memory Integrity cannot run)' }
        }
    } catch { $alerts += 'WARNING: Could not query boot configuration' }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: Test signing off, driver signature enforcement on' }
    return $alerts
}

function Get-PowerShellBinaryIntegrityAlerts {
    $alerts = @()
    $paths = @("$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe")
    $pwsh = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if ($pwsh -and $pwsh.Source) { $paths += $pwsh.Source }
    foreach ($path in ($paths | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        try {
            $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
            $isMicrosoft = $sig.SignerCertificate -and ($sig.SignerCertificate.Subject -match '(?i)(Microsoft Corporation|Microsoft Windows)')
            if ($sig.Status -eq 'Valid' -and $isMicrosoft) { $alerts += "SUCCESS: PowerShell binary signature valid -> $path" }
            else { $alerts += "FAILURE: PowerShell binary signature invalid -> $path [$($sig.Status)]" }
        } catch { $alerts += "WARNING: Could not verify PowerShell binary -> $path" }
    }
    if ($alerts.Count -eq 0) { $alerts += 'WARNING: No PowerShell binary could be located for verification' }
    return $alerts
}

$script:MasqueradeProcessPaths = @{
    'svchost.exe'       = @('\windows\system32\svchost.exe','\windows\syswow64\svchost.exe')
    'explorer.exe'      = @('\windows\explorer.exe')
    'csrss.exe'         = @('\windows\system32\csrss.exe')
    'lsass.exe'         = @('\windows\system32\lsass.exe')
    'services.exe'      = @('\windows\system32\services.exe')
    'smss.exe'          = @('\windows\system32\smss.exe')
    'winlogon.exe'      = @('\windows\system32\winlogon.exe')
    'dwm.exe'           = @('\windows\system32\dwm.exe')
    'taskhostw.exe'     = @('\windows\system32\taskhostw.exe')
    'runtimebroker.exe' = @('\windows\system32\runtimebroker.exe')
    'conhost.exe'       = @('\windows\system32\conhost.exe','\windows\syswow64\conhost.exe')
    'dllhost.exe'       = @('\windows\system32\dllhost.exe','\windows\syswow64\dllhost.exe')
    'spoolsv.exe'       = @('\windows\system32\spoolsv.exe')
    'wininit.exe'       = @('\windows\system32\wininit.exe')
    'sihost.exe'        = @('\windows\system32\sihost.exe')
    'fontdrvhost.exe'   = @('\windows\system32\fontdrvhost.exe')
}

function Normalize-ProcessImagePath {
    param([string]$ExecutablePath)
    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) { return $null }
    $path = [Environment]::ExpandEnvironmentVariables($ExecutablePath.Trim().Trim('"')).Replace('/','\')
    if ($path.StartsWith('\??\', [StringComparison]::OrdinalIgnoreCase)) { $path = $path.Substring(4) }
    elseif ($path.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) { $path = $path.Substring(4) }
    try { if ([IO.Path]::IsPathRooted($path)) { $path = [IO.Path]::GetFullPath($path) } } catch {}
    return $path.TrimEnd('\')
}

function Test-MasqueradeProcessPath {
    param([string]$ProcessName, [string]$ExecutablePath)
    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) { return $null }
    $nameLower = ([string]$ProcessName).ToLower(); if (-not $nameLower.EndsWith('.exe')) { $nameLower += '.exe' }
    if (-not $script:MasqueradeProcessPaths.ContainsKey($nameLower)) { return $null }
    $path = Normalize-ProcessImagePath -ExecutablePath $ExecutablePath
    $systemRoot = Normalize-ProcessImagePath -ExecutablePath $env:SystemRoot
    if (-not $path.StartsWith($systemRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        return "Windows process '$ProcessName' running from non-standard path: $ExecutablePath"
    }
    foreach ($legitSuffix in $script:MasqueradeProcessPaths[$nameLower]) {
        if ($path.EndsWith($legitSuffix, [StringComparison]::OrdinalIgnoreCase)) { return $null }
    }
    return "Windows process '$ProcessName' running from non-standard path: $ExecutablePath"
}

function Get-SuspiciousProcessHits {
    $hits = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $messages = @()
    try {
        Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
            $procName = $_.Name; $procPath = $_.ExecutablePath; $procId = $_.ProcessId
            $masquerade = Test-MasqueradeProcessPath -ProcessName $procName -ExecutablePath $procPath
            if ($masquerade) { $key = "masquerade|$procName|$procPath"; if ($hits.Add($key)) { $messages += "FAILURE: Masquerade $procName (PID $procId)" } }
            $nameKw = Get-MatchedCheatKeyword -Text $procName
            if ($nameKw) { $key = "name|$procName|$nameKw"; if ($hits.Add($key)) { $messages += "FAILURE: $procName (PID $procId) [$nameKw]" } }
            if ($procPath -and -not (Test-TrustedProcessPath -ExecutablePath $procPath)) {
                $pathKw = Get-MatchedCheatKeyword -Text $procPath
                if ($pathKw) { $key = "path|$procPath|$pathKw|$procId"; if ($hits.Add($key)) { $messages += "FAILURE: $procPath (PID $procId) [$pathKw]" } }
            }
        }
    } catch {
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $nameKw = Get-MatchedCheatKeyword -Text $_.Name
            if ($nameKw) { $key = "name|$($_.Name)|$nameKw"; if ($hits.Add($key)) { $messages += "FAILURE: $($_.Name) (PID $($_.Id)) [$nameKw]" } }
        }
    }
    return $messages
}

function Get-UnsignedUserProgramAlerts {
    $alerts = @()
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction Stop
        $grouped = @{}
        foreach ($p in $procs) {
            $path = [string]$p.ExecutablePath
            if (-not (Test-UntrustedUserProgramPath -Path $path)) { continue }
            $status = Get-CachedSignatureStatus -Path $path
            if ($status -eq 'Valid') { continue }
            if (-not $grouped.ContainsKey($path)) { $grouped[$path] = @{ Name = $p.Name; Status = $status; Pids = New-Object System.Collections.Generic.List[int] } }
            $grouped[$path].Pids.Add([int]$p.ProcessId)
        }
        foreach ($path in $grouped.Keys) {
            $item = $grouped[$path]; $kw = Get-MatchedCheatKeyword -Text $path; $kwTag = if ($kw) { " [$kw]" } else { '' }
            $pidStr = if ($item.Pids.Count -eq 1) { "PID $($item.Pids[0])" } else { "PID $($item.Pids -join ', ')" }
            if ($kw) { $alerts += "FAILURE: Unsigned program$kwTag from user folder ($($item.Status)) -> $($item.Name) ($pidStr) $path" }
            else { $alerts += "WARNING: Unsigned program from user folder ($($item.Status)) -> $($item.Name) ($pidStr) $path" }
        }
    } catch { $alerts += 'WARNING: Could not enumerate processes for signature check' }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No unsigned programs running from user folders' }
    return @($alerts | Select-Object -Unique)
}

function Test-UntrustedUserProgramPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $l = $Path.ToLower()
    if ($l -match '\\roblox\\versions\\|\\bloxstrap\\|\\fishstrap\\|\\discord\\app-|\\microsoft\\teams\\|\\spotify\\|\\antigravity\\|\\telegram desktop\\|\\programs\\microsoft vs code\\') { return $false }
    return ($l -match '\\(downloads|desktop|temp|appdata)\\')
}

# ====================================================================
# REMAINING ORIGINAL FUNCTIONS
# ====================================================================

function Resolve-ProcessIdentity {
    param([int]$TargetPid)
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid" -ErrorAction Stop | Select-Object -First 1
        if ($p) { return @{ Name = [string]$p.Name; Path = [string]$p.ExecutablePath } }
    } catch {}
    try { $p = Get-Process -Id $TargetPid -ErrorAction Stop; return @{ Name = "$($p.ProcessName).exe"; Path = [string]$p.Path } } catch {}
    return @{ Name = "PID $TargetPid"; Path = '' }
}

function Resolve-ExecutablePathFromCommandLine {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($expanded.StartsWith('\??\',  [StringComparison]::OrdinalIgnoreCase)) { $expanded = $expanded.Substring(4) }
    elseif ($expanded.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) { $expanded = $expanded.Substring(4) }
    $match = [regex]::Match($expanded, '^\s*"([^"]+)"')
    if ($match.Success) { return $match.Groups[1].Value }
    $match = [regex]::Match($expanded, '^\s*(?<path>.*?\.sys)(?:\s+.*)?$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($match.Success) { return $match.Groups['path'].Value.Trim().Trim('"') }
    $tokens = $expanded -split '\s+'
    if ($tokens.Count -gt 1) {
        for ($i = $tokens.Count; $i -ge 1; $i--) {
            $candidate = ($tokens[0..($i-1)] -join ' ').Trim().Trim('"')
            if (-not $candidate) { continue }
            try { if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction Stop) { return $candidate } } catch {}
        }
    }
    $match = [regex]::Match($expanded, '^\s*(\S+)')
    if ($match.Success) { return $match.Groups[1].Value.Trim('"') }
    return $null
}

function Normalize-KernelDriverPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $path = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
    if ($path.StartsWith('\??\',  [StringComparison]::OrdinalIgnoreCase)) { $path = $path.Substring(4) }
    elseif ($path.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) { $path = $path.Substring(4) }
    if ($path.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) { $path = $env:SystemRoot + $path.Substring(11) }
    elseif ($path.StartsWith('SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) { $path = Join-Path $env:SystemRoot $path.Substring(11) }
    elseif ($path.StartsWith('System32\',   [StringComparison]::OrdinalIgnoreCase)) { $path = Join-Path $env:SystemRoot $path }
    return $path.Trim('"')
}

function Resolve-KernelDriverImagePath {
    param([string]$ServiceName, [string]$PathName)
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    $direct = Resolve-ExecutablePathFromCommandLine -CommandLine $PathName
    if ($direct) { [void]$candidates.Add($direct) }
    if ($ServiceName) {
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
            $imagePath = Get-ItemPropertyValue -Path $regPath -Name ImagePath -ErrorAction Stop
            $fromRegistry = Resolve-ExecutablePathFromCommandLine -CommandLine ([string]$imagePath)
            if ($fromRegistry) { [void]$candidates.Add($fromRegistry) }
        } catch {}
    }
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        $normalized = Normalize-KernelDriverPath -Path $candidate
        if ([string]::IsNullOrWhiteSpace($normalized)) { continue }
        try { if (Test-Path -LiteralPath $normalized -PathType Leaf -ErrorAction Stop) { return (Get-Item -LiteralPath $normalized -Force -ErrorAction Stop).FullName } } catch {}
    }
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        $normalized = Normalize-KernelDriverPath -Path $candidate
        if ($normalized) { return $normalized }
    }
    return $null
}

function Get-SuspiciousDriverAlerts {
    $alerts = @()
    try { $drivers = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | Where-Object { $_.State -eq 'Running' } }
    catch { $alerts += 'WARNING: Could not enumerate kernel drivers.'; return $alerts }
    foreach ($drv in $drivers) {
        $rawPath = [string]$drv.PathName
        $resolvedPath = Resolve-KernelDriverImagePath -ServiceName ([string]$drv.Name) -PathName $rawPath
        $kw = Get-MatchedCheatKeyword -Text $drv.Name
        if (-not $kw) { $kw = Get-MatchedCheatKeyword -Text $drv.DisplayName }
        if (-not $kw) { $kw = Get-MatchedCheatKeyword -Text $resolvedPath }
        if ($kw) { $alerts += "FAILURE: Suspicious kernel driver [$kw] $($drv.Name) -> $resolvedPath"; continue }
        if ([string]::IsNullOrWhiteSpace($resolvedPath)) { $alerts += "WARNING: Could not resolve kernel driver image path: $($drv.Name)"; continue }
        if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf -ErrorAction SilentlyContinue)) { $alerts += "WARNING: Kernel driver image not found: $($drv.Name) -> $resolvedPath"; continue }
        try {
            $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $resolvedPath -ErrorAction Stop
            switch ([string]$sig.Status) {
                'Valid'        { }
                'NotSigned'    { $entropy = Get-FileEntropy -FilePath $resolvedPath; $alerts += "WARNING: Unsigned kernel driver: $($drv.Name) [Entropy: $entropy] -> $resolvedPath" }
                'HashMismatch' { $alerts += "FAILURE: Kernel driver signature hash mismatch: $($drv.Name) -> $resolvedPath" }
                'NotTrusted'   { if ($sig.SignerCertificate) { $alerts += "INFO: Kernel driver not trusted: $($drv.Name) -> $resolvedPath [$([string]$sig.SignerCertificate.Subject)]" } else { $alerts += "WARNING: Kernel driver signature untrusted: $($drv.Name) -> $resolvedPath" } }
                default        { $alerts += "WARNING: Kernel driver signature status $([string]$sig.Status): $($drv.Name) -> $resolvedPath" }
            }
        } catch { $alerts += "WARNING: Could not verify kernel driver signature: $($drv.Name) -> $resolvedPath" }
    }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No suspicious kernel drivers detected.' }
    return @($alerts | Select-Object -Unique)
}

$script:VulnerableDriverTiers = @{
    'iqvw64e.sys'='FAILURE';'iqvw64.sys'='FAILURE';'gdrv.sys'='FAILURE';'dbutil_2_3.sys'='FAILURE';
    'kprocesshacker.sys'='FAILURE';'mhyprot2.sys'='FAILURE';'mhyprot3.sys'='FAILURE';'capcom.sys'='FAILURE';
    'physmem.sys'='FAILURE';'hw.sys'='FAILURE';'speedfan.sys'='FAILURE';'viragt64.sys'='FAILURE';
    'tfsysmon.sys'='FAILURE';'amsdk.sys'='FAILURE';'adv64drv.sys'='FAILURE';'bs_def64.sys'='FAILURE';
    'bs_hwmio64.sys'='FAILURE';'iomap64.sys'='FAILURE';'asupio.sys'='FAILURE';'ucorew64.sys'='FAILURE';
    'msio64.sys'='FAILURE';'ntiolib_x64.sys'='FAILURE';'winio64.sys'='FAILURE';'inpoutx64.sys'='FAILURE';
    'kevp64.sys'='FAILURE';'procexp152.sys'='SKIP';
    'rtcore64.sys'='WARNING';'winring0x64.sys'='WARNING';'winring0.sys'='WARNING';'ene.sys'='WARNING';
    'eneio64.sys'='WARNING';'enetechio64.sys'='WARNING';'asio.sys'='WARNING';'asio2.sys'='WARNING';
    'asio3.sys'='WARNING';'aswarpot.sys'='WARNING';'directio64.sys'='WARNING';'cpuz141.sys'='WARNING';
    'atillk64.sys'='WARNING';'amifldrv64.sys'='WARNING'
}

function Get-VulnerableDriverAlerts {
    $alerts = @()
    try { $drivers = @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop) }
    catch { return @('WARNING: Could not enumerate drivers for vulnerable-driver check') }
    foreach ($drv in $drivers) {
        $path = Resolve-KernelDriverImagePath -ServiceName ([string]$drv.Name) -PathName ([string]$drv.PathName)
        $leaf = if ($path) { (Split-Path -Leaf $path).ToLower() } else { '' }
        if (-not $leaf -or -not $script:VulnerableDriverTiers.ContainsKey($leaf)) { continue }
        $tier = $script:VulnerableDriverTiers[$leaf]
        if ($tier -eq 'SKIP') { continue }
        if ($drv.State -eq 'Running') { $alerts += "${tier}: Known-vulnerable driver LOADED: $($drv.Name) -> $path" }
        else { $alerts += "INFO: Known-vulnerable driver installed but not running: $($drv.Name) -> $path" }
    }
    try {
        Get-ChildItem -LiteralPath "$env:SystemRoot\System32\drivers" -Filter '*.sys' -ErrorAction Stop | ForEach-Object {
            $leaf = $_.Name.ToLower()
            if ($script:VulnerableDriverTiers.ContainsKey($leaf) -and $script:VulnerableDriverTiers[$leaf] -ne 'SKIP') {
                $line = "INFO: Known-vulnerable driver file present: $($_.FullName)"
                if (-not ($alerts -match [regex]::Escape($leaf))) { $alerts += $line }
            }
        }
    } catch {}
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No known-vulnerable drivers found' }
    return @($alerts | Select-Object -Unique)
}

$script:InputDriverServices = @(
    @{ Service = 'ViGEmBus';     Level = 'WARNING'; Label = 'ViGEmBus virtual gamepad driver' },
    @{ Service = 'HidHide';      Level = 'WARNING'; Label = 'HidHide input-hiding driver' },
    @{ Service = 'WinIo';        Level = 'WARNING'; Label = 'WinIo direct hardware access driver' },
    @{ Service = 'interception'; Level = 'WARNING'; Label = 'Interception input driver' }
)
$script:FpgaPciVendorIds = @{ '10EE'='Xilinx';'1172'='Altera/Intel FPGA';'1204'='Lattice';'11AA'='Microsemi/Actel';'1D0F'='Amazon (Xilinx-based)' }

function Get-InputAndDmaDeviceAlerts {
    $alerts = @()
    foreach ($spec in $script:InputDriverServices) {
        try { $svc = Get-Service -Name $spec.Service -ErrorAction Stop; $alerts += "$($spec.Level): $($spec.Label) installed (service $($svc.Name), $($svc.Status))" } catch {}
    }
    foreach ($name in @('keyboard','mouse')) {
        try {
            $img = [string](Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -Name ImagePath -ErrorAction Stop)
            if ($img -match "(?i)\\drivers\\$name\.sys") { $alerts += "WARNING: Interception input driver installed as service '$name' -> $img" }
        } catch {}
    }
    try {
        Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object { $_.DeviceID -like 'PCI\VEN_*' } | ForEach-Object {
            if ($_.DeviceID -match '^PCI\\VEN_([0-9A-Fa-f]{4})') {
                $ven = $matches[1].ToUpper()
                if ($script:FpgaPciVendorIds.ContainsKey($ven)) { $alerts += "FAILURE: FPGA PCIe device present ($($script:FpgaPciVendorIds[$ven])) -> $($_.Name) [$($_.DeviceID)]" }
            }
        }
    } catch { $alerts += 'WARNING: Could not enumerate PCI devices' }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No virtual-input drivers or DMA hardware found' }
    return @($alerts | Select-Object -Unique)
}

function Get-ClarityDetectionAlerts {
    $alerts = @()
    $cdPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\ConfigDefender"
    if (Test-Path $cdPath) {
        $cdFiles = Get-ChildItem $cdPath -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }
        foreach ($file in $cdFiles) {
            $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
            if ($sig.Status -ne 'Valid' -or ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -notmatch 'Microsoft')) {
                $alerts += "FAILURE: Unsigned/non-Microsoft file in ConfigDefender: '$($file.FullName)'"
            }
        }
        $psm1File = Join-Path $cdPath "ConfigDefender.psm1"
        if (Test-Path $psm1File) {
            try {
                $content = Get-Content $psm1File -Raw -ErrorAction Stop
                if ($content -match 'Spoofed ConfigDefender|No-op|Silently fail') { $alerts += 'FAILURE: ConfigDefender.psm1 contains spoofed/fake module markers.' }
            } catch {}
        }
    }
    if (-not ('SOLNalCheck' -as [type])) {
        try { Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public class SOLNalCheck {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr CreateFileA(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr template);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
'@ -ErrorAction Stop } catch {}
    }
    if ('SOLNalCheck' -as [type]) {
        try {
            $nalHandle = [SOLNalCheck]::CreateFileA("\\.\Nal", [uint32]2147483648, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
            if ($nalHandle -ne [IntPtr]::new(-1)) { $alerts += "FAILURE: Vulnerable Intel driver device (\\.\Nal) is ACTIVE - BYOVD attack"; [SOLNalCheck]::CloseHandle($nalHandle) | Out-Null }
        } catch {}
    }
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Nal") { $alerts += 'FAILURE: Intel Nal driver service exists in registry' }
    $defenderProc = Get-Process -Name "MsMpEng" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $defenderProc) { $alerts += "FAILURE: MsMpEng.exe is NOT running - Defender may be killed" }
    elseif ($defenderProc.Path -and $defenderProc.Path -notlike "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe") {
        $alerts += "FAILURE: MsMpEng.exe running from unexpected path: '$($defenderProc.Path)'"
    }
    try {
        $val = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -ErrorAction Stop
        if ($val -ne 0) { $alerts += "FAILURE: Registry shows Defender real-time protection is DISABLED" }
    } catch {}
    if ($alerts.Count -eq 0) { $alerts += "SUCCESS: Clarity/Defender detection checks passed." }
    return @($alerts | Select-Object -Unique)
}

function Get-PowerShellModuleIntegrityAlerts {
    $alerts = @()
    $moduleRoots = @()
    foreach ($root in ($env:PSModulePath -split ';')) {
        if (-not [string]::IsNullOrWhiteSpace($root) -and (Test-Path -LiteralPath $root -PathType Container)) { $moduleRoots += $root }
    }
    foreach ($moduleName in $script:CorePowerShellModules) {
        $moduleDirs = @()
        foreach ($root in ($moduleRoots | Select-Object -Unique)) {
            $candidate = Join-Path $root $moduleName
            if (Test-Path -LiteralPath $candidate -PathType Container) { $moduleDirs += $candidate }
        }
        foreach ($moduleDir in ($moduleDirs | Select-Object -Unique)) {
            try {
                Get-ChildItem -LiteralPath $moduleDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $file = $_
                    if ($file.Extension -notmatch '(?i)^\.(ps1|psm1|psd1|dll|exe|ps1xml|cdxml)$') { return }
                    try { $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction Stop } catch { $alerts += "WARNING: Could not verify PowerShell module file -> $($file.FullName)"; return }
                    $isMicrosoft = $sig.SignerCertificate -and ($sig.SignerCertificate.Subject -match '(?i)(Microsoft Corporation|Microsoft Windows)')
                    if ($sig.Status -eq 'Valid' -and $isMicrosoft) { return }
                    if ($sig.Status -eq 'NotSigned') { $alerts += "WARNING: Unsigned PowerShell module file -> $($file.FullName)" }
                    else { $alerts += "FAILURE: PowerShell module integrity issue -> $($file.FullName) [$($sig.Status)]" }
                }
            } catch { $alerts += "WARNING: Could not scan PowerShell module -> $moduleDir" }
        }
    }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: Core PowerShell module files have acceptable signatures' }
    return @($alerts | Select-Object -Unique)
}

$script:WellKnownCaPattern = '(?i)DigiCert|GlobalSign|Sectigo|COMODO|USERTrust|Entrust|Go ?Daddy|Baltimore|VeriSign|Thawte|GeoTrust|ISRG|Let.s Encrypt|Amazon|Google Trust|Apple|Certum|IdenTrust|Kaspersky|ESET|Avast|Bitdefender|Norton|McAfee|Sophos|Cisco|Adobe|VMware|Oracle|Intel|NVIDIA|AMD|Dell|HP Inc|Lenovo|ASUS|Samsung|Valve|Discord|Roblox|Logitech|Razer|Corsair|Steelseries'

function Get-RootCertificateAlerts {
    $alerts = @()
    $stores = @(@{ Path = 'Cert:\CurrentUser\Root'; Label = 'user' },@{ Path = 'Cert:\LocalMachine\Root'; Label = 'machine' })
    foreach ($store in $stores) {
        $certs = @(); try { $certs = @(Get-ChildItem -Path $store.Path -ErrorAction Stop) } catch { continue }
        foreach ($cert in $certs) {
            if (-not (Test-UserInstalledRootThumbprint -Thumbprint $cert.Thumbprint)) { continue }
            $subject = [string]$cert.Subject; $short = $subject
            if ($subject -match 'CN=([^,]+)') { $short = $matches[1] }
            $when = Get-Date $cert.NotBefore -Format 'yyyy-MM-dd'
            $desc = "'$short' ($($store.Label) store, issued $when, $($cert.Thumbprint.Substring(0,8))...)"
            if ($subject -match '(?i)microsoft') { $alerts += "FAILURE: Forged Microsoft root certificate $desc" }
            elseif ($store.Label -eq 'user') { $alerts += "WARNING: Root certificate installed in user store $desc" }
            elseif ($subject -match $script:WellKnownCaPattern) { $alerts += "INFO: Non-default root certificate $desc" }
            else { $alerts += "WARNING: Unknown root certificate installed $desc" }
        }
    }
    if (-not ($alerts | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) { $alerts = @('SUCCESS: No user-installed root certificates') + $alerts }
    return @($alerts | Select-Object -Unique)
}

function Get-RootCertificateThumbprintSet {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in @('Cert:\CurrentUser\Root','Cert:\LocalMachine\Root')) {
        try { Get-ChildItem -Path $p -ErrorAction Stop | ForEach-Object { [void]$set.Add("$p|$($_.Thumbprint)|$($_.Subject)") } } catch {}
    }
    return $set
}

# ====================================================================
# ROBLOX, SESSION, HISTORY FUNCTIONS
# ====================================================================

$script:LogonTime = $null
function Get-LogonTime {
    if ($script:LogonTime) { return $script:LogonTime }
    try { $exp = Get-Process -Name explorer -ErrorAction Stop | Sort-Object StartTime | Select-Object -First 1; if ($exp -and $exp.StartTime) { $script:LogonTime = $exp.StartTime; return $script:LogonTime } } catch {}
    try { $script:LogonTime = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { $script:LogonTime = (Get-Date).AddHours(-12) }
    return $script:LogonTime
}
function Get-BootTime { try { return (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { return $null } }

function Get-BamEntries {
    $entries = @()
    $roots = @('SYSTEM\CurrentControlSet\Services\bam\State\UserSettings','SYSTEM\CurrentControlSet\Services\dam\State\UserSettings')
    foreach ($root in $roots) {
        try {
            $rootKey = Open-LocalMachineRegistryKey -SubKeyPath $root; if (-not $rootKey) { continue }
            foreach ($sidName in $rootKey.GetSubKeyNames()) {
                if ($sidName -eq 'S-1-5-18') { continue }
                $sidKey = $rootKey.OpenSubKey($sidName); if (-not $sidKey) { continue }
                foreach ($valueName in $sidKey.GetValueNames()) {
                    if (-not $valueName -or $valueName -notmatch '\\') { continue }
                    $raw = $sidKey.GetValue($valueName)
                    if (-not ($raw -is [byte[]]) -or $raw.Length -lt 8) { continue }
                    $ranAt = $null
                    try { $ranAt = [DateTime]::FromFileTime([BitConverter]::ToInt64($raw, 0)) } catch {}
                    $resolved = $null
                    if ($valueName -match '^\\Device\\HarddiskVolume\d+\\(.+)$') { $resolved = Join-Path $env:SystemDrive $matches[1] }
                    elseif ($valueName -match '^[A-Za-z]:\\') { $resolved = $valueName }
                    $entries += [pscustomobject]@{ Raw = $valueName; Path = $resolved; Leaf = (Split-Path -Leaf $valueName); Time = $ranAt; Sid = $sidName }
                }
                $sidKey.Close()
            }
            $rootKey.Close()
        } catch {}
    }
    return $entries
}

function Get-BamHistoryAlerts {
    $alerts = @()
    $roots = @('SYSTEM\CurrentControlSet\Services\bam\State\UserSettings','SYSTEM\CurrentControlSet\Services\dam\State\UserSettings')
    foreach ($root in $roots) {
        try {
            $rootKey = Open-LocalMachineRegistryKey -SubKeyPath $root; if (-not $rootKey) { continue }
            foreach ($sidName in $rootKey.GetSubKeyNames()) {
                if ($sidName -eq 'S-1-5-18') { continue }
                $sidKey = $rootKey.OpenSubKey($sidName); if (-not $sidKey) { continue }
                foreach ($valueName in $sidKey.GetValueNames()) {
                    if (-not $valueName) { continue }
                    $raw = $sidKey.GetValue($valueName)
                    if (-not $raw -or $raw.Length -lt 8) { continue }
                    $resolvedPath = $null
                    if ($valueName -match '^\\Device\\HarddiskVolume\d+\\(.+)$') { $resolvedPath = Join-Path $env:SystemDrive $matches[1] }
                    $leaf = Split-Path -Leaf $valueName
                    $kw = Get-MatchedCheatKeyword -Text $valueName
                    if (-not $kw -and $resolvedPath) { $kw = Get-MatchedCheatKeyword -Text $resolvedPath }
                    if ($kw) {
                        $hex = [System.BitConverter]::ToString($raw[7..0]) -replace '-',''
                        $ranAt = 'unknown time'
                        try { $ranAt = (Get-Date ([DateTime]::FromFileTime([Convert]::ToInt64($hex, 16))) -Format 'yyyy-MM-dd HH:mm:ss') } catch {}
                        $alerts += "FAILURE: Execution history [$kw] '$leaf' ran $ranAt -> $valueName"
                    }
                }
                $sidKey.Close()
            }
            $rootKey.Close()
        } catch {}
    }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No suspicious entries in execution history.' }
    return @($alerts | Select-Object -Unique)
}

function Get-BamRegistryFingerprints {
    $fps = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $roots = @('SYSTEM\CurrentControlSet\Services\bam\State\UserSettings','SYSTEM\CurrentControlSet\Services\dam\State\UserSettings')
    foreach ($root in $roots) {
        try {
            $rootKey = Open-LocalMachineRegistryKey -SubKeyPath $root; if (-not $rootKey) { continue }
            foreach ($sidName in $rootKey.GetSubKeyNames()) {
                if ($sidName -eq 'S-1-5-18') { continue }
                $sidKey = $rootKey.OpenSubKey($sidName); if (-not $sidKey) { continue }
                foreach ($valueName in $sidKey.GetValueNames()) { if ($valueName) { [void]$fps.Add("$root|$sidName|$valueName") } }
                $sidKey.Close()
            }
            $rootKey.Close()
        } catch {}
    }
    return @($fps)
}

function Get-PrefetchFileNames {
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $prefetchPath = "$env:WINDIR\Prefetch"
    if (-not (Test-Path $prefetchPath)) { return @($names) }
    try { Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction Stop | ForEach-Object { [void]$names.Add($_.Name) } } catch {}
    return @($names)
}

function Get-SessionSummaryAlerts {
    $alerts = @()
    $logon = Get-LogonTime; $boot = Get-BootTime
    $alerts += "INFO: User logon (explorer.exe start) -> $(Get-Date $logon -Format 'yyyy-MM-dd HH:mm:ss')"
    if ($boot) { $alerts += "INFO: Last boot -> $(Get-Date $boot -Format 'yyyy-MM-dd HH:mm:ss')" }
    try {
        $install = (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallDate -ErrorAction Stop)
        $installDate = [DateTimeOffset]::FromUnixTimeSeconds([int64]$install).LocalDateTime
        $alerts += "INFO: Windows installed -> $(Get-Date $installDate -Format 'yyyy-MM-dd')"
        if ($installDate -gt (Get-Date).AddDays(-14)) { $alerts += "WARNING: Windows was installed less than 14 days ago (fresh install wipes execution history)" }
    } catch {}
    $recent = @(Get-BamEntries | Where-Object { $_.Time -and $_.Time -ge $logon -and $_.Raw -notmatch '(?i)\\windows\\' } | Sort-Object Time -Descending)
    if ($recent.Count -eq 0) { $alerts += 'INFO: No non-Windows executables recorded since logon' }
    else {
        $shown = 0
        foreach ($e in $recent) {
            if ($shown -ge 25) { $alerts += "INFO: ... and $($recent.Count - 25) more"; break }
            $alerts += "INFO: Ran $(Get-Date $e.Time -Format 'HH:mm:ss') -> $($e.Raw)"; $shown++
        }
    }
    return $alerts
}

function Get-PrefetchHealthAlerts {
    $alerts = @()
    $prefetchPath = "$env:WINDIR\Prefetch"
    if (-not (Test-Path -LiteralPath $prefetchPath)) { $alerts += 'FAILURE: Prefetch folder is missing' }
    else {
        $count = 0; try { $count = @(Get-ChildItem -LiteralPath $prefetchPath -Filter '*.pf' -ErrorAction Stop).Count } catch {}
        if ($count -eq 0) { $alerts += 'FAILURE: Prefetch folder is empty (execution history wiped or prefetch disabled)' }
        elseif ($count -lt 20) { $alerts += "WARNING: Only $count prefetch files present (recently cleaned?)" }
        else { $alerts += "INFO: $count prefetch files present" }
        try {
            $newest = Get-ChildItem -LiteralPath $prefetchPath -Filter '*.pf' -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($newest -and $newest.LastWriteTime -lt (Get-Date).AddHours(-6)) { $alerts += "WARNING: Newest prefetch file is from $(Get-Date $newest.LastWriteTime -Format 'yyyy-MM-dd HH:mm') (prefetch may be off)" }
        } catch {}
    }
    try {
        $ep = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name EnablePrefetcher -ErrorAction Stop
        if ([int]$ep -eq 0) { $alerts += 'FAILURE: EnablePrefetcher is 0 (prefetch logging turned off)' }
        elseif ([int]$ep -eq 2) { $alerts += 'WARNING: EnablePrefetcher is 2 (boot-only; application prefetch off)' }
    } catch { $alerts += 'WARNING: EnablePrefetcher value unreadable' }
    try {
        $svc = Get-Service -Name SysMain -ErrorAction Stop
        if ($svc.Status -ne 'Running') { $alerts += "FAILURE: SysMain service is $($svc.Status) (prefetch/superfetch not recording)" }
        if ($svc.StartType -eq 'Disabled') { $alerts += 'FAILURE: SysMain service is Disabled' }
    } catch { $alerts += 'WARNING: SysMain service not found' }
    if (-not ($alerts | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) { $alerts = @('SUCCESS: Prefetch enabled and recording') + $alerts }
    return $alerts
}

function Get-BamServiceAlerts {
    $alerts = @()
    try {
        $svc = Get-Service -Name bam -ErrorAction Stop
        if ($svc.Status -ne 'Running') { $alerts += "FAILURE: BAM service is $($svc.Status)" }
        if ($svc.StartType -eq 'Disabled') { $alerts += 'FAILURE: BAM service start type is Disabled' }
    } catch { $alerts += 'FAILURE: BAM service not found' }
    try { $start = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\bam' -Name Start -ErrorAction Stop; if ([int]$start -eq 4) { $alerts += 'FAILURE: BAM driver Start=4 (disabled in registry)' } } catch {}
    $entryCount = @(Get-BamEntries).Count
    if ($entryCount -eq 0) { $alerts += 'FAILURE: BAM execution history is empty' }
    else { $alerts += "INFO: $entryCount BAM/DAM entries" }
    if (-not ($alerts | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) { $alerts = @('SUCCESS: BAM service running and recording') + $alerts }
    return $alerts
}

function Get-UsnJournalState {
    param([string]$Drive = $env:SystemDrive)
    $state = @{ Present = $false; JournalId = $null; Created = $null; Error = $null }
    try {
        $out = & "$env:SystemRoot\System32\fsutil.exe" usn queryjournal $Drive 2>&1 | Out-String
        if ($out -match '(?i)not active|no.*journal') { $state.Error = 'not active'; return $state }
        if ($out -match '(?im)^\s*Usn Journal ID\s*:\s*0x([0-9a-f]+)') { $state.Present = $true; $state.JournalId = $matches[1]; try { $state.Created = [DateTime]::FromFileTime([Convert]::ToInt64($matches[1], 16)) } catch {} }
        elseif ($out -match '(?i)denied|privilege') { $state.Error = 'access denied' }
        else { $state.Error = 'unparsed' }
    } catch { $state.Error = $_.Exception.Message }
    return $state
}

function Get-UsnJournalAlerts {
    $alerts = @()
    $state = Get-UsnJournalState
    if ($state.Error -eq 'not active') { $alerts += "FAILURE: USN change journal is not present on $env:SystemDrive (deleted)"; return $alerts }
    if ($state.Error -eq 'access denied') { $alerts += 'WARNING: USN journal unreadable (run as Administrator)'; return $alerts }
    if (-not $state.Present) { $alerts += 'WARNING: USN journal state could not be determined'; return $alerts }
    $boot = Get-BootTime
    if ($state.Created) {
        $alerts += "INFO: USN journal created $(Get-Date $state.Created -Format 'yyyy-MM-dd HH:mm:ss')"
        if ($boot -and $state.Created -gt $boot.AddMinutes(10)) { $alerts += "FAILURE: USN journal was recreated after boot ($(Get-Date $boot -Format 'HH:mm:ss')) - journal was deleted this session" }
        elseif ($state.Created -gt (Get-Date).AddDays(-2)) { $alerts += 'WARNING: USN journal is less than 2 days old' }
    }
    if (-not ($alerts | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) { $alerts = @('SUCCESS: USN change journal present and intact') + $alerts }
    return $alerts
}

function Get-ClockChangeAlerts {
    param([datetime]$Since = (Get-LogonTime))
    $alerts = @(); $found = $false
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4616; StartTime = $Since } -ErrorAction Stop | ForEach-Object {
            $msg = [string]$_.Message
            if ($msg -match '(?i)svchost\.exe|w32time|VBoxService|vmtoolsd') { return }
            $proc = ''; if ($msg -match '(?m)Process Name:\s*(.+)$') { $proc = $matches[1].Trim() }
            $found = $true; $alerts += "WARNING: System time changed at $(Get-Date $_.TimeCreated -Format 'HH:mm:ss') by $proc"
        }
    } catch { if ($_.Exception.Message -notmatch '(?i)no events were found') { $alerts += 'INFO: Security log unreadable for time-change events (run as Administrator)' } }
    if (-not $found -and -not ($alerts | Where-Object { $_ -like 'WARNING*' })) { $alerts = @('SUCCESS: No manual system clock changes since logon') + $alerts }
    return @($alerts | Select-Object -Unique)
}

$script:AntiForensicCommandPatterns = @(
    @{ Level = 'FAILURE'; Label = 'event log cleared';        Pattern = 'wevtutil\s+(cl|clear-log)|Clear-EventLog|Limit-EventLog' },
    @{ Level = 'FAILURE'; Label = 'shadow copies deleted';    Pattern = 'vssadmin.*delete\s+shadows|shadowcopy\s+delete|Win32_ShadowCopy.*Delete' },
    @{ Level = 'FAILURE'; Label = 'USN journal deleted';      Pattern = 'fsutil\s+usn\s+deletejournal' },
    @{ Level = 'FAILURE'; Label = 'prefetch wiped';           Pattern = '(Remove-Item|del |rd |rmdir|erase )[^\r\n]*prefetch' },
    @{ Level = 'FAILURE'; Label = 'BAM history wiped';        Pattern = '(reg\s+delete|Remove-Item|Remove-ItemProperty)[^\r\n]*\\bam\\' },
    @{ Level = 'FAILURE'; Label = 'Defender disabled';        Pattern = 'Set-MpPreference[^\r\n]*-Disable(RealtimeMonitoring|IOAVProtection|BehaviorMonitoring)\s+\$?true' },
    @{ Level = 'FAILURE'; Label = 'test signing enabled';     Pattern = 'bcdedit[^\r\n]*testsigning\s+on|nointegritychecks\s+on' },
    @{ Level = 'WARNING'; Label = 'Defender exclusion added'; Pattern = 'Add-MpPreference[^\r\n]*-Exclusion' },
    @{ Level = 'WARNING'; Label = 'encoded command';          Pattern = '-(EncodedCommand|enc)\s+[A-Za-z0-9+/=]{20,}' },
    @{ Level = 'WARNING'; Label = 'permissions changed';      Pattern = 'icacls[^\r\n]*(prefetch|\\bam|eventlog|winevt)' }
)

function Get-CommandHistoryAlerts {
    $alerts = @(); $sources = @()
    $historyFile = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path -LiteralPath $historyFile) {
        try { $lines = @(Get-Content -LiteralPath $historyFile -ErrorAction Stop | Select-Object -Last 2000); $sources += @{ Name = 'PowerShell history'; Lines = $lines } }
        catch {}
    } else { $alerts += 'INFO: No PowerShell history file (never used interactively, or cleared)' }
    try {
        $since = (Get-LogonTime).AddDays(-7)
        $evLines = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $since } -MaxEvents 500 -ErrorAction Stop |
            ForEach-Object { [string]$_.Message } | Where-Object { $_ -notmatch 'AntiForensicCommandPatterns|sol_recording_policy|SOLVersion|Get-CommandHistoryAlerts' })
        if ($evLines.Count -gt 0) { $sources += @{ Name = 'PowerShell script log'; Lines = $evLines } }
    } catch {}
    foreach ($src in $sources) {
        foreach ($rule in $script:AntiForensicCommandPatterns) {
            $hits = @($src.Lines | Where-Object { $_ -match "(?i)$($rule.Pattern)" } | Select-Object -Unique | Select-Object -First 3)
            foreach ($hit in $hits) {
                if ($hit -match '(?i)ror_security_events|SOL v\d') { continue }
                $snippet = ($hit -replace '\s+',' ').Trim(); if ($snippet.Length -gt 140) { $snippet = $snippet.Substring(0,140) + '...' }
                $alerts += "$($rule.Level): $($rule.Label) in $($src.Name) -> $snippet"
            }
        }
    }
    if (-not ($alerts | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) { $alerts = @('SUCCESS: No anti-forensic commands in command history') + $alerts }
    return @($alerts | Select-Object -Unique)
}

function Get-ArtifactCrossCheckAlerts {
    $alerts = @()
    try { $sysMain = Get-Service -Name SysMain -ErrorAction SilentlyContinue; if ($sysMain -and $sysMain.Status -ne 'Running') { return @('INFO: SysMain not running - prefetch artifact cross-check skipped') } } catch {}
    $logon = Get-LogonTime
    $prefetch = @(Get-PrefetchFileNames)
    if ($prefetch.Count -eq 0) { return @('WARNING: No prefetch files to cross-check against BAM') }
    $pfIndex = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($pf in $prefetch) { if ($pf -match '^(.+?)-[0-9A-F]{8}\.pf$') { [void]$pfIndex.Add($matches[1]) } }
    $recent = @(Get-BamEntries | Where-Object { $_.Time -and $_.Time -ge $logon -and $_.Leaf -match '(?i)\.exe$' -and $_.Raw -notmatch '(?i)\\windows\\|\\windowsapps\\|\\microsoft\\edge' })
    $missing = @($recent | Where-Object { -not $pfIndex.Contains($_.Leaf) })
    if ($recent.Count -gt 0 -and $missing.Count -eq $recent.Count -and $recent.Count -ge 3) { $alerts += "FAILURE: None of the $($recent.Count) programs run since logon have a prefetch file (prefetch cleaned or disabled)" }
    foreach ($e in ($missing | Sort-Object Time -Descending | Select-Object -First 10)) { $alerts += "WARNING: Ran since logon but has no prefetch file -> $($e.Raw) ($(Get-Date $e.Time -Format 'HH:mm:ss'))" }
    if ($missing.Count -gt 10) { $alerts += "INFO: ... and $($missing.Count - 10) more without prefetch" }
    if ($alerts.Count -eq 0) { $alerts += "SUCCESS: BAM and prefetch agree for $($recent.Count) programs run since logon" }
    return $alerts
}

# ====================================================================
# ROBLOX-SPECIFIC FUNCTIONS
# ====================================================================

function Get-RobloxVersionInfo {
    $result = [pscustomobject]@{ Installed=$false;IsRunning=$false;Pid=0;Path='';FileVersion='';ProductVersion='';VersionHash='';Is64Bit=$false }
    try {
        $proc = Get-Process -Name 'RobloxPlayerBeta' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($proc -and $proc.Path -and (Test-Path -LiteralPath $proc.Path -PathType Leaf)) { $result.IsRunning=$true;$result.Pid=[int]$proc.Id;$result.Path=[string]$proc.Path }
    } catch {}
    if (-not $result.Path) {
        $searchDirs = @((Join-Path $env:LOCALAPPDATA 'Roblox\Versions'),(Join-Path $env:LOCALAPPDATA 'Bloxstrap\Versions'),(Join-Path $env:LOCALAPPDATA 'Fishstrap\Versions'))
        $candidates = @()
        foreach ($dir in $searchDirs) { if (Test-Path -LiteralPath $dir -PathType Container) { try { $found = Get-ChildItem -LiteralPath $dir -Filter 'RobloxPlayerBeta.exe' -Recurse -File -ErrorAction SilentlyContinue; if ($found) { $candidates += $found } } catch {} } }
        if ($candidates.Count -gt 0) { $latest = $candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1; $result.Path = $latest.FullName }
    }
    if (-not $result.Path -or -not (Test-Path -LiteralPath $result.Path -PathType Leaf)) { return $result }
    $result.Installed = $true
    try { $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($result.Path); $result.FileVersion=[string]$fvi.FileVersion;$result.ProductVersion=[string]$fvi.ProductVersion } catch {}
    $parent = Split-Path -Path $result.Path -Parent; if ($parent) { $result.VersionHash = Split-Path -Path $parent -Leaf }
    try { $bytes = [System.IO.File]::ReadAllBytes($result.Path); $peOffset = [BitConverter]::ToInt32($bytes,0x3C); $machine = [BitConverter]::ToUInt16($bytes,$peOffset+4); $result.Is64Bit = ($machine -eq 0x8664) } catch {}
    return $result
}

function Get-RobloxVersionAlerts {
    $alerts = @(); $v = Get-RobloxVersionInfo
    if (-not $v.Installed) { $alerts += "WARNING: Roblox installation not found in %LocalAppData%"; return $alerts }
    $arch = if ($v.Is64Bit) { "x64" } else { "x86" }
    $runTag = if ($v.IsRunning) { " (ACTIVE - PID $($v.Pid))" } else { " (Inactive/Last Installed)" }
    $alerts += "INFO: Client Status$runTag"
    $alerts += "SUCCESS: Build Hash -> $($v.VersionHash)"
    $alerts += "SUCCESS: File Version -> $($v.FileVersion) ($arch)"
    if ($v.ProductVersion -and ($v.ProductVersion -ne $v.FileVersion)) { $alerts += "INFO: Product Version -> $($v.ProductVersion)" }
    $alerts += "INFO: Executable -> $($v.Path)"
    return $alerts
}

function Get-RobloxModuleAlerts {
    $alerts = @(); $procs = @()
    try { $procs = @(Get-Process -Name RobloxPlayerBeta -ErrorAction Stop) } catch {}
    if ($procs.Count -eq 0) { return @('INFO: Roblox is not running - loaded-module check skipped') }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase); $checked = 0
    foreach ($proc in $procs) {
        $modules = $null; try { $modules = $proc.Modules } catch { $alerts += "WARNING: Could not list modules of RobloxPlayerBeta (PID $($proc.Id))"; continue }
        foreach ($m in $modules) {
            $file = [string]$m.FileName; if (-not $file -or -not $seen.Add($file)) { continue }
            $lower = $file.ToLower(); if ($lower.StartsWith("$($env:SystemRoot.ToLower())\")) { continue }
            $checked++
            $sig = $null; try { $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $file -ErrorAction Stop } catch {}
            $status = if ($sig) { [string]$sig.Status } else { 'Unknown' }
            $userLand = Test-UserLandProcessPath -ExecutablePath $file; $kw = Get-MatchedCheatKeyword -Text $file; $kwTag = if ($kw) { " [$kw]" } else { '' }
            if ($status -ne 'Valid') { $entropy = Get-FileEntropy -FilePath $file; $alerts += "FAILURE: Unsigned/invalid module$kwTag loaded in Roblox ($status) [Entropy: $entropy] -> $file" }
            elseif (-not (Test-SignedByShippedRoot -Path $file)) { $alerts += "FAILURE: Module$kwTag signed by user-installed root loaded in Roblox -> $file" }
            elseif ($userLand -and $kw) { $alerts += "FAILURE: Module [$kw] from a user folder loaded in Roblox -> $file" }
            elseif ($userLand) { $signer = ''; if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'CN=([^,]+)') { $signer = $matches[1] }; $alerts += "WARNING: Signed module from a user folder loaded in Roblox ($signer) -> $file" }
        }
    }
    if ($alerts.Count -eq 0) { $alerts += "SUCCESS: All $checked non-Windows modules in Roblox are validly signed" }
    return @($alerts | Select-Object -Unique)
}

function Get-RobloxNamedPipeAlerts {
    $alerts = @()
    $cheatPipeKeywords = @('krampus','solara','wavepipe','celery','fluxus','krnl','wearedevs','oxygen','electron','hydrogen','swift','comet','valyse','xeno','synapse')
    try {
        $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\')
        foreach ($pipe in $pipes) {
            $leaf = Split-Path -Leaf $pipe; $leafLower = $leaf.ToLower()
            foreach ($kw in $cheatPipeKeywords) { if ($leafLower.Contains($kw)) { $alerts += "FAILURE: Detected cheat named pipe: \\.\pipe\$leaf"; break } }
        }
    } catch {}
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No suspicious or cheat named pipes detected' }
    return $alerts
}

function Get-FastFlagsAlerts {
    $alerts = @()
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Roblox\Versions\*\ClientSettings\ClientAppSettings.json'),
        (Join-Path $env:LOCALAPPDATA 'Bloxstrap\Modifications\ClientSettings\ClientAppSettings.json'),
        (Join-Path $env:LOCALAPPDATA 'Fishstrap\Modifications\ClientSettings\ClientAppSettings.json')
    )
    $suspiciousFlags = @('FFlagDebugDisplayUntrackedMemory','FFlagDebugGraphicsDisableDirect3D11','FFlagVisualEngine')
    $foundFiles = Resolve-Path $candidates -ErrorAction SilentlyContinue
    foreach ($file in $foundFiles) {
        try {
            $jsonText = [System.IO.File]::ReadAllText($file.Path)
            foreach ($sf in $suspiciousFlags) { if ($jsonText.Contains($sf)) { $alerts += "WARNING: Exploit-associated FastFlag in $($file.Path): $sf" } }
        } catch {}
    }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No exploit-associated FastFlags detected' }
    return $alerts
}

function Get-AntiBypassNetworkAlerts {
    $alerts = @()
    try {
        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        if (Test-Path $hostsPath) {
            $lines = Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue
            foreach ($line in $lines) {
                $trimmed = $line.Trim(); if ($trimmed.StartsWith('#') -or -not $trimmed) { continue }
                if ($trimmed -match '(?i)(roblox|rbxcdn|clientsettings)') { $alerts += "FAILURE: Hosts file redirection: $trimmed" }
            }
        }
        $proxyKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        if (Test-Path $proxyKey) {
            $proxyEnabled = (Get-ItemProperty -Path $proxyKey -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
            if ($proxyEnabled -eq 1) { $server = (Get-ItemProperty -Path $proxyKey -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer; $alerts += "WARNING: System proxy enabled: $server" }
        }
    } catch {}
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: Network configuration and hosts file clean' }
    return $alerts
}

function Get-KeyAuthAlerts {
    $alerts = @()
    try {
        $keyAuthHits = @()
        $keyRoot = Join-Path $env:ProgramData 'KeyAuth'
        if (Test-Path $keyRoot) { $keyAuthHits += $keyRoot; Get-ChildItem $keyRoot -Recurse -Directory -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object { $keyAuthHits += $_.FullName } }
        if ($keyAuthHits.Count -eq 0) { $alerts += 'SUCCESS: KeyAuth clean' }
        else { foreach ($hit in ($keyAuthHits | Select-Object -Unique)) { $alerts += "FAILURE: KeyAuth $hit" } }
    } catch { $alerts += 'WARNING: KeyAuth check failed' }
    return $alerts
}

function Get-RegistryMarkerAlerts {
    $alerts = @()
    try { if (Test-Path -LiteralPath 'HKCU:\Antenna') { $alerts += 'FAILURE: Cheat registry marker found (HKCU:\Antenna)' } } catch {}
    # v2.0: additional cheat registry markers
    $additionalCheatKeys = @(
        'HKCU:\SOFTWARE\Solara', 'HKCU:\SOFTWARE\Krnl', 'HKCU:\SOFTWARE\Synapse',
        'HKCU:\SOFTWARE\Celery', 'HKCU:\SOFTWARE\Hydrogen', 'HKCU:\SOFTWARE\Electron',
        'HKCU:\SOFTWARE\Arceus', 'HKCU:\SOFTWARE\Fluxus', 'HKCU:\SOFTWARE\Delta',
        'HKLM:\SOFTWARE\Solara', 'HKLM:\SOFTWARE\Krnl'
    )
    foreach ($key in $additionalCheatKeys) {
        try { if (Test-Path $key -ErrorAction SilentlyContinue) { $kw = Split-Path $key -Leaf; $alerts += "FAILURE: Cheat registry key found [$kw]: $key" } } catch {}
    }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: Registry clean' }
    return $alerts
}

function Get-CpuGpuAlerts {
    $alerts = @()
    try {
        $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Name
        if ($cpu) { $alerts += "SUCCESS: CPU -> $cpu" }
        $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction Stop | Select-Object -ExpandProperty Name)
        foreach ($gpu in $gpus) { $alerts += "SUCCESS: GPU -> $gpu" }
        if (-not $cpu -or $gpus.Count -eq 0) { $alerts += 'WARNING: CPU or GPU could not be identified' }
    } catch { $alerts += 'WARNING: Unable to query CPU/GPU information.' }
    return $alerts
}

function Get-DefenderStep1Alerts {
    $alerts = @()
    try {
        if (-not $script:DefenderAvailable) { $alerts += 'WARNING: Windows Defender status check unavailable.' }
        else {
            $def = Defender\Get-MpComputerStatus -ErrorAction Stop
            if ($def.RealTimeProtectionEnabled) { $alerts += 'SUCCESS: Real-time protection enabled' } else { $alerts += 'FAILURE: Real-time protection disabled' }
            if (-not $def.IsTamperProtected) { $alerts += 'WARNING: Tamper protection disabled' }
            if ($def.AntivirusSignatureAge -gt 7) { $alerts += "WARNING: Defender signatures are $($def.AntivirusSignatureAge) days old" }
        }
    } catch { $alerts += "WARNING: Unable to query Defender: $($_.Exception.Message)" }
    foreach ($disableKey in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender','HKLM:\SOFTWARE\Microsoft\Windows Defender')) {
        try { $disabled = Get-ItemPropertyValue -Path $disableKey -Name 'DisableAntiSpyware' -ErrorAction Stop; if ($disabled -eq 1) { $alerts += 'FAILURE: DisableAntiSpyware active' } } catch {}
    }
    return $alerts
}

function Get-ExclusionAlerts {
    $alerts = @()
    try {
        $allExclusions = @(Get-Exclusions)
        if ($allExclusions.Count -eq 0) { $alerts += if ($script:DefenderAvailable) { 'SUCCESS: No Defender exclusions' } else { 'WARNING: Defender exclusions could not be fully verified.' } }
        else { foreach ($excl in $allExclusions) { $kw = Get-MatchedCheatKeyword -Text $excl; if ($kw) { $alerts += "FAILURE: Defender exclusion [$kw] -> $excl" } else { $alerts += "FAILURE: Defender exclusion -> $excl" } } }
    } catch { $alerts += 'WARNING: Exclusions check failed.' }
    return $alerts
}

function Get-AllowedThreatAlerts {
    $alerts = @()
    try {
        $allowed = @(Get-AllowedDefenderThreats)
        if ($allowed.Count -eq 0) { $alerts += 'SUCCESS: No allowed threats' }
        else { foreach ($threat in $allowed) { $alerts += "FAILURE: Allowed threat -> $threat" } }
    } catch { $alerts += 'WARNING: Allowed threats check failed.' }
    return $alerts
}

function Get-DefenderHistoryAlerts {
    if (-not $script:DefenderAvailable) { return @('WARNING: Defender cmdlets unavailable') }
    $alerts = @()
    try {
        $dets = @(Defender\Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending)
        if ($dets.Count -eq 0) { return @('SUCCESS: No Defender detection history') }
        $names = @{}; try { Defender\Get-MpThreat -ErrorAction Stop | ForEach-Object { $names[[string]$_.ThreatID] = [string]$_.ThreatName } } catch {}
        $shown = 0
        foreach ($d in $dets) {
            if ($shown -ge 10) { $alerts += "INFO: ... and $($dets.Count - 10) more detections"; break }
            $name = $names[[string]$d.ThreatID]; if (-not $name) { $name = "ThreatID $($d.ThreatID)" }
            $res = ([string]($d.Resources -join ', ')) -replace '^(file|containerfile|process):_',''
            $when = Get-Date $d.InitialDetectionTime -Format 'yyyy-MM-dd HH:mm'
            $kw = Get-MatchedCheatKeyword -Text $res
            if ($kw) { $alerts += "WARNING: Defender detected [$kw] $name at $when -> $res" }
            else { $alerts += "INFO: Defender detected $name at $when -> $res" }
            $shown++
        }
        $alerts = @("INFO: $($dets.Count) Defender detections on record") + $alerts
    } catch { $alerts += 'WARNING: Could not read Defender detection history' }
    return $alerts
}

function Get-DnsCacheAlerts {
    $alerts = @()
    $script:DnsAllowlistPattern = '(?i)(^|\.)(microsoft\.com|roblox\.com|rbxcdn\.com|discord\.com|github\.com|steamstatic\.com|epicgames\.com|unity3d\.com|spotify\.com|googleapis\.com|cloudflare\.com|akamaized\.net|windowsupdate\.com|live\.com|nvidia\.com|intel\.com)$'
    try {
        $entries = @(Get-DnsClientCache -ErrorAction Stop | Select-Object -ExpandProperty Entry -Unique)
    } catch { return @('WARNING: Could not read DNS cache') }
    foreach ($hostName in $entries) {
        if (-not $hostName -or $hostName -match $script:DnsAllowlistPattern) { continue }
        $kw = Get-MatchedCheatKeyword -Text $hostName
        if ($kw) { $alerts += "WARNING: DNS cache entry [$kw] -> $hostName" }
    }
    if ($alerts.Count -eq 0) { $alerts += "SUCCESS: No cheat keywords in DNS cache ($($entries.Count) entries)" }
    return @($alerts | Select-Object -Unique)
}

function Get-UsbHistoryAlerts {
    $alerts = @(); $logon = Get-LogonTime; $removed = @()
    $propKey = 'Properties\{83da6326-97a6-4088-9453-a1923f573b29}'
    foreach ($enumRoot in @('SYSTEM\CurrentControlSet\Enum\USBSTOR','SYSTEM\CurrentControlSet\Enum\USB')) {
        try {
            $root = Open-LocalMachineRegistryKey -SubKeyPath $enumRoot; if (-not $root) { continue }
            foreach ($dev in $root.GetSubKeyNames()) {
                $devKey = $root.OpenSubKey($dev); if (-not $devKey) { continue }
                foreach ($inst in $devKey.GetSubKeyNames()) {
                    $instKey = $devKey.OpenSubKey($inst); if (-not $instKey) { continue }
                    $removalKey = $instKey.OpenSubKey("$propKey\0067")
                    if ($removalKey) {
                        $raw = $removalKey.GetValue('')
                        if ($raw -is [byte[]] -and $raw.Length -ge 8) {
                            try { $removedAt = [DateTime]::FromFileTime([BitConverter]::ToInt64($raw, 0)) } catch { $removedAt = $null }
                            if ($removedAt -and $removedAt -ge $logon) {
                                $name = [string]$instKey.GetValue('FriendlyName'); if (-not $name) { $name = $dev }
                                $removed += [pscustomobject]@{ Name = $name; Time = $removedAt; Id = $dev }
                            }
                        }
                        $removalKey.Close()
                    }
                    $instKey.Close()
                }
                $devKey.Close()
            }
            $root.Close()
        } catch {}
    }
    if ($removed.Count -eq 0) { return @('SUCCESS: No USB devices removed since logon') }
    foreach ($r in ($removed | Sort-Object Time -Descending | Select-Object -First 15)) { $alerts += "INFO: USB device removed $(Get-Date $r.Time -Format 'HH:mm:ss') -> $($r.Name)" }
    if ($removed.Count -gt 15) { $alerts += "INFO: ... and $($removed.Count - 15) more" }
    return $alerts
}

$script:WindhawkProcessName = 'windhawk.exe'
$script:WindhawkWatchPaths = @(
    (Join-Path $env:USERPROFILE 'Downloads\windhawk.exe'),
    (Join-Path ${env:ProgramFiles} 'Windhawk\windhawk.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Windhawk\windhawk.exe')
)

function Get-WindhawkStep1Alerts {
    $alerts = @()
    if (Get-Process -Name 'windhawk' -ErrorAction SilentlyContinue) { $alerts += 'FAILURE: Windhawk is running'; return $alerts }
    foreach ($p in $script:WindhawkWatchPaths) { if ($p -and (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) { $alerts += "WARNING: Windhawk found at $p"; return $alerts } }
    $alerts += 'SUCCESS: Windhawk not detected'; return $alerts
}

$script:NvidiaShadowPlayFtsRegPath = 'SOFTWARE\NVIDIA Corporation\Global\NvApp\ShadowPlay\FTS'
function Test-NvidiaGpuPresent {
    try { $gpus = Get-CimInstance Win32_VideoController -ErrorAction Stop | Select-Object -ExpandProperty Name; foreach ($gpu in $gpus) { if ($gpu -match '(?i)nvidia') { return $true } } } catch {}
    return $false
}
function Get-NvidiaShadowPlayFtsAlerts {
    $alerts = @()
    if (-not (Test-NvidiaGpuPresent)) { $alerts += 'SUCCESS: NVIDIA ShadowPlay N/A'; return $alerts }
    try {
        $key = Open-LocalMachineRegistryKey -SubKeyPath $script:NvidiaShadowPlayFtsRegPath
        if (-not $key) { $alerts += 'SUCCESS: ShadowPlay FTS not present'; return $alerts }
        foreach ($name in ($key.GetValueNames() | Sort-Object)) { $alerts += "SUCCESS: ShadowPlay FTS $name = $($key.GetValue($name))" }
        $key.Close()
    } catch {}
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: ShadowPlay FTS not present' }
    return $alerts
}

# ====================================================================
# EXTERNAL CHEAT SCAN (from original, condensed)
# ====================================================================

$script:ExternalReaderAllowlist = @(
    'robloxplayerbeta','robloxcrashhandler','robloxplayerlauncher','bloxstrap','fishstrap','lunarstrap',
    'msmpeng','nissrv','securityhealthservice','mpdefendercoreservice','csrss','lsass','wininit',
    'services','searchindexer','wmiprvse','procexp','procexp64','taskmgr','perfmon','resmon'
)
$script:CaptureWindowAllowlist = @(
    'logonui','consent','dwm','textinputhost','screenclippinghost','snippingtool','searchhost',
    'startmenuexperiencehost','applicationframehost','systemsettings','shellexperiencehost'
)

function Initialize-ExternalScanApi {
    if ('SOL.ExternalScan' -as [type]) { return $true }
    try {
        Add-Type -Namespace SOL -Name ExternalScan -UsingNamespace System.Text, System.Collections.Generic -MemberDefinition @'
[DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
[DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);
[DllImport("user32.dll", SetLastError=true)] private static extern bool GetWindowDisplayAffinity(IntPtr hWnd, out uint dwAffinity);
[DllImport("user32.dll", SetLastError=true)] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
[DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
[DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetClassNameW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
[DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);
[DllImport("kernel32.dll", SetLastError=true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll", SetLastError=true)] private static extern bool DuplicateHandle(IntPtr srcProc, IntPtr srcHandle, IntPtr tgtProc, out IntPtr tgtHandle, uint access, bool inherit, uint options);
[DllImport("kernel32.dll", SetLastError=true)] private static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll", SetLastError=true)] private static extern int GetProcessId(IntPtr h);
[DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
private const int SystemExtendedHandleInformation = 0x40;
private const uint PROCESS_DUP_HANDLE = 0x0040;
private const uint PROCESS_VM_READ = 0x0010;
private const uint DUPLICATE_SAME_ACCESS = 0x0002;
private static List<string> _winHits;
private static EnumWindowsProc _winCb;
private static bool WindowCallback(IntPtr hWnd, IntPtr lParam) {
    try {
        if (!IsWindowVisible(hWnd)) return true;
        uint affinity; if (!GetWindowDisplayAffinity(hWnd, out affinity)) return true;
        if (affinity == 0) return true;
        uint pid = 0; GetWindowThreadProcessId(hWnd, out pid);
        StringBuilder title = new StringBuilder(256); GetWindowTextW(hWnd, title, title.Capacity);
        StringBuilder cls = new StringBuilder(256); GetClassNameW(hWnd, cls, cls.Capacity);
        _winHits.Add(pid.ToString() + "|" + affinity.ToString() + "|" + title.ToString() + "|" + cls.ToString());
    } catch {} return true;
}
public static string[] FindCaptureProtectedWindows() {
    _winHits = new List<string>(); _winCb = new EnumWindowsProc(WindowCallback);
    try { EnumWindows(_winCb, IntPtr.Zero); } catch { return null; } return _winHits.ToArray();
}
public static int[] FindRobloxMemoryReaders(int[] targetPids) {
    List<int> readers = new List<int>();
    if (targetPids == null || targetPids.Length == 0) return readers.ToArray();
    HashSet<int> targets = new HashSet<int>(targetPids);
    int length = 0x20000; IntPtr buffer = Marshal.AllocHGlobal(length);
    try {
        int needed = 0, status = 0;
        for (int tries = 0; tries < 16; tries++) {
            status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, length, out needed);
            if (status == unchecked((int)0xC0000004)) { Marshal.FreeHGlobal(buffer); length = (needed > length ? needed : length*2) + 0x10000; buffer = Marshal.AllocHGlobal(length); continue; }
            break;
        }
        if (status != 0) return null;
        int ptr = IntPtr.Size; long handleCount = Marshal.ReadIntPtr(buffer).ToInt64();
        int headerSize = ptr*2, entrySize = ptr*3+16;
        IntPtr self = GetCurrentProcess();
        Dictionary<int,IntPtr> opened = new Dictionary<int,IntPtr>(); HashSet<int> done = new HashSet<int>();
        for (long i = 0; i < handleCount; i++) {
            int offset = (int)(headerSize + i*entrySize);
            int ownerPid = (int)Marshal.ReadIntPtr(buffer, offset+ptr).ToInt64();
            if (ownerPid <= 4 || done.Contains(ownerPid) || targets.Contains(ownerPid)) continue;
            uint access = (uint)Marshal.ReadInt32(buffer, offset+ptr*3);
            if ((access & PROCESS_VM_READ) == 0) continue;
            IntPtr handleValue = Marshal.ReadIntPtr(buffer, offset+ptr*2);
            IntPtr owner;
            if (!opened.TryGetValue(ownerPid, out owner)) { owner = OpenProcess(PROCESS_DUP_HANDLE, false, ownerPid); opened[ownerPid] = owner; }
            if (owner == IntPtr.Zero) continue;
            IntPtr dup;
            if (!DuplicateHandle(owner, handleValue, self, out dup, 0, false, DUPLICATE_SAME_ACCESS)) continue;
            try { int objPid = GetProcessId(dup); if (objPid != 0 && targets.Contains(objPid)) { readers.Add(ownerPid); done.Add(ownerPid); } } catch {} finally { CloseHandle(dup); }
        }
        foreach (var kv in opened) { if (kv.Value != IntPtr.Zero) CloseHandle(kv.Value); }
    } catch { return null; } finally { Marshal.FreeHGlobal(buffer); }
    return readers.ToArray();
}
'@ -ErrorAction Stop
        return $true
    } catch { return $false }
}

function Get-RobloxTargetIds {
    $ids = New-Object 'System.Collections.Generic.List[int]'
    try { Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '(?i)^RobloxPlayerBeta$' } | ForEach-Object { $ids.Add([int]$_.Id) } } catch {}
    return @($ids)
}

function Get-ProcessForensicDetails {
    param([int]$TargetPid)
    $details = [ordered]@{ Pid=$TargetPid;Name="PID $TargetPid";Path='';CommandLine='';ParentPid=0;ParentName='';Services=@();ForeignModules=@();UnsignedModules=@();SignatureStatus='Unknown';Signer='' }
    try {
        $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid" -ErrorAction Stop | Select-Object -First 1
        if ($cimProc) {
            if ($cimProc.Name) { $details.Name=[string]$cimProc.Name }; if ($cimProc.ExecutablePath) { $details.Path=[string]$cimProc.ExecutablePath }
            if ($cimProc.CommandLine) { $details.CommandLine=[string]$cimProc.CommandLine }
            if ($cimProc.ParentProcessId) { $details.ParentPid=[int]$cimProc.ParentProcessId; try { $p=Get-Process -Id $details.ParentPid -ErrorAction Stop; $details.ParentName="$($p.ProcessName).exe" } catch { $details.ParentName="PID $($details.ParentPid)" } }
        }
    } catch {}
    if (-not $details.Path) { try { $p=Get-Process -Id $TargetPid -ErrorAction Stop; $details.Name="$($p.ProcessName).exe"; $details.Path=[string]$p.Path } catch {} }
    try { $svcs=@(Get-CimInstance Win32_Service -Filter "ProcessId=$TargetPid" -ErrorAction Stop); foreach ($s in $svcs) { $details.Services += "$($s.Name) ($($s.DisplayName))" } } catch {}
    if ($details.Path -and (Test-Path -LiteralPath $details.Path)) {
        try { $sig=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $details.Path -ErrorAction Stop; $details.SignatureStatus=[string]$sig.Status; if ($sig.SignerCertificate) { $details.Signer=[string]$sig.SignerCertificate.Subject } } catch {}
    }
    return $details
}

function Get-ExternalCheatHits {
    if (-not (Initialize-ExternalScanApi)) { return 'WARNING: External scan unavailable' }
    $messages = @()
    $targets = @(Get-RobloxTargetIds)
    if ($targets.Count -gt 0) {
        $rawReaders = $null
        try { $rawReaders = [SOL.ExternalScan]::FindRobloxMemoryReaders([int[]]$targets) } catch {}
        if ($null -eq $rawReaders) { $messages += 'WARNING: Memory-reader scan failed to run' }
        else {
            $knownBenignServices = @('sysmain','audiosrv','audioendpointbuilder','diagtrack','wsearch','wersvc','dcomlaunch','rpcss','cryptsvc','winmgmt','themes','schedule','appinfo','shellhwdetection','bits','iphlpsvc','lanmanserver','seclogon','usermgr','usermanager','usosvc','wpnservice','gpsvc','profsvc','eventlog','plugplay','samss','nsi','netman','dnscache','dhcp','wuauserv','bfe','mpssvc','wlidsvc','dusmsvc','dps','wscsvc','coremessagingregistrar','sens')
            foreach ($ownerId in (@($rawReaders) | Select-Object -Unique)) {
                $diag = Get-ProcessForensicDetails -TargetPid $ownerId
                $nameLower = ($diag.Name -replace '\.exe$','').ToLower()
                if ($nameLower -in @('robloxplayerbeta','robloxcrashhandler','robloxplayerlauncher')) { if ($diag.SignatureStatus -eq 'Valid' -and ($diag.Signer -match 'Roblox Corporation') -and $diag.ForeignModules.Count -eq 0) { continue } }
                if ($script:ExternalReaderAllowlist -contains $nameLower) { if ($diag.UnsignedModules.Count -eq 0 -and $diag.ForeignModules.Count -eq 0) { continue } }
                if ($nameLower -eq 'svchost') {
                    if ($diag.ForeignModules.Count -gt 0) { $messages += "FAILURE: Injected DLL inside svchost.exe reading Roblox memory (PID $ownerId) -> $($diag.Path)"; continue }
                    $allKnown = $true; $svcNames = @()
                    foreach ($svc in $diag.Services) { $sName = ($svc -split ' ')[0].ToLower(); $svcNames += $sName; if ($knownBenignServices -notcontains $sName) { $allKnown = $false } }
                    if ($allKnown -and $svcNames.Count -gt 0) {
                        $entry = "INFO: Benign Windows Service reading Roblox memory: svchost.exe (PID $ownerId) -> Services: $($diag.Services -join ', ')"
                        $messages += $entry; continue
                    }
                }
                if ((Test-TrustedHandleHolder -ExecutablePath $diag.Path) -and $diag.ForeignModules.Count -eq 0) { continue }
                $label = "$($diag.Name) (PID $ownerId)"; if ($diag.Path) { $label += " -> $($diag.Path)" }
                $entry = "FAILURE: Unauthorized process reading Roblox memory: $label"
                if ($diag.ParentName) { $entry += "`n  |-> Parent: $($diag.ParentName) (PID $($diag.ParentPid))" }
                if ($diag.SignatureStatus) { $entry += "`n  |-> Signature: $($diag.SignatureStatus)$(if ($diag.Signer) { " ($($diag.Signer))" })" }
                $messages += $entry
            }
        }
    }
    $rawWindows = $null; try { $rawWindows = [SOL.ExternalScan]::FindCaptureProtectedWindows() } catch {}
    if ($null -ne $rawWindows) {
        foreach ($w in @($rawWindows)) {
            $parts = $w -split '\|', 4; if ($parts.Count -lt 2) { continue }
            $winPid = 0; [void][int]::TryParse($parts[0],[ref]$winPid); if ($winPid -eq $PID -or $winPid -le 0) { continue }
            $info = Resolve-ProcessIdentity -TargetPid $winPid; $nameLower = ($info.Name -replace '\.exe$','').ToLower()
            if ($script:CaptureWindowAllowlist -contains $nameLower) { continue }
            $affLabel = switch ($parts[1]) { '1' { 'WDA_MONITOR' } '17' { 'WDA_EXCLUDEFROMCAPTURE' } default { "affinity=$($parts[1])" } }
            $title = if ($parts.Count -ge 3 -and $parts[2]) { " '$($parts[2])'" } else { '' }
            $label = "$($info.Name) (PID $winPid)$title [$affLabel]"
            if ($info.Path -and -not (Test-TrustedProcessPath -ExecutablePath $info.Path)) { $messages += "FAILURE: Window hidden from capture $label -> $($info.Path)" }
            else { $messages += "WARNING: Window hidden from capture $label" }
        }
    }
    if ($messages.Count -eq 0) { return 'SUCCESS: No external/overlay cheat detected' }
    if (-not ($messages | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) { $messages = @('SUCCESS: No unauthorized memory readers or hidden overlays detected') + $messages }
    return $messages
}

function Get-TaskManagerIntegrityAlerts {
    $alerts = @()
    $ifeoKeys = @('Taskmgr.exe','procexp.exe','procexp64.exe')
    foreach ($exe in $ifeoKeys) {
        $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"
        if (Test-Path $ifeoPath) {
            $debugger = (Get-ItemProperty -Path $ifeoPath -ErrorAction SilentlyContinue).Debugger
            if ($debugger) {
                if ($exe -eq 'Taskmgr.exe' -and ($debugger -match 'procexp(64)?\.exe')) { $alerts += "INFO: Task Manager replaced by Sysinternals Process Explorer: $debugger" }
                else { $alerts += "FAILURE: IFEO Redirection on $exe! Launches: $debugger" }
            }
        }
    }
    $taskmgrBinary = "$env:SystemRoot\System32\Taskmgr.exe"
    if (-not (Test-Path $taskmgrBinary)) { $alerts += "FAILURE: Taskmgr.exe missing from System32!" }
    else {
        $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -FilePath $taskmgrBinary -ErrorAction SilentlyContinue
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft Windows') { $alerts += "FAILURE: Taskmgr.exe binary signature invalid: $($sig.Status)" }
    }
    if (-not ($alerts | Where-Object { $_ -like 'FAILURE*' })) { $alerts = @('SUCCESS: Process Explorer & Task Manager integrity verified') + $alerts }
    return @($alerts | Select-Object -Unique)
}

function Get-PowerShellHostIntegrityAlerts {
    $alerts = @()
    $ic = $ExecutionContext.InvokeCommand
    foreach ($hookName in 'PreCommandLookupAction','PostCommandLookupAction','CommandNotFoundAction') {
        $action = $ic.$hookName
        if ($null -ne $action) { $alerts += "FAILURE: PowerShell command-lookup hook set -> $hookName" }
    }
    try {
        foreach ($bp in @(Microsoft.PowerShell.Utility\Get-PSBreakpoint -ErrorAction Stop)) {
            $target = if ($bp.Command) { "command '$($bp.Command)'" } elseif ($bp.Variable) { "variable '$($bp.Variable)'" } else { "script $($bp.Script)" }
            $lvl = if ($bp.Action) { 'FAILURE' } else { 'WARNING' }; $alerts += "${lvl}: PowerShell breakpoint on $target"
        }
    } catch {}
    try {
        $cmdlets = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        Microsoft.PowerShell.Core\Get-Command -CommandType Cmdlet -ErrorAction SilentlyContinue | ForEach-Object { [void]$cmdlets.Add($_.Name) }
        foreach ($fn in @(Microsoft.PowerShell.Management\Get-ChildItem Function:\ -ErrorAction SilentlyContinue)) {
            if ($cmdlets.Contains($fn.Name)) {
                $srcFile = if ($fn.ScriptBlock.File) { " [File: $($fn.ScriptBlock.File)]" } elseif ($fn.Module.Path) { " [Module: $($fn.Module.Path)]" } else { " [Code: $($fn.ScriptBlock.ToString().Trim())]" }
                $alerts += "FAILURE: Function overrides built-in cmdlet -> $($fn.Name)$srcFile"
            }
        }
        foreach ($al in @(Microsoft.PowerShell.Management\Get-ChildItem Alias:\ -ErrorAction SilentlyContinue)) {
            if ($cmdlets.Contains($al.Name)) { $alerts += "FAILURE: Alias overrides built-in cmdlet -> $($al.Name) => $($al.Definition)" }
        }
    } catch { $alerts += 'WARNING: Could not check for cmdlet overrides' }
    if (Microsoft.PowerShell.Management\Test-Path 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers') {
        if (@(Microsoft.PowerShell.Management\Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue).Count -eq 0) { $alerts += 'FAILURE: No AMSI providers registered (script scanning disabled)' }
    } else { $alerts += 'WARNING: AMSI providers key missing' }
    if (-not ($alerts | Where-Object { $_ -like 'FAILURE*' -or $_ -like 'WARNING*' })) { $alerts = @('SUCCESS: No PowerShell host hijacking detected') + $alerts }
    return @($alerts | Select-Object -Unique)
}

function Get-PersistenceAlerts {
    $alerts = @()
    $runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
    foreach ($keyPath in $runKeys) {
        try {
            $props = Get-ItemProperty -Path $keyPath -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -match '^PS(Path|ParentPath|ChildName|Provider)$') { continue }
                $value = [string]$prop.Value; $kw = Get-MatchedCheatKeyword -Text $value; if (-not $kw) { $kw = Get-MatchedCheatKeyword -Text $prop.Name }
                if ($kw) { $alerts += "FAILURE: Autorun entry [$kw] '$($prop.Name)' in $keyPath -> $value" }
            }
        } catch {}
    }
    try {
        Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
            $task = $_
            if ($task.TaskPath -like '\Microsoft\Windows\*' -and $task.Author -match '(?i)^Microsoft') { return }
            $actions = @($task.Actions | ForEach-Object { if ($_.Execute) { "$($_.Execute) $($_.Arguments)".Trim() } else { '(no command)' } }); $actionText = $actions -join '; '
            $kw = Get-MatchedCheatKeyword -Text $actionText
            if ($kw) { $alerts += "FAILURE: Scheduled task [$kw] '$($task.TaskPath)$($task.TaskName)' -> $actionText" }
        }
    } catch { $alerts += 'WARNING: Could not enumerate scheduled tasks.' }
    if ($alerts.Count -eq 0) { $alerts += 'SUCCESS: No suspicious autorun/persistence entries found.' }
    return @($alerts | Select-Object -Unique)
}

function Get-CheatFolderHits {
    $hits = New-Object 'System.Collections.Generic.HashSet[string]'
    $scanPaths = @((Join-Path $env:USERPROFILE "Downloads"),(Join-Path $env:USERPROFILE "Desktop"),$env:LOCALAPPDATA,$env:APPDATA,$env:ProgramData,$env:TEMP,"$env:SystemDrive\")
    foreach ($scanPath in $scanPaths) {
        if (-not (Test-Path $scanPath)) { continue }
        $maxDepth = 2; if ($scanPath -eq "$env:SystemDrive\") { $maxDepth = 1 }
        Get-ChildItem -Path $scanPath -Directory -Recurse -Depth $maxDepth -ErrorAction SilentlyContinue | ForEach-Object {
            $matched = Get-MatchedCheatKeyword -Text $_.Name.ToLower() -FolderName
            if ($matched) { [void]$hits.Add($_.FullName) }
        }
    }
    return @($hits)
}

function Get-RegistryToolProcessHits {
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'; $messages = @()
    foreach ($procName in @('regedit.exe','reg.exe')) {
        try {
            Get-CimInstance Win32_Process -Filter "Name='$procName'" -ErrorAction Stop | ForEach-Object {
                $procId = [int]$_.ProcessId; if (-not $seen.Add($procId)) { return }
                $path = [string]$_.ExecutablePath; $cmd = [string]$_.CommandLine
                $label = "$procName (PID $procId)"; if ($path) { $label += " -> $path" }; if ($cmd) { $label += " [$cmd]" }
                $messages += $label
            }
        } catch {}
    }
    return $messages
}

function Get-WindhawkProcessHits {
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'; $messages = @()
    try {
        Get-CimInstance Win32_Process -Filter "Name='$($script:WindhawkProcessName)'" -ErrorAction Stop | ForEach-Object {
            $procId = [int]$_.ProcessId; if (-not $seen.Add($procId)) { return }
            $path = [string]$_.ExecutablePath; $label = "$($script:WindhawkProcessName) (PID $procId)"; if ($path) { $label += " -> $path" }
            $messages += $label
        }
    } catch {}
    return $messages
}

function Get-MainCplProcessHits {
    $seen = New-Object 'System.Collections.Generic.HashSet[int]'; $messages = @()
    foreach ($procName in @('rundll32.exe','control.exe')) {
        try {
            Get-CimInstance Win32_Process -Filter "Name='$procName'" -ErrorAction Stop | ForEach-Object {
                $cmd = [string]$_.CommandLine; if ($cmd -notmatch '(?i)main\.cpl') { return }
                if (-not $seen.Add([int]$_.ProcessId)) { return }
                $messages += "main.cpl opened PID $($_.ProcessId)"
            }
        } catch {}
    }
    return $messages
}

# ====================================================================
# UI / DISPLAY HELPERS
# ====================================================================

function Get-AlertSetSummary {
    param([string[]]$Lines)
    $s = @{ Fail=0;Warn=0;Info=0;Pass=0 }
    foreach ($line in @($Lines)) {
        if ($line -like 'FAILURE*') { $s.Fail++ } elseif ($line -like 'WARNING*') { $s.Warn++ } elseif ($line -like 'INFO*') { $s.Info++ } elseif ($line -like 'SUCCESS*') { $s.Pass++ }
    }
    if ($s.Fail -gt 0) { $s.Status = 'FAIL' } elseif ($s.Warn -gt 0) { $s.Status = 'WARN' } elseif ($null -eq $Lines -or $Lines.Count -eq 0) { $s.Status = 'WARN'; $s.Warn = 1 } else { $s.Status = 'PASS' }
    return $s
}

function Get-TagColor { param([string]$Tag); switch ($Tag) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'WARN' { 'Yellow' } 'INFO' { 'DarkGray' } default { 'Gray' } } }

function Write-TaggedLine {
    param([string]$Line, [string]$Indent = '  ')
    $tag = 'NOTE'; $text = $Line
    if ($Line -match '(?s)^(SUCCESS|FAILURE|WARNING|INFO):\s*(.*)$') {
        $text = $matches[2]
        switch ($matches[1]) { 'SUCCESS' { $tag = 'PASS' } 'FAILURE' { $tag = 'FAIL' } 'WARNING' { $tag = 'WARN' } 'INFO' { $tag = 'INFO' } }
    }
    Write-Host "$Indent[" -NoNewline; Write-Host $tag -ForegroundColor (Get-TagColor $tag) -NoNewline; Write-Host "] " -NoNewline
    Write-Host $text -ForegroundColor $(if ($tag -eq 'INFO') { 'DarkGray' } else { 'Gray' })
}

function Write-Rule { param([int]$Width = 72,[string]$Color = 'DarkGray'); Write-Host ('-' * $Width) -ForegroundColor $Color }

function Write-Section {
    param($Title,$Lines)
    $summary = Get-AlertSetSummary -Lines @($Lines)
    Write-Host ''; Write-Host '  ' -NoNewline; Write-Host $Title -ForegroundColor Cyan -NoNewline
    Write-Host ' [' -NoNewline; Write-Host $summary.Status -ForegroundColor (Get-TagColor $summary.Status) -NoNewline; Write-Host ']'
    foreach ($line in @($Lines)) { Write-TaggedLine -Line $line -Indent '    ' }
}

function Write-StepHeader {
    param([int]$Step,[string]$Text,[switch]$NoClear)
    $dots = ''
    foreach ($n in 1..3) { $dots += $(if ($n -eq $Step) { '[#] ' } else { '[ ] ' }) }
    Write-Host ''
    Write-Host '  ' -NoNewline; Write-Host $Text -ForegroundColor White -NoNewline
    Write-Host ('   Step {0} of 3   ' -f $Step) -ForegroundColor DarkGray -NoNewline; Write-Host $dots -ForegroundColor Cyan
    Write-Rule 60
}

# Throws away any keys pressed earlier, then waits for a REAL Enter press.
# (Fixes Step 2 launching by itself: Read-Host used to swallow a buffered Enter.)
function Wait-ForEnter {
    param([string]$Text)
    try { $Host.UI.RawUI.FlushInputBuffer() } catch {}
    Write-Host ''
    Write-Host '  > ' -NoNewline -ForegroundColor Cyan; Write-Host $Text -ForegroundColor Yellow
    try {
        while ($true) {
            $k = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            if ($k.VirtualKeyCode -eq 13) { break }
        }
    } catch { $null = Read-Host }
    Write-Host ''
}

function Invoke-ConsoleRefresh { try { [Console]::Out.Flush() } catch {}; try { [Console]::Error.Flush() } catch {} }

$script:ProgressWidth = 30
function Write-CheckProgress {
    param([int]$Done,[int]$Total,[string]$Text)
    $percent = 0; if ($Total -gt 0) { $percent = [math]::Floor(($Done/$Total)*100) }
    $filled = [math]::Floor(($percent/100)*$script:ProgressWidth)
    $bar = ('#' * $filled) + ('.' * ($script:ProgressWidth - $filled))
    $line = "  [$bar] {0,3}%  {1}" -f $percent,$Text
    $width = 100; try { if ([Console]::WindowWidth -gt 1) { $width = [Console]::WindowWidth - 1 } } catch {}
    if ($line.Length -gt $width) { $line = $line.Substring(0,$width) }
    Write-Host ("`r" + $line.PadRight($width)) -NoNewline
}

# Monitor helpers
$script:MonitorAlertCounts = @{ FAIL=0;WARN=0;INFO=0 }
$script:MonitorStatusShown = $false
$script:TamperLogFailureWarned = @{}
$script:MainLoopFailureWarned = @{}
$script:MonitorSeenKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

function Clear-MonitorStatusLine {
    if (-not $script:MonitorStatusShown) { return }
    $width = 100; try { if ([Console]::WindowWidth -gt 1) { $width = [Console]::WindowWidth - 1 } } catch {}
    Write-Host ("`r" + (' ' * $width) + "`r") -NoNewline; $script:MonitorStatusShown = $false
}
function Write-MonitorStatusLine {
    param([datetime]$Since)
    $elapsed = (Get-Date) - $Since
    $text = ("  $($script:Brand) monitoring {0:hh\:mm\:ss}  |  {1} fail  {2} warn  {3} info  |  Ctrl+C to stop") -f $elapsed,$script:MonitorAlertCounts.FAIL,$script:MonitorAlertCounts.WARN,$script:MonitorAlertCounts.INFO
    Write-Host ("`r" + $text) -NoNewline -ForegroundColor DarkCyan; $script:MonitorStatusShown = $true
}

function Write-MonitorAlert {
    param([string]$Message,[string]$LogFile,[string]$Color='',[ValidateSet('','FAIL','WARN','INFO','NOTE')][string]$Level='')
    $text = $Message
    if ($Message -match '(?s)^(SUCCESS|FAILURE|WARNING|INFO):\s*(.*)$') {
        $text = $matches[2]
        if (-not $Level) { switch ($matches[1]) { 'FAILURE' { $Level='FAIL' } 'WARNING' { $Level='WARN' } 'INFO' { $Level='INFO' } 'SUCCESS' { $Level='INFO' } } }
    }
    if (-not $Level) { $Level = if ($Color -eq 'Yellow') { 'WARN' } else { 'NOTE' } }
    $tagColor = switch ($Level) { 'FAIL' { 'Red' } 'WARN' { 'Yellow' } 'INFO' { 'DarkGray' } default { 'Cyan' } }
    if ($script:MonitorAlertCounts.ContainsKey($Level)) { $script:MonitorAlertCounts[$Level]++ }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Clear-MonitorStatusLine
    Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] " -NoNewline -ForegroundColor DarkGray
    Write-Host "[$Level]" -NoNewline -ForegroundColor $tagColor
    Write-Host " $text" -ForegroundColor $(if ($Level -eq 'FAIL') { 'Red' } elseif ($Level -eq 'INFO') { 'DarkGray' } else { 'Gray' })
    Invoke-ConsoleRefresh
    try { Add-Content -LiteralPath $LogFile -Value "[$timestamp] [$Level] $text" -ErrorAction Stop }
    catch { $fallback = Join-Path $env:TEMP 'sol_recording_policy.log'; try { Add-Content -LiteralPath $fallback -Value "[$timestamp] [$Level] $text" -ErrorAction SilentlyContinue } catch {} }
}

function Get-AlertDedupKey {
    param([string]$Category,[string]$Message)
    $k = $Message -replace '^(SUCCESS|FAILURE|WARNING|INFO):\s*',''
    $k = $k -replace '\(PID[s]? [^\)]+\)','(PID)' -replace '\bPID \d+','PID' -replace '\b\d{1,2}:\d{2}:\d{2}\b','TIME' -replace '\[Entropy: [\d\.\-]+\]','[Entropy]' -replace '\s+',' '
    return "$Category|$($k.Trim())"
}

function Register-MonitorBaseline { param([string]$Category,[string[]]$Lines); foreach ($line in @($Lines)) { if ($line -and $line -notlike 'SUCCESS*') { [void]$script:MonitorSeenKeys.Add((Get-AlertDedupKey -Category $Category -Message $line)) } } }

function Write-MonitorAlertOnce {
    param([string]$Category,[string]$Message,[string]$LogFile,[string]$Level='',[string]$Color='')
    $key = Get-AlertDedupKey -Category $Category -Message $Message
    if (-not $script:MonitorSeenKeys.Add($key)) { return }
    $p = @{ Message=$Message;LogFile=$LogFile }; if ($Level) { $p.Level=$Level }; if ($Color) { $p.Color=$Color }
    Write-MonitorAlert @p
}

function Get-TamperLogEvents {
    param([datetime]$Since,[string]$LogFile)
    $events = @()
    foreach ($filter in @(@{ LogName='Security';Id=1102 },@{ LogName='System';Id=104 })) {
        try { $filter.StartTime=$Since; Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | ForEach-Object { $events += $_ } }
        catch { if ($_.Exception.Message -notmatch '(?i)no events were found') { $warnKey="winevent|$($filter.LogName)"; if (-not $script:TamperLogFailureWarned.ContainsKey($warnKey)) { $script:TamperLogFailureWarned[$warnKey]=$true; Write-MonitorAlert -Message "WARNING: Could not query '$($filter.LogName)' log ($($_.Exception.Message))" -LogFile $LogFile -Color Yellow } } }
    }
    return $events
}

$script:CursorSchemeValueNames = @('(Default)','Arrow','Help','AppStarting','Wait','Crosshair','IBeam','NWPen','No','SizeNS','SizeWE','SizeNWSE','SizeNESW','SizeAll','UpArrow','Hand','CursorBaseSize')
function Get-CursorSchemeState {
    $state = @{}; $keyPath = 'HKCU:\Control Panel\Cursors'; if (-not (Test-Path $keyPath)) { return $state }
    foreach ($name in $script:CursorSchemeValueNames) { try { $state[$name]=[string](Get-ItemPropertyValue -Path $keyPath -Name $name -ErrorAction Stop) } catch { $state[$name]='' } }
    return $state
}
function Get-CursorSchemeChanges {
    param([hashtable]$Baseline,[hashtable]$Current)
    $changes = @()
    foreach ($name in $script:CursorSchemeValueNames) {
        $old = if ($Baseline.ContainsKey($name)) { [string]$Baseline[$name] } else { '' }
        $new = if ($Current.ContainsKey($name)) { [string]$Current[$name] } else { '' }
        if ($old -eq $new) { continue }
        $displayNew = [Environment]::ExpandEnvironmentVariables($new)
        $msg = "$name changed: '$old' -> '$new'"
        if ($displayNew -match '(?i)\.(cur|ani)$' -and $displayNew -notmatch '(?i)\\windows\\cursors\\') { $msg += ' [non-standard cursor path]' }
        $kw = Get-MatchedCheatKeyword -Text $displayNew; if ($kw) { $msg += " [keyword: $kw]" }
        $changes += $msg
    }
    return $changes
}

$script:MonitoredServices = @('bam','SysMain','WinDefend','EventLog','Sense','wscsvc')

$script:LastRobloxBuildAnnounced = $null

function Get-ProcessSnapshot {
    $snap = @{}
    try {
        Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
            $procId=[int]$_.ProcessId; $path=[string]$_.ExecutablePath; $name=[string]$_.Name; $cmd=[string]$_.CommandLine
            $reasons = @()
            if ([string]::IsNullOrWhiteSpace($path)) { if ($name -notmatch '(?i)^(System|Registry|Secure System|Memory Compression|Idle)$') { $reasons += 'no image path' } }
            else { if ($name -and (Split-Path $path -Leaf) -and ($name.ToLower() -ne (Split-Path $path -Leaf).ToLower())) { $reasons += 'name/path mismatch' } }
            $masq = Test-MasqueradeProcessPath -ProcessName $name -ExecutablePath $path; if ($masq) { $reasons += 'masquerade' }
            $nameKw = Get-MatchedCheatKeyword -Text $name; if ($nameKw) { $reasons += $nameKw }
            if ($path) { $pathKw = Get-MatchedCheatKeyword -Text $path; if ($pathKw) { $reasons += $pathKw } }
            $snap[$procId] = @{ Name=$name;Path=$path;CommandLine=$cmd;Reasons=$reasons;UserLand=(Test-UserLandProcessPath -ExecutablePath $path);Suspicious=($reasons.Count -gt 0) }
        }
    } catch { return $null }
    return $snap
}

$script:MonitorProcessAllowlist = @('robloxplayerbeta.exe','fishstrap.exe','robloxcrashhandler.exe','bloxstrap.exe')

function Test-ShouldLogProcessMonitorEvent {
    param($Proc)
    $seriousReasons = @($Proc.Reasons | Where-Object { $_ -ne 'no image path' })
    $nameLower = [string]$Proc.Name; if ($nameLower) { $nameLower = $nameLower.ToLower() }
    if ($nameLower -and $script:MonitorProcessAllowlist -contains $nameLower) { if ($seriousReasons.Count -eq 0) { return $false } }
    if ($seriousReasons.Count -gt 0) { return $true }; if ($Proc.UserLand) { return $true }
    return $false
}

function Update-ProcessChangeMonitor {
    param([hashtable]$Previous,[hashtable]$Current,[hashtable]$Watched,[string]$LogFile)
    foreach ($procId in $Current.Keys) {
        if ($Previous.ContainsKey($procId)) { continue }
        $proc = $Current[$procId]; $name = [string]$proc.Name; $cmd = [string]$proc.CommandLine
        $isNotepad = ($name -ieq 'notepad.exe'); $isBat = ($name -ieq 'cmd.exe') -and ($cmd -match '\.bat(\b|"|\s|$)')
        if ($isNotepad -or $isBat) {
            $toolTag = if ($isNotepad) { 'Notepad' } else { 'Batch (.bat)' }
            Write-MonitorAlert -Message "Script/Editor Launched ($toolTag): $name (PID $procId)$(if ($cmd) { " [$cmd]" })" -LogFile $LogFile -Level WARN
            $Watched[$procId] = $proc; continue
        }
        if (-not (Test-ShouldLogProcessMonitorEvent -Proc $proc)) { continue }
        $label = "$($proc.Name) (PID $procId)"; if ($proc.Path) { $label += " -> $($proc.Path)" }
        $tags = @($proc.Reasons | Where-Object { $_ -ne 'no image path' })
        if ($tags.Count -gt 0) {
            $level = if ($tags -match 'masquerade' -or ($tags | Where-Object { $_ -ne 'name/path mismatch' }).Count -gt 0) { 'FAIL' } else { 'WARN' }
            Write-MonitorAlert -Message "Started [$($tags -join ', ')]: $label" -LogFile $LogFile -Level $level
        } else { Write-MonitorAlert -Message "Started [userland]: $label" -LogFile $LogFile -Level WARN }
        $Watched[$procId] = $proc
    }
    foreach ($procId in $Previous.Keys) {
        if ($Current.ContainsKey($procId)) { continue }; if (-not $Watched.ContainsKey($procId)) { continue }
        $proc = $Previous[$procId]; $label = "$($proc.Name) (PID $procId)"; if ($proc.Path) { $label += " -> $($proc.Path)" }
        $tags = @($proc.Reasons | Where-Object { $_ -ne 'no image path' })
        if ($tags.Count -gt 0) { Write-MonitorAlert -Message "Exited [$($tags -join ', ')]: $label" -LogFile $LogFile -Level INFO }
        else { Write-MonitorAlert -Message "Exited [userland]: $label" -LogFile $LogFile -Level INFO }
        $Watched.Remove($procId) | Out-Null
    }
}

# ====================================================================
# TOOL DOWNLOAD / LAUNCH (for Step 2 - Process Explorer)
# ====================================================================

function Invoke-ToolDownload {
    param([string]$Url,[string]$ZipPath,[string]$DestDir)
    if (-not $Url -or -not $ZipPath -or -not $DestDir) { return $false }
    try {
        $zipParent = Split-Path $ZipPath -Parent
        if ($zipParent -and -not (Test-Path $zipParent)) { New-Item -ItemType Directory -Path $zipParent -Force | Out-Null }
        if (-not (Test-Path $DestDir)) { New-Item -ItemType Directory -Path $DestDir -Force | Out-Null }
        if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $downloaded = $false
        try {
            foreach ($attempt in 1..2) {
                try {
                    Microsoft.PowerShell.Utility\Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing -TimeoutSec 120 -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' | Out-Null
                    if ((Test-Path -LiteralPath $ZipPath) -and ((Get-Item -LiteralPath $ZipPath).Length -gt 1024)) { $downloaded = $true; break }
                } catch { if ($attempt -eq 2) { throw }; Start-Sleep -Seconds 2 }
            }
        } finally {}
        if (-not $downloaded) { return $false }
        Expand-Archive -Path $ZipPath -DestinationPath $DestDir -Force; return $true
    } catch { Write-Warning "Download failed: $($_.Exception.Message)"; return $false }
}

function Resolve-ToolExecutable {
    param([string]$DestDir,[string]$ExeName,[string[]]$FallbackNames = @())
    foreach ($name in @($ExeName) + @($FallbackNames)) { $direct = Join-Path $DestDir $name; if (Test-Path -LiteralPath $direct) { return $direct } }
    foreach ($name in @($ExeName) + @($FallbackNames)) { $found = Get-ChildItem -Path $DestDir -Filter $name -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1; if ($found) { return $found.FullName } }
    return $null
}

function Start-SOLExternalTool {
    param([string]$Name,[string]$Url,[string]$ZipPath,[string]$DestDir,[string]$ExeName,[string[]]$FallbackExeNames=@(),[string[]]$StartArguments=@(),[string[]]$KillProcessNames=@(),[switch]$Wait,[ValidateSet('Normal','Maximized')][string]$WindowStyle='Normal')
    foreach ($killName in $KillProcessNames) { Get-Process -Name $killName -ErrorAction SilentlyContinue | ForEach-Object { try { Microsoft.PowerShell.Management\Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {} } }
    try {
        $exe = $null
        if (Invoke-ToolDownload -Url $Url -ZipPath $ZipPath -DestDir $DestDir) { $exe = Resolve-ToolExecutable -DestDir $DestDir -ExeName $ExeName -FallbackNames $FallbackExeNames }
        if (-not $exe) { Write-Host "WARNING: $Name unavailable (download or extract failed)." -ForegroundColor Yellow; return $false }
        $strayDlls = @(Get-ChildItem -LiteralPath $DestDir -Filter '*.dll' -Recurse -Force -ErrorAction SilentlyContinue)
        if ($strayDlls.Count -gt 0) { Write-Host "WARNING: $Name rejected because unexpected DLL files were found next to it." -ForegroundColor Yellow; return $false }
        if (-not (Test-SignedMicrosoftFile -Path $exe)) { Write-Host "WARNING: $Name rejected because its Microsoft Authenticode signature could not be validated." -ForegroundColor Yellow; return $false }
        try {
            $startParams = @{ FilePath=$exe;WindowStyle=$WindowStyle;PassThru=$true;ErrorAction='Stop' }
            if ($StartArguments.Count -gt 0) { $startParams['ArgumentList']=$StartArguments }
            $proc = Start-Process @startParams; if ($Wait) { $proc.WaitForExit() }; return $true
        } catch { Write-Host "WARNING: $Name failed to start: $($_.Exception.Message)" -ForegroundColor Yellow; return $false }
    } finally { if ($Wait) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $DestDir -Recurse -Force -ErrorAction SilentlyContinue; Microsoft.PowerShell.Management\Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue } }
}

# ====================================================================
# BANNER
# ====================================================================

# ====================================================================
# MISSING HELPER STUBS (called by existing functions)
# ====================================================================
function Test-ClarityExpectedProcessPath {
    param([string]$ProcessName, [string]$ExecutablePath)
    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) { return $false }
    $nameLower = ([string]$ProcessName).ToLower().Trim()
    if (-not $nameLower.EndsWith('.exe')) { $nameLower += '.exe' }
    $path = $ExecutablePath.ToLower().Replace('/','\')
    $root = $env:SystemRoot.ToLower() + '\'
    $programData = $env:ProgramData.ToLower()
    $leaf = [System.IO.Path]::GetFileName($path)
    switch ($nameLower) {
        'svchost.exe' { return $path.Contains('\windows\system32\svchost.exe') -or $path.Contains('\windows\syswow64\svchost.exe') }
        'msmpeng.exe' {
            $prefix = "$programData\microsoft\windows defender\platform\"
            return ($leaf -ieq 'msmpeng.exe' -and $path.StartsWith($prefix))
        }
        'tiworker.exe' { return ($leaf -ieq 'tiworker.exe' -and $path.StartsWith($root)) }
        default { return $false }
    }
}

function Test-NoImagePathIgnoredProcess {
    param([string]$ProcessName)
    if ([string]::IsNullOrWhiteSpace($ProcessName)) { return $true }
    return $ProcessName -match '(?i)^(svchost|conhost|dllhost|RuntimeBroker|WmiPrvSE|SearchHost|ShellHost|ctfmon|sihost|taskhostw|spoolsv|lsass|services|smss|csrss|wininit|winlogon|fontdrvhost|dwm|explorer|msedgewebview2|SecurityHealthService|audiodg|smartscreen|SearchIndexer|Registry|NisSrv|MpDefenderCoreService|MsMpEng)\.exe$'
}

function Get-ProcessScanAlerts {
    $hits = @(Get-SuspiciousProcessHits)
    if ($hits.Count -eq 0) { return @('SUCCESS: Processes clean') }
    return $hits
}

function Convert-RegistryFileTime {
    param($Raw)
    try {
        if ($Raw -is [byte[]] -and $Raw.Length -ge 8) { return [DateTime]::FromFileTime([BitConverter]::ToInt64($Raw, 0)) }
        if ($Raw -is [int64]) { return [DateTime]::FromFileTime($Raw) }
    } catch {}
    return $null
}

function Get-RobloxMemoryIntegrityAlerts {
    $alerts = @()
    $proc = Get-Process -Name 'RobloxPlayerBeta' -ErrorAction SilentlyContinue
    if (-not $proc) { $alerts += 'INFO: Roblox (RobloxPlayerBeta) is not currently running'; return $alerts }
    try {
        if ($proc.Responding -eq $false) { $alerts += "WARNING: Roblox process (PID $($proc.Id)) is not responding" }
        else { $alerts += "SUCCESS: Roblox process (PID $($proc.Id)) memory space accessible" }
    } catch { $alerts += "INFO: Roblox memory check completed" }
    return $alerts
}

Write-Host ''
Write-Host ''
Write-Host ('  ' + $script:Brand) -ForegroundColor Cyan -NoNewline; Write-Host "  v$($script:SOLVersion)" -ForegroundColor DarkGray
Write-Host '  Match integrity check' -ForegroundColor Gray
Write-Rule 60
Write-Host '  1  System Check     2  Process Explorer     3  Live Monitor' -ForegroundColor DarkGray
Write-Host ''
if (-not (Test-Admin)) { Write-Host '  [WARN] Not running as Administrator - several checks will be incomplete.' -ForegroundColor Yellow; Write-Host '' }

# ====================================================================
# v2.0 MONITOR INTEGRITY (runtime drift detection)
# ====================================================================
function Get-MonitorIntegrityAlerts {
    param([datetime]$Since)
    $out = @()
    foreach ($name in $script:MonitoredServices) {
        if (-not $baselineServices.ContainsKey($name)) { continue }
        try {
            $status = [string](Get-Service -Name $name -ErrorAction Stop).Status
            if ($status -ne $baselineServices[$name] -and $status -ne 'Running') { $out += "FAILURE: Service $name changed from $($baselineServices[$name]) to $status during the match" }
        } catch {}
    }
    $usn = Get-UsnJournalState
    if ($baselineUsn.Present) {
        if ($usn.Error -eq 'not active') { $out += "FAILURE: USN change journal was deleted during the match" }
        elseif ($usn.Present -and $usn.JournalId -ne $baselineUsn.JournalId) { $out += "FAILURE: USN change journal was recreated during the match (deleted and re-enabled)" }
    }
    foreach ($entry in (Get-RootCertificateThumbprintSet)) {
        if ($baselineRootCerts.Contains($entry)) { continue }
        $parts = $entry -split '\|',3; $short = $parts[2]; if ($short -match 'CN=([^,]+)') { $short = $matches[1] }
        $lvl = if ($parts[2] -match '(?i)microsoft') { 'FAILURE' } else { 'WARNING' }
        $out += "${lvl}: Root certificate installed during match -> '$short' ($($parts[0]))"
    }
    foreach ($line in (Get-ClockChangeAlerts -Since $Since)) { if ($line -like 'WARNING*') { $out += $line } }
    foreach ($line in (Get-RobloxModuleAlerts)) { if ($line -like 'FAILURE*' -or $line -like 'WARNING*') { $out += $line } }
    return $out
}

# ====================================================================
# SYSTEM CHECKS ARRAY (v2.0 - includes all new checks)
# ====================================================================
$script:SystemChecks = @(
    @{ Name = 'PowerShell Modules';             Caption = 'Loading PowerShell modules';          Run = { Initialize-SOLModules } },
    @{ Name = 'CPU & GPU';                       Caption = 'Reading CPU and GPU';                 Run = { Get-CpuGpuAlerts } },
    @{ Name = 'Roblox Client Version';           Caption = 'Checking Roblox version';             Run = { Get-RobloxVersionAlerts } },
    @{ Name = 'Session';                         Caption = 'Reading logon time and run history';  Run = { Get-SessionSummaryAlerts } },
    @{ Name = 'Windows Defender';                Caption = 'Checking Windows Defender';           Run = { Get-DefenderStep1Alerts } },
    @{ Name = 'Defender Exclusions';             Caption = 'Checking Defender exclusions';        Run = { Get-ExclusionAlerts } },
    @{ Name = 'Allowed Threats';                 Caption = 'Checking allowed threats';            Run = { Get-AllowedThreatAlerts } },
    @{ Name = 'Active Defender Threats';         Caption = 'Checking active Defender threats';    Run = { Get-ActiveDefenderThreatAlerts } },
    @{ Name = 'Defender History';                Caption = 'Reading Defender detection history';  Run = { Get-DefenderHistoryAlerts } },
    @{ Name = 'Clarity / Defender Integrity';    Caption = 'Checking Defender integrity';         Run = { Get-ClarityDetectionAlerts } },
    @{ Name = 'Memory Integrity (HVCI)';         Caption = 'Checking Memory Integrity';           Run = { Get-MemoryIntegrityAlerts } },
    @{ Name = 'CLR Profiler Hijack';             Caption = 'Checking .NET profiler environment';  Run = { Get-ClrHijackAlerts } },
    @{ Name = 'Native Syscall Hooks';            Caption = 'Auditing NTDLL syscall stubs';        Run = { Get-NtdllSyscallIntegrityAlerts } },
    @{ Name = 'ETW Session Integrity';           Caption = 'Checking ETW tamper resistance';      Run = { Get-EtwTamperingAlerts } },          # v2.0
    @{ Name = 'AMSI Integrity';                  Caption = 'Verifying AMSI is not patched';       Run = { Get-AmsiIntegrityAlerts } },          # v2.0
    @{ Name = 'Hidden Processes';                Caption = 'Cross-checking process lists';        Run = { Get-HiddenProcessAlerts } },          # v2.0
    @{ Name = 'Injected Threads';                Caption = 'Scanning for injected threads';       Run = { Get-InjectedThreadAlerts } },         # v2.0
    @{ Name = 'Virtual Machine';                 Caption = 'Checking for VM environment';         Run = { Get-VirtualMachineAlerts } },         # v2.0
    @{ Name = 'Cheat Engine';                    Caption = 'Checking for Cheat Engine';           Run = { Get-CheatEngineAlerts } },            # v2.0
    @{ Name = 'Debugger / Analysis Tools';       Caption = 'Checking for analysis tools';         Run = { Get-DebuggerDetectionAlerts } },      # v2.0
    @{ Name = 'Recording Authenticity';          Caption = 'Checking recording authenticity';     Run = { Get-RecordingAuthenticityAlerts } },  # v2.0
    @{ Name = 'OBS & App Tamper';                Caption = 'Auditing browsers, streaming & apps'; Run = { Get-StreamingProcessIntegrityAlerts } },
    @{ Name = 'Transparent Overlays';            Caption = 'Scanning topmost click-through windows'; Run = { Get-TransparentOverlayAlerts } },
    @{ Name = 'Process Explorer & Taskmgr';      Caption = 'Auditing Process Explorer & Taskmgr'; Run = { Get-TaskManagerIntegrityAlerts } },
    @{ Name = 'Test Signing';                    Caption = 'Checking boot configuration';         Run = { Get-TestSigningAlerts } },
    @{ Name = 'Kernel Drivers';                  Caption = 'Verifying kernel drivers';            Run = { Get-SuspiciousDriverAlerts } },
    @{ Name = 'Vulnerable Drivers';              Caption = 'Checking for vulnerable drivers';     Run = { Get-VulnerableDriverAlerts } },
    @{ Name = 'Input & DMA Devices';             Caption = 'Checking input drivers and PCIe';     Run = { Get-InputAndDmaDeviceAlerts } },
    @{ Name = 'PowerShell Module Integrity';     Caption = 'Verifying PowerShell modules';        Run = { @(Get-PowerShellHostIntegrityAlerts; Get-PowerShellModuleIntegrityAlerts) | Select-Object -Unique } },
    @{ Name = 'PowerShell Binary Integrity';     Caption = 'Verifying PowerShell binaries';       Run = { Get-PowerShellBinaryIntegrityAlerts } },
    @{ Name = 'Root Certificates';               Caption = 'Checking root certificates';          Run = { Get-RootCertificateAlerts } },
    @{ Name = 'Process Scan';                    Caption = 'Scanning processes';                  Run = { @(Get-SuspiciousProcessHits; Get-UnsignedUserProgramAlerts) | Select-Object -Unique } },
    @{ Name = 'External / Overlay';              Caption = 'Scanning external/overlay activity';  Run = { Get-ExternalCheatHits } },
    @{ Name = 'Roblox Modules';                  Caption = 'Checking modules loaded in Roblox';   Run = { Get-RobloxModuleAlerts } },
    @{ Name = 'Roblox Named Pipes (Enhanced)';   Caption = 'Auditing named pipes (full scan)';    Run = { Get-EnhancedNamedPipeAlerts } },      # v2.0 replaces basic scan
    @{ Name = 'Anti-Bypass & Network';           Caption = 'Checking network and hosts bypass';   Run = { Get-AntiBypassNetworkAlerts } },
    @{ Name = 'Suspicious Network Connections';  Caption = 'Checking active TCP connections';     Run = { Get-SuspiciousNetworkAlerts } },      # v2.0
    @{ Name = 'FastFlags (ClientAppSettings)';   Caption = 'Auditing FastFlags';                  Run = { Get-FastFlagsAlerts } },
    @{ Name = 'KeyAuth';                         Caption = 'Checking KeyAuth';                    Run = { Get-KeyAuthAlerts } },
    @{ Name = 'Suspicious Files';                Caption = 'Scanning for high-entropy binaries';  Run = { Get-SuspiciousHighEntropyFileAlerts } },
    @{ Name = 'Windhawk';                        Caption = 'Checking Windhawk';                   Run = { Get-WindhawkStep1Alerts } },
    @{ Name = 'Registry Markers';                Caption = 'Checking registry markers';           Run = { Get-RegistryMarkerAlerts } },
    @{ Name = 'NVIDIA ShadowPlay';               Caption = 'Checking NVIDIA ShadowPlay';          Run = { Get-NvidiaShadowPlayFtsAlerts } },
    @{ Name = 'Execution History (BAM/DAM)';     Caption = 'Reading execution history';           Run = { Get-BamHistoryAlerts } },
    @{ Name = 'BAM Service';                     Caption = 'Checking BAM service';                Run = { Get-BamServiceAlerts } },
    @{ Name = 'Prefetch Health';                 Caption = 'Checking prefetch';                   Run = { Get-PrefetchHealthAlerts } },
    @{ Name = 'Artifact Cross-Check';            Caption = 'Cross-checking BAM vs prefetch';      Run = { Get-ArtifactCrossCheckAlerts } },
    @{ Name = 'USN Journal';                     Caption = 'Checking USN change journal';         Run = { Get-UsnJournalAlerts } },
    @{ Name = 'System Clock';                    Caption = 'Checking for clock changes';          Run = { Get-ClockChangeAlerts } },
    @{ Name = 'Command History';                 Caption = 'Scanning command history';            Run = { Get-CommandHistoryAlerts } },
    @{ Name = 'Autorun / Persistence';           Caption = 'Checking autorun and persistence';    Run = { Get-PersistenceAlerts } },
    @{ Name = 'DNS Cache';                       Caption = 'Checking DNS cache';                  Run = { Get-DnsCacheAlerts } },
    @{ Name = 'USB History';                     Caption = 'Reading USB removal history';         Run = { Get-UsbHistoryAlerts } }
)

# ====================================================================
# STEP 1 - SYSTEM CHECK RUNNER
# ====================================================================
Write-StepHeader -Step 1 -Text 'System Check'
Write-Host ''

$script:SystemCheckResults = @()
$checkTotal = $script:SystemChecks.Count
$checkDone = 0
$step1Start = Get-Date

foreach ($check in $script:SystemChecks) {
    Write-CheckProgress -Done $checkDone -Total $checkTotal -Text "$($check.Caption)..."
    $lines = @()
    try { $lines = @(& $check.Run) } catch { $lines = @("WARNING: Check crashed ($($_.Exception.Message))") }
    $script:SystemCheckResults += @{ Name = $check.Name; Lines = $lines; Summary = (Get-AlertSetSummary -Lines $lines) }
    $checkDone++
}
Write-CheckProgress -Done $checkTotal -Total $checkTotal -Text "Done in $([math]::Round(((Get-Date) - $step1Start).TotalSeconds))s"
Write-Host ''; Write-Host ''

$failCount = @($script:SystemCheckResults | Where-Object { $_.Summary.Status -eq 'FAIL' }).Count
$warnCount = @($script:SystemCheckResults | Where-Object { $_.Summary.Status -eq 'WARN' }).Count
$passCount = $checkTotal - $failCount
$successRate = if ($checkTotal -gt 0) { [math]::Round(($passCount/$checkTotal)*100) } else { 0 }

Write-Host '  Results' -ForegroundColor White; Write-Rule 60
foreach ($r in $script:SystemCheckResults) {
    $s = $r.Summary; $counts = @()
    if ($s.Fail -gt 0) { $counts += "$($s.Fail) fail" }; if ($s.Warn -gt 0) { $counts += "$($s.Warn) warn" }; if ($s.Info -gt 0) { $counts += "$($s.Info) info" }
    $countText = if ($counts.Count -gt 0) { '  (' + ($counts -join ', ') + ')' } else { '' }
    Write-Host ('  {0,-36} [' -f $r.Name) -NoNewline; Write-Host $s.Status -ForegroundColor (Get-TagColor $s.Status) -NoNewline; Write-Host ']' -NoNewline; Write-Host $countText -ForegroundColor DarkGray
}
Write-Rule 60
$rateColor = 'Green'; if ($failCount -gt 0) { $rateColor = 'Red' } elseif ($warnCount -gt 0) { $rateColor = 'Yellow' }
Write-Host "  Pass rate: " -NoNewline; Write-Host "$successRate%" -ForegroundColor $rateColor -NoNewline
Write-Host "   $passCount/$checkTotal sections without FAIL, $warnCount with warnings" -ForegroundColor DarkGray

Write-Host ''; Write-Host '  Details' -ForegroundColor White; Write-Rule 60
foreach ($r in $script:SystemCheckResults) {
    if ($r.Summary.Status -eq 'PASS' -and $r.Summary.Info -eq 0) { continue }
    Write-Section $r.Name $r.Lines
}
Write-Host ''; Write-Rule 60; Write-Host ''
Wait-ForEnter 'Press ENTER to open Process Explorer (Step 2)'

# ====================================================================
# STEP 2 - PROCESS EXPLORER
# ====================================================================
Write-Host ''
Write-StepHeader -Step 2 -Text 'Process Explorer'
Write-Host ''; Write-Host '  Process Explorer is opening. Show the process list on your recording,' -ForegroundColor Gray
Write-Host '  then close it (File > Exit) to continue.' -ForegroundColor Yellow; Write-Host ''
$procexpDir = Join-Path $env:TEMP ('SOL_' + [guid]::NewGuid().ToString('N'))
if (Start-SOLExternalTool -Name 'Process Explorer' `
        -Url 'https://download.sysinternals.com/files/ProcessExplorer.zip' `
        -ZipPath "$procexpDir.zip" -DestDir $procexpDir `
        -ExeName 'procexp64.exe' -FallbackExeNames @('procexp.exe') `
        -StartArguments @('/accepteula') -KillProcessNames @('procexp','procexp64','procexp64a') `
        -WindowStyle Maximized -Wait) {
    Write-Host ''; Write-Host '  Process Explorer closed.' -ForegroundColor Cyan
}
Wait-ForEnter 'Press ENTER to start the Live Monitor (Step 3)'

# ====================================================================
# STEP 3 - LIVE MONITOR (v2.0 Enhanced with tighter intervals)
# ====================================================================
Write-Host ''
Write-StepHeader -Step 3 -Text 'Live Monitor'
Write-Host ''; Write-Host '  Keep this window open for the whole match.' -ForegroundColor Yellow
Write-Host '  Quiet is normal - only suspicious activity shows up. Ctrl+C to stop.' -ForegroundColor DarkGray
Write-Host ''; Write-Host '  Tags: ' -NoNewline -ForegroundColor DarkGray
Write-Host '[FAIL]' -NoNewline -ForegroundColor Red; Write-Host ' serious   ' -NoNewline -ForegroundColor DarkGray
Write-Host '[WARN]' -NoNewline -ForegroundColor Yellow; Write-Host ' needs a look   ' -NoNewline -ForegroundColor DarkGray
Write-Host '[INFO]' -NoNewline -ForegroundColor DarkGray; Write-Host ' context' -ForegroundColor DarkGray
Write-Rule 60; Write-Host ''

$logFile = Join-Path $env:ProgramData 'sol_recording_policy.log'
try {
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }
    Write-MonitorAlert -Message "$($script:Brand) monitor started (Step 1: $failCount FAIL, $warnCount WARN sections)" -LogFile $logFile -Level INFO
} catch {
    $logFile = Join-Path $env:TEMP 'sol_recording_policy.log'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }
    Write-Host "  [WARN] Logging to $logFile" -ForegroundColor Yellow
    Write-MonitorAlert -Message "$($script:Brand) monitor started (Step 1: $failCount FAIL, $warnCount WARN sections)" -LogFile $logFile -Level INFO
}

$usbMonitoringAvailable = $false
try {
    Get-EventSubscriber -SourceIdentifier USBChange -ErrorAction SilentlyContinue | Unregister-Event -Force -ErrorAction SilentlyContinue
    Register-WmiEvent -Class Win32_VolumeChangeEvent -SourceIdentifier USBChange -ErrorAction Stop | Out-Null
    $usbMonitoringAvailable = $true
} catch { Write-MonitorAlert -Message "WARNING: USB insertion/removal monitoring unavailable ($($_.Exception.Message))" -LogFile $logFile -Color Yellow }

trap { Write-MonitorAlert -Message "SOL monitor error ($($_.Exception.Message))" -LogFile $logFile -Color Yellow; break }

# Baselines
$script:BaselineBamKeys     = @{}; foreach ($fp in (Get-BamRegistryFingerprints)) { $script:BaselineBamKeys[$fp] = $true }
$script:BaselinePrefetchFiles = @{}; foreach ($pf in (Get-PrefetchFileNames)) { $script:BaselinePrefetchFiles[$pf] = $true }

$previousExclusions = @{}; foreach ($ex in (Get-Exclusions)) { $previousExclusions[$ex] = $true }
$knownCheatFolders = @{}; foreach ($folder in (Get-CheatFolderHits)) { $knownCheatFolders[$folder] = $true }
$reportedBamDeletions   = @{}; $reportedPrefetchDeletions = @{}; $reportedTamperEvents = @{}
$reportedPrefetchHits   = @{}; $reportedCursorChanges = @{}
$baselineCursorScheme   = Get-CursorSchemeState
$reportedDefenderRegChanges = @{}
$baselineDefenderReg    = Get-DefenderRegistryFingerprints
$defenderRegLabels      = Get-DefenderRegistryMonitorLabels
$lastProcessSnapshot    = Get-ProcessSnapshot
$watchedProcesses       = @{}
$monitoringStart        = Get-Date

$baselineUsn       = Get-UsnJournalState
$baselineRootCerts = Get-RootCertificateThumbprintSet
$baselineServices  = @{}
foreach ($name in $script:MonitoredServices) { try { $baselineServices[$name] = [string](Get-Service -Name $name -ErrorAction Stop).Status } catch {} }

# Register Step 1 baselines for dedup
$step1Categories = @{ 'PowerShell Module Integrity'='pshost';'Process Scan'='userprog';'Transparent Overlays'='overlay';'External / Overlay'='external';'Process Explorer & Taskmgr'='taskmgr';'Roblox Modules'='integrity';'Windows Defender'='defender';'Active Defender Threats'='threats';'Hidden Processes'='hiddenps';'Injected Threads'='threads';'Virtual Machine'='vm';'Cheat Engine'='ce';'Debugger / Analysis Tools'='debugger';'AMSI Integrity'='amsi';'ETW Session Integrity'='etw' }
foreach ($r in $script:SystemCheckResults) {
    if ($step1Categories.ContainsKey($r.Name)) { Register-MonitorBaseline -Category $step1Categories[$r.Name] -Lines $r.Lines }
}

# Counter variables
$folderScanCounter=0;$deletionScanCounter=0;$processChangeCounter=0;$mainCplScanCounter=0
$defenderScanCounter=0;$activeThreatScanCounter=0;$externalScanCounter=0;$integrityScanCounter=0
$statusLineCounter=0;$v2ScanCounter=0

try {
while ($true) {
    $usbEvent = $null
    if ($usbMonitoringAvailable) { $usbEvent = Wait-Event -SourceIdentifier USBChange -Timeout 1 -ErrorAction SilentlyContinue }
    else { Start-Sleep -Seconds 1 }
    if ($usbEvent) {
        $eventType = $usbEvent.SourceEventArgs.NewEvent.EventType; $driveLetter = $usbEvent.SourceEventArgs.NewEvent.DriveName
        if ($eventType -eq 2) { Write-MonitorAlert -Message "USB drive inserted ($driveLetter)" -LogFile $logFile -Level NOTE }
        elseif ($eventType -eq 3) { Write-MonitorAlert -Message "USB drive removed ($driveLetter)" -LogFile $logFile -Level NOTE }
        Remove-Event -EventIdentifier $usbEvent.EventIdentifier -ErrorAction SilentlyContinue
    }

    # Defender exclusions (every tick)
    try {
        $currentExclusions = @{}; foreach ($ex in (Get-Exclusions)) { $currentExclusions[$ex] = $true }
        foreach ($ex in $currentExclusions.Keys) {
            if (-not $previousExclusions.ContainsKey($ex)) {
                $exclKw = Get-MatchedCheatKeyword -Text $ex
                if ($exclKw) { Write-MonitorAlert -Message "Defender exclusion added [$exclKw]: $ex" -LogFile $logFile -Level FAIL }
                else { Write-MonitorAlert -Message "Defender exclusion added during match: $ex" -LogFile $logFile -Level FAIL }
            }
        }
        $previousExclusions = $currentExclusions
    } catch {}

    # Cursor scheme changes (every tick)
    foreach ($change in (Get-CursorSchemeChanges -Baseline $baselineCursorScheme -Current (Get-CursorSchemeState))) {
        if (-not $reportedCursorChanges.ContainsKey($change)) { $reportedCursorChanges[$change]=$true; Write-MonitorAlert -Message "Cursor changed: $change" -LogFile $logFile -Color Yellow }
    }

    # Registry/Windhawk tools (every 5 ticks)
    $mainCplScanCounter++
    if ($mainCplScanCounter -ge 5) {
        $mainCplScanCounter = 0
        foreach ($hit in (Get-MainCplProcessHits))     { Write-MonitorAlertOnce -Category 'maincpl'  -Message $hit -LogFile $logFile -Color Yellow }
        foreach ($hit in (Get-RegistryToolProcessHits)) { Write-MonitorAlertOnce -Category 'regtool'  -Message "Registry tool: $hit" -LogFile $logFile -Color Yellow }
        foreach ($hit in (Get-WindhawkProcessHits))     { Write-MonitorAlertOnce -Category 'windhawk' -Message "Windhawk running: $hit" -LogFile $logFile -Level FAIL }
    }

    # Defender status (every 5 ticks)
    $defenderScanCounter++
    if ($defenderScanCounter -ge 5) {
        $defenderScanCounter = 0
        try {
            foreach ($line in (Get-DefenderStatusAlerts)) { Write-MonitorAlertOnce -Category 'defender' -Message $line -LogFile $logFile -Color Yellow }
            foreach ($entry in (Get-DefenderRegistryFingerprints).GetEnumerator()) {
                $root=$entry.Key; $currentFp=$entry.Value; $baselineFp=$baselineDefenderReg[$root]
                if ($currentFp -eq $baselineFp) { continue }
                $changeKey="$root|$currentFp"; if ($reportedDefenderRegChanges.ContainsKey($changeKey)) { continue }
                $reportedDefenderRegChanges[$changeKey]=$true
                $label = if ($defenderRegLabels.ContainsKey($root)) { $defenderRegLabels[$root] } else { $root }
                Write-MonitorAlert -Message "$label changed" -LogFile $logFile -Color Yellow
            }
        } catch {}
    }

    # Active threats (every 5 ticks)
    $activeThreatScanCounter++
    if ($activeThreatScanCounter -ge 5) {
        $activeThreatScanCounter = 0
        foreach ($line in (Get-ActiveDefenderThreatAlerts)) { if ($line -like 'SUCCESS*') { continue }; Write-MonitorAlertOnce -Category 'threats' -Message $line -LogFile $logFile -Color Yellow }
    }

    # External/overlay/taskmgr (every 5 ticks)
    $externalScanCounter++
    if ($externalScanCounter -ge 5) {
        $externalScanCounter = 0
        foreach ($line in (Get-ExternalCheatHits)) { if ($line -like 'SUCCESS*') { continue }; Write-MonitorAlertOnce -Category 'external' -Message $line -LogFile $logFile -Color Yellow }
        foreach ($line in (Get-TransparentOverlayAlerts)) { if ($line -like 'SUCCESS*') { continue }; Write-MonitorAlertOnce -Category 'overlay' -Message $line -LogFile $logFile -Level WARN }
        foreach ($line in (Get-TaskManagerIntegrityAlerts)) { if ($line -like 'SUCCESS*' -or $line -like 'INFO*') { continue }; Write-MonitorAlertOnce -Category 'taskmgr' -Message $line -LogFile $logFile -Level FAIL }
        foreach ($line in (Get-UnsignedUserProgramAlerts)) { if ($line -like 'SUCCESS*') { continue }; Write-MonitorAlertOnce -Category 'userprog' -Message $line -LogFile $logFile }
    }

    # v2.0 NEW: Hidden processes, injected threads, cheat engine, debugger (every 4 ticks)
    $v2ScanCounter++
    if ($v2ScanCounter -ge 4) {
        $v2ScanCounter = 0
        foreach ($line in (Get-HiddenProcessAlerts)) { if ($line -like 'SUCCESS*') { continue }; Write-MonitorAlertOnce -Category 'hiddenps' -Message $line -LogFile $logFile -Level FAIL }
        foreach ($line in (Get-InjectedThreadAlerts)) { if ($line -like 'SUCCESS*' -or $line -like 'INFO*') { continue }; Write-MonitorAlertOnce -Category 'threads' -Message $line -LogFile $logFile -Level FAIL }
        foreach ($line in (Get-CheatEngineAlerts)) { if ($line -like 'SUCCESS*') { continue }; Write-MonitorAlertOnce -Category 'ce' -Message $line -LogFile $logFile -Level FAIL }
        foreach ($line in (Get-DebuggerDetectionAlerts)) { if ($line -like 'SUCCESS*') { continue }; Write-MonitorAlertOnce -Category 'debugger' -Message $line -LogFile $logFile }
        foreach ($line in (Get-EnhancedNamedPipeAlerts)) { if ($line -like 'SUCCESS*' -or $line -like 'INFO*') { continue }; Write-MonitorAlertOnce -Category 'pipes' -Message $line -LogFile $logFile -Level FAIL }
    }

    # Folder scan (every 30 ticks)
    $folderScanCounter++
    if ($folderScanCounter -ge 30) {
        $folderScanCounter = 0
        foreach ($folder in (Get-CheatFolderHits)) {
            if (-not $knownCheatFolders.ContainsKey($folder)) { $knownCheatFolders[$folder]=$true; Write-MonitorAlert -Message "Cheat folder: $folder" -LogFile $logFile -Color Yellow }
        }
    }

    # Process changes (every 3 ticks)
    $processChangeCounter++
    if ($processChangeCounter -ge 3) {
        $processChangeCounter = 0
        $currentProcessSnapshot = Get-ProcessSnapshot
        if ($null -ne $currentProcessSnapshot) {
            if ($null -ne $lastProcessSnapshot) { Update-ProcessChangeMonitor -Previous $lastProcessSnapshot -Current $currentProcessSnapshot -Watched $watchedProcesses -LogFile $logFile }
            $lastProcessSnapshot = $currentProcessSnapshot
        }
        $rTarget = Get-Process -Name 'RobloxPlayerBeta' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($rTarget) {
            $rbxToken = "$($rTarget.Id)|$($rTarget.StartTime.Ticks)"
            if ($script:LastRobloxBuildAnnounced -ne $rbxToken) {
                $script:LastRobloxBuildAnnounced = $rbxToken
                $v = Get-RobloxVersionInfo
                Write-MonitorAlert -Message "Roblox client running: $($v.VersionHash) (Ver: $($v.FileVersion), PID $($rTarget.Id))" -LogFile $logFile -Level INFO
            }
        } else { $script:LastRobloxBuildAnnounced = $null }
    }

    # BAM/prefetch/tamper log (every 10 ticks)
    $deletionScanCounter++
    if ($deletionScanCounter -ge 10) {
        $deletionScanCounter = 0
        $currentBam = @{}; foreach ($fp in (Get-BamRegistryFingerprints)) { $currentBam[$fp]=$true }
        foreach ($fp in $script:BaselineBamKeys.Keys) {
            if (-not $currentBam.ContainsKey($fp) -and -not $reportedBamDeletions.ContainsKey($fp)) {
                $reportedBamDeletions[$fp]=$true; $display=($fp -split '\|')[-1]
                Write-MonitorAlert -Message "BAM execution-history entry removed: $display" -LogFile $logFile -Level FAIL
            }
        }
        $currentPrefetch = @{}; foreach ($pf in (Get-PrefetchFileNames)) { $currentPrefetch[$pf]=$true }
        foreach ($pf in $currentPrefetch.Keys) {
            if ($script:BaselinePrefetchFiles.ContainsKey($pf) -or $reportedPrefetchHits.ContainsKey($pf)) { continue }
            $pfKw = Get-MatchedCheatKeyword -Text $pf
            if ($pfKw) { $reportedPrefetchHits[$pf]=$true; Write-MonitorAlert -Message "Prefetch added [$pfKw]: $pf" -LogFile $logFile -Level FAIL }
        }
        foreach ($pf in $script:BaselinePrefetchFiles.Keys) {
            if (-not $currentPrefetch.ContainsKey($pf) -and -not $reportedPrefetchDeletions.ContainsKey($pf)) {
                $pfKw = Get-MatchedCheatKeyword -Text $pf
                if ($pfKw) { $reportedPrefetchDeletions[$pf]=$true; Write-MonitorAlert -Message "Prefetch deleted [$pfKw]: $pf" -LogFile $logFile -Level FAIL }
            }
        }
        foreach ($ev in (Get-TamperLogEvents -Since $monitoringStart -LogFile $logFile)) {
            $eventKey="$($ev.LogName)|$($ev.RecordId)"; if ($reportedTamperEvents.ContainsKey($eventKey)) { continue }
            $reportedTamperEvents[$eventKey]=$true; Write-MonitorAlert -Message "Event log cleared ($($ev.LogName) event $($ev.Id))" -LogFile $logFile -Level FAIL
        }
    }

    # Full integrity sweep (every 15 ticks)
    $integrityScanCounter++
    if ($integrityScanCounter -ge 15) {
        $integrityScanCounter = 0
        try {
            foreach ($line in (Get-MonitorIntegrityAlerts -Since $monitoringStart)) { Write-MonitorAlertOnce -Category 'integrity' -Message $line -LogFile $logFile }
            foreach ($line in (Get-PowerShellHostIntegrityAlerts)) { if ($line -like 'SUCCESS*' -or $line -like 'INFO*') { continue }; Write-MonitorAlertOnce -Category 'pshost' -Message $line -LogFile $logFile }
            foreach ($line in (Get-NtdllSyscallIntegrityAlerts)) { if ($line -like 'SUCCESS*' -or $line -like 'INFO*') { continue }; Write-MonitorAlertOnce -Category 'pshost' -Message $line -LogFile $logFile }
            foreach ($line in (Get-EtwTamperingAlerts)) { if ($line -like 'SUCCESS*') { continue }; Write-MonitorAlertOnce -Category 'etw' -Message $line -LogFile $logFile -Level FAIL }
            foreach ($line in (Get-AmsiIntegrityAlerts)) { if ($line -like 'SUCCESS*') { continue }; Write-MonitorAlertOnce -Category 'amsi' -Message $line -LogFile $logFile -Level FAIL }
        } catch { Write-MonitorAlertOnce -Category 'error' -Message "WARNING: Integrity tracking failed ($($_.Exception.Message))" -LogFile $logFile }
    }

    # Status line
    $statusLineCounter++
    if ($statusLineCounter -ge 2) { $statusLineCounter=0; Write-MonitorStatusLine -Since $monitoringStart }
}
} finally {
    Clear-MonitorStatusLine
    $elapsed = (Get-Date) - $monitoringStart
    Write-MonitorAlert -Message ("$($script:Brand) monitor stopped after {0:hh\:mm\:ss} ({1} fail, {2} warn, {3} info)" -f $elapsed,$script:MonitorAlertCounts.FAIL,$script:MonitorAlertCounts.WARN,$script:MonitorAlertCounts.INFO) -LogFile $logFile -Level INFO
    Get-EventSubscriber -SourceIdentifier USBChange -ErrorAction SilentlyContinue | Unregister-Event -Force -ErrorAction SilentlyContinue
}
# (end of script)
