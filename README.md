# ZeroProbe Enumration Framework
ZeroProbe is an advanced enumeration and analysis framework designed for exploit developers, security researchers, and red teamers. It provides a set of enumeration tools to identify security vulnerabilities, analyze system protections, and facilitate exploit development.

![Screenshot from 2025-03-08 06-13-03](https://github.com/user-attachments/assets/741717f5-1354-46be-8a4d-1b0d272aaa38)

# Overview
ZeroProbe is an exploit development and enumeration framework designed for security researchers, exploit developers, penetration testers, and red teamers. It provides a set of powerful modules to analyze system vulnerabilities, detect privilege escalation paths, map kernel exploits, identify weak file permissions, and enumerate security misconfigurations. By leveraging direct syscall execution, memory analysis, and DLL hijacking detection, ExploitForge helps professionals assess security defenses and develop exploitation strategies while maintaining a low forensic footprint.

# Note
Tested and works in windows 10, 11, Server 2019 
(ZeroProbe-V1.0-pwsh7.ps1) is compatible with PowerShell Version  7
(ZeroProbe-V1.0-All-PWH.ps1) is compatible with all other versions of powershell

# Features

# 1- Kernel Exploit Detection with CVE Mapping

Detects unpatched Windows kernel vulnerabilities by mapping the system's kernel version to known CVEs. It retrieves a list of potential kernel exploits and alerts the user if vulnerabilities are found. The results help identify security risks that may be leveraged for privilege escalation or remote execution.

# 2- ROP & JOP Gadget Finder

Scans a DLL file for Return-Oriented Programming (ROP) and Jump-Oriented Programming (JOP) gadgets. It analyzes exploitability, attempts to generate an ROP chain, and checks for potential DEP bypass techniques. The results help identify security risks in executable files and aid in exploit development.

# 3- Real Syscall Index Extractor

Extracts real syscall numbers from ntdll.dll by resolving the function addresses of specified system calls. It reads the syscall instruction sequence to determine the correct syscall index for direct system calls. The results help in low-level exploit development, syscall-based evasion, and malware analysis.

# 4- Heap Spray Analysis

Scans running processes to identify potential heap spray targets based on high memory usage. It excludes common trusted applications and lists processes that could be exploited for heap spray attacks. The results help in analyzing security risks related to heap-based exploitation. (It exclude the well-known applications that consume a large space on Heap so to reduce false positives. Feel free the updates the list on the fucnction).

# 5- DLL Hijacking Scanner

Scans for unquoted service paths that may lead to DLL hijacking vulnerabilities. It categorizes vulnerabilities into high, medium, and low risk based on the service's execution state and location. The results help identify security risks that attackers could exploit to load malicious DLLs.

# 6- Enumrate NamedPipes

Enumerates active named pipes and checks their access control permissions. It identifies weak permissions that could allow unauthorized access or privilege escalation.
The results help assess potential security risks in named pipe communication.

# 7- Direct Syscall Execution

Attempts to allocate executable memory regions within a process to support direct syscall execution. It verifies that allocated memory is executable and does not contain null bytes to avoid syscall failures. The results help in assessing memory allocation security and executing direct syscalls without API hooking.

# 8- Detect Privilege Escalation Paths

Analyzes running processes and their privilege levels to identify potential privilege escalation opportunities. It checks for processes running as SYSTEM or Administrator and lists the privileges assigned to the current user. The results help in assessing security risks and identifying escalation vectors.

# 9- Memory Analysis for Suspicious Regions

Scans running processes for suspicious memory regions by identifying those consuming excessive memory. It flags processes with unusually high private memory usage, which may indicate malware, exploits, or memory leaks. The results help in detecting anomalies and analyzing potential security threats.

# 10- Detect Suspicious COM-Hijacking

Scans registry locations for potential COM object hijacking attempts. It checks for suspicious references in CLSID entries that could allow attackers to execute malicious code. The results help in identifying security risks related to persistence mechanisms and privilege escalation.

# 11- Enumerate Kernel Memory

Enumerates kernel memory regions and categorizes them based on their address ranges. It identifies conventional memory, kernel space, GPU memory, and other reserved regions for analysis. The results help in detecting potential security risks, debugging drivers, or analyzing system memory layout.

# 12- Enumerate-Non ASLR-DLLs

Scans loaded DLLs or a specified directory for security weaknesses related to ASLR, DEP, SafeSEH, and CFG. It identifies high-risk DLLs that lack these protections, which could be exploited for memory corruption or code execution attacks. The results help assess system security by detecting potentially vulnerable DLLs.

# 13- Enumerate-Weak File Permissions

Scans predefined system directories or a user-specified path for weak file permissions. It identifies files that allow Everyone, Authenticated Users, or BUILTIN\Users to write, modify, or gain full control. The results help detect security risks that could allow unauthorized file modifications or privilege escalation.

# 14- Check PrivEsc Vulnerability

Checks for privilege escalation vulnerabilities by analyzing high-risk privileges, token manipulation capabilities, and writable MSI files. It identifies exploitable processes running with SYSTEM privileges and assesses compatibility with known privilege escalation techniques. The results help detect potential security risks that could allow attackers to escalate privileges.

# 15- Detect SyscallHooks

Scans for syscall hooks in ntdll.dll to detect potential tampering by security software or malware. It reads the first few bytes of key system calls to check for redirection, breakpoints, or other modifications. The results help identify potential syscall interceptions that may impact security research or evasion techniques.

# 16- Generate ReverseShell

Generates and executes a reverse shell in memory using C#. It establishes a connection to an attacker's machine, allowing remote command execution. The results help test remote access techniques and assess security defenses.

# License
This project is released under the MIT License - see the https://github.com/yehia-mamdouh/ZeroProbe/blob/main/LICENSE file for more details.

# Author 

Created by Mrvar0x https://github.com/yehia-mamdouh/

# Contributing

Contributions are welcome!
