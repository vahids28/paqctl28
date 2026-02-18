#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Paqet/GFK Windows Client - Bypass Firewall Restrictions

.DESCRIPTION
    This script helps you connect to your server through firewalls that block normal connections.
    It supports two backends:

    PAQET (Recommended for most users)
    ─────────────────────────────────
    • Simple all-in-one solution with built-in SOCKS5 proxy
    • Uses KCP protocol over raw sockets to bypass DPI
    • Works on: Windows (with Npcap)
    • Configuration: Just needs server IP, port, and encryption key
    • Proxy: 127.0.0.1:1080 (SOCKS5)

    GFW-KNOCKER (For heavily restricted networks)
    ─────────────────────────────────────────────
    • Uses "violated TCP" packets + QUIC tunnel to evade deep packet inspection
    • More complex but better at evading sophisticated firewalls (like GFW)
    • Works on: Windows (with Npcap + Python)
    • Requires: Xray running on server port 443
    • Proxy: 127.0.0.1:14000 (forwards to server's Xray SOCKS5)

    CAN I RUN BOTH?
    ───────────────
    Yes! Both can run simultaneously on different ports:
    • Paqet SOCKS5: 127.0.0.1:1080
    • GFK tunnel:   127.0.0.1:14000
    This lets you have a backup if one method gets blocked.

.NOTES
    Requirements:
    • Administrator privileges (for raw socket access)
    • Npcap (https://npcap.com) - auto-installed if missing
    • Python 3.10+ (GFK only) - auto-installed if missing
#>

param(
    [string]$ServerAddr,
    [string]$Key,
    [string]$Action = "menu",  # menu, run, install, config, stop, status
    [string]$Backend = ""      # paqet, gfk (auto-detect if not specified)
)

$ErrorActionPreference = "Stop"

# Directories and pinned versions (for stability - update after testing new releases)
$InstallDir = "C:\paqet"
$PaqetExe = "$InstallDir\paqet_windows_amd64.exe"
$PaqetVersion = "v1.0.0-alpha.16"   # Pinned paqet version
$GfkDir = "$InstallDir\gfk"
$ConfigFile = "$InstallDir\config.yaml"
$SettingsFile = "$InstallDir\settings.conf"

# Npcap (pinned version)
$NpcapVersion = "1.80"
$NpcapUrl = "https://npcap.com/dist/npcap-$NpcapVersion.exe"
$NpcapInstaller = "$env:TEMP\npcap-$NpcapVersion.exe"

# GFK scripts - bundled locally for faster setup (only works when running from downloaded repo)
# When running via "irm | iex", $MyInvocation.MyCommand.Path is null
$ScriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { $null }
$GfkLocalDir = if ($ScriptDir) { "$ScriptDir\..\gfk\client" } else { $null }
$GfkFiles = @("mainclient.py", "quic_client.py", "vio_client.py")  # parameters.py is generated

# Colors
function Write-Info { Write-Host "[INFO] $args" -ForegroundColor Cyan }
function Write-Success { Write-Host "[OK] $args" -ForegroundColor Green }
function Write-Warn { Write-Host "[WARN] $args" -ForegroundColor Yellow }
function Write-Err { Write-Host "[ERROR] $args" -ForegroundColor Red }

# Input validation (security: prevent config injection)
function Test-ValidIP {
    param([string]$IP)
    return $IP -match '^(\d{1,3}\.){3}\d{1,3}$'
}

function Test-ValidMAC {
    param([string]$MAC)
    return $MAC -match '^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$'
}

function Test-SafeString {
    param([string]$s)
    # Block characters that could break Python string literals
    if ($s.Contains('"') -or $s.Contains("'") -or $s.Contains('\') -or $s.Contains([char]10) -or $s.Contains([char]13)) {
        return $false
    }
    return $true
}

#═══════════════════════════════════════════════════════════════════════
# Prerequisite Checks
#═══════════════════════════════════════════════════════════════════════

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Npcap {
    $npcapPath = "C:\Windows\System32\Npcap"
    $wpcapDll = "C:\Windows\System32\wpcap.dll"
    return (Test-Path $npcapPath) -or (Test-Path $wpcapDll)
}

function Test-Python {
    try {
        $version = & python --version 2>&1
        return $version -match "Python 3\."
    } catch {
        return $false
    }
}

function Install-NpcapIfMissing {
    if (Test-Npcap) { return $true }

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Red
    Write-Host "  NPCAP REQUIRED" -ForegroundColor Red
    Write-Host "===============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Npcap is required for raw socket access."
    Write-Host ""
    Write-Host "  IMPORTANT: During installation, check:" -ForegroundColor Yellow
    Write-Host "  [x] Install Npcap in WinPcap API-compatible Mode" -ForegroundColor Yellow
    Write-Host ""

    $choice = Read-Host "  Download and install Npcap now? [Y/n]"
    if ($choice -match "^[Nn]") {
        Write-Warn "Please install Npcap from https://npcap.com"
        return $false
    }

    Write-Info "Downloading Npcap $NpcapVersion..."
    try {
        Invoke-WebRequest -Uri $NpcapUrl -OutFile $NpcapInstaller -UseBasicParsing
        Write-Success "Downloaded"
    } catch {
        Write-Err "Download failed. Please install manually from https://npcap.com"
        Start-Process "https://npcap.com/#download"
        return $false
    }

    Write-Info "Launching Npcap installer..."
    Write-Host "  Check: [x] WinPcap API-compatible Mode" -ForegroundColor Yellow
    Start-Process -FilePath $NpcapInstaller -Wait | Out-Null
    Remove-Item $NpcapInstaller -Force -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 2
    if (Test-Npcap) {
        Write-Success "Npcap installed!"
        return $true
    } else {
        Write-Err "Npcap installation failed or cancelled"
        return $false
    }
}

function Install-PythonIfMissing {
    if (Test-Python) { return $true }

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Red
    Write-Host "  PYTHON 3 REQUIRED" -ForegroundColor Red
    Write-Host "===============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  GFW-knocker requires Python 3.x"
    Write-Host ""
    Write-Host "  Please install Python from:" -ForegroundColor Yellow
    Write-Host "  https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  IMPORTANT: Check 'Add Python to PATH' during install!" -ForegroundColor Yellow
    Write-Host ""

    $choice = Read-Host "  Open Python download page? [Y/n]"
    if ($choice -notmatch "^[Nn]") {
        Start-Process "https://www.python.org/downloads/"
    }

    Read-Host "  Press Enter after installing Python"

    if (Test-Python) {
        Write-Success "Python detected!"
        return $true
    } else {
        Write-Err "Python not found. Please restart PowerShell after installing."
        return $false
    }
}

function Install-PythonPackages {
    Write-Info "Installing Python packages (scapy, aioquic)..."
    try {
        & python -m pip install --quiet --upgrade pip 2>&1 | Out-Null
        & python -m pip install --quiet scapy aioquic 2>&1 | Out-Null
        Write-Success "Python packages installed"
        return $true
    } catch {
        Write-Err "Failed to install Python packages: $_"
        Write-Info "Try manually: pip install scapy aioquic"
        return $false
    }
}

#═══════════════════════════════════════════════════════════════════════
# Network Detection
#═══════════════════════════════════════════════════════════════════════

function Get-NetworkInfo {
    $adapter = Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -and
        $_.InterfaceDescription -notmatch "Virtual|VirtualBox|VMware|Hyper-V|Loopback"
    } | Select-Object -First 1

    if (-not $adapter) {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    }

    if (-not $adapter) {
        Write-Err "No active network adapter found"
        return $null
    }

    $ifIndex = $adapter.ifIndex
    $ipConfig = Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 |
                Where-Object { $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1
    $gateway = Get-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
               Select-Object -First 1

    if (-not $ipConfig) {
        Write-Err "No IPv4 address found on $($adapter.Name)"
        return $null
    }

    $gatewayIP = if ($gateway) { $gateway.NextHop } else { $null }
    $gatewayMAC = $null

    if ($gatewayIP) {
        $null = Test-Connection -ComputerName $gatewayIP -Count 1 -ErrorAction SilentlyContinue
        $arpEntry = Get-NetNeighbor -IPAddress $gatewayIP -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($arpEntry -and $arpEntry.LinkLayerAddress) {
            $gatewayMAC = $arpEntry.LinkLayerAddress -replace "-", ":"
        }
    }

    return @{
        Name = $adapter.Name
        Guid = $adapter.InterfaceGuid
        IP = $ipConfig.IPAddress
        GatewayIP = $gatewayIP
        GatewayMAC = $gatewayMAC
    }
}

#═══════════════════════════════════════════════════════════════════════
# Backend Detection
#═══════════════════════════════════════════════════════════════════════

function Get-InstalledBackend {
    if (Test-Path $SettingsFile) {
        $content = Get-Content $SettingsFile -ErrorAction SilentlyContinue
        foreach ($line in $content) {
            if ($line -match '^BACKEND="?(\w+)"?') {
                return $Matches[1]
            }
        }
    }
    if (Test-Path $PaqetExe) { return "paqet" }
    if (Test-Path "$GfkDir\mainclient.py") { return "gfk" }
    return $null
}

function Save-Settings {
    param([string]$Backend, [string]$ServerAddr = "", [string]$SocksPort = "1080")

    $settings = @"
BACKEND="$Backend"
SERVER_ADDR="$ServerAddr"
SOCKS_PORT="$SocksPort"
"@
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($SettingsFile, $settings)
}

#═══════════════════════════════════════════════════════════════════════
# Paqet Functions
#═══════════════════════════════════════════════════════════════════════

function Install-Paqet {
    Write-Host ""
    Write-Host "  Installing PAQET" -ForegroundColor Green
    Write-Host "  ────────────────" -ForegroundColor Green
    Write-Host "  Paqet is an all-in-one proxy solution with built-in SOCKS5."
    Write-Host "  It uses KCP protocol over raw sockets to bypass firewalls."
    Write-Host ""
    Write-Host "  What will be installed:" -ForegroundColor Yellow
    Write-Host "    1. Npcap (for raw socket access)"
    Write-Host "    2. Paqet binary"
    Write-Host ""
    Write-Host "  After setup, configure with your server's IP:port and key."
    Write-Host "  Your proxy will be: 127.0.0.1:1080 (SOCKS5)"
    Write-Host ""

    if (-not (Install-NpcapIfMissing)) {
        Write-Err "Cannot continue without Npcap"
        return $false
    }

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    if (Test-Path $PaqetExe) {
        Write-Info "paqet already installed"
        return $true
    }

    $zipUrl = "https://github.com/hanselime/paqet/releases/download/$PaqetVersion/paqet-windows-amd64-$PaqetVersion.zip"
    $zipFile = "$env:TEMP\paqet.zip"

    Write-Info "Downloading paqet $PaqetVersion..."
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile
    } catch {
        Write-Err "Download failed: $_"
        return $false
    }

    Write-Info "Extracting..."
    Expand-Archive -Path $zipFile -DestinationPath $InstallDir -Force
    Remove-Item $zipFile -Force

    Write-Success "paqet installed to $InstallDir"
    Save-Settings -Backend "paqet"
    return $true
}

function New-PaqetConfig {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$SecretKey,
        [string]$TcpLocalFlag = "PA",
        [string]$TcpRemoteFlag = "PA"
    )

    # Validate TCP flags (uppercase letters F,S,R,P,A,U,E,C, optionally comma-separated)
    if ($TcpLocalFlag -cnotmatch '^[FSRPAUEC]+(,[FSRPAUEC]+)*$') {
        Write-Warn "Invalid TCP local flag. Using default: PA"
        $TcpLocalFlag = "PA"
    }
    if ($TcpRemoteFlag -cnotmatch '^[FSRPAUEC]+(,[FSRPAUEC]+)*$') {
        Write-Warn "Invalid TCP remote flag. Using default: PA"
        $TcpRemoteFlag = "PA"
    }

    Write-Info "Detecting network..."
    $net = Get-NetworkInfo
    if (-not $net) { return $false }

    Write-Info "  Adapter:     $($net.Name)"
    Write-Info "  Local IP:    $($net.IP)"
    Write-Info "  Gateway MAC: $($net.GatewayMAC)"

    if (-not $net.GatewayMAC) {
        $net.GatewayMAC = Read-Host "  Enter gateway MAC (aa:bb:cc:dd:ee:ff)"
    }

    # Convert comma-separated flags to YAML array format: PA,A -> ["PA", "A"]
    $localFlagArray = ($TcpLocalFlag -split ',') | ForEach-Object { "`"$_`"" }
    $remoteFlagArray = ($TcpRemoteFlag -split ',') | ForEach-Object { "`"$_`"" }
    $localFlagYaml = "[" + ($localFlagArray -join ", ") + "]"
    $remoteFlagYaml = "[" + ($remoteFlagArray -join ", ") + "]"

    $guidEscaped = "\\Device\\NPF_$($net.Guid)"
    $config = @"
role: "client"

log:
  level: "info"

socks5:
  - listen: "127.0.0.1:1080"

network:
  interface: "$($net.Name)"
  guid: "$guidEscaped"
  ipv4:
    addr: "$($net.IP):0"
    router_mac: "$($net.GatewayMAC)"
  tcp:
    local_flag: $localFlagYaml
    remote_flag: $remoteFlagYaml

server:
  addr: "$Server"

transport:
  protocol: "kcp"
  kcp:
    mode: "fast"
    key: "$SecretKey"
"@

    # Ensure install directory exists
    if (-not (Test-Path $InstallDir)) {
        Write-Err "Paqet is not installed. Please install paqet first (option 1)."
        return $false
    }

    [System.IO.File]::WriteAllText($ConfigFile, $config)
    Save-Settings -Backend "paqet" -ServerAddr $Server
    Write-Success "Configuration saved"
    return $true
}

function Start-Paqet {
    if (-not (Test-Npcap)) {
        if (-not (Install-NpcapIfMissing)) { return }
    }

    if (-not (Test-Path $PaqetExe)) {
        Write-Err "paqet not installed"
        return
    }

    if (-not (Test-Path $ConfigFile)) {
        Write-Err "Config not found. Configure first."
        return
    }

    Write-Host ""
    Write-Host "  Starting PAQET" -ForegroundColor Green
    Write-Host "  ──────────────"
    Write-Host "  Paqet will connect to your server using KCP over raw sockets."
    Write-Host ""
    Write-Host "  Your SOCKS5 proxy will be: 127.0.0.1:1080"
    Write-Host "  Configure your browser to use this proxy."
    Write-Host ""
    Write-Info "Starting paqet..."
    Write-Info "SOCKS5 proxy: 127.0.0.1:1080"
    Write-Info "Press Ctrl+C to stop"
    Write-Host ""

    & $PaqetExe run -c $ConfigFile
}

#═══════════════════════════════════════════════════════════════════════
# GFW-knocker Functions
#═══════════════════════════════════════════════════════════════════════

function Install-Gfk {
    Write-Host ""
    Write-Host "  Installing GFW-KNOCKER" -ForegroundColor Yellow
    Write-Host "  ──────────────────────" -ForegroundColor Yellow
    Write-Host "  GFK is an advanced anti-censorship tool designed for heavy DPI."
    Write-Host "  It uses 'violated TCP' packets + QUIC tunneling to evade detection."
    Write-Host ""
    Write-Host "  What will be installed:" -ForegroundColor Yellow
    Write-Host "    1. Npcap (for raw socket access)"
    Write-Host "    2. Python 3.10+ (for QUIC protocol)"
    Write-Host "    3. Python packages: scapy, aioquic"
    Write-Host "    4. GFK client scripts"
    Write-Host ""
    Write-Host "  IMPORTANT: Your server must have Xray running on port 443." -ForegroundColor Cyan
    Write-Host "  GFK is just a tunnel - Xray provides the actual SOCKS5 proxy."
    Write-Host ""
    Write-Host "  After setup, your proxy will be: 127.0.0.1:14000 (SOCKS5)"
    Write-Host ""

    # Check prerequisites
    if (-not (Install-NpcapIfMissing)) { return $false }
    if (-not (Install-PythonIfMissing)) { return $false }
    if (-not (Install-PythonPackages)) { return $false }

    # Create directories
    if (-not (Test-Path $GfkDir)) {
        New-Item -ItemType Directory -Path $GfkDir -Force | Out-Null
    }

    # Copy bundled GFK scripts or download from GitHub
    Write-Info "Setting up GFW-knocker scripts..."
    $GfkGitHubBase = "https://raw.githubusercontent.com/SamNet-dev/paqctl/main/gfk/client"
    foreach ($file in $GfkFiles) {
        $dest = "$GfkDir\$file"
        $src = if ($GfkLocalDir) { "$GfkLocalDir\$file" } else { $null }

        if ($src -and (Test-Path $src)) {
            # Copy from local bundled files (faster)
            Copy-Item -Path $src -Destination $dest -Force
            Write-Info "  Copied $file"
        } else {
            # Download from GitHub (for one-liner installation)
            Write-Info "  Downloading $file..."
            try {
                Invoke-WebRequest -Uri "$GfkGitHubBase/$file" -OutFile $dest -UseBasicParsing
                Write-Info "  Downloaded $file"
            } catch {
                Write-Err "Failed to download $file from GitHub"
                return $false
            }
        }
    }

    Write-Success "GFW-knocker installed to $GfkDir"
    Save-Settings -Backend "gfk"
    return $true
}

function New-GfkConfig {
    param(
        [Parameter(Mandatory)][string]$ServerIP,
        [Parameter(Mandatory)][string]$AuthCode,
        [string]$SocksPort = "1080",
        [string]$TcpFlags = "AP"
    )

    # Validate inputs (security: prevent config injection)
    if (-not (Test-ValidIP $ServerIP)) {
        Write-Err "Invalid server IP format"
        return $false
    }
    if (-not (Test-SafeString $AuthCode)) {
        Write-Err "Invalid auth code format"
        return $false
    }
    # Validate TCP flags (uppercase letters only: F,S,R,P,A,U,E,C)
    if ($TcpFlags -cnotmatch '^[FSRPAUEC]+$') {
        Write-Warn "Invalid TCP flags. Using default: AP"
        $TcpFlags = "AP"
    }

    Write-Info "Detecting network..."
    $net = Get-NetworkInfo
    if (-not $net) { return $false }

    Write-Info "  Adapter:  $($net.Name)"
    Write-Info "  Local IP: $($net.IP)"
    Write-Info "  Gateway:  $($net.GatewayMAC)"

    if (-not $net.GatewayMAC) {
        $net.GatewayMAC = Read-Host "  Enter gateway MAC (aa:bb:cc:dd:ee:ff)"
    }

    # Validate detected network values
    if (-not (Test-ValidIP $net.IP)) {
        Write-Err "Invalid local IP detected"
        return $false
    }
    if ($net.GatewayMAC -and -not (Test-ValidMAC $net.GatewayMAC)) {
        Write-Err "Invalid gateway MAC format"
        return $false
    }

    # Create parameters.py for GFK (matching expected variable names)
    $params = @"
# GFW-knocker client configuration (auto-generated)
from scapy.all import conf

# Network interface for scapy (Windows Npcap)
conf.iface = r"\Device\NPF_$($net.Guid)"
my_ip = "$($net.IP)"
gateway_mac = "$($net.GatewayMAC)"

# Server settings
vps_ip = "$ServerIP"
xray_server_ip = "127.0.0.1"

# Port mappings (local_port: remote_port)
tcp_port_mapping = {14000: 443}
udp_port_mapping = {}

# VIO (raw socket) ports
vio_tcp_server_port = 45000
vio_tcp_client_port = 40000
vio_udp_server_port = 35000
vio_udp_client_port = 30000

# QUIC tunnel ports
quic_server_port = 25000
quic_client_port = 20000
quic_local_ip = "127.0.0.1"

# QUIC settings
quic_verify_cert = False
quic_idle_timeout = 86400
udp_timeout = 300
quic_mtu = 1420
quic_max_data = 1073741824
quic_max_stream_data = 1073741824
quic_auth_code = "$AuthCode"
quic_certificate = "cert.pem"
quic_private_key = "key.pem"

# TCP flags for violated packets (default: AP = ACK+PSH)
tcp_flags = "$TcpFlags"

# SOCKS proxy
socks_port = $SocksPort
"@

    # Ensure GFK directory exists
    if (-not (Test-Path $GfkDir)) {
        Write-Err "GFK is not installed. Please install GFK first (option 2)."
        return $false
    }

    [System.IO.File]::WriteAllText("$GfkDir\parameters.py", $params)
    Save-Settings -Backend "gfk" -ServerAddr $ServerIP -SocksPort $SocksPort
    Write-Success "GFK configuration saved"
    return $true
}

function Start-Gfk {
    if (-not (Test-Npcap)) {
        if (-not (Install-NpcapIfMissing)) { return }
    }

    if (-not (Test-Python)) {
        Write-Err "Python not found"
        return
    }

    if (-not (Test-Path "$GfkDir\mainclient.py")) {
        Write-Err "GFK not installed"
        return
    }

    if (-not (Test-Path "$GfkDir\parameters.py")) {
        Write-Err "GFK not configured"
        return
    }

    Write-Host ""
    Write-Host "  Starting GFW-KNOCKER" -ForegroundColor Yellow
    Write-Host "  ────────────────────"
    Write-Host "  This will start:"
    Write-Host "    1. VIO client (raw socket handler)"
    Write-Host "    2. QUIC client (tunnel to server)"
    Write-Host ""
    Write-Host "  Your SOCKS5 proxy will be: 127.0.0.1:14000"
    Write-Host "  Configure your browser to use this proxy."
    Write-Host ""
    Write-Info "Starting GFW-knocker client..."
    Write-Info "This will start the raw socket client + Python SOCKS5 proxy"
    Write-Info "Press Ctrl+C to stop"
    Write-Host ""

    # Start GFK client
    Push-Location $GfkDir
    try {
        & python mainclient.py
    } finally {
        Pop-Location
    }
}

function Stop-GfkClient {
    # Get-Process doesn't have CommandLine property - use CIM instead
    $procs = Get-CimInstance Win32_Process -Filter "Name LIKE 'python%'" -ErrorAction SilentlyContinue |
             Where-Object { $_.CommandLine -match "mainclient|gfk" }
    if ($procs) {
        $procs | ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Write-Success "GFK client stopped"
    } else {
        Write-Info "GFK client not running"
    }
}

#═══════════════════════════════════════════════════════════════════════
# Common Functions
#═══════════════════════════════════════════════════════════════════════

function Stop-Client {
    # Stop paqet
    $paqetProc = Get-Process -Name "paqet_windows_amd64" -ErrorAction SilentlyContinue
    if ($paqetProc) {
        Stop-Process -Name "paqet_windows_amd64" -Force
        Write-Success "paqet stopped"
    }

    # Stop GFK
    Stop-GfkClient
}

function Get-ClientStatus {
    Write-Host "`n=== Client Status ===" -ForegroundColor Cyan

    $backend = Get-InstalledBackend
    Write-Host "Backend: $(if ($backend) { $backend } else { 'Not installed' })"

    # Npcap
    if (Test-Npcap) {
        Write-Success "Npcap: Installed"
    } else {
        Write-Err "Npcap: NOT installed"
    }

    # Python (for GFK)
    if ($backend -eq "gfk" -or -not $backend) {
        if (Test-Python) {
            Write-Success "Python: Installed"
        } else {
            Write-Warn "Python: Not found (needed for GFK)"
        }
    }

    # Paqet
    if (Test-Path $PaqetExe) {
        Write-Success "Paqet binary: Found"
    }

    # GFK
    if (Test-Path "$GfkDir\mainclient.py") {
        Write-Success "GFK scripts: Found"
    }

    # Config
    if (Test-Path $ConfigFile) {
        Write-Success "Paqet config: Found"
    }
    if (Test-Path "$GfkDir\parameters.py") {
        Write-Success "GFK config: Found"
    }

    # Running processes
    $paqetRunning = Get-Process -Name "paqet_windows_amd64" -ErrorAction SilentlyContinue
    if ($paqetRunning) {
        Write-Success "Paqet: RUNNING (PID: $($paqetRunning.Id))"
        Write-Info "  SOCKS5 proxy: 127.0.0.1:1080"
    }

    Write-Host ""
}

#═══════════════════════════════════════════════════════════════════════
# Update Function
#═══════════════════════════════════════════════════════════════════════

function Get-InstalledPaqetVersion {
    # Check settings file first for tracked version
    if (Test-Path $SettingsFile) {
        $content = Get-Content $SettingsFile -ErrorAction SilentlyContinue
        foreach ($line in $content) {
            if ($line -match '^PAQET_VERSION="?([^"]+)"?') {
                return $Matches[1]
            }
        }
    }
    # Fall back to pinned version if paqet is installed
    if (Test-Path $PaqetExe) {
        return $PaqetVersion
    }
    return $null
}

function Save-PaqetVersion {
    param([string]$Version)

    if (-not (Test-Path $SettingsFile)) {
        return
    }

    $content = Get-Content $SettingsFile -Raw -ErrorAction SilentlyContinue
    if ($content -match 'PAQET_VERSION=') {
        # Update existing
        $content = $content -replace 'PAQET_VERSION="[^"]*"', "PAQET_VERSION=`"$Version`""
    } else {
        # Add new line
        $content = $content.TrimEnd() + "`nPAQET_VERSION=`"$Version`""
    }
    [System.IO.File]::WriteAllText($SettingsFile, $content)
}

function Update-Paqet {
    Write-Host ""
    Write-Host "  CHECKING FOR UPDATES" -ForegroundColor Cyan
    Write-Host "  ────────────────────" -ForegroundColor Cyan
    Write-Host ""

    # Check if paqet is installed
    if (-not (Test-Path $PaqetExe)) {
        Write-Warn "Paqet is not installed. Use option 1 to install first."
        return $false
    }

    # Get installed version
    $installedVersion = Get-InstalledPaqetVersion
    if (-not $installedVersion) {
        $installedVersion = $PaqetVersion
    }

    # Query GitHub API for latest release
    Write-Info "Querying GitHub for latest release..."
    try {
        $apiUrl = "https://api.github.com/repos/hanselime/paqet/releases/latest"
        $response = Invoke-RestMethod -Uri $apiUrl -TimeoutSec 30
        $latestVersion = $response.tag_name
    } catch {
        Write-Err "Failed to check for updates: $_"
        return $false
    }

    # Show version info
    Write-Host ""
    Write-Host "  Installed version:  $installedVersion" -ForegroundColor White
    Write-Host "  Latest version:     $latestVersion" -ForegroundColor White
    Write-Host ""

    # Compare versions
    if ($installedVersion -eq $latestVersion) {
        Write-Success "You are already on the latest version!"
        return $true
    }

    # Confirm update
    Write-Host "  A new version is available!" -ForegroundColor Yellow
    $confirm = Read-Host "  Update to $latestVersion? [y/N]"
    if ($confirm -notmatch "^[Yy]") {
        Write-Info "Update cancelled"
        return $false
    }

    # Stop running paqet first
    $paqetProc = Get-Process -Name "paqet_windows_amd64" -ErrorAction SilentlyContinue
    if ($paqetProc) {
        Write-Info "Stopping paqet..."
        Stop-Process -Name "paqet_windows_amd64" -Force
        Start-Sleep -Seconds 2
    }

    # Download new version
    $zipUrl = "https://github.com/hanselime/paqet/releases/download/$latestVersion/paqet-windows-amd64-$latestVersion.zip"
    $zipFile = "$env:TEMP\paqet-update.zip"
    $extractDir = "$env:TEMP\paqet-update"

    Write-Info "Downloading paqet $latestVersion..."
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -TimeoutSec 120
    } catch {
        Write-Err "Download failed: $_"
        return $false
    }

    # Validate download
    if (-not (Test-Path $zipFile) -or (Get-Item $zipFile).Length -lt 1000) {
        Write-Err "Downloaded file is invalid or too small"
        return $false
    }

    # Extract
    Write-Info "Extracting..."
    try {
        if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
        Expand-Archive -Path $zipFile -DestinationPath $extractDir -Force
    } catch {
        Write-Err "Extraction failed: $_"
        Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
        return $false
    }

    # Find the binary
    $newBinary = Get-ChildItem -Path $extractDir -Filter "paqet_windows_amd64.exe" -Recurse | Select-Object -First 1
    if (-not $newBinary) {
        Write-Err "Could not find paqet binary in archive"
        Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
        return $false
    }

    # Backup old binary
    $backupPath = "$InstallDir\paqet_windows_amd64.exe.bak"
    try {
        Copy-Item $PaqetExe $backupPath -Force
        Write-Info "Backed up old binary"
    } catch {
        Write-Warn "Could not backup old binary: $_"
    }

    # Install new binary
    try {
        Copy-Item $newBinary.FullName $PaqetExe -Force
    } catch {
        Write-Err "Failed to install new binary: $_"
        # Try to restore backup
        if (Test-Path $backupPath) {
            Copy-Item $backupPath $PaqetExe -Force -ErrorAction SilentlyContinue
        }
        return $false
    }

    # Save version to settings
    Save-PaqetVersion -Version $latestVersion

    # Cleanup
    Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Success "Updated to $latestVersion!"
    Write-Host ""
    Write-Info "Restart the client to use the new version"
    Write-Host ""

    return $true
}

#═══════════════════════════════════════════════════════════════════════
# Interactive Menu
#═══════════════════════════════════════════════════════════════════════

function Show-Menu {
    param([string]$InitBackend = "")

    # Use passed backend parameter, or detect if not specified
    $backend = if ($InitBackend) { $InitBackend } else { Get-InstalledBackend }

    while ($true) {
        Write-Host ""
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host "  PAQET/GFK CLIENT MANAGER" -ForegroundColor Cyan
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host ""
        if ($backend) {
            Write-Host "  Active backend: " -NoNewline
            Write-Host "$backend" -ForegroundColor Green
            if ($backend -eq "paqet") {
                Write-Host "  Proxy: 127.0.0.1:1080 (SOCKS5)" -ForegroundColor DarkGray
            } else {
                Write-Host "  Proxy: 127.0.0.1:14000 (SOCKS5 via tunnel)" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "  No backend installed yet" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  1. Install paqet        (simple, all-in-one SOCKS5)"
        Write-Host "  2. Install GFW-knocker  (advanced, for heavy DPI)"
        Write-Host "  3. Configure connection"
        Write-Host "  4. Start client"
        Write-Host "  5. Stop client"
        Write-Host "  6. Show status"
        Write-Host "  7. Update paqet"
        Write-Host "  8. About (how it works)"
        Write-Host "  0. Exit"
        Write-Host ""

        $choice = Read-Host "  Select option"

        switch ($choice) {
            "1" {
                if (Install-Paqet) { $backend = "paqet" }
            }
            "2" {
                if (Install-Gfk) { $backend = "gfk" }
            }
            "3" {
                if (-not $backend) {
                    Write-Warn "Install a backend first (option 1 or 2)"
                    continue
                }

                if ($backend -eq "paqet") {
                    Write-Host ""
                    Write-Host "  PAQET CONFIGURATION" -ForegroundColor Green
                    Write-Host "  Get these values from your server admin or 'paqctl info' on server"
                    Write-Host ""
                    $server = Read-Host "  Server address (e.g., 1.2.3.4:8443)"
                    $key = Read-Host "  Encryption key (16+ chars)"

                    # Advanced options (hidden by default - just press Enter)
                    Write-Host ""
                    Write-Host "  Advanced options (press Enter for defaults - recommended):" -ForegroundColor DarkGray
                    Write-Host "    TCP flags must match your server config. Only change if server admin says so." -ForegroundColor DarkGray
                    Write-Host "    Valid flags: S A P R F U E C  |  Multiple: PA,A" -ForegroundColor DarkGray
                    $tcpLocal = Read-Host "  TCP local flag [PA]"
                    $tcpRemote = Read-Host "  TCP remote flag [PA]"
                    if (-not $tcpLocal) { $tcpLocal = "PA" }
                    if (-not $tcpRemote) { $tcpRemote = "PA" }

                    if ($server -and $key) {
                        if (New-PaqetConfig -Server $server -SecretKey $key -TcpLocalFlag $tcpLocal -TcpRemoteFlag $tcpRemote) {
                            Write-Host ""
                            Write-Host "  Your SOCKS5 proxy: 127.0.0.1:1080" -ForegroundColor Green
                        }
                    }
                } else {
                    Write-Host ""
                    Write-Host "  GFK CONFIGURATION" -ForegroundColor Yellow
                    Write-Host "  Get these values from your server admin or 'paqctl info' on server"
                    Write-Host ""
                    $server = Read-Host "  Server IP (e.g., 1.2.3.4)"
                    $auth = Read-Host "  Auth code (from server setup)"

                    # Advanced options (hidden by default - just press Enter)
                    Write-Host ""
                    Write-Host "  Advanced options (press Enter for defaults - recommended):" -ForegroundColor DarkGray
                    Write-Host "    TCP flags must match your server config. Only change if server admin says so." -ForegroundColor DarkGray
                    Write-Host "    Valid flags: S A P R F U E C" -ForegroundColor DarkGray
                    $tcpFlags = Read-Host "  TCP flags [AP]"
                    if (-not $tcpFlags) { $tcpFlags = "AP" }

                    if ($server -and $auth) {
                        if (New-GfkConfig -ServerIP $server -AuthCode $auth -SocksPort "14000" -TcpFlags $tcpFlags) {
                            Write-Host ""
                            Write-Host "  Your SOCKS5 proxy: 127.0.0.1:14000" -ForegroundColor Green
                        }
                    }
                }
            }
            "4" {
                if (-not $backend) {
                    Write-Warn "Install a backend first"
                    continue
                }
                if ($backend -eq "paqet") {
                    Start-Paqet
                } else {
                    Start-Gfk
                }
            }
            "5" { Stop-Client }
            "6" { Get-ClientStatus }
            "7" { Update-Paqet }
            "8" { Show-About }
            "0" { return }
            default { Write-Warn "Invalid option" }
        }
    }
}

function Show-About {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  HOW IT WORKS" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  This tool helps bypass firewall restrictions"
    Write-Host "  by disguising your traffic. You have TWO options:"
    Write-Host ""
    Write-Host "  --- PAQET - Simple and Fast ---" -ForegroundColor Green
    Write-Host "  How: Uses KCP protocol over raw sockets"
    Write-Host "  Proxy: 127.0.0.1:1080 (SOCKS5)"
    Write-Host "  Best for: Most situations, easy setup"
    Write-Host ""
    Write-Host "  --- GFW-KNOCKER - Advanced Anti-DPI ---" -ForegroundColor Yellow
    Write-Host "  How: Violated TCP packets + QUIC tunnel"
    Write-Host "  Proxy: 127.0.0.1:14000 (SOCKS5 via Xray)"
    Write-Host "  Best for: When paqet is blocked, heavy censorship"
    Write-Host ""
    Write-Host "  --- CAN I RUN BOTH? ---" -ForegroundColor Magenta
    Write-Host "  YES! They use different ports:"
    Write-Host "    - Paqet: 127.0.0.1:1080"
    Write-Host "    - GFK:   127.0.0.1:14000"
    Write-Host "  Install both as backup - if one gets blocked, use the other!"
    Write-Host ""
    Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray
    Read-Host | Out-Null
}

#═══════════════════════════════════════════════════════════════════════
# Main Entry Point
#═══════════════════════════════════════════════════════════════════════

if (-not (Test-Admin)) {
    Write-Err "Administrator privileges required"
    Write-Info "Right-click PowerShell -> Run as Administrator"
    exit 1
}

# Auto-detect backend if not specified
if (-not $Backend) {
    $Backend = Get-InstalledBackend
}

switch ($Action.ToLower()) {
    "install" {
        if ($Backend -eq "gfk") {
            Install-Gfk
        } else {
            Install-Paqet
        }
    }
    "config" {
        if ($Backend -eq "gfk") {
            if (-not $ServerAddr -or -not $Key) {
                Write-Err "Usage: -Action config -ServerAddr [ip] -Key [authcode]"
                exit 1
            }
            New-GfkConfig -ServerIP $ServerAddr -AuthCode $Key
        } else {
            if (-not $ServerAddr -or -not $Key) {
                Write-Err "Usage: -Action config -ServerAddr [ip:port] -Key [key]"
                exit 1
            }
            New-PaqetConfig -Server $ServerAddr -SecretKey $Key
        }
    }
    "run" {
        if ($ServerAddr -and $Key) {
            if ($Backend -eq "gfk") {
                Install-Gfk
                New-GfkConfig -ServerIP $ServerAddr -AuthCode $Key
                Start-Gfk
            } else {
                Install-Paqet
                New-PaqetConfig -Server $ServerAddr -SecretKey $Key
                Start-Paqet
            }
        } else {
            if ($Backend -eq "gfk") {
                Start-Gfk
            } else {
                Start-Paqet
            }
        }
    }
    "start" {
        if ($Backend -eq "gfk") { Start-Gfk } else { Start-Paqet }
    }
    "stop" { Stop-Client }
    "status" { Get-ClientStatus }
    "menu" { Show-Menu -InitBackend $Backend }
    default { Show-Menu -InitBackend $Backend }
}
