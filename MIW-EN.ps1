# Automated Installation and Service Startup Script for Monerod
# For Windows 10 and Later Versions

# Set execution policy to allow script running
Set-ExecutionPolicy Bypass -Scope Process -Force

# Check if running with administrator privileges
function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $user
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "This script requires administrator privileges. Please right-click PowerShell and select 'Run as Administrator'." -ForegroundColor Red
    exit
}

# Display welcome message
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  Monero Node Automated Installation Script (Windows 10+) by PyXMR" -ForegroundColor Cyan
Write-Host "  Donate Monero:857Z6i8PrSq7kUJRHdYsRRAmTkt9EG6Gz9SXghbG3eGd3bGaJDk1biYZ5DzK1Wb6zKb4oJeonutzG7J1QMn2MKqWVUwxcVn" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# User customization options
$defaultInstallDir = "C:\Monero"
$installDir = Read-Host "Enter installation directory [$defaultInstallDir]"
if ([string]::IsNullOrEmpty($installDir)) {
    $installDir = $defaultInstallDir
}

# Ensure path doesn't end with backslash
if ($installDir.EndsWith("\\")) {
    $installDir = $installDir.Substring(0, $installDir.Length - 1)
}

$defaultRpcPort = 18081
$rpcPort = Read-Host "Enter RPC port [$defaultRpcPort]"
if ([string]::IsNullOrEmpty($rpcPort)) {
    $rpcPort = $defaultRpcPort
}

# Validate port number
while (-not ([int]::TryParse($rpcPort, [ref]0) -and $rpcPort -ge 1 -and $rpcPort -le 65535)) {
    Write-Host "Invalid port number. Please enter a number between 1 and 65535." -ForegroundColor Red
    $rpcPort = Read-Host "Enter RPC port [$defaultRpcPort]"
    if ([string]::IsNullOrEmpty($rpcPort)) {
        $rpcPort = $defaultRpcPort
    }
}

$defaultZmqPort = 18083
$zmqPort = Read-Host "Enter ZMQ port [$defaultZmqPort]"
if ([string]::IsNullOrEmpty($zmqPort)) {
    $zmqPort = $defaultZmqPort
}

# Validate ZMQ port number
while (-not ([int]::TryParse($zmqPort, [ref]0) -and $zmqPort -ge 1 -and $zmqPort -le 65535 -and $zmqPort -ne $rpcPort)) {
    Write-Host "Invalid ZMQ port number. Please enter a number between 1 and 65535 different from the RPC port." -ForegroundColor Red
    $zmqPort = Read-Host "Enter ZMQ port [$defaultZmqPort]"
    if ([string]::IsNullOrEmpty($zmqPort)) {
        $zmqPort = $defaultZmqPort
    }
}

$defaultDataDir = "$installDir\data"
$dataDir = Read-Host "Enter blockchain data storage location [$defaultDataDir]"
if ([string]::IsNullOrEmpty($dataDir)) {
    $dataDir = $defaultDataDir
}

# Generate random password
function Generate-RandomPassword {
    param (
        [int]$Length = 16
    )
    $characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    $password = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $password += $characters[$(Get-Random -Minimum 0 -Maximum $characters.Length)]
    }
    return $password
}

$defaultRpcUser = "monero"
$rpcUser = Read-Host "Enter RPC username [$defaultRpcUser]"
if ([string]::IsNullOrEmpty($rpcUser)) {
    $rpcUser = $defaultRpcUser
}

$generateRandomPassword = Read-Host "Generate random RPC password? (Y/N) [Y]"
if ([string]::IsNullOrEmpty($generateRandomPassword) -or $generateRandomPassword.ToUpper() -eq "Y") {
    $rpcPassword = Generate-RandomPassword -Length 20
    Write-Host "Random RPC password generated: $rpcPassword" -ForegroundColor Yellow
    Write-Host "Please save this password securely!" -ForegroundColor Yellow
} else {
    $rpcPassword = Read-Host "Enter RPC password (at least 8 characters)" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($rpcPassword)
    $rpcPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    
    # Validate password length
    while ($rpcPassword.Length -lt 8) {
        Write-Host "Password must be at least 8 characters long." -ForegroundColor Red
        $rpcPassword = Read-Host "Enter RPC password (at least 8 characters)" -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($rpcPassword)
        $rpcPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

$enablePruning = Read-Host "Enable blockchain pruning? (reduces disk space usage) (Y/N) [N]"
$pruningEnabled = $enablePruning.ToUpper() -eq "Y"

$enableP2p = Read-Host "Allow P2P connections? (Y/N) [Y]"
$p2pEnabled = ![string]::IsNullOrEmpty($enableP2p) -and $enableP2p.ToUpper() -ne "N"

$p2pBindIp = "0.0.0.0"
if ($p2pEnabled) {
    $defaultP2pPort = 18080
    $p2pPort = Read-Host "Enter P2P port [$defaultP2pPort]"
    if ([string]::IsNullOrEmpty($p2pPort)) {
        $p2pPort = $defaultP2pPort
    }
    
    # Validate P2P port number
    while (-not ([int]::TryParse($p2pPort, [ref]0) -and $p2pPort -ge 1 -and $p2pPort -le 65535 -and $p2pPort -ne $rpcPort -and $p2pPort -ne $zmqPort)) {
        Write-Host "Invalid P2P port number. Please enter a number between 1 and 65535 different from RPC and ZMQ ports." -ForegroundColor Red
        $p2pPort = Read-Host "Enter P2P port [$defaultP2pPort]"
        if ([string]::IsNullOrEmpty($p2pPort)) {
            $p2pPort = $defaultP2pPort
        }
    }
}

# Display configuration summary
Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "Configuration Summary:" -ForegroundColor Cyan
Write-Host "Installation Directory: $installDir" -ForegroundColor White
Write-Host "Data Storage Location: $dataDir" -ForegroundColor White
Write-Host "RPC Port: $rpcPort" -ForegroundColor White
Write-Host "ZMQ Port: $zmqPort" -ForegroundColor White
Write-Host "RPC Username: $rpcUser" -ForegroundColor White
Write-Host "Blockchain Pruning: $(if ($pruningEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
Write-Host "P2P Connections: $(if ($p2pEnabled) { "Enabled ($p2pBindIp`:$p2pPort)" } else { 'Disabled' })" -ForegroundColor White
Write-Host "=========================================" -ForegroundColor Cyan

$confirm = Read-Host "Confirm installation? (Y/N) [Y]"
if ([string]::IsNullOrEmpty($confirm) -or $confirm.ToUpper() -ne "Y") {
    Write-Host "Installation cancelled." -ForegroundColor Yellow
    exit
}

# Configuration variables
$downloadUrl = "https://downloads.getmonero.org/cli/win64"  # Official download URL
$tempDir = "$env:TEMP\MoneroInstall"
$zipFile = "$tempDir\monero-win-x64.zip"
$checksumUrl = "https://www.getmonero.org/downloads/hashes.txt"
$checksumFile = "$tempDir\hashes.txt"

# Create temporary directory
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Download Monero CLI
Write-Host "Downloading Monero CLI..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile -UseBasicParsing
    Write-Host "Download complete." -ForegroundColor Green
} catch {
    Write-Host "Download failed: $_" -ForegroundColor Red
    exit
}

# Download checksum file
Write-Host "Downloading checksum file..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $checksumUrl -OutFile $checksumFile -UseBasicParsing
    Write-Host "Checksum file downloaded." -ForegroundColor Green
} catch {
    Write-Host "Warning: Failed to download checksum file. Skipping integrity check." -ForegroundColor Yellow
}

# Verify file integrity
if (Test-Path $checksumFile) {
    Write-Host "Verifying file integrity..." -ForegroundColor Cyan
    $expectedHash = Get-Content $checksumFile | Select-String -Pattern "monero-win-x64\.zip" | ForEach-Object { $_.ToString().Split(' ')[0] }
    
    if ($expectedHash) {
        $actualHash = (Get-FileHash -Path $zipFile -Algorithm SHA256).Hash
        if ($actualHash -eq $expectedHash) {
            Write-Host "File integrity verified." -ForegroundColor Green
        } else {
            Write-Host "File integrity check failed! Downloaded file may be corrupted." -ForegroundColor Red
            exit
        }
    } else {
        Write-Host "Warning: Expected hash not found in checksum file. Skipping integrity check." -ForegroundColor Yellow
    }
}

# Create installation directory
Write-Host "Creating installation directory..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

# Extract files
Write-Host "Extracting files..." -ForegroundColor Cyan
try {
    Expand-Archive -Path $zipFile -DestinationPath $installDir -Force
    Write-Host "Extraction complete." -ForegroundColor Green
} catch {
    Write-Host "Extraction failed: $_" -ForegroundColor Red
    exit
}

# Get extracted directory name (usually contains version number)
$extractedDir = Get-ChildItem -Path $installDir -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# Move files to root installation directory
if ($extractedDir) {
    Write-Host "Organizing files..." -ForegroundColor Cyan
    Get-ChildItem -Path $extractedDir.FullName -Recurse | Move-Item -Destination $installDir -Force
    Remove-Item -Path $extractedDir.FullName -Recurse -Force
    Write-Host "Files organized." -ForegroundColor Green
}

# Create service configuration file
$configFile = "$installDir\monerod.conf"
Write-Host "Creating configuration file..." -ForegroundColor Cyan

$configContent = @"
# Monerod configuration file
data-dir=$dataDir
rpc-bind-ip=0.0.0.0
rpc-bind-port=$rpcPort
confirm-external-bind=1
rpc-login=$rpcUser`:$rpcPassword
restricted-rpc=1
zmq-rpc-bind-port=$zmqPort
"@

if ($pruningEnabled) {
    $configContent += "`nprune-blockchain=1"
}

if ($p2pEnabled) {
    $configContent += @"
p2p-bind-ip=$p2pBindIp
p2p-bind-port=$p2pPort
"@
} else {
    $configContent += "`nno-igd=1"
    $configContent += "`nno-p2p=1"
}

$configContent | Out-File -FilePath $configFile -Encoding ASCII
Write-Host "Configuration file created." -ForegroundColor Green

# Create startup script
$startScript = "$installDir\start-monerod.ps1"
@"
# Start Monerod service
`$monerodPath = "$installDir\monerod.exe"
`$configPath = "$installDir\monerod.conf"

# Check if service is running
`$service = Get-Service -Name "MonerodService" -ErrorAction SilentlyContinue
if (`$service -and `$service.Status -eq "Running") {
    Write-Host "Monerod service is already running..." -ForegroundColor Yellow
} else {
    Write-Host "Starting Monerod service..." -ForegroundColor Cyan
    Start-Service -Name "MonerodService"
}

# Display service status
Get-Service -Name "MonerodService" | Format-Table
"@ | Out-File -FilePath $startScript -Encoding ASCII

# Create Windows service
Write-Host "Creating Monerod Windows service..." -ForegroundColor Cyan
try {
    $serviceName = "MonerodService"
    $serviceDescription = "Monero daemon service for blockchain synchronization and RPC interface"
    $servicePath = """$installDir\monerod.exe"" --config-file ""$configFile"" --detach"
    
    # Check if service exists
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Host "Service exists, stopping and recreating..." -ForegroundColor Yellow
        Stop-Service -Name $serviceName -Force
        sc.exe delete $serviceName
    }
    
    # Create new service
    New-Service -Name $serviceName -BinaryPathName $servicePath -Description $serviceDescription -DisplayName "Monerod Service" -StartupType Automatic -ErrorAction Stop
    Write-Host "Service created successfully." -ForegroundColor Green
    
    # Start service
    Write-Host "Starting Monerod service..." -ForegroundColor Cyan
    Start-Service -Name $serviceName
    
    # Verify service status
    Start-Sleep -Seconds 5  # Wait for service to start
    $serviceStatus = Get-Service -Name $serviceName
    if ($serviceStatus.Status -eq "Running") {
        Write-Host "Monerod service started successfully." -ForegroundColor Green
    } else {
        Write-Host "Warning: Monerod service did not start successfully. Status: $($serviceStatus.Status)" -ForegroundColor Yellow
        Write-Host "Check service configuration and logs for more information." -ForegroundColor Yellow
    }
    
    # Add to system PATH
    Write-Host "Adding Monero directory to system PATH environment variable..." -ForegroundColor Cyan
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if (-not $currentPath.Contains($installDir)) {
        [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$installDir", "Machine")
        Write-Host "Monero directory added to PATH. Changes will take effect after next login." -ForegroundColor Green
    } else {
        Write-Host "Monero directory already in PATH." -ForegroundColor Green
    }
    
    # Create desktop shortcut
    Write-Host "Creating desktop shortcut..." -ForegroundColor Cyan
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Monerod Service.lnk")
    $Shortcut.TargetPath = "powershell.exe"
    $Shortcut.Arguments = "-File `"$startScript`""
    $Shortcut.Description = "Start Monerod Service"
    $Shortcut.Save()
    Write-Host "Desktop shortcut created." -ForegroundColor Green
    
    # Clean up temporary files
    Write-Host "Cleaning up temporary files..." -ForegroundColor Cyan
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Temporary files cleaned." -ForegroundColor Green
    
    # Display completion message
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Monero node installation and configuration complete!" -ForegroundColor Green
    Write-Host "`nInstallation Directory: $installDir" -ForegroundColor Cyan
    Write-Host "Data Storage Location: $dataDir" -ForegroundColor Cyan
    Write-Host "Configuration File: $configFile" -ForegroundColor Cyan
    Write-Host "Service Name: MonerodService" -ForegroundColor Cyan
    Write-Host "RPC Address: http://localhost:$rpcPort/json_rpc" -ForegroundColor Cyan
    Write-Host "`nKeep your RPC credentials secure:" -ForegroundColor Yellow
    Write-Host "Username: $rpcUser" -ForegroundColor White
    Write-Host "Password: $rpcPassword" -ForegroundColor White
    Write-Host "=========================================" -ForegroundColor Cyan
    
} catch {
    Write-Host "Service creation failed: $_" -ForegroundColor Red
    Write-Host "Please create the service manually or check error logs." -ForegroundColor Yellow
}
