# 自动安装Monerod并启动服务的PowerShell脚本
# 适用于Windows 10及以上版本

# 设置执行策略以允许脚本运行
Set-ExecutionPolicy Bypass -Scope Process -Force

# 检查是否以管理员权限运行
function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $user
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "此脚本需要管理员权限运行。请右键点击PowerShell并选择'以管理员身份运行'。" -ForegroundColor Red
    exit
}

# 显示欢迎信息
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  Monero节点自动安装脚本 (Windows 10+) 来自 PyXMR" -ForegroundColor Cyan
Write-Host "  捐助我Monero:857Z6i8PrSq7kUJRHdYsRRAmTkt9EG6Gz9SXghbG3eGd3bGaJDk1biYZ5DzK1Wb6zKb4oJeonutzG7J1QMn2MKqWVUwxcVn" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 用户自定义选项
$defaultInstallDir = "C:\Monero"
$installDir = Read-Host "请输入安装目录 [$defaultInstallDir]"
if ([string]::IsNullOrEmpty($installDir)) {
    $installDir = $defaultInstallDir
}

# 确保路径不以反斜杠结尾
if ($installDir.EndsWith("\")) {
    $installDir = $installDir.Substring(0, $installDir.Length - 1)
}

$defaultRpcPort = 18081
$rpcPort = Read-Host "请输入RPC端口 [$defaultRpcPort]"
if ([string]::IsNullOrEmpty($rpcPort)) {
    $rpcPort = $defaultRpcPort
}

# 验证端口是否有效
while (-not ([int]::TryParse($rpcPort, [ref]0) -and $rpcPort -ge 1 -and $rpcPort -le 65535)) {
    Write-Host "无效的端口号，请输入1-65535之间的数字。" -ForegroundColor Red
    $rpcPort = Read-Host "请输入RPC端口 [$defaultRpcPort]"
    if ([string]::IsNullOrEmpty($rpcPort)) {
        $rpcPort = $defaultRpcPort
    }
}

$defaultZmqPort = 18083
$zmqPort = Read-Host "请输入ZMQ端口 [$defaultZmqPort]"
if ([string]::IsNullOrEmpty($zmqPort)) {
    $zmqPort = $defaultZmqPort
}

# 验证ZMQ端口是否有效
while (-not ([int]::TryParse($zmqPort, [ref]0) -and $zmqPort -ge 1 -and $zmqPort -le 65535 -and $zmqPort -ne $rpcPort)) {
    Write-Host "无效的ZMQ端口号，请输入1-65535之间且不同于RPC端口的数字。" -ForegroundColor Red
    $zmqPort = Read-Host "请输入ZMQ端口 [$defaultZmqPort]"
    if ([string]::IsNullOrEmpty($zmqPort)) {
        $zmqPort = $defaultZmqPort
    }
}

$defaultDataDir = "$installDir\data"
$dataDir = Read-Host "请输入区块链数据存储位置 [$defaultDataDir]"
if ([string]::IsNullOrEmpty($dataDir)) {
    $dataDir = $defaultDataDir
}

# 生成随机密码
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
$rpcUser = Read-Host "请输入RPC用户名 [$defaultRpcUser]"
if ([string]::IsNullOrEmpty($rpcUser)) {
    $rpcUser = $defaultRpcUser
}

$generateRandomPassword = Read-Host "是否生成随机RPC密码? (Y/N) [Y]"
if ([string]::IsNullOrEmpty($generateRandomPassword) -or $generateRandomPassword.ToUpper() -eq "Y") {
    $rpcPassword = Generate-RandomPassword -Length 20
    Write-Host "已生成随机RPC密码: $rpcPassword" -ForegroundColor Yellow
    Write-Host "请妥善保存此密码!" -ForegroundColor Yellow
} else {
    $rpcPassword = Read-Host "请输入RPC密码 (至少8个字符)" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($rpcPassword)
    $rpcPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    
    # 验证密码长度
    while ($rpcPassword.Length -lt 8) {
        Write-Host "密码长度必须至少8个字符。" -ForegroundColor Red
        $rpcPassword = Read-Host "请输入RPC密码 (至少8个字符)" -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($rpcPassword)
        $rpcPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

$enablePruning = Read-Host "是否启用区块链裁剪? (减少磁盘空间使用) (Y/N) [N]"
$pruningEnabled = $enablePruning.ToUpper() -eq "Y"

$enableP2p = Read-Host "是否允许P2P连接? (Y/N) [Y]"
$p2pEnabled = ![string]::IsNullOrEmpty($enableP2p) -and $enableP2p.ToUpper() -ne "N"

$p2pBindIp = "0.0.0.0"
if ($p2pEnabled) {
    $defaultP2pPort = 18080
    $p2pPort = Read-Host "请输入P2P端口 [$defaultP2pPort]"
    if ([string]::IsNullOrEmpty($p2pPort)) {
        $p2pPort = $defaultP2pPort
    }
    
    # 验证P2P端口是否有效
    while (-not ([int]::TryParse($p2pPort, [ref]0) -and $p2pPort -ge 1 -and $p2pPort -le 65535 -and $p2pPort -ne $rpcPort -and $p2pPort -ne $zmqPort)) {
        Write-Host "无效的P2P端口号，请输入1-65535之间且不同于RPC和ZMQ端口的数字。" -ForegroundColor Red
        $p2pPort = Read-Host "请输入P2P端口 [$defaultP2pPort]"
        if ([string]::IsNullOrEmpty($p2pPort)) {
            $p2pPort = $defaultP2pPort
        }
    }
}

# 显示配置摘要
Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host "配置摘要:" -ForegroundColor Cyan
Write-Host "安装目录: $installDir" -ForegroundColor White
Write-Host "数据存储位置: $dataDir" -ForegroundColor White
Write-Host "RPC端口: $rpcPort" -ForegroundColor White
Write-Host "ZMQ端口: $zmqPort" -ForegroundColor White
Write-Host "RPC用户名: $rpcUser" -ForegroundColor White
Write-Host "区块链裁剪: $(if ($pruningEnabled) { '启用' } else { '禁用' })" -ForegroundColor White
Write-Host "P2P连接: $(if ($p2pEnabled) { "启用 ($p2pBindIp`:$p2pPort)" } else { '禁用' })" -ForegroundColor White
Write-Host "=========================================" -ForegroundColor Cyan

$confirm = Read-Host "确认继续安装? (Y/N) [Y]"
if ([string]::IsNullOrEmpty($confirm) -or $confirm.ToUpper() -ne "Y") {
    Write-Host "安装已取消。" -ForegroundColor Yellow
    exit
}

# 配置变量
$downloadUrl = "https://downloads.getmonero.org/cli/win64"  # 官方下载地址
$tempDir = "$env:TEMP\MoneroInstall"
$zipFile = "$tempDir\monero-win-x64.zip"
$checksumUrl = "https://www.getmonero.org/downloads/hashes.txt"
$checksumFile = "$tempDir\hashes.txt"

# 创建临时目录
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# 下载Monero CLI
Write-Host "正在下载Monero CLI..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile -UseBasicParsing
    Write-Host "下载完成。" -ForegroundColor Green
} catch {
    Write-Host "下载失败: $_" -ForegroundColor Red
    exit
}

# 下载校验和文件
Write-Host "正在下载校验和文件..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $checksumUrl -OutFile $checksumFile -UseBasicParsing
    Write-Host "校验和文件下载完成。" -ForegroundColor Green
} catch {
    Write-Host "警告: 无法下载校验和文件。跳过完整性检查。" -ForegroundColor Yellow
}

# 验证下载文件的完整性
if (Test-Path $checksumFile) {
    Write-Host "正在验证下载文件的完整性..." -ForegroundColor Cyan
    $expectedHash = Get-Content $checksumFile | Select-String -Pattern "monero-win-x64\.zip" | ForEach-Object { $_.ToString().Split(' ')[0] }
    
    if ($expectedHash) {
        $actualHash = (Get-FileHash -Path $zipFile -Algorithm SHA256).Hash
        if ($actualHash -eq $expectedHash) {
            Write-Host "文件完整性验证通过。" -ForegroundColor Green
        } else {
            Write-Host "文件完整性验证失败! 下载的文件可能已损坏。" -ForegroundColor Red
            exit
        }
    } else {
        Write-Host "警告: 无法从校验和文件中获取预期哈希值。跳过完整性检查。" -ForegroundColor Yellow
    }
}

# 创建安装目录
Write-Host "正在创建安装目录..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

# 解压文件
Write-Host "正在解压文件..." -ForegroundColor Cyan
try {
    Expand-Archive -Path $zipFile -DestinationPath $installDir -Force
    Write-Host "解压完成。" -ForegroundColor Green
} catch {
    Write-Host "解压失败: $_" -ForegroundColor Red
    exit
}

# 获取实际解压目录名（通常包含版本号）
$extractedDir = Get-ChildItem -Path $installDir -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# 移动文件到安装目录根
if ($extractedDir) {
    Write-Host "正在整理文件..." -ForegroundColor Cyan
    Get-ChildItem -Path $extractedDir.FullName -Recurse | Move-Item -Destination $installDir -Force
    Remove-Item -Path $extractedDir.FullName -Recurse -Force
    Write-Host "文件整理完成。" -ForegroundColor Green
}

# 创建服务配置文件
$configFile = "$installDir\monerod.conf"
Write-Host "正在创建配置文件..." -ForegroundColor Cyan

$configContent = @"
# Monerod配置文件
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
Write-Host "配置文件创建完成。" -ForegroundColor Green

# 创建启动脚本
$startScript = "$installDir\start-monerod.ps1"
@"
# 启动Monerod服务
`$monerodPath = "$installDir\monerod.exe"
`$configPath = "$installDir\monerod.conf"

# 检查服务是否已运行
`$service = Get-Service -Name "MonerodService" -ErrorAction SilentlyContinue
if (`$service -and `$service.Status -eq "Running") {
    Write-Host "Monerod服务已在运行中..." -ForegroundColor Yellow
} else {
    Write-Host "正在启动Monerod服务..." -ForegroundColor Cyan
    Start-Service -Name "MonerodService"
}

# 显示服务状态
Get-Service -Name "MonerodService" | Format-Table
"@ | Out-File -FilePath $startScript -Encoding ASCII

# 创建服务
Write-Host "正在创建Monerod Windows服务..." -ForegroundColor Cyan
try {
    $serviceName = "MonerodService"
    $serviceDescription = "Monero daemon service for blockchain synchronization and RPC interface"
    $servicePath = """$installDir\monerod.exe"" --config-file ""$configFile"" --detach"
    
    # 检查服务是否已存在
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Host "服务已存在，正在停止并重新创建..." -ForegroundColor Yellow
        Stop-Service -Name $serviceName -Force
        sc.exe delete $serviceName
    }
    
    # 创建新服务
    New-Service -Name $serviceName -BinaryPathName $servicePath -Description $serviceDescription -DisplayName "Monerod Service" -StartupType Automatic -ErrorAction Stop
    Write-Host "服务创建成功。" -ForegroundColor Green
    
    # 启动服务
    Write-Host "正在启动Monerod服务..." -ForegroundColor Cyan
    Start-Service -Name $serviceName
    
    # 验证服务状态
    Start-Sleep -Seconds 5  # 等待服务启动
    $serviceStatus = Get-Service -Name $serviceName
    if ($serviceStatus.Status -eq "Running") {
        Write-Host "Monerod服务已成功启动并运行。" -ForegroundColor Green
    } else {
        Write-Host "警告: Monerod服务未成功启动。状态: $($serviceStatus.Status)" -ForegroundColor Yellow
        Write-Host "请检查服务配置和日志以获取更多信息。" -ForegroundColor Yellow
    }
    
    # 添加到PATH环境变量
    Write-Host "正在将Monero目录添加到系统PATH环境变量..." -ForegroundColor Cyan
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if (-not $currentPath.Contains($installDir)) {
        [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$installDir", "Machine")
        Write-Host "已将Monero目录添加到PATH环境变量。" -ForegroundColor Green
        Write-Host "注意: 新的PATH设置将在下次登录后生效。" -ForegroundColor Yellow
    } else {
        Write-Host "Monero目录已在PATH环境变量中。" -ForegroundColor Green
    }
    
    # 创建桌面快捷方式
    Write-Host "正在创建桌面快捷方式..." -ForegroundColor Cyan
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Monerod Service.lnk")
    $Shortcut.TargetPath = "powershell.exe"
    $Shortcut.Arguments = "-File `"$startScript`""
    $Shortcut.Description = "启动Monerod服务"
    $Shortcut.Save()
    Write-Host "桌面快捷方式已创建。" -ForegroundColor Green
    
    # 清理临时文件
    Write-Host "正在清理临时文件..." -ForegroundColor Cyan
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "临时文件已清理。" -ForegroundColor Green
    
    # 显示完成信息
    Write-Host "`n=========================================" -ForegroundColor Cyan
    Write-Host "Monero节点安装和配置已完成!" -ForegroundColor Green
    Write-Host "`n安装目录: $installDir" -ForegroundColor Cyan
    Write-Host "数据存储位置: $dataDir" -ForegroundColor Cyan
    Write-Host "配置文件: $configFile" -ForegroundColor Cyan
    Write-Host "服务名称: MonerodService" -ForegroundColor Cyan
    Write-Host "RPC访问地址: http://localhost:$rpcPort/json_rpc" -ForegroundColor Cyan
    Write-Host "`n请妥善保存你的RPC登录凭证:" -ForegroundColor Yellow
    Write-Host "用户名: $rpcUser" -ForegroundColor White
    Write-Host "密码: $rpcPassword" -ForegroundColor White
    Write-Host "=========================================" -ForegroundColor Cyan
    
} catch {
    Write-Host "服务创建失败: $_" -ForegroundColor Red
    Write-Host "请手动创建服务或检查错误信息。" -ForegroundColor Yellow
}    
