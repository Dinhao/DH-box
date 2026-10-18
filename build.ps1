# ============================================================
# DH-BOX（SecretVault）一键编译脚本 —— WebView2 架构
#   界面：前端网页 web\cipherbox-ui.html（由 WebView2 渲染，不用 WinForms 画界面）
#   后端：C# 加密逻辑（AES-256-CBC + HMAC-SHA256、PBKDF2-HMAC-SHA256 20 万次）
#   桥接：Microsoft.Web.WebView2（CoreWebView2 WebMessage / postMessage）
# 编译器：便携版 Roslyn（%LOCALAPPDATA%\RoslynToolset，免安装、免管理员）
# 产物：bin\SecretVault.exe + WebView2 运行库 + web\cipherbox-ui.html
# 用法：powershell -ExecutionPolicy Bypass -File build.ps1
# ============================================================
$ErrorActionPreference = "Stop"

$root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcDir = Join-Path $root "src"
$outDir = Join-Path $root "bin"
$wv2    = Join-Path $root "tools\webview2"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# 定位便携版 Roslyn 编译器
$csc = Join-Path $env:LOCALAPPDATA "RoslynToolset\tasks\net472\csc.exe"
if (-not (Test-Path $csc))
{
    throw @"
未找到便携版 Roslyn 编译器。一键安装（约 21MB，免管理员，删除 RoslynToolset 目录即卸载）：

Invoke-WebRequest "https://api.nuget.org/v3-flatcontainer/microsoft.net.compilers.toolset/4.8.0/microsoft.net.compilers.toolset.4.8.0.nupkg" -OutFile "$env:TEMP\roslyn.zip"
Expand-Archive "$env:TEMP\roslyn.zip" -DestinationPath "$env:LOCALAPPDATA\RoslynToolset" -Force
Remove-Item "$env:TEMP\roslyn.zip"
"@
}
Write-Host ("编译器：便携版 Roslyn {0}" -f ((& $csc /version | Select-Object -First 1)))

# 定位 WebView2 SDK（Microsoft.Web.WebView2，随仓库放在 tools\webview2）
$wvCore = Join-Path $wv2 "lib\net462\Microsoft.Web.WebView2.Core.dll"
$wvWin  = Join-Path $wv2 "lib\net462\Microsoft.Web.WebView2.WinForms.dll"
$wvLoad = Join-Path $wv2 "runtimes\win-x64\native\WebView2Loader.dll"
if (-not (Test-Path $wvCore) -or -not (Test-Path $wvWin))
{
    throw @"
未找到 WebView2 SDK。一键下载（约 9MB）：

`$tools = "$wv2"
Invoke-WebRequest "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/1.0.4258.31/microsoft.web.webview2.1.0.4258.31.nupkg" -OutFile "`$env:TEMP\wv2.nupkg"
Expand-Archive "`$env:TEMP\wv2.nupkg" -DestinationPath `$tools -Force
Remove-Item "`$env:TEMP\wv2.nupkg"
"@
}
Write-Host ("WebView2 SDK：{0}" -f (Split-Path -Leaf $wv2))

$srcs = Get-ChildItem -Path $srcDir -Filter *.cs | ForEach-Object { $_.FullName }
$refs = @(
    "System.dll",
    "System.Core.dll",
    "System.Drawing.dll",
    "System.Windows.Forms.dll",
    "Microsoft.CSharp.dll",          # 供 Shell.Application COM 动态调用
    "System.Web.Extensions.dll",     # 供 JavaScriptSerializer 读写 JSON 配置与状态
    "System.ValueTuple.dll",         # 供 C# 元组
    $wvCore,                          # Microsoft.Web.WebView2.Core.dll（显式引用 SDK 的 DLL）
    $wvWin                            # Microsoft.Web.WebView2.WinForms.dll
)
$refArgs = $refs | ForEach-Object { "/r:$_" }

Write-Host "编译 SecretVault.exe ..."
& $csc /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001 /utf8output /nullable:enable `
       "/win32icon:$(Join-Path $root 'tools\dhbox.ico')" `
       "/resource:$(Join-Path $root 'web\cipherbox-ui.html'),DHBOX_UI_HTML" `
       "/out:$(Join-Path $outDir 'SecretVault.exe')" $refArgs $srcs
if ($LASTEXITCODE -ne 0) { throw "编译失败（退出码 $LASTEXITCODE）" }

# 收集运行所需文件（WebView2 托管 DLL、原生 Loader、前端网页）
Copy-Item $wvCore $outDir -Force
Copy-Item $wvWin  $outDir -Force
if (Test-Path $wvLoad) { Copy-Item $wvLoad $outDir -Force }   # 64 位 WebView2Loader.dll
New-Item -ItemType Directory -Force -Path (Join-Path $outDir "web") | Out-Null
Copy-Item (Join-Path $root "web\cipherbox-ui.html") (Join-Path $outDir "web") -Force

$exe = Join-Path $outDir "SecretVault.exe"
Write-Host ""
Write-Host "编译成功：$exe"
Write-Host ("大小：{0:N0} KB" -f ((Get-Item $exe).Length / 1KB))
Write-Host ""
Write-Host "运行目录内容（这些文件必须放在一起）："
Get-ChildItem $outDir -File | ForEach-Object { Write-Host ("  " + $_.Name) }
Write-Host "  web\cipherbox-ui.html"
Write-Host ""
Write-Host "使用："
Write-Host "  1) 双击 SecretVault.exe（可重命名为 DH-BOX.exe）；"
Write-Host "  2) 界面完全由 web\cipherbox-ui.html 渲染，数据由 C# 后端 AES-256 加密存入"
Write-Host "     程序旁 DH-BOX.vault；首次运行请在网页的「首次使用」弹窗设置主密码。"
