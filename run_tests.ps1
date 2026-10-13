# ============================================================
# SecretVault 核心逻辑测试脚本
# 编译 tests\TestVault.cs（+ 核心源码）为控制台程序并运行。
# 编译器：便携版 Roslyn（与 build.ps1 相同）。
# 用法：powershell -ExecutionPolicy Bypass -File run_tests.ps1
# ============================================================
$ErrorActionPreference = "Stop"

$root    = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcDir  = Join-Path $root "src"
$outDir  = Join-Path $root "tests\bin"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$csc = Join-Path $env:LOCALAPPDATA "RoslynToolset\tasks\net472\csc.exe"
if (-not (Test-Path $csc)) { throw "未找到便携版 Roslyn 编译器（请先运行 build.ps1 查看安装指引）。" }

# 只编译不依赖 UI 的核心模块 + 测试入口
$srcs = @(
    (Join-Path $srcDir "AppPaths.cs"),
    (Join-Path $srcDir "CryptoUtil.cs"),
    (Join-Path $srcDir "VaultContainer.cs"),
    (Join-Path $srcDir "VaultFile.cs"),
    (Join-Path $srcDir "AppConfig.cs"),
    (Join-Path $srcDir "LockoutPolicy.cs"),
    (Join-Path $srcDir "Logger.cs"),
    (Join-Path $root  "tests\TestVault.cs")
)

Write-Host "编译并运行核心逻辑测试 ..."
& $csc /nologo /target:exe /platform:anycpu /optimize+ /codepage:65001 /nullable:enable `
       /r:System.dll /r:System.Core.dll /r:System.Web.Extensions.dll /r:System.ValueTuple.dll `
       "/out:$(Join-Path $outDir 'VaultTests.exe')" $srcs
if ($LASTEXITCODE -ne 0) { throw "测试程序编译失败" }

& (Join-Path $outDir "VaultTests.exe")
exit $LASTEXITCODE
