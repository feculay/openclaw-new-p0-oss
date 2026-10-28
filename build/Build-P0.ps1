[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT'){throw 'WINDOWS_BUILD_REQUIRED'}
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$proj=Join-Path $root 'src\OpenClawNew.P0\OpenClawNew.P0.csproj'
$dest=Join-Path $root 'artifacts\windows-x64'
if(-not(Test-Path $proj -PathType Leaf)){throw 'SOURCE_MISSING'}
$dotnet=Get-Command dotnet.exe -ErrorAction Stop
& $dotnet.Source publish $proj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=false -p:DebugType=none -p:Deterministic=true -p:ContinuousIntegrationBuild=true -o $dest -v:minimal
if($LASTEXITCODE -ne 0){throw 'PUBLISH_FAILED'}
$exe=Join-Path $dest 'OpenClawNew.P0.exe'
if(-not(Test-Path $exe -PathType Leaf)){throw 'EXE_MISSING'}
Write-Output ('BUILD_PASS_SHA256='+((Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()))
Write-Output 'NO_SERVICE_INSTALL_NO_WIN_POLICY_CHANGE'
