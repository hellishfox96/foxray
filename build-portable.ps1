# Сборка портативной папки Foxray для передачи другому человеку.
# Результат: dist\Foxray\ (Foxray.exe + sing-box.exe + «Прочти меня.txt») и dist\Foxray-<версия>.zip.
# Личные данные (серверы, подписки, настройки, правила) в сборку НЕ попадают.

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$version = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
Write-Host "Foxray $version — сборка..." -ForegroundColor Cyan

cargo build --release --bin foxray-gui
if ($LASTEXITCODE -ne 0) { throw "cargo build завершился с ошибкой" }

if (-not (Test-Path 'sing-box.exe')) { throw "Не найден sing-box.exe в папке проекта" }

$out = Join-Path 'dist' 'Foxray'
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $out | Out-Null

Copy-Item 'target\release\foxray-gui.exe' (Join-Path $out 'Foxray.exe')
Copy-Item 'sing-box.exe' $out
# Библиотеки рядом с sing-box (в некоторых сборках sing-box они есть)
Get-ChildItem -Path . -Filter '*.dll' -File -ErrorAction SilentlyContinue | Copy-Item -Destination $out
Copy-Item 'dist-files\Прочти меня.txt' $out

$zip = Join-Path 'dist' "Foxray-$version.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $out -DestinationPath $zip

Write-Host ""
Write-Host "Готово:" -ForegroundColor Green
Write-Host "  папка  $((Resolve-Path $out).Path)"
Write-Host "  архив  $((Resolve-Path $zip).Path)"
