#!/bin/sh
# Сборка портативной папки Foxray для Linux.
# Результат: dist/foxray/ (foxray, sing-box, значок, «Прочти меня») и dist/Foxray-<версия>-linux-x86_64.tar.gz.
# Личные данные (серверы, подписки, настройки, правила) в сборку НЕ попадают.
#
# Нужно заранее:
#   sudo apt install build-essential libgtk-3-dev libxdo-dev libayatana-appindicator3-dev libfontconfig1-dev
#   Linux-версия sing-box (файл sing-box без .exe) в папке проекта —
#   sing-box-*-linux-amd64.tar.gz с https://github.com/SagerNet/sing-box/releases
set -e
cd "$(dirname "$0")"

version=$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -n 1)
echo "Foxray $version — сборка..."

cargo build --release --bin foxray-gui

if [ ! -f sing-box ]; then
    echo "Не найден sing-box (Linux-версия) в папке проекта" >&2
    exit 1
fi

out=dist/foxray
rm -rf "$out"
mkdir -p "$out"
cp target/release/foxray-gui "$out/foxray"
cp sing-box "$out/sing-box"
chmod +x "$out/foxray" "$out/sing-box"
cp ui/icon.png "$out/foxray.png"
cp dist-files/linux/* "$out/"
chmod +x "$out/install-menu.sh"

archive="dist/Foxray-$version-linux-x86_64.tar.gz"
rm -f "$archive"
tar -czf "$archive" -C dist foxray

echo
echo "Готово:"
echo "  папка  $(cd "$out" && pwd)"
echo "  архив  $(cd dist && pwd)/$(basename "$archive")"
