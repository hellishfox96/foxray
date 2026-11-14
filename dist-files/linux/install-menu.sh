#!/bin/sh
# Добавить Foxray в меню приложений (только для текущего пользователя).
# Запускать из папки Foxray. Если папку потом перенести — запустить ещё раз.
set -e
dir=$(cd "$(dirname "$0")" && pwd)
apps="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$apps"
cat > "$apps/foxray.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Foxray
Comment=VPN-клиент (VLESS Reality, Hysteria2)
Exec="$dir/foxray"
Icon=$dir/foxray.png
Terminal=false
Categories=Network;
DESKTOP
echo "Готово: Foxray появится в меню приложений."
echo "Убрать: rm \"$apps/foxray.desktop\""
