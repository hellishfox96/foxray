# Foxray

VPN-клиент для Windows и Linux поверх [sing-box](https://github.com/SagerNet/sing-box).
Протоколы VLESS (Reality) и Hysteria2, работает через TUN — весь трафик системы, без настройки прокси в программах.

## Возможности
- Серверы по ссылкам и подпискам, пинг, ручное добавление.
- Правила: что пускать через VPN, что напрямую, что блокировать — домены, IP, программы
  и готовые наборы (YouTube, Discord, Telegram, российские сайты, реклама…).
- Режимы «Всё через VPN» и «Только списки».
- Скорость, трафик по маршрутам и список открытых соединений с программой и маршрутом.
- Zapret — Discord и YouTube без VPN (см. ниже).
- Трей, автозапуск, переподключение при обрыве.
- Обновление прямо из программы.

## Установка
Скачать архив из [Releases](https://github.com/hellishfox96/foxray/releases/latest) и распаковать в любую папку.

**Windows** — `Foxray-…-windows-x64.zip`. Запустить `Foxray.exe` (попросит права администратора — они нужны для TUN).

**Linux** — `Foxray-…-linux-x86_64.tar.gz` (Ubuntu 20.04+ и похожие). Распаковать в домашнюю папку
(не на NTFS/FAT) и запустить `./foxray`. `./install-menu.sh` добавит Foxray в меню приложений.
При первом подключении система спросит пароль — чтобы выдать sing-box права на TUN.
Для трея в GNOME нужно расширение AppIndicator (в Ubuntu включено).

Серверы и настройки хранятся рядом с программой (`profiles.json`, `settings.json`, `rules.json`).

## Обновления
«Настройки → Обновление»: Foxray сам проверяет новые версии и по кнопке «Обновить» скачивает и перезапускается.
Серверы, подписки, настройки и правила при этом не трогаются.

## Zapret
«Настройки → Zapret» — Discord (вместе с голосом) и YouTube мимо VPN, через обход блокировок
[zapret](https://github.com/bol-van/zapret). Используются стратегии и списки сборки
[Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) — кнопка «Скачать» загружает её.
«Подобрать стратегию» по очереди проверяет все и выбирает рабочую.

- Windows: запускается `winws.exe` из сборки.
- Linux: вместо него `nfqws` (скачивается вместе со сборкой), нужны `nftables` и `pkexec`;
  при включении система спросит пароль.
- Discord ловится по программе: обычный клиент, PTB/Canary, Vesktop, Equibop, Legcord.
  Discord в браузере — сайты идут через zapret, голос через VPN.

## Сборка из исходников
Нужен [Rust](https://rustup.rs).

Windows:

    cargo build --release
    build-portable.cmd          # dist\Foxray\ и zip с sing-box

Linux (Ubuntu/Debian):

    sudo apt install build-essential libgtk-3-dev libxdo-dev libayatana-appindicator3-dev libfontconfig1-dev
    cargo build --release
    ./build-portable.sh         # dist/foxray/ и tar.gz с sing-box

Рядом с программой должен лежать `sing-box` (`sing-box.exe`) из
[выпусков sing-box](https://github.com/SagerNet/sing-box/releases) — проверено с 1.12.12.

Кроме окна (`foxray-gui`) есть консольная утилита `foxray`: `foxray gen "vless://…" -o config.json`
собирает конфиг sing-box из ссылки (`foxray --help` — остальное).

## Лицензии
sing-box — GPL-3.0 (© SagerNet), zapret — © bol-van, сборка стратегий — © Flowseal.
