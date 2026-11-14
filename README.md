# foxray

## Окно (foxray-gui)
1. `cargo build --release` (первая сборка долгая — несколько минут)
2. `sing-box.exe` должен лежать в папке foxray (или рядом с foxray-gui.exe)
3. Запуск: `target\release\foxray-gui.exe` — Windows спросит права администратора (нужны для TUN)

Удобно: правый клик по foxray-gui.exe → «Отправить» → «Рабочий стол (создать ярлык)».

Вкладки внизу окна:
- Главная — переключатель, текущий сервер, скорость с графиками, режим
  («Всё через VPN» / «Только списки»), итоги сессии.
- Серверы — группы «Мои» и по подпискам, поиск, «⚡» пинг, «+» добавить
  (ссылки или подписка https://, кнопка «Из буфера»). Правый клик или «⋮» по серверу —
  изменить (форма со всеми параметрами), копировать ссылку, удалить. Двойной клик — переименовать.
  В панели «+» есть «Вручную» — ввести сервер по полям, без ссылки.
- Правила — три базовых списка («Напрямую», «Через VPN», «Блок» — не удаляются, можно выключить
  или очистить) и свои списки. Клик открывает список: тип, записи, «Программа» — выбор из
  запущенных, «Готовый набор» — каталог сервисов (YouTube, Discord, Telegram, российские сайты,
  реклама…). Набор — обычная запись в списке: `geosite:youtube`, `geoip:telegram`, `geoip:ru`;
  файлы .srs скачиваются в папку rulesets и обновляются раз в неделю. Свои записи важнее наборов.
  Изменения применяются сами через 1.5 с.
- Настройки — локальная сеть, автозапуск, подключение при старте, подписки, журнал.

Рамка как в Telegram: окно Windows с тенью и скруглёнными углами, но без заголовка —
своя полоса с кнопками «свернуть» и «закрыть», за неё можно таскать окно. Размер фиксированный.
Кнопка «Закрыть» настраивается: в трей / в панель задач (без иконки в трее) / выход.
Меню на кнопке в панели задач (правый клик): подключить/отключить, открыть, выйти
(`--toggle`, `--quit`).
Надёжность: sing-box привязан к Foxray (умирает вместе с ним, даже при падении);
при обрыве — до 5 повторов (3, 5, 10, 20, 30 с); при автозапуске сначала ждём сеть (до минуты).
Запускается только одна копия: повторный запуск показывает окно, `foxray-gui.exe --quit` закрывает запущенный.
Пинг серверов — сам: при открытии вкладки «Серверы» и каждые 45 с, пока она открыта;
текущего сервера на «Главной» — раз в минуту при подключении.
Значок окна — ui/icon.png (можно заменить своей картинкой 256×256 и пересобрать), логотип в заголовке — icon.svg.
Название в меню панели задач — FileDescription в build.rs.

Трей: закрытие окна прячет его в трей (VPN продолжает работать). Левый клик — открыть,
правый — меню: подключить/отключить, выбор сервера, автозапуск, выход.
Автозапуск делается через Планировщик заданий (задача «Foxray»), запуск свёрнутым: --minimized.

Серверы и настройки хранятся рядом с sing-box.exe: profiles.json, settings.json, rules.json.
При первом запуске серверы импортируются из links.txt, если он есть.

## Zapret (Windows и Linux)
Настройки → «Zapret — Discord и YouTube без VPN». Использует сборку
[Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) как есть:
кнопка «Скачать» кладёт её в папку `zapret` рядом с Foxray (свои *-user.txt при обновлении сохраняются).
- Foxray берёт из выбранного `general*.bat` строку запуска `winws.exe`, подставляет пути и запускает
  winws скрыто, вместе с собой (Game Filter выключен, как по умолчанию в service.bat).
- При включённом zapret домены из `list-general.txt`, `list-google.txt`, `list-general-user.txt`
  и `Discord.exe` идут «напрямую» (мимо VPN) — их обрабатывает zapret. Голос Discord ловится по программе.
- Адрес VPN-сервера zapret не трогает: он записывается в `lists/ipset-exclude-foxray.txt`
  и добавляется в каждый профиль стратегии (`--ipset-exclude`).
- «Подобрать стратегию»: по очереди запускает каждую стратегию и открывает discord.com, gateway.discord.gg,
  cdn.discordapp.com, updates.discord.com, youtube.com, i.ytimg.com, redirector.googlevideo.com
  (читает до 64 КБ — ловит «заморозку» на 16–20 КБ). Лучшая выбирается сама. Голос (UDP) так не проверить —
  только звонком.
- Если уже запущен другой zapret (батник или служба), Foxray свой не запускает — два сразу мешают друг другу.

### Zapret в Linux
Сборка Flowseal — под Windows (winws.exe + WinDivert). В Linux Foxray берёт из неё стратегии и списки,
а вместо winws запускает **nfqws** из [bol-van/zapret](https://github.com/bol-van/zapret) — «Скачать» скачивает и его
(файл `zapret/nfqws` под процессор компьютера). Параметры стратегий те же, кроме `--wf-tcp/--wf-udp`:
их заменяют правила nftables (таблица `inet foxray_zapret`, очередь NFQUEUE 4242) — первые пакеты соединений
на порты стратегии уходят в nfqws. Пакеты в TUN Foxray (`foxray`) не трогаются.
- Правилам и nfqws нужен root: Foxray один раз за запуск поднимает помощника через pkexec
  (`foxray --zapret-helper`, система спросит пароль). Помощник живёт, пока жив Foxray,
  и при выходе (даже при падении) убирает правила и останавливает nfqws.
- Нужны пакеты `nftables` и `policykit-1` (в Ubuntu/Fedora обычно уже стоят).
- Discord ловится по программе: обычный Discord (в т. ч. с Vencord внутри), PTB/Canary, Vesktop, Equibop, Legcord/ArmCord.
  Discord в браузере: сайты идут через zapret, а голос — через VPN (браузер нельзя целиком пускать мимо VPN).
- Все 22 стратегии сборки 1.10.4 проходят проверку параметров `nfqws --dry-run` (тест `tests/zapret.rs`).

## Linux
Собирать на самом Linux (Ubuntu/Debian):

    sudo apt install build-essential libgtk-3-dev libxdo-dev libayatana-appindicator3-dev libfontconfig1-dev
    cargo build --release

Рядом нужен Linux-бинарник `sing-box` (без .exe) — из sing-box-*-linux-amd64.tar.gz.
Портативная версия: `./build-portable.sh` → `dist/foxray/` и `dist/Foxray-<версия>-linux-x86_64.tar.gz`
(внутри `install-menu.sh` — добавить Foxray в меню приложений).

Отличия от Windows:
- Foxray работает от обычного пользователя. Права на TUN получает только sing-box —
  при первом подключении `pkexec setcap cap_net_admin,cap_net_bind_service,cap_net_raw+ep sing-box`
  (система спросит пароль; после замены файла sing-box — спросит снова).
  Папка должна быть на разделе Linux: на FAT/NTFS setcap не работает.
- Рамка окна — своя полоса Foxray без системного заголовка (окно без рамки).
- Трей — через appindicator; в GNOME нужен AppIndicator (в Ubuntu включён).
- Автозапуск — файл `~/.config/autostart/foxray.desktop`.
- sing-box останавливается через SIGTERM (сам убирает маршруты). Если Foxray упал,
  оставшийся sing-box закрывается при следующем запуске (по `sing-box.pid`).
- Программы в правилах: `process:firefox` или полный путь `/usr/bin/firefox`.

## Обновления и выпуски (GitHub)
Foxray проверяет новые версии в «Настройки → Обновление» (и тихо — при запуске). Источник — выпуски (Releases)
репозитория из поля `repository` в Cargo.toml. «Обновить» скачивает архив под свою систему, заменяет Foxray
и sing-box (старые файлы становятся `*.old` и удаляются при следующем запуске) и перезапускает программу.
Серверы, подписки, настройки и правила не трогаются.

Выпустить новую версию:

    # 1. поменять version в Cargo.toml, например на 0.7.0
    git commit -am "Foxray 0.7.0"
    git tag v0.7.0
    git push && git push --tags

GitHub Actions (`.github/workflows/release.yml`) сам соберёт Windows (`Foxray-0.7.0-windows-x64.zip`)
и Linux (`Foxray-0.7.0-linux-x86_64.tar.gz`, glibc 2.31) вместе с sing-box и выложит выпуск.
Метка должна совпадать с версией в Cargo.toml — иначе сборка остановится.

Личные файлы (`profiles.json` с ключами серверов, `settings.json`, `rules.json`, `config.json`, `links.txt`)
в репозиторий не попадают — они в `.gitignore`.

## Консольная утилита (foxray)

Консольная утилита: ссылка VLESS+Reality / Hysteria2 → config.json для sing-box
с TUN-режимом и обходом локальной сети.

## Сборка (Windows)
1. Установить Rust: https://rustup.rs
2. `cargo build --release` → `target\release\foxray.exe`
3. `cargo test` — тесты парсера

## Портативная версия (чтобы отдать другу)
Двойной клик по `build-portable.cmd` (или `powershell -File build-portable.ps1`).
Получится `dist\Foxray\` (Foxray.exe, sing-box.exe, «Прочти меня.txt») и `dist\Foxray-<версия>.zip`.
Свои серверы, подписки и настройки в сборку не попадают.

## Использование
    foxray parse "vless://..."
    foxray gen "vless://..." -o config.json
    foxray gen -f links.txt -n 2 -o config.json
    foxray gen "hy2://..." -o config.json --bypass 10.8.0.0/24 --dns 8.8.8.8

Опции: --no-lan-bypass, --bypass CIDR (несколько раз), --dns IP, --ipv6, --rules файл, --verbose (подробный лог)

## Списки (rules.json)
    foxray rules init     — создать пример rules.json рядом
    foxray rules check    — показать, как распознались записи

rules.json подхватывается автоматически, если лежит в текущей папке (или --rules путь).

    {
      "final": "proxy",                 ← всё остальное: "proxy" (через VPN) или "direct"
      "lists": [
        { "name": "Напрямую", "enabled": true, "action": "direct",
          "entries": ["qbittorrent.exe", "vk.com", "10.8.0.0/24"] },
        { "name": "Блок", "enabled": false, "action": "block",
          "entries": ["doubleclick.net"] }
      ]
    }

action: "proxy" — через VPN, "direct" — напрямую, "block" — заблокировать.

Записи (тип определяется сам):
- `youtube.com` — домен и все поддомены
- `qbittorrent.exe` — программа (имя как в Диспетчере задач, регистр важен)
- `C:\Games\game.exe` — программа по полному пути (в JSON обратный слэш пишется двойным)
- `1.2.3.4`, `10.8.0.0/24` — IP или подсеть
- `full:vk.com` — только этот домен, без поддоменов
- `keyword:google` — любой домен, содержащий слово

Блок-списки срабатывают первыми, остальные — по порядку в файле.
Домены из «напрямую» резолвятся обычным DNS, из «через VPN» — через VPN.
Ошибочные записи пропускаются с предупреждением, конфиг всё равно собирается.

## Запуск
Скачать sing-box для Windows (sing-box-*-windows-amd64.zip) с
https://github.com/SagerNet/sing-box/releases, положить sing-box.exe рядом
(wintun.dll уже встроен в sing-box), затем в консоли **от администратора**:

    sing-box.exe run -c config.json

## Что в конфиге
- TUN `foxray`, auto_route + strict_route
- route_exclude_address: 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, мультикаст, IPv6 ULA/link-local — локалка мимо туннеля
- DNS: DoH 1.1.1.1 через прокси; .lan/.local/.home.arpa и адрес самого сервера — системным DNS
- Свой DNS (Настройки → «Свой DNS-сервер»): домашний адрес (AdGuard Home, Pi-hole) — напрямую по локальной сети, ему же уходят домашние домены и сайты «напрямую»; внешний адрес — через VPN
- Clash API на 127.0.0.1:9090 (для будущего UI: статистика, скорость)

Проверено `sing-box check` (1.12.12).
