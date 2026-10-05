# mcp-node-zig

[![CI](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/alexchen-sys/mcp-node-zig)](https://github.com/alexchen-sys/mcp-node-zig/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](README.md) | Русский

MCP-сервер, через который ИИ-агент выполняет команды и работает с файлами на вашей машине. Один статический бинарь: без Node, Python и SSH.

![mcp-node-zig: узел за NAT дозванивается до хаба, хаб выполняет на нём команду](assets/demo.gif)

Старт за 1.9 мс, 0.62 МиБ RSS в простое, 8.70 МиБ на диске, exec p50 0.7 мс / p99 1.5 мс, +288 КиБ на соединение. [Как мерили](BENCHMARKS.md).

mcp-node-zig — узел удалённого исполнения, который говорит на MCP: положите один статический бинарь на машину, и ваш агент сможет запускать там команды, вести долгие сессии и читать или писать файлы. С v0.2.0 узел умеет сам звонить на хаб вместо того, чтобы слушать порт, поэтому до машины за NAT или за чужим файрволом можно достучаться без входящих портов и без SSH. Первый MCP-ответ он отдаёт через 1.9 мс после старта, в простое занимает 0.62 МиБ, так что держать его на каждой машине почти ничего не стоит.

## Установка

```sh
curl -fsSL https://raw.githubusercontent.com/alexchen-sys/mcp-node-zig/main/install.sh | sh
```

Скрипт сам определяет платформу, скачивает свежий релиз, сверяет его с `SHA256SUMS.txt` и ставит в `/usr/local/bin` (или `~/.local/bin`). Зафиксировать версию: `MCP_NODE_VERSION=0.2.0`, другой каталог: `PREFIX=/some/dir`.

Ручная установка, Linux x86_64:

```sh
curl -L https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.2.0/mcp-node-v0.2.0-x86_64-linux.tar.gz | tar xz
```

Для Linux ARM64, macOS (Apple Silicon) и Windows замените имя архива: `aarch64-linux.tar.gz`, `aarch64-macos.tar.gz`, `x86_64-windows.zip`. Все архивы и `SHA256SUMS.txt` лежат на [странице релиза](https://github.com/alexchen-sys/mcp-node-zig/releases).

## Быстрый старт

```sh
openssl rand -hex 32 > token
./mcp-node-v0.2.0-x86_64-linux/mcp-node &

curl -sS http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $(cat token)" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
```

В ответе придут имя хоста, ОС, load, память и uptime. Нода готова.

Подключение к Claude Code:

```sh
claude mcp add --transport http mcp-node http://127.0.0.1:8341/mcp \
  --header "Authorization: Bearer $(cat token)"
```

<details>
<summary>Windows (PowerShell)</summary>

```powershell
curl.exe -L -o mcp-node.zip https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.2.0/mcp-node-v0.2.0-x86_64-windows.zip
Expand-Archive mcp-node.zip
[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N') | Set-Content -NoNewline -Encoding Ascii token
.\mcp-node-v0.2.0-x86_64-windows\mcp-node.exe
```

</details>

## Возможности

- Не нужно ничего ставить на целевую машину. Бинарь работает на Linux, macOS и Windows, включая хосты без OpenSSH.
- Долгие задачи не обрываются вместе с запросом. `exec_start` запускает процесс как сессию, агент читает вывод через `exec_poll` и `exec_wait`, пишет в stdin через `exec_write`. `exec_kill` убивает всё дерево процессов.
- Команды без сюрпризов от shell. `exec` передаёт argv напрямую, метасимволы остаются данными. Для пайпов и редиректов есть отдельный `exec_shell`.
- Файлы с проверкой. `read_file`, `list_dir`, а `write_file` возвращает SHA-256 записанного.
- Работает с любым MCP-клиентом по HTTP: Claude Code, Cursor, VS Code, Codex, Claude Desktop. Для stdio-клиентов есть мост [mcp-remote](https://github.com/geelen/mcp-remote).

Всего 13 инструментов, схемы отдаёт `tools/list`.

## Чем это отличается от SSH?

Это разные инструменты, и вместе они работают хорошо. SSH остаётся защищённым транспортом и терминалом для человека: шифрование, ключи, PTY, scp/sftp/rsync. mcp-node даёт агенту API исполнения: argv без повторного разбора удалённым шеллом, JSON-результат с `exit_code` и таймаутами, сессии, которые переживают обрыв соединения, запись файлов с SHA-256 и самоописание через `tools/list`.

Своего шифрования у ноды нет, поэтому для удалённых машин их обычно ставят вместе: нода слушает `127.0.0.1`, а доступ к ней идёт через SSH-туннель (`ssh -L 8341:127.0.0.1:8341 host`), VPN или reverse proxy с TLS.

## Конфиг

Всё задаётся переменными окружения:

| Переменная | По умолчанию |
| --- | --- |
| `MCP_NODE_HOST` | `127.0.0.1` |
| `MCP_NODE_PORT` | `8341` |
| `MCP_NODE_TOKEN_FILE` | `./token` |
| `MCP_NODE_ALLOWED_HOSTS` | `127.0.0.1:*,localhost:*,[::1]:*` |
| `MCP_NODE_MAX_CONN` | `128` |
| `MCP_NODE_MAX_SESSIONS` | `64` |
| `MCP_NODE_SESSION_TTL_S` | `600` |
| `MCP_NODE_MAX_OUT` | `400000` байт на поток |

Остальные (`MCP_NODE_NAME`, `MCP_NODE_ALLOWED_ORIGINS`, `MCP_NODE_SOCKET_TIMEOUT_S`, `MCP_NODE_TEXT_MIRROR`) описаны в [README.md](README.md#configuration).

## Безопасность

- Без токена нода не стартует. Токен принимается в `Authorization: Bearer` или `X-Node-Token`, сравнение по SHA-256 за константное время.
- По умолчанию слушает только loopback. Чужой `Host` получает 421, чужой `Origin` получает 403.
- TLS встроенного нет. Для доступа снаружи поставьте спереди reverse proxy, например `caddy reverse-proxy --from node.example.com --to 127.0.0.1:8341`, или ходите через VPN.
- Агент получает права пользователя, от которого запущена нода. Запускайте её от того пользователя, чьи права готовы отдать.

Пока нет PTY и аудит-лога, оба в планах. Версия `0.1.x`, контракт может меняться.

## Ссылки

- [Бенчмарки](BENCHMARKS.md)
- [Полный README на английском](README.md): все клиенты, протокол, диагностика
- [Сборка из исходников](README.md#building-from-source): Zig 0.16.x, `zig build -Doptimize=ReleaseSafe`
- [Безопасность](SECURITY.md) · [Участие](CONTRIBUTING.md) · [MIT](LICENSE)
