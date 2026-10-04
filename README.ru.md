# mcp-node-zig

[![CI](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/alexchen-sys/mcp-node-zig)](https://github.com/alexchen-sys/mcp-node-zig/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](README.md) | Русский

MCP-сервер, через который ИИ-агент выполняет команды и работает с файлами на вашей машине. Один статический бинарь: без Node, Python и SSH.

![mcp-node-zig: старт 1.86 мс, 0.98 МиБ в простое, один бинарь 4.30 МиБ](assets/demo.gif)

Старт за 1.86 мс, 0.98 МиБ RSS в простое, 4.30 МиБ на диске, exec p50 0.66 мс / p99 1.81 мс, +576 КиБ на соединение. [Как мерили](BENCHMARKS.md).

## Установка

Linux x86_64:

```sh
curl -L https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.1.2/mcp-node-v0.1.2-x86_64-linux.tar.gz | tar xz
```

Для Linux ARM64, macOS (Apple Silicon) и Windows замените имя архива: `aarch64-linux.tar.gz`, `aarch64-macos.tar.gz`, `x86_64-windows.zip`. Все архивы и `SHA256SUMS.txt` лежат на [странице релиза](https://github.com/alexchen-sys/mcp-node-zig/releases).

## Быстрый старт

```sh
openssl rand -hex 32 > token
./mcp-node-v0.1.2-x86_64-linux/mcp-node &

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
curl.exe -L -o mcp-node.zip https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.1.2/mcp-node-v0.1.2-x86_64-windows.zip
Expand-Archive mcp-node.zip
[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N') | Set-Content -NoNewline -Encoding Ascii token
.\mcp-node-v0.1.2-x86_64-windows\mcp-node.exe
```

</details>

## Возможности

- Не нужно ничего ставить на целевую машину. Бинарь работает на Linux, macOS и Windows, включая хосты без OpenSSH.
- Долгие задачи не обрываются вместе с запросом. `exec_start` запускает процесс как сессию, агент читает вывод через `exec_poll` и `exec_wait`, пишет в stdin через `exec_write`. `exec_kill` убивает всё дерево процессов.
- Команды без сюрпризов от shell. `exec` передаёт argv напрямую, метасимволы остаются данными. Для пайпов и редиректов есть отдельный `exec_shell`.
- Файлы с проверкой. `read_file`, `list_dir`, а `write_file` возвращает SHA-256 записанного.
- Работает с любым MCP-клиентом по HTTP: Claude Code, Cursor, VS Code, Codex, Claude Desktop. Для stdio-клиентов есть мост [mcp-remote](https://github.com/geelen/mcp-remote).

Всего 13 инструментов, схемы отдаёт `tools/list`.

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
