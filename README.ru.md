# mcp-node-zig

[![CI](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/alexchen-sys/mcp-node-zig)](https://github.com/alexchen-sys/mcp-node-zig/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](README.md) | Русский | [中文](README.zh.md)

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
curl -L https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.2.1/mcp-node-v0.2.1-x86_64-linux.tar.gz | tar xz
```

Для Linux ARM64, macOS (Apple Silicon) и Windows замените имя архива: `aarch64-linux.tar.gz`, `aarch64-macos.tar.gz`, `x86_64-windows.zip`. Все архивы и `SHA256SUMS.txt` лежат на [странице релиза](https://github.com/alexchen-sys/mcp-node-zig/releases).

## Быстрый старт

```sh
openssl rand -hex 32 > token
./mcp-node-v0.2.1-x86_64-linux/mcp-node &

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
curl.exe -L -o mcp-node.zip https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.2.1/mcp-node-v0.2.1-x86_64-windows.zip
Expand-Archive mcp-node.zip
[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N') | Set-Content -NoNewline -Encoding Ascii token
.\mcp-node-v0.2.1-x86_64-windows\mcp-node.exe
```

</details>

## Возможности

- Не нужно ничего ставить на целевую машину. Бинарь работает на Linux, macOS и Windows, включая хосты без OpenSSH.
- Долгие задачи не обрываются вместе с запросом. `exec_start` запускает процесс как сессию, агент читает вывод через `exec_poll` и `exec_wait`, пишет в stdin через `exec_write`. `exec_kill` убивает всё дерево процессов.
- Команды без сюрпризов от shell. `exec` передаёт argv напрямую, метасимволы остаются данными. Для пайпов и редиректов есть отдельный `exec_shell`.
- Файлы с проверкой. `read_file`, `list_dir`, а `write_file` возвращает SHA-256 записанного.
- Работает с любым MCP-клиентом по HTTP: Claude Code, Cursor, VS Code, Codex, Claude Desktop. stdio-клиенты запускают ноду напрямую через `--stdio`, см. ниже.

Всего 13 инструментов, схемы отдаёт `tools/list`.

## Режим stdio

Клиенты, которые сами запускают сервер подпроцессом, могут звать ноду напрямую с флагом `--stdio` (или `MCP_NODE_STDIO=1`). Сообщения идут построчно в формате JSON-RPC: один запрос на строку в stdin, один ответ на строку в stdout. Порт не слушается и токен не нужен: пайпы держит тот, кто запустил процесс. Логи пишутся только в stderr. Когда stdin закрывается, нода убивает оставшиеся сессии и выходит с кодом 0.

```json
{
  "mcpServers": {
    "mcp-node": {
      "command": "mcp-node",
      "args": ["--stdio"]
    }
  }
}
```

`--stdio` нельзя совмещать с `--connect` и `MCP_NODE_HUB_LISTEN`.

## Чем это отличается от SSH?

Это разные инструменты, и вместе они работают хорошо. SSH остаётся защищённым транспортом и терминалом для человека: шифрование, ключи, PTY, scp/sftp/rsync. mcp-node даёт агенту API исполнения: argv без повторного разбора удалённым шеллом, JSON-результат с `exit_code` и таймаутами, сессии, которые переживают обрыв соединения, запись файлов с SHA-256 и самоописание через `tools/list`.

У HTTP-сервера ноды своего шифрования нет, поэтому для удалённых машин их обычно ставят вместе: нода слушает `127.0.0.1`, а доступ к ней идёт через SSH-туннель (`ssh -L 8341:127.0.0.1:8341 host`), VPN или reverse proxy с TLS.

## Обратное подключение (без входящих портов)

Машину за NAT или без sshd запускают с `--connect hub:port`: нода сама звонит хабу (тот же бинарь с `MCP_NODE_HUB_LISTEN`), а клиенты ходят к ней через `/n/<name>/mcp` на хабе. По умолчанию канал идёт через TLS: порт хаба для нод слушает `127.0.0.1`, перед ним стоит TLS-терминатор (nginx `stream`, stunnel, HAProxy), а нода подключается с `MCP_NODE_CONNECT_TLS=1`:

```sh
# хаб; nginx/stunnel принимает TLS на :8400 и передаёт на 127.0.0.1:8401
MCP_NODE_HUB_LISTEN=127.0.0.1:8401 MCP_NODE_HUB_SECRET_FILE=nodes ./mcp-node
# нода; в `nodes` на хабе строка laptop:<secret>, в `secret` здесь только <secret>
MCP_NODE_NAME=laptop MCP_NODE_CONNECT_SECRET_FILE=secret MCP_NODE_CONNECT_TLS=1 \
  ./mcp-node --connect hub.example.com:8400
```

Для своего CA добавьте `MCP_NODE_CONNECT_CA_FILE`, для подключения по IP задайте `MCP_NODE_CONNECT_SERVER_NAME`. Конфиг терминатора и вариант без TLS для доверенной сети описаны в [docs/reverse-connect.md](docs/reverse-connect.md).

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
| `MCP_NODE_STDIO` | не задано; `1` — обслуживать одного клиента через stdin/stdout, без слушателя (то же, что `--stdio`) |

Остальные (`MCP_NODE_NAME`, `MCP_NODE_ALLOWED_ORIGINS`, `MCP_NODE_SOCKET_TIMEOUT_S`, `MCP_NODE_TEXT_MIRROR`) описаны в [README.md](README.md#configuration).

## Безопасность

- Без токена нода не стартует. Токен принимается в `Authorization: Bearer` или `X-Node-Token`, сравнение по SHA-256 за константное время.
- По умолчанию слушает только loopback. Чужой `Host` получает 421, чужой `Origin` получает 403.
- Встроенного TLS-сервера нет. Для доступа снаружи поставьте спереди reverse proxy, например `caddy reverse-proxy --from node.example.com --to 127.0.0.1:8341`, или ходите через VPN.
- Агент получает права пользователя, от которого запущена нода. Запускайте её от того пользователя, чьи права готовы отдать.

### Модель угроз

- Кто держит клиентский токен, тот запускает команды. Токен хаба открывает все подключённые ноды.
- Хаб видит весь трафик открытым текстом, а хаб с секретом ноды может выполнить на ней что угодно.
- Секрет ноды равен шеллу на ней и закрепляет за ней имя. Строки `name:secret` дают каждому имени свой секрет; один общий секрет позволяет занять любое имя.
- Рукопожатие (HMAC-SHA256 по свежим nonce) только аутентифицирует стороны. Следующие кадры без TLS не шифруются и не защищены от подмены.
- Через чужие сети используйте `MCP_NODE_CONNECT_TLS=1`: нода всегда проверяет цепочку сертификатов и имя сервера, отключить проверку нельзя. Голый TCP оставьте для одного хоста или доверенной LAN.
- Лимита на IP нет: хаб держит не больше 16 неаутентифицированных рукопожатий всего, поэтому закройте порт для нод файрволом.

Пока нет PTY и аудит-лога, оба в планах. Версия `0.1.x`, контракт может меняться.

## Ссылки

- [Бенчмарки](BENCHMARKS.md)
- [Полный README на английском](README.md): все клиенты, протокол, диагностика
- [Сборка из исходников](README.md#build-from-source): Zig 0.16.x, `zig build -Doptimize=ReleaseSafe`
- [Безопасность](SECURITY.md) · [Участие](CONTRIBUTING.md) · [MIT](LICENSE)
