# mcp-node-zig

[![CI](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/alexchen-sys/mcp-node-zig)](https://github.com/alexchen-sys/mcp-node-zig/releases)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-blue)](#статус)
[![Built in Zig](https://img.shields.io/badge/built%20in-Zig-f7a41d)](#сборка-из-исходников)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](README.md) | Русский

Крошечный доверенный edge-агент, который даёт ИИ руки на ваших машинах — один статический бинарный файл, без рантайма, без SSH.

<!-- TODO: session demo gif -->

Запустите его на любой машине, куда хотите дать доступ ИИ: build-сервер, домашний сервер, Windows-хост, небольшой парк VPS. Нода поднимает единственный streamable-HTTP MCP-endpoint с токен-аутентификацией, allowlist'ом хостов и сессиями процессов, которые переживают отдельные HTTP-запросы. Агент запускает команды, ведёт долгоживущие процессы, читает и записывает файлы.

SSH-мостам нужны ключи и OpenSSH. Рантаймам нужен Node или Python на каждой машине. mcp-node-zig не нужно ни то, ни другое.

[Быстрый старт](#быстрый-старт) • [Клиенты](#подключение-mcp-клиентов) • [Почему не SSH](#почему-не-ssh-based-mcp) • [Бенчмарки](#бенчмарки) • [Настройка](#настройка) • [Примеры](#примеры) • [Безопасность](#заметки-о-безопасности) • [Ограничения](#ограничения) • [Диагностика](#диагностика) • [Сборка](#сборка-из-исходников)

## Быстрый старт

Четыре команды до рабочей ноды (Linux, x86_64):

```sh
curl -L https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.1.1/mcp-node-v0.1.1-x86_64-linux.tar.gz | tar xz
openssl rand -hex 32 > token
./mcp-node-v0.1.1-x86_64-linux/mcp-node &
curl -sS http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H "X-Node-Token: $(cat token)" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
```

В ответ вы увидите примерно это (переформатировано для читаемости; реальный ответ — одна строка и дополнительно несёт текстовый блок `content`, зеркалирующий `structuredContent`; значения у вас будут другими):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "structuredContent": {
      "node": "mcp-node",
      "hostname": "your-machine",
      "os": "Linux",
      "machine": "x86_64",
      "loadavg_raw": "0.31 0.26 0.19 ...",
      "uptime_raw": "86400.00 ...",
      "mem": { "MemTotal": 16384000, "MemAvailable": 8192000 }
    },
    "isError": false
  }
}
```

Нет `openssl`? Сработает и `head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > token`.

**macOS (Apple Silicon)** — тот же флоу с aarch64-архивом:

```sh
curl -L https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.1.1/mcp-node-v0.1.1-aarch64-macos.tar.gz | tar xz
openssl rand -hex 32 > token
./mcp-node-v0.1.1-aarch64-macos/mcp-node &
```

затем тот же `curl`-verify, что и на Linux. Linux ARM64: подставьте `mcp-node-v0.1.1-aarch64-linux.tar.gz`. Intel Mac: [сборка из исходников](#сборка-из-исходников).

**Windows (PowerShell)** — запустите сервер в одном окне:

```powershell
curl.exe -L -o mcp-node.zip https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.1.1/mcp-node-v0.1.1-x86_64-windows.zip
Expand-Archive mcp-node.zip
[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N') | Set-Content -NoNewline -Encoding Ascii token
.\mcp-node-v0.1.1-x86_64-windows\mcp-node.exe
```

и проверьте из второго окна:

```powershell
$sys = Invoke-RestMethod -Uri http://127.0.0.1:8341/mcp -Method Post -ContentType "application/json" `
  -Headers @{ "X-Node-Token" = (Get-Content token) } `
  -Body '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
$sys.result.structuredContent
```

Каждый релиз несёт манифест `SHA256SUMS.txt` — сверьте с ним скачанный архив (`sha256sum` на Linux, `shasum -a 256` на macOS, `Get-FileHash` на Windows).

## Инструменты

Фиксированный набор практичных инструментов поверх единственного streamable-HTTP JSON-RPC endpoint (`POST /mcp`):

- `sys_info` — имя хоста, ОС, load, память, uptime
- `exec` — запуск argv-массива напрямую, без слоя shell, с ожиданием завершения
- `exec_shell` — запуск одного скрипта через shell (`bash`/`sh`/`fish`/`zsh -c`; `cmd`/`powershell` на Windows)
- `exec_start` — запуск долгоживущего argv-процесса как сессии с пайпами stdin/stdout/stderr
- `exec_poll` — чтение вывода сессии по байтовым смещениям, с флагами done/exit_code/обрезки
- `exec_wait` — long-poll сессии до завершения или `timeout` (по умолчанию 30 с, максимум 300 с)
- `exec_write` — запись base64-байтов в stdin сессии; `eof=true` закрывает stdin
- `exec_kill` — убийство всей группы процессов сессии
- `exec_close` — join потоков сессии и освобождение её состояния; идемпотентен
- `exec_list` — список живых сессий: id, pid, argv, done, exit_code, метки времени
- `read_file` — чтение UTF-8 текста с заменой, смещением и лимитом в символах
- `write_file` — base64-запись с mkdirs и SHA-256-квитанцией
- `list_dir` — листинг каталога с типом/размером/mtime, сортировка по имени

Полные input-схемы доступны в рантайме через `tools/list`.

## Подключение MCP-клиентов

Любой MCP-клиент с поддержкой HTTP-транспорта может подключиться. Выберите свой:

### Claude Code

```sh
claude mcp add --transport http mcp-node http://127.0.0.1:8341/mcp \
  --header "X-Node-Token: $(cat token)"
```

### Cursor

Сохраните как `.cursor/mcp.json` в проекте или `~/.cursor/mcp.json` для глобального сервера (Settings → MCP → Add new global MCP server):

```json
{
  "mcpServers": {
    "mcp-node": {
      "url": "http://127.0.0.1:8341/mcp",
      "headers": { "X-Node-Token": "<token>" }
    }
  }
}
```

### VS Code

Сохраните как `.vscode/mcp.json` в workspace или откройте Command Palette → «MCP: Open User Configuration» для пользовательского файла:

```json
{
  "servers": {
    "mcp-node": {
      "type": "http",
      "url": "http://127.0.0.1:8341/mcp",
      "headers": { "X-Node-Token": "<token>" }
    }
  }
}
```

### Codex

Добавьте в `~/.codex/config.toml` и перезапустите Codex:

```toml
[mcp_servers.mcp-node]
url = "http://127.0.0.1:8341/mcp"
http_headers = { "X-Node-Token" = "<token>" }
```

### Claude Desktop и другие JSON-клиенты

```json
{
  "mcpServers": {
    "mcp-node": {
      "type": "http",
      "url": "http://127.0.0.1:8341/mcp",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

Стандартная схема Bearer работает везде; `X-Node-Token` выше — альтернатива для клиентов, которые не могут задать заголовок `Authorization`. Запрос с обоими заголовками должен нести одинаковое значение.

### Клиенты только с stdio

Мост к HTTP-endpoint через [mcp-remote](https://github.com/geelen/mcp-remote):

```sh
npx mcp-remote http://127.0.0.1:8341/mcp --header "X-Node-Token: <token>"
```

Теперь попросите агента:

> «Запусти sys_info на mcp-node и покажи использование памяти.»

## Почему не SSH-based MCP

SSH-мосты — честный рабочий выбор, когда на каждой целевой машине уже стоит OpenSSH и вас устраивает хранение SSH-ключей в каждом MCP-клиенте. mcp-node-zig существует для машин, где это не так: Windows-хосты без OpenSSH, контейнеры, закрытые сегменты сети, парки машин, где раздача SSH-ключей — ровно то, чего хочется избежать.

| | SSH-based MCP-мост | Локальный stdio-сервер | mcp-node-zig |
| --- | --- | --- | --- |
| Установка на целевой машине | ничего (только OpenSSH) | рантайм + сервер (Node/Python) | один статический бинарь |
| Рантайм на целевой машине | OpenSSH | Node или Python | нет |
| Модель аутентификации | SSH-ключи в каждом клиенте | права OS-пользователя клиента | один токен, сравнение за константное время |
| Долгоживущие процессы | привязаны к SSH-соединению | привязаны к процессу клиента | сессии переживают запросы |
| Windows без OpenSSH | нужна установка OpenSSH | нужен рантайм | работает из коробки |
| NAT / закрытые сети | нужен доступный SSH-порт | только локально | любой HTTP-путь (reverse-туннель, VPN) |

Колонка SSH — не соломенное чучело: если OpenSSH у вас везде, мост может оказаться проще. Выгода появляется там, где SSH нет, нежелателен или дорог в поддержке.

## Бенчмарки

Один и тот же вопрос всем участникам, запущенным штатным путём из их README: сколько стоит поставить command-сервер на машину? Замер на 4-ядерном десктопе против `uvx mcp-shell-server` и `npx mcp-server-commands` (кэши установщиков прогреты, дочерняя команда одинаковая, N=50 холодных стартов / N=200 round-trip): mcp-node-zig отвечает на первый MCP-вызов через **1.9 мс** после запуска (у соперников 463 / 888 мс), держит **0.98 МиБ** RSS в простое (у соперников 189 / 197 МиБ), а вся установка — **один статический бинарь 4.3 МиБ** без рантайма (стеки соперников: ~93–198 МиБ). Полные таблицы, честные оговорки и воспроизведение одной командой: [BENCHMARKS.md](BENCHMARKS.md).

## Настройка

Настройка — только через переменные окружения:

- `MCP_NODE_NAME` — имя в serverInfo, по умолчанию `mcp-node`
- `MCP_NODE_HOST` — IP-литерал для bind, по умолчанию `127.0.0.1`
- `MCP_NODE_PORT` — порт, по умолчанию `8341`
- `MCP_NODE_TOKEN_FILE` — путь к файлу токена, по умолчанию `./token`
- `MCP_NODE_ALLOWED_HOSTS` — список через запятую, по умолчанию `127.0.0.1:*,localhost:*,[::1]:*`
- `MCP_NODE_ALLOWED_ORIGINS` — список через запятую, проверяется при наличии заголовка `Origin`, по умолчанию `http://127.0.0.1:*,http://localhost:*,http://[::1]:*`
- `MCP_NODE_MAX_OUT` — лимит на поток stdout/stderr, по умолчанию `400000`
- `MCP_NODE_SOCKET_TIMEOUT_S` — дедлайн на чтение и на весь запрос, по умолчанию `60` (`0` -> `60`)
- `MCP_NODE_MAX_CONN` — максимум одновременных TCP-соединений, по умолчанию `128` (`0` -> `128`)
- `MCP_NODE_MAX_SESSIONS` — максимум живых exec-сессий, по умолчанию `64` (`0` -> `64`)
- `MCP_NODE_SESSION_TTL_S` — задержка сбора завершённых сессий, по умолчанию `600` (`0` -> `600`)
- `MCP_NODE_TEXT_MIRROR=0` — отдавать только `structuredContent`, без JSON-зеркала в `content[0].text`; вдвое меньше байт в ответе для клиентов, читающих структуру (инструменты декларируют `outputSchema`). По умолчанию зеркало включено, как рекомендует спецификация; ошибки всегда несут текст
- `MCP_NODE_INSECURE=1` — разрешить старт без токена (не рекомендуется); на Windows отсутствие файла токена всегда валит старт — создайте пустой файл

Заголовок аутентификации: стандартная схема Bearer, которую шлют большинство MCP-клиентов, или `X-Node-Token: <token>`. Если запрос несёт оба — значения обязаны совпадать, иначе 401.

## Примеры

Разовый вызов:

```sh
curl -sS http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H "X-Node-Token: $(cat token)" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["uname","-a"]}}}'
```

Долгая работа идёт через сессии. С маленьким хелпером для читабельности тура:

```sh
mcp() {
  curl -sS http://127.0.0.1:8341/mcp \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "X-Node-Token: $(cat token)" \
    --data "$1"
}
```

Стартуйте сессию; в ответе придёт целочисленный `session_id`:

```sh
mcp '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_start","arguments":{"argv":["bash","-c","for i in 1 2 3; do echo tick$i; sleep 5; done"]}}}'
```

Блокируйтесь до её завершения (или до истечения `timeout`), затем вычитывайте вывод инкрементально — смещения продолжаются с места прошлого poll:

```sh
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_wait","arguments":{"session_id":1,"timeout":30}}}'
mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec_poll","arguments":{"session_id":1,"stdout_offset":0,"stderr_offset":0}}}'
```

Освободите состояние сессии (`exec_close` идемпотентен):

```sh
mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec_close","arguments":{"session_id":1}}}'
```

## Асинхронные сессии процессов

`exec_start` запускает argv как сессию (своя группа процессов, пайпы stdin/stdout/stderr) и возвращает `session_id`; управляйте ею через `exec_poll`/`exec_wait`/`exec_write`/`exec_kill`/`exec_close`, живой набор смотрите через `exec_list`.

- Сессии считаются по ссылкам; `exec_close` идемпотентен (`already_closed: true` на повторный/поздний close) и безопасен при гонке с идущими `exec_poll`/`exec_write`/`exec_kill` из других соединений.
- `exec_kill`/`exec_close` убивают всё дерево процессов (`SIGKILL` по группе на POSIX, терминирование Job Object на Windows), поэтому дочерние shell-процессы не держат пайпы открытыми.
- Буферы вывода ограничены на поток (`MCP_NODE_MAX_OUT`); переполнение выставляет `truncated_stdout`/`truncated_stderr` вместо падения процесса.
- Дельты `exec_poll` никогда не режут многобайтовую UTF-8 последовательность на границе чанка, пока процесс жив; возвращённые смещения всегда указывают на следующий непрочитанный байт.
- Завершённые сессии собираются автоматически через `MCP_NODE_SESSION_TTL_S` секунд; переполненное хранилище (`MCP_NODE_MAX_SESSIONS`) лениво выселяет завершённые сессии до отказа новым.

## Статус

Ранний `0.1.x`; контракт может меняться.

Поддержка платформ: **Linux**, **macOS** и **Windows** — все три собираются, покрываются юнит-тестами и smoke-тестами (auth-гейт, `initialize`, `sys_info`) при каждом push в CI-матрице. Linux — основная production-платформа. На Windows деревья процессов управляются через Job Objects, а таймауты сокетов — через overlapped AFD I/O с программными дедлайнами.

## Заметки о протоколе

- Ошибки парсинга JSON-RPC возвращают HTTP 400 с `-32700`; уведомления без `id` возвращают HTTP 202 с пустым телом.
- Доменные ошибки инструментов возвращают `{ok:false,...}` с `isError=false`; неизвестные инструменты — `isError=true`.
- HTTP/1.1 keep-alive поддерживается для последовательных запросов в одном соединении; `Connection: close` закрывает соединение после ответа.

## Заметки о безопасности

- Аутентификация — сравнение SHA-256-хеша токена из стандартного Bearer-заголовка или `X-Node-Token` за константное время; отсутствующий токен, неверный, не-Bearer-схема или два расходящихся заголовка дают HTTP 401 с `WWW-Authenticate: Bearer`. Повторённый заголовок `Authorization` отклоняется с 400, а отсутствующий/пустой файл токена валит старт, если не задан `MCP_NODE_INSECURE=1`.
- `Host` проверяется до парсинга JSON; неизвестные хосты получают HTTP 421. Присутствующий заголовок `Origin` проверяется по `MCP_NODE_ALLOWED_ORIGINS`; неизвестные origin получают HTTP 403.
- Запросы больше 32 МиБ получают HTTP 413; конфликтующие дубликаты `Content-Length` отклоняются. На `Expect: 100-continue` отвечается до чтения тела. Обслуживается только `POST /mcp` с `Content-Type: application/json` (иначе 404/405/415; заголовки больше 64 КиБ получают 431).
- Таймауты `exec`/`exec_shell` зажаты в `[1, 1800]` секунд (по умолчанию 120 с).
- Соединения обслуживаются по потоку на каждое, с потолком `MCP_NODE_MAX_CONN`; избыточные соединения получают HTTP 503.
- `exec` не проходит через shell; метасимволы shell — это данные. `exec_shell` — намеренно один явный слой shell для пайплайнов и редиректов.
- `write_file` возвращает SHA-256-дайджест для сверки.

## Ограничения

- **Нет встроенного TLS.** Endpoint говорит чистым HTTP. Держите его на loopback и терминируйте TLS впереди — с Caddy это одна строка: `caddy reverse-proxy --from node.example.com --to 127.0.0.1:8341` — или достучитесь через туннель/VPN в закрытых сетях.
- **Нет PTY.** stdin/stdout/stderr сессии — пайпы, поэтому интерактивные TUI-программы не покрыты.
- **Пока нет аудит-лога** — в планах (см. [Roadmap](#roadmap)).

## Roadmap

- [ ] Встроенная терминация TLS (до неё — рецепт Caddy/туннеля выше)
- [ ] Поддержка PTY для интерактивных программ
- [ ] Структурированный аудит-лог

## Диагностика

- **HTTP 401** — токен отсутствует или неверный. Проверьте, что заголовок — `X-Node-Token: <token>` или стандартный Bearer-заголовок, и что клиент с обоими шлёт одинаковое значение; сервер также отказывается стартовать с отсутствующим/пустым файлом токена, если не задан `MCP_NODE_INSECURE=1`.
- **HTTP 421** — заголовок `Host` запроса не входит в `MCP_NODE_ALLOWED_HOSTS`; добавьте `host:port`, через который вы реально подключаетесь (всё, кроме loopback, требует явной записи).
- **HTTP 403** — присутствовал заголовок `Origin` (браузерный вызов) и он не входит в `MCP_NODE_ALLOWED_ORIGINS`.
- **HTTP 415** — POST без `Content-Type: application/json`.
- **Connection refused / пустой ответ** — сервер не слушает этот адрес:порт. Проверьте `MCP_NODE_HOST` (по умолчанию `127.0.0.1` — с других машин недоступен) и `MCP_NODE_PORT`, убедитесь, что процесс жив.
- **Сервер падает на старте** — файл токена отсутствует или пуст (fail-closed by design). Создайте его; на Windows файл токена обязан существовать даже с `MCP_NODE_INSECURE=1` (пустой подойдёт).

## Обновление и удаление

- **Обновление** — скачайте архив более нового релиза, замените бинарь, перезапустите ноду.
- **Удаление** — остановите процесс, затем удалите бинарь, файл токена и созданный вами service-юнит.

<!-- Used by: место зарезервировано для первой истории внешнего пользователя (цитата + ссылка). -->

## Сборка из исходников

Требуется Zig 0.16.x. Таргеты Linux, macOS и Windows (см. [Статус](#статус)).

```sh
git clone https://github.com/alexchen-sys/mcp-node-zig
cd mcp-node-zig
zig build test
zig build -Doptimize=ReleaseSafe
```

Бинарь: `zig-out/bin/mcp-node` (на Linux статически слинкован без libc; macOS линкует libSystem, Windows — kernel32/ntdll, других зависимостей нет).

## Лицензия

MIT — см. [LICENSE](LICENSE).
