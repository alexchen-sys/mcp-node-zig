# mcp-node-zig

[![CI](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/alexchen-sys/mcp-node-zig)](https://github.com/alexchen-sys/mcp-node-zig/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](README.md) | [Русский](README.ru.md) | 中文

让你的 AI 智能体在任何机器上拥有一个 shell。单个二进制文件，无需运行时，无需 SSH。

![mcp-node-zig：NAT 后面的节点主动连接枢纽，枢纽在节点上执行命令](assets/demo.gif)

**1.9 ms** 冷启动 · **0.62 MiB** 空闲 RSS · **8.70 MiB** 磁盘占用 · **0.7 ms** p50 执行往返（[基准测试](BENCHMARKS.md)）

mcp-node-zig 是一个支持 MCP 的远程执行节点：在机器上放一个静态二进制文件，你的智能体就能在那里执行命令、驱动长时间运行的会话，以及读写文件。从 v0.2.0 起，节点可以主动连接枢纽，而不必监听端口，因此位于 NAT 或他人防火墙后面的机器也能访问，无需开放入站端口，也无需 SSH。它启动后 1.9 ms 即可响应第一个 MCP 请求，空闲时仅占 0.62 MiB，所以在每台机器上都留一个节点常驻，基本不花什么成本。

## 安装

```sh
curl -fsSL https://raw.githubusercontent.com/alexchen-sys/mcp-node-zig/main/install.sh | sh
```

脚本会检测平台，下载最新版本，用 `SHA256SUMS.txt` 校验后安装到 `/usr/local/bin`（或 `~/.local/bin`）。用 `MCP_NODE_VERSION=0.2.0` 固定版本，用 `PREFIX=/some/dir` 更改安装目录。

手动安装（Linux x86_64）：

```sh
curl -L https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.2.0/mcp-node-v0.2.0-x86_64-linux.tar.gz | tar xz
```

其他平台见 [Releases 页面](https://github.com/alexchen-sys/mcp-node-zig/releases)：`aarch64-linux`、`aarch64-macos`、`x86_64-windows`。每个版本都附带 `SHA256SUMS.txt`。

## 快速上手

```sh
openssl rand -hex 32 > token
./mcp-node-v0.2.0-x86_64-linux/mcp-node &

curl -sS http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H "X-Node-Token: $(cat token)" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
```

返回的 JSON 包含主机名、操作系统、负载、内存和运行时长。接下来接入你的智能体：

```sh
claude mcp add --transport http mcp-node http://127.0.0.1:8341/mcp \
  --header "X-Node-Token: $(cat token)"
```

<details>
<summary>Windows（PowerShell）</summary>

```powershell
curl.exe -L -o mcp-node.zip https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.2.0/mcp-node-v0.2.0-x86_64-windows.zip
Expand-Archive mcp-node.zip
[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N') | Set-Content -NoNewline -Encoding Ascii token
.\mcp-node-v0.2.0-x86_64-windows\mcp-node.exe
```

在另一个窗口中执行：

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8341/mcp -Method Post -ContentType "application/json" `
  -Headers @{ "X-Node-Token" = (Get-Content token) } `
  -Body '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
```

</details>

## 为什么用它

- **无需任何准备。** 不需要 Node、Python、OpenSSH，也不用分发密钥。复制一个文件，运行即可。
- **进程比请求活得久。** 启动一次构建，断开连接，回来后按偏移量读取输出。
- **常驻成本很低。** 空闲时不到 1 MiB。每多连接一个智能体，只增加约 288 KiB，而不是再起一个约 190 MiB 的服务器进程。
- **除非你要求，否则不用 shell。** `exec` 原样传递 argv。`exec_shell` 是唯一显式的 shell 层。
- **终止整棵进程树。** POSIX 上用进程组，Windows 上用 Job Object。不会留下占着管道的孤儿子进程。
- **支持 Linux、macOS、Windows。** 每次推送，CI 都会构建这三个平台并跑冒烟测试。

## 它和 SSH 有什么不同？

两者解决的是不同的问题，搭配使用效果很好。

SSH 是安全传输通道，也是给人用的终端。它有加密、密钥管理、agent 转发、PTY、scp/sftp/rsync，以及几十年的安全加固。这些场景请继续用它。

mcp-node 是面向智能体的执行 API。通过 SSH，智能体拿到的是一个还要被远程 shell 再解析一遍的字符串，外加原始字节和退出状态。而在这里，它拿到的是：

- **不经过 shell 的 argv。** 不用为远程 shell 的二次解析再做一轮转义。只有在你调用 `exec_shell` 时才会用到 shell。
- **结构化结果。** `stdout`、`stderr`、`exit_code`、`truncated_*` 和耗时以 JSON 返回，每次调用可单独设置超时。
- **比请求活得久的会话。** 用 `exec_start` 启动，用 `exec_poll` 按字节偏移读取，用 `exec_write` 写入 stdin，用 `exec_wait` 最多等待 300 s，用 `exec_kill` 终止整棵进程树。连接断了，构建也不会中断。
- **可校验的文件写入。** `write_file` 接收 base64，并返回实际落盘内容的 SHA-256。
- **自描述的接口。** 任何 MCP 客户端都能通过 `tools/list` 发现工具，无需额外教智能体。

速度不是重点：连接建立后，两者都很快。mcp-node 本身不做加密，所以对远程机器的常见做法是两者配合：节点监听 `127.0.0.1`，你通过 SSH 隧道（`ssh -L 8341:127.0.0.1:8341 host`）、VPN 或 TLS 反向代理访问它。

## 反向连接（无需入站端口）

对于位于 NAT 后面或没有 sshd 的机器，用
`--connect hub:port` 启动节点：它会主动连接枢纽（即设置了
`MCP_NODE_HUB_LISTEN` 的同一个二进制文件），客户端通过枢纽上的 `/n/<name>/mcp` 访问它。
详见 [docs/reverse-connect.md](docs/reverse-connect.md)。

## 工具

| 工具 | 作用 |
| --- | --- |
| `sys_info` | 主机名、操作系统、负载、内存、运行时长 |
| `exec` | 执行 argv 直到结束，不经过 shell |
| `exec_shell` | 通过 `bash`/`sh`/`fish`/`zsh` 执行脚本，Windows 上用 `cmd`/`powershell` |
| `exec_start` | 以会话形式启动长时间运行的进程 |
| `exec_poll` | 按字节偏移读取会话输出 |
| `exec_wait` | 阻塞直到会话退出或达到 `timeout`（默认 30 s，最长 300 s） |
| `exec_write` | 向 stdin 写入 base64 字节；`eof=true` 关闭 stdin |
| `exec_kill` | 终止会话的进程树 |
| `exec_close` | 释放会话；幂等 |
| `exec_list` | 列出存活的会话 |
| `read_file` | 按 offset/limit 读取 UTF-8 文本 |
| `write_file` | 写入 base64 内容，自动创建父目录，返回 SHA-256 |
| `list_dir` | 列出目录项及其类型、大小、mtime |

完整 schema 可通过 `tools/list` 获取。`exec` 和 `exec_shell` 的超时默认 120 s，取值限制在 1–1800 s。

## 客户端

下面所有客户端都使用相同的 URL 和 token。`Authorization: Bearer <token>` 在所有客户端中都可用；对于无法设置 `Authorization` 的客户端，也接受 `X-Node-Token: <token>`。

Cursor（`.cursor/mcp.json`）：

```json
{
  "mcpServers": {
    "mcp-node": {
      "url": "http://127.0.0.1:8341/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

VS Code（`.vscode/mcp.json`）：

```json
{
  "servers": {
    "mcp-node": {
      "type": "http",
      "url": "http://127.0.0.1:8341/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

Codex（`~/.codex/config.toml`）：

```toml
[mcp_servers.mcp-node]
url = "http://127.0.0.1:8341/mcp"
http_headers = { "Authorization" = "Bearer <token>" }
```

Claude Desktop 和其他使用 JSON 配置的客户端：与 Cursor 相同，另加 `"type": "http"`。

仅支持 stdio 的客户端：`npx mcp-remote http://127.0.0.1:8341/mcp --header "Authorization: Bearer <token>"`

## 安全

- **必须提供 token。** token 文件缺失或为空时，服务器拒绝启动。比较采用常数时间。
- **默认仅监听回环地址。** 它绑定 `127.0.0.1`。如需对外暴露，设置 `MCP_NODE_HOST`，并把客户端使用的 `host:port` 加入 `MCP_NODE_ALLOWED_HOSTS`。
- **先校验 Host 和 Origin**，再解析请求体：未知 Host 返回 421，未知 Origin 返回 403。
- **不内置 TLS。** 请放在反向代理、隧道或 VPN 后面，例如 `caddy reverse-proxy --from node.example.com --to 127.0.0.1:8341`。
- **拿到 token 就等于拿到节点运行用户的 shell。** 请用权限只覆盖智能体所需范围的账户来运行它。

## 配置

只通过环境变量配置。

| 变量 | 默认值 |
| --- | --- |
| `MCP_NODE_HOST` | `127.0.0.1`（IP 字面量） |
| `MCP_NODE_PORT` | `8341` |
| `MCP_NODE_TOKEN_FILE` | `./token` |
| `MCP_NODE_ALLOWED_HOSTS` | `127.0.0.1:*,localhost:*,[::1]:*` |
| `MCP_NODE_ALLOWED_ORIGINS` | `http://127.0.0.1:*,http://localhost:*,http://[::1]:*` |
| `MCP_NODE_NAME` | `mcp-node`（serverInfo 名称） |
| `MCP_NODE_MAX_OUT` | 每个输出流 `400000` 字节，超出后标记为 `truncated_*` |
| `MCP_NODE_MAX_CONN` | `128` 个并发连接，超出后返回 503 |
| `MCP_NODE_MAX_SESSIONS` | `64` 个存活会话 |
| `MCP_NODE_SESSION_TTL_S` | `600`，已结束会话的回收延迟 |
| `MCP_NODE_SOCKET_TIMEOUT_S` | `60` |
| `MCP_NODE_MAX_INFLIGHT_BYTES` | `67108864`，在途请求体的总大小上限 |
| `MCP_NODE_TEXT_MIRROR` | `1`；设为 `0` 时只返回 `structuredContent`，响应体积减半 |
| `MCP_NODE_INSECURE` | 未设置；设为 `1` 时允许空 token（不建议） |

`mcp-node --version` 输出版本号，`--help` 输出参数说明；除这两个和 `--connect` 之外，传入其他参数都会报错。

反向连接相关变量（`MCP_NODE_CONNECT*`、`MCP_NODE_HUB_*`）见
[docs/reverse-connect.md](docs/reverse-connect.md)。

## 故障排查

| 现象 | 解决办法 |
| --- | --- |
| 401 | token 错误或缺失。如果同时发送两个请求头，两者必须一致。 |
| 421 | 把你连接时使用的 `host:port` 加入 `MCP_NODE_ALLOWED_HOSTS`。 |
| 403 | 浏览器的 `Origin` 不在 `MCP_NODE_ALLOWED_ORIGINS` 中。 |
| 415 | 发送 `Content-Type: application/json`。 |
| 连接被拒绝 | 检查 `MCP_NODE_HOST`/`MCP_NODE_PORT`；回环地址无法从其他机器访问。 |
| 启动即退出 | 创建一个非空的 token 文件。 |

## 局限

仅支持明文 HTTP，不支持 PTY（交互式 TUI 无法使用），暂无审计日志。这三项都已列入路线图。API 版本为 `0.1.x`，后续可能变动。

## 从源码构建

需要 Zig 0.16。

```sh
git clone https://github.com/alexchen-sys/mcp-node-zig
cd mcp-node-zig
zig build test
zig build -Doptimize=ReleaseSafe   # → zig-out/bin/mcp-node
```

在 Linux 上，二进制文件是静态链接的，不依赖 libc。macOS 上只链接 libSystem；Windows 上只链接 kernel32/ntdll。

## 许可证

MIT
