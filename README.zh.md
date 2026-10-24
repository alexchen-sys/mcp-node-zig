# mcp-node-zig

[![CI](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/alexchen-sys/mcp-node-zig)](https://github.com/alexchen-sys/mcp-node-zig/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](README.md) | [Русский](README.ru.md) | 中文

你的服务器主动连回你的枢纽。智能体在任何机器上（哪怕在 NAT 后面）都能拿到结构化的 shell；密钥、边界和紧急开关始终在你手里。

![mcp-node-zig：冷启动、一次 exec 调用、本地节点上的活动会话列表（v0.5.0）](assets/demo.gif)

mcp-node-zig 是一个支持 MCP 的静态二进制文件。把它放到机器上，你的智能体就能在那里执行命令、驱动长时间运行的会话、读写文件。节点主动连接你自己运行的枢纽（同一个二进制文件），所以机器不开放任何入站端口，SSH 密钥永远不会交到智能体手里，路径上也没有第三方云。链路用 HMAC-SHA256 双向认证并走 TLS，枢纽按来源限制握手，每次工具调用都可以写入防篡改的审计日志。

**2.0 ms** 冷启动 · **1.2 ms** p50 执行往返 · **1.57 MiB** 空闲 RSS · **9.6 MiB** 单文件体积（[基准测试](BENCHMARKS.md)）

## 安装

```sh
curl -fsSL https://raw.githubusercontent.com/alexchen-sys/mcp-node-zig/main/install.sh | sh
```

脚本会检测平台，下载最新版本，用 `SHA256SUMS.txt` 校验后安装到 `/usr/local/bin`（或 `~/.local/bin`）。需要内置 TLS 服务器的枢纽，加上 `MCP_NODE_FLAVOR=tls`（Linux 和 macOS 版本）。用 `MCP_NODE_VERSION=0.5.0` 固定版本，用 `PREFIX=/some/dir` 更改安装目录。

手动安装（Linux x86_64）：

```sh
curl -L https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.5.0/mcp-node-v0.5.0-x86_64-linux.tar.gz | tar xz
```

其他平台见 [Releases 页面](https://github.com/alexchen-sys/mcp-node-zig/releases)：`aarch64-linux`、`aarch64-macos`、`x86_64-windows`。每个版本都附带 `SHA256SUMS.txt`，并用 [cosign](https://github.com/sigstore/cosign) 无密钥（Sigstore）签名；当 PATH 中有 cosign 时，`install.sh` 会校验签名。

## 快速上手

```sh
openssl rand -hex 32 > token
./mcp-node-v0.5.0-x86_64-linux/mcp-node &

curl -sS http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H "X-Node-Token: $(cat token)" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
```

返回的 JSON 包含主机名、操作系统、负载、内存和运行时间。接下来接入你的智能体：

```sh
claude mcp add --transport http mcp-node http://127.0.0.1:8341/mcp \
  --header "X-Node-Token: $(cat token)"
```

<details>
<summary>Windows（PowerShell）</summary>

```powershell
curl.exe -L -o mcp-node.zip https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.5.0/mcp-node-v0.5.0-x86_64-windows.zip
Expand-Archive mcp-node.zip
[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N') | Set-Content -NoNewline -Encoding Ascii token
.\mcp-node-v0.5.0-x86_64-windows\mcp-node.exe
```

在另一个窗口中执行：

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8341/mcp -Method Post -ContentType "application/json" `
  -Headers @{ "X-Node-Token" = (Get-Content token) } `
  -Body '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
```

</details>

## 为什么用它

- **密钥留在你手里。** 智能体拿到的是节点的 token，而不是 SSH 密钥。停掉节点，访问立即失效；轮换 token，所有旧副本随即作废。
- **无需部署任何依赖。** 不需要 Node、Python、OpenSSH，也不用分发密钥。复制一个文件，运行即可。
- **进程不随请求结束。** 启动一次构建，断开连接，回来后按偏移量读取输出。
- **常驻成本很低。** 空闲 RSS 1.57 MiB。每多连接一个智能体，只增加约 304 KiB，而不是再起一个约 100–150 MiB 的服务器进程。
- **除非你要求，否则不用 shell。** `exec` 原样传递 argv。`exec_shell` 是唯一显式的 shell 层。
- **终止整棵进程树。** POSIX 上用进程组，Windows 上用 Job Object。不会留下占着管道的孤儿子进程。
- **每次调用都有记录。** 开启审计日志后，每次工具调用都会写入一行 HMAC 链式 JSONL，`audit-verify` 可离线校验。
- **支持 Linux、macOS、Windows。** 每次推送，CI 都会构建这三个平台并跑冒烟测试。

## 它和 SSH 有什么不同？

两者解决的是不同的问题，搭配使用效果很好。

SSH 是安全传输通道，也是给人用的终端。它有加密、密钥管理、agent 转发、PTY、scp/sftp/rsync，以及几十年的安全加固。这些场景请继续用它。

mcp-node 是面向智能体的执行 API。通过 SSH，智能体拿到的是一个还要被远程 shell 再解析一遍的字符串，外加原始字节和退出状态。而在这里，它拿到的是：

- **不经过 shell 的 argv。** 不用为远程 shell 的二次解析再做一轮转义。只有在你调用 `exec_shell` 时才会用到 shell。
- **结构化结果。** `stdout`、`stderr`、`exit_code`、`truncated_*` 和耗时以 JSON 返回，每次调用可单独设置超时。
- **会话独立于请求存在。** 用 `exec_start` 启动，用 `exec_poll` 按字节偏移读取，用 `exec_write` 写入 stdin，用 `exec_wait` 最多等待 300 s，用 `exec_kill` 终止整棵进程树。连接断了，构建也不会中断。
- **可校验的文件写入。** `write_file` 接收纯文本或 base64，并返回实际落盘内容的 SHA-256。
- **自描述的接口。** 任何 MCP 客户端都能通过 `tools/list` 发现工具，无需额外教智能体。

对远程机器，[反向连接](#反向连接无需入站端口)可以取代隧道：目标机器不需要 sshd，密钥也不会交到智能体手里。已经部署了 SSH 的地方，两者可以配合：节点监听 `127.0.0.1`，再转发端口（`ssh -L 8341:127.0.0.1:8341 host`）。

## 反向连接（无需入站端口）

对于位于 NAT 后面或没有 sshd 的机器，用 `--connect hub:port` 启动节点：它会主动连接枢纽（即设置了 `MCP_NODE_HUB_LISTEN` 的同一个二进制文件），客户端通过枢纽上的 `/n/<name>/mcp` 访问它。默认配置用 TLS 保护这条链路：枢纽的节点端口只监听 `127.0.0.1`，前面由 TLS 终结器（nginx `stream`、stunnel、HAProxy）接管公网端口，节点用 `MCP_NODE_CONNECT_TLS=1` 连接：

```sh
# 枢纽；nginx/stunnel 在 :8400 终结 TLS，转发到 127.0.0.1:8401
MCP_NODE_HUB_LISTEN=127.0.0.1:8401 MCP_NODE_HUB_SECRET_FILE=nodes ./mcp-node
# 节点；枢纽上的 `nodes` 含一行 laptop:<secret>，这里的 `secret` 只含 <secret>
MCP_NODE_NAME=laptop MCP_NODE_CONNECT_SECRET_FILE=secret MCP_NODE_CONNECT_TLS=1 \
  ./mcp-node --connect hub.example.com:8400
```

`-tls` 发布版本（或任何用 `-Dtls-server` 构建的二进制）可以在节点链路端口上直接提供 TLS（`MCP_NODE_HUB_TLS_CERT_FILE` / `MCP_NODE_HUB_TLS_KEY_FILE`），无需前置终结器；此时枢纽能看到真实的对端地址，按来源的握手限制完全生效。

完整的配置步骤、终结器配置，以及可信局域网下的明文 TCP 方式见 [docs/reverse-connect.md](docs/reverse-connect.md)。

## stdio 模式

以子进程方式启动服务器的客户端，可以直接用 `--stdio` 运行节点（或设置
`MCP_NODE_STDIO=1`）。消息是按行分隔的 JSON-RPC：stdin 每行一个请求，
stdout 每行一个响应。没有监听端口，也不需要 token；管道由启动这个
进程的一方持有。日志只写到 stderr；stdin 关闭时节点以 0 退出，并杀掉
所有仍在运行的非持久会话（持久会话正是那个显式可选的例外：它们会脱离
进程并存活下来，见[持久会话](#持久会话)）。

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

`--stdio` 不能与 `--connect` 或 `MCP_NODE_HUB_LISTEN` 同时使用。

## 审计日志

设置 `MCP_NODE_AUDIT_FILE` 后，每次工具调用都会留下一条仅追加的 JSONL 记录，
记录之间用 HMAC-SHA256 链接，因此对历史记录的篡改、删除和乱序都可以离线检测：

```sh
openssl rand -hex 32 > audit-key && chmod 600 audit-key
MCP_NODE_AUDIT_FILE=/var/log/mcp-node.jsonl MCP_NODE_AUDIT_KEY_FILE=./audit-key ./mcp-node
mcp-node audit-verify --anchor /var/log/mcp-node.jsonl
```

节点记录每个 `tools/call`（工具、传输方式、对端、按工具的参数摘要、结果），
枢纽记录 `relay` 路由与链路生命周期；两侧通过 `req_id` 关联。
脚本、文件内容和 stdout 永远不会被记录。
细节与威胁模型见 [docs/audit-log.md](docs/audit-log.md)。

## 工具

| 工具 | 作用 |
| --- | --- |
| `sys_info` | 主机名、操作系统、负载、内存、运行时间 |
| `exec` | 执行 argv 直到结束，不经过 shell；`max_bytes`/`head_lines`/`tail_lines` 可裁剪超长输出 |
| `exec_shell` | 通过 `bash`/`sh`/`fish`/`zsh` 执行脚本，Windows 上用 `cmd`/`powershell`；支持与 `exec` 相同的输出裁剪 |
| `exec_start` | 以会话形式启动长时间运行的进程 |
| `exec_poll` | 按字节偏移读取会话输出，`max_bytes` 分页 |
| `exec_wait` | 阻塞直到会话退出或达到 `timeout`（默认 30 s，最长 300 s） |
| `exec_write` | 向 stdin 写入 base64 字节；`eof=true` 关闭 stdin |
| `exec_kill` | 终止会话的进程树 |
| `exec_close` | 释放会话；幂等 |
| `exec_list` | 列出存活的会话 |
| `read_file` | 按 offset/limit 或 `line_offset`/`line_limit` 行窗口读取 UTF-8 文本 |
| `write_file` | 写入纯文本（`content`）或 base64（`content_b64`），自动创建父目录，返回 SHA-256 |
| `list_dir` | 列出目录项及其类型、大小、mtime |
| `copy_path` | 将文件或目录树复制到精确的新目标；暂存后原子发布，绝不覆盖已有内容 |

完整 schema 可通过 `tools/list` 获取。`exec` 和 `exec_shell` 的超时默认 120 s，取值限制在 1–1800 s。

## 持久会话

Exec 会话存在于节点进程中，不属于任何连接。会话能挺过枢纽<->节点
链路断开、枢纽重启以及任意客户端断连：没有人轮询时捕获照常进行，
重连后同一个 `session_id` 从你上次回复的字节 offset 继续（无空洞、
无重复）。回复丢失时用 `exec_list` 找回 id。

默认情况下会话保存在内存中（节点进程崩溃、OOM-kill 或机器重启后，旧 id 返回 `unknown_session`）。每个
输出流上限为 `MCP_NODE_MAX_OUT` 字节；达到上限后保留头部，设置
`truncated_*` 标志，并通过 `lost_*_bytes` 报告后续丢弃的字节数。已结束的会话在 `MCP_NODE_SESSION_TTL_S` 之后
回收；运行中的会话不会按时间回收。

### 可选的磁盘持久化（`durable: true`）

配置 `MCP_NODE_STATE_DIR`（或 `--state-dir`）后，`exec_start` 接受
`"durable": true`：子进程的 stdout/stderr 从启动起追加写入
按会话划分的磁盘日志文件，且会话记录在子进程开始写入前提交。
节点重启后会恢复该会话：用同一个 id 调用 `exec_poll` 会返回
`recovered: true` 以及相对原偏移量的字节级增量，`exec_kill` 在发送信号前会校验进程身份（PID + 启动时间 + 启动号）。
主进程通过 pidfd 接收信号，不会命中被复用的 PID。仍存在一个
狭窄竞态：在身份校验和向进程组发送信号之间，旧进程组可能退出且新
进程组可能复用其数字 ID。

落盘数据：`argv`、`cwd` 以及完整的 stdout/stderr 日志以**明文**保存在
state 目录下（若命令可能输出机密，请按 shell 历史同等保护）。目录仅保存在本地磁盘，要求权限为 `0700`。

恢复后的会话通过状态字段显式报告受限能力：`stdin_available: false`
（`exec_write` 返回 `StdinUnavailable`）；若子进程在节点停机期间
退出，`exit_code` 为 `null`，并带 `completion_reason: "orphaned_exit"`。
启用策略文件时，记录按 token 所有者哈希隔离（owner binding）；未配置策略时所有请求共享默认零号所有者。已关闭或已回收的持久会话在墓碑保留窗口内
返回 `unknown_session` 且带 `expired: true`。未配置 state dir 时使用
`durable: true` 会返回 `DurabilityDisabled`；state 目录本身必须为
`0700`，并通过文件锁防止多个节点实例共用（`StateDirLocked`）。本地状态目录总容量受
`MCP_NODE_STATE_MAX_BYTES`（默认 64 MiB）限制。v0.5.0 中持久会话
仅支持 Linux；其他平台返回 `DurabilityUnsupported`。

未知或过期的 `session_id` 返回
`{"ok": false, "error": "unknown_session", "session_id": ..., "expired": ..., "message": ...}`
结构化工具结果（`isError: true`），而非 JSON-RPC 协议层 `-32602`。`expired: true`
表示本节点最近持有过该会话并关闭/回收/驱逐了它（新鲜度窗口有界：
很久以前移除的 id 会被遗忘而回答 `expired: false`，本节点从未持有
的 id、或早于节点重启的 id 同样如此：消息里写明了这一点）。同一
情况下 `exec_close` 保持幂等的
`{"ok": true, "already_closed": true}`。

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

仅支持 stdio 的客户端：让节点自己以 `--stdio` 运行（见 [stdio 模式](#stdio-模式)），或者通过 HTTP 用 `npx mcp-remote http://127.0.0.1:8341/mcp --header "Authorization: Bearer <token>"` 桥接到远程节点。

## 安全

- **必须提供 token。** token 文件缺失或为空时，服务器拒绝启动。比较采用常数时间。
- **按令牌的参数限制（可选）。** `MCP_NODE_POLICY_FILE` 在参数层面约束每个客户端 token 能做什么：argv[0] 白名单、读写与 cwd 的路径前缀、超时与写入模式上限、归属于 token 的会话。见[参数限制](docs/arg-gating.md)，配置示例见[按令牌的权限](#按令牌的权限)。
- **默认仅监听回环地址。** 它绑定 `127.0.0.1`。如需对外暴露，设置 `MCP_NODE_HOST`，并把客户端使用的 `host:port` 加入 `MCP_NODE_ALLOWED_HOSTS`。
- **先校验 Host 和 Origin**，再解析请求体：未知 Host 返回 421，未知 Origin 返回 403。
- **链路走 TLS。** 节点链路使用 TLS，可由 `-Dtls-server` 构建的枢纽直接提供，也可由任意终结器提供。本地 HTTP API 只监听回环地址；如需对外暴露，请放在反向代理、隧道或 VPN 后面，例如 `caddy reverse-proxy --from node.example.com --to 127.0.0.1:8341`。
- **拿到 token 就等于拿到节点运行用户的 shell。** 请用权限只覆盖智能体所需范围的账户来运行它。

## 安全模型

- **持有客户端 token 的人就能执行命令。** 在普通节点上这意味着该节点；在枢纽上，token 可以触达每一台已连接的节点，所以请把枢纽 token 视为所有节点权限之和。
- **枢纽能看到全部内容。** TLS 终结在它上面（或它前面），因此它以明文处理每个请求和响应；掌握某个节点密钥的枢纽可以在该节点上执行任何操作。
- **节点密钥等于该节点上的 shell，并占有其名称。** `name:secret` 每行为一个名称设置独立密钥；单一共享密钥允许任何持有者以任意名称连接，包括尚未被占用的名称。
- **握手负责认证，之后每个帧都带标签。** 枢纽与节点用基于新鲜 nonce 的 HMAC-SHA256 证明密钥，握手后的帧按方向携带带严格序号的 HMAC-SHA256 标签，因此主动中继无法伪造、重排或重放它们。明文 TCP 上的帧仍然不加密：中继可以读取（但无法修改）它们。
- **跨越不受你控制的网络时使用 TLS。** `MCP_NODE_CONNECT_TLS=1` 让节点校验证书链和服务器名，没有关闭校验的开关。用 `-Dtls-server` 构建的二进制可以直接在枢纽的链路端口上提供 TLS（见[反向连接](#反向连接无需入站端口)）；否则请在该端口前面终结 TLS，并让端口留在回环地址上。
- **明文 TCP 链路只用于同一主机或可信局域网。**
- **握手限制按来源地址计算。** 枢纽总共最多进行 16 个未认证的握手，来自同一 IPv4 地址或 IPv6 /64 的最多 4 个；同一来源一分钟内失败 8 次握手会被拒绝一分钟。127.0.0.1 和 ::1 不受此限制，所以在本机 TLS 终结器后面所有节点看起来来自同一地址：请在终结器上设置按 IP 的限制（nginx `limit_conn`），并尽量用防火墙把公网端口限制到已知来源。使用内置 TLS 服务器时枢纽能看到真实的对端地址，上述限制完全生效。
- **权限是可选开启的，不是沙箱。** 未设置 `MCP_NODE_POLICY_FILE` 时，任何 token 都能调用所有工具；设置后，每个 token 只能使用自己的工具列表和参数范围（[参数限制](docs/arg-gating.md)）。允许的解释器仍然等于任意代码。
- **不在范围内：** 沙箱，以及已被攻破的枢纽或节点主机。节点以其操作系统用户的完整权限运行。（审计日志可检测记录篡改，但无法防御控制主机的攻击者。）

## 按令牌的权限

`MCP_NODE_POLICY_FILE` 把单一共享 token 变成一组 token，每个 token 有自己的工具列表和参数边界：

```json
{
  "version": 1,
  "tokens": [
    {
      "file": "/etc/mcp-node/tokens/build",
      "tools": ["sys_info", "exec", "read_file", "list_dir"],
      "exec_argv0": ["/usr/bin/git", "/usr/bin/make"],
      "exec_cwd": ["/srv/build"],
      "max_timeout_s": 120,
      "read_paths": ["/srv/build"],
      "read_deny": ["/srv/build/keys"]
    },
    {"file": "/etc/mcp-node/tokens/admin", "allow_all": true}
  ]
}
```

节点在执行前检查每次调用：被拒绝的 `exec` 不会启动，被拒绝的写入不会打开文件。策略可以限制 argv[0]、`cwd`、读写路径、超时上限和新建文件的权限模式。路径先规范化（符号链接、`..`），再按完整路径段匹配。会话归启动它的 token 所有。拒绝结果为 `{"ok": false, "error": "PolicyDenied", "reason": ...}`，并以 `policy.deny` 事件写入审计日志。token 的值不会进入策略文件或日志。

不设置该变量时，节点行为与之前完全相同。设置策略后，节点自身的令牌（`MCP_NODE_TOKEN_FILE`）也必须是 `tokens[].file` 中的一项，否则节点会以 `InvalidConfig` 拒绝启动。解析是严格的：未知键或互相矛盾的配置会让启动失败。枢纽设置了策略文件会拒绝启动，因为 `/n/<name>/mcp` 路由把请求体原样转发给节点；请在每个节点上配置策略。允许一个解释器（`python3`、`bash`）仍然等于允许任意代码。细节与限制见 [docs/arg-gating.md](docs/arg-gating.md)。

## 配置

环境变量，加上两个命令行参数：`--connect`（反向连接目标）和 `--state-dir`
（持久会话日志；等同于 `MCP_NODE_STATE_DIR`，参数优先）。

| 变量 | 默认值 |
| --- | --- |
| `MCP_NODE_STATE_DIR` | 未设置；设置后（或给出 `--state-dir`）`exec_start` 接受 `durable:true`，会话可跨越节点重启。目录必须是私有的（`0700`）、归节点所有，并在节点生命周期内加锁 |
| `MCP_NODE_STATE_MAX_BYTES` | `67108864`（64 MiB）；持久会话的总准入预算（每个会话预留：2 x 输出上限 + 80 KiB；节点在每次刷新时以及按 1 Hz 的清扫检查 spool 大小，合并日志超出预留的会话会以已校验的身份被终止，并返回 `completion_reason: "output_cap"`；这是尽力而为的边界：写入方可能在两次检查之间超额，而节点停机期间写入的输出会在下次启动时核对，而不是被阻止） |
| `MCP_NODE_HOST` | `127.0.0.1`（IP 字面量） |
| `MCP_NODE_PORT` | `8341` |
| `MCP_NODE_TOKEN_FILE` | `./token` |
| `MCP_NODE_POLICY_FILE` | 未设置（不启用参数限制；见 [docs/arg-gating.md](docs/arg-gating.md)） |
| `MCP_NODE_ALLOWED_HOSTS` | `127.0.0.1:*,localhost:*,[::1]:*` |
| `MCP_NODE_ALLOWED_ORIGINS` | `http://127.0.0.1:*,http://localhost:*,http://[::1]:*` |
| `MCP_NODE_NAME` | `mcp-node`（serverInfo 名称） |
| `MCP_NODE_MAX_OUT` | 每个输出流 `400000` 字节，超出后置位 `truncated_*` 并计入 `lost_*_bytes` |
| `MCP_NODE_MAX_CONN` | `128` 个并发连接，超出后返回 503 |
| `MCP_NODE_MAX_SESSIONS` | `64` 个存活会话 |
| `MCP_NODE_SESSION_TTL_S` | `600`，已结束会话的回收延迟 |
| `MCP_NODE_SOCKET_TIMEOUT_S` | `60` |
| `MCP_NODE_MAX_INFLIGHT_BYTES` | `67108864`，在途请求体的总大小上限 |
| `MCP_NODE_TEXT_MIRROR` | `1`；设为 `0` 时只返回 `structuredContent`，响应体积减半 |
| `MCP_NODE_INSECURE` | 未设置；设为 `1` 时允许空 token（不建议） |
| `MCP_NODE_STDIO` | 未设置；`1` 时通过 stdin/stdout 服务单个客户端，无监听器（等同于 `--stdio`） |
| `MCP_NODE_AUDIT_FILE` | 未设置；在此路径启用[审计日志](docs/audit-log.md) |
| `MCP_NODE_AUDIT_KEY_FILE` | 未设置；审计链的 HMAC 密钥（0600），独立于 token 和链路密钥 |
| `MCP_NODE_AUDIT_ARGS` | `summary`；`full` 记录完整 argv 与路径，但绝不记录内容 |
| `MCP_NODE_AUDIT_ON_FULL` | `block`；`drop` 在磁盘卡顿时丢弃记录并留下带链的 `dropped` 标记 |
| `MCP_NODE_AUDIT_MAX_BYTES` | `67108864`；超过后文件轮转为 `<file>.<chain-gen>.<first-seq>`（绝不覆盖已有文件），链在新文件中继续 |

`mcp-node --version` 输出版本号，`--help` 输出参数说明；除这两个参数以及
`--connect`、`--stdio`、`--state-dir` 之外，传入其他参数都会报错。唯一的
子命令是 `mcp-node audit-verify [--anchor] <file>...`，用于离线校验审计日志链。

反向连接相关变量（`MCP_NODE_CONNECT*`、`MCP_NODE_HUB_*`）见 [docs/reverse-connect.md](docs/reverse-connect.md)。

## 故障排查

| 现象 | 解决办法 |
| --- | --- |
| 401 | token 错误或缺失。如果同时发送两个请求头，两者必须一致。 |
| 421 | 把你连接时使用的 `host:port` 加入 `MCP_NODE_ALLOWED_HOSTS`。 |
| 403 | 浏览器的 `Origin` 不在 `MCP_NODE_ALLOWED_ORIGINS` 中。 |
| 415 | 发送 `Content-Type: application/json`。 |
| 连接被拒绝 | 检查 `MCP_NODE_HOST`/`MCP_NODE_PORT`；回环地址无法从其他机器访问。 |
| 启动即退出 | 创建一个非空的 token 文件。 |

## 路线图

已发布：带双向 HMAC 握手的反向连接，以及经认证并校验序号的帧、节点链路 TLS（全平台）、按来源的握手限制、防篡改审计日志、按 token 的工具与参数权限、在链路断开或枢纽重启后仍存活的 exec 会话、在节点重启后仍存活的持久 exec 会话（可选开启，仅 Linux）、带构建溯源的 cosign 签名发布。

下一步：用每节点密钥对取代共享密钥、macOS/Windows 上的持久会话，以及支持交互式 TUI 的 PTY。API 仍是 `0.x`，1.0 之前仍可能变动。

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

MIT。节点、枢纽、按令牌的权限和审计日志永远保持 MIT；如果将来出现付费产品，那会是托管的控制平面，而不是从这个二进制文件里拿走的功能。
