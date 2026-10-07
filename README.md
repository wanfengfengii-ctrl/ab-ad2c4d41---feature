# Attestation Guard

卫星载荷配置下发前的**签名与版本承接校验服务**。只有供应商签名有效、且版本号承接当前已接纳版本的配置证明才会被接纳，从而防止重放、回退和并发请求造成分叉。

- 纯 Python 3.11 标准库实现（内置 RFC 8032 Ed25519），镜像构建无需联网安装依赖。
- 状态持久化在 SQLite（WAL + `BEGIN IMMEDIATE`），重启后仍可查询唯一已接纳代次。
- 提供 Dockerfile 与 Docker Compose，包含健康检查、宿主机端口 `APP_PORT` 配置，以及一次性 `verify` 服务。

## API

### `GET /healthz`

健康检查，返回 `200 {"status":"ok"}`。

### `POST /api/attestations`

请求体（UTF-8 JSON）：

| 字段 | 说明 |
| --- | --- |
| `attestationId` | 本次证明的唯一编号（全局唯一，用于重放检测） |
| `keyId` | 随部署声明的供应商公钥编号 |
| `payloadBase64` | 载荷的 Base64；载荷为 UTF-8 JSON 的原始字节 |
| `signatureBase64` | 对**载荷解码后原始字节**的 Ed25519 签名，Base64 |

载荷 JSON 必须包含：

```json
{
  "deviceId": "sat-alpha",
  "generation": 2,
  "previousGeneration": 1,
  "configSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
```

可选字段：

| 字段 | 说明 |
| --- | --- |
| `activateAt` | 计划生效时刻：带 `Z`、精确到秒的 RFC 3339 UTC 时刻，如 `2026-10-07T12:34:56Z`。省略时记录在 `acceptedAt` 立即生效（行为与旧版完全一致）。 |

**接纳不等于生效**：带 `activateAt` 的证明一旦通过校验即成为设备当前已接纳头（`/head` 立刻可见），但在约定 UTC 时刻到来前不会成为生效配置；时刻跨过之后，生效配置自动切换，无需再次调用任何接口。

`configSha256` 必须是 **64 位小写十六进制**的配置 SHA-256。

接纳规则：

1. 用 `keyId` 对应的部署公钥验证签名；未知密钥 / 错误签名一律拒绝，且**不改变状态**。
2. 每台设备**首次**提交的 `previousGeneration` 必须为 `0`，且 `generation > 0`。
3. 后续提交必须 `previousGeneration == 当前已接纳 generation` 且 `generation` 严格更大（允许跳号）。
4. **相同编号 + 字节级相同内容**的重试：返回原接纳结果（`200`，`status:"duplicate"`），不写新状态；即使约定生效时刻已经过去，重试也只回放原记录，绝不生成新记录。
5. 相同编号但内容不同、同代次异内容、过期前代：均为 `409` 冲突，状态不变。
6. **生效次序不得倒退**：后继记录的生效时刻（显式 `activateAt`；省略时为接纳瞬间）不得早于上一代的生效时刻（上一代无 `activateAt` 时为其 `acceptedAt`）。同一时刻允许。
7. 并发请求由数据库写锁串行化，同一后继代次只有一个胜者，败者得到 `409 CONCURRENT_UPDATE`/冲突码，不产生分叉。

非法 `activateAt`（格式不符或不存在的日历时间）返回 `400 INVALID_JSON_PAYLOAD`；生效次序倒退返回 `409 ACTIVATION_NOT_ORDERED`。二者连同错误签名、并发竞争失败一样，**都不改变已接纳头或当前生效配置**。

成功响应：`201`（首次）或 `200`（重试）：

```json
{
  "status": "accepted",
  "deviceId": "sat-alpha",
  "generation": 2,
  "previousGeneration": 1,
  "configSha256": "...",
  "attestationId": "...",
  "acceptedAt": "2026-10-06T16:34:16Z",
  "activateAt": "2026-10-07T00:00:00Z"
}
```

仅当载荷携带 `activateAt` 时响应才包含该字段；省略时响应与旧版逐字段一致。

### `GET /api/devices/{deviceId}/head`

返回设备当前**唯一**已接纳代次与配置摘要（**不论是否已到生效时刻**）；服务重启后结果不变。未知设备返回 `404 DEVICE_NOT_FOUND`。

### `GET /api/devices/{deviceId}/effective`

按当前 UTC 时间返回**已到期计划中代次最高**的配置：

- 新接纳头的 `activateAt` 尚未到时，旧代继续作为生效配置返回；
- 跨过约定的那一秒后，只能查询到唯一的新生效代次（按 `generation` 取最高的已到期记录）；
- 省略 `activateAt` 的记录在 `acceptedAt` 即到期；**升级前卷中的旧记录视为在原 `acceptedAt` 立即生效**；
- 设备未知，或其全部已接纳配置都尚未到期：`404 NO_EFFECTIVE_CONFIG`。

响应体与 `/head` 的单条记录结构相同（到期记录携带自己的 `activateAt`，立即生效记录不含该字段）。

### 稳定错误码

| HTTP | code | 触发条件 |
| --- | --- | --- |
| 400 | `MALFORMED_REQUEST` | 请求字段缺失/类型错误、非 JSON |
| 400 | `INVALID_BASE64` | Base64 无法解码 |
| 400 | `INVALID_JSON_PAYLOAD` | 载荷非 UTF-8 JSON、缺字段、代次非整数、哈希格式错、`activateAt` 非合法时刻 |
| 401 | `UNKNOWN_KEY_ID` | 部署声明中不存在该 `keyId` |
| 401 | `INVALID_SIGNATURE` | Ed25519 验签失败 |
| 403 | `KEY_NOT_BOUND_TO_DEVICE` | 密钥绑定了其它设备 |
| 404 | `NO_EFFECTIVE_CONFIG` | `/effective`：设备未知或尚无任何已到期配置 |
| 409 | `FIRST_PREDECESSOR_NOT_ZERO` | 设备首单前代非 0 |
| 409 | `GENERATION_ZERO` | 新代次为 0 |
| 409 | `GENERATION_NOT_GREATER` | 新代次未严格递增 |
| 409 | `STALE_PREDECESSOR` | 前代不等于当前头（过期/回退/重放） |
| 409 | `ACTIVATION_NOT_ORDERED` | 新生效时刻早于上一代生效时刻 |
| 409 | `ATTESTATION_ID_CONTENT_MISMATCH` | 编号复用但签名内容不同 |
| 409 | `GENERATION_CONTENT_CONFLICT` | 同代次已接纳不同内容 |
| 409 | `CONCURRENT_UPDATE` | 并发竞争失败（请重新读取 head 后重试） |

所有冲突/鉴权失败都不会推进设备状态。

## 部署声明的公钥

编辑 `deploy/keys.json`（随部署提供，不经过 API 下发）：

```json
{
  "keys": {
    "vendor-sat-alpha-1": {
      "algorithm": "Ed25519",
      "publicKeyBase64": "BASE64(32 字节公钥)",
      "deviceId": "sat-alpha"
    }
  }
}
```

`deviceId` 可省略；填写后该密钥只能为该设备签名。生成密钥：

```bash
python3 -m scripts.keytool generate --key-id vendor-x --device-id sat-x --pretty
```

> 仓库 `deploy/keys.json` 中的密钥仅用于开发/演示（对应种子见 `deploy/dev-seeds.txt`，该文件不入镜像、不提交）。生产环境请替换。

## 运行

本地（无需 Docker）：

```bash
python3 -m app.server                     # 默认 :8080，数据 /data/attestations.db
APP_PORT=9090 DB_PATH=./data/att.db KEYS_PATH=./deploy/keys.json python3 -m app.server
```

Docker Compose：

```bash
cp .env.example .env        # 设置 APP_PORT（宿主机端口）
docker compose up -d --build api
curl -s localhost:${APP_PORT:-8080}/healthz
```

容器内部固定监听 8080；宿主机发布端口由 `APP_PORT` 控制（`${APP_PORT:-8080}:8080`）。
接纳数据保存在命名卷 `attest-data`（`/data`），因此重启后 head 依旧唯一可查。

### 一次性 `verify` 服务

运行代码测试、构建检查（字节码编译）和签名接纳冒烟，结束后**自行退出并以退出码汇总结果**：

```bash
docker compose run --build --rm verify
# 全部通过 -> 退出码 0；任一失败 -> 退出码非 0
```

冒烟在容器内自起一个临时 HTTP 服务，覆盖：健康检查、首次接纳、幂等重试、错误签名/未知密钥拒绝、后继承接、过期前代冲突、**计划生效（接纳头先推进、旧代继续生效、跨秒后唯一新代生效、非法时刻/次序倒退拒绝、到期后重试仍回放）**、以及**重启同一数据库后 head 与生效配置均保持唯一且分叉尝试被拒**。

## 测试

```bash
sh scripts/verify.sh        # = compileall + 全部 unittest + smoke
# 或
python3 -m unittest discover -v -s tests
```

测试包含 RFC 8032 官方向量、与 `cryptography` 库的双向互操作校验、接纳链规则、
同编号/同代次冲突、线程内与**跨进程**并发竞争、以及真实进程 `kill -9` 后的持久化验证。
