# 遥测网关 UDP 最大负载探测

小包能到回显端、大包却超时？本服务为值班员确认遥测网关**可用的最大 UDP 负载**：
FastAPI + asyncio 实现的探测 API 与本地回显端，默认探测范围 **576～1400 字节**，
二分搜索收敛，当次返回最大确认长度、各次探测结果及无法判定原因。

## 快速开始

### Docker Compose（推荐）

```bash
docker compose up --build
# 打开 http://localhost:8000/docs
```

### 本地运行

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 运行测试

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

## 值班流程（/docs 内即可操作）

1. **设置回显端行为**：`PUT /echo/config`
   - `{"mode": "normal", "drop_threshold": 1000}` — UDP 负载超过 1000 字节即丢弃；
   - `{"mode": "disconnect", "drop_threshold": null}` — 断联，丢弃一切报文；
   - 入参校验失败返回 422，**原配置保持不变**。
2. **发起探测**：`POST /probe`（Body 可全部缺省）

   ```json
   {"min_size": 576, "max_size": 1400, "timeout_ms": 500, "small_size": 64}
   ```
3. **读取结论**：

   | `status` | 含义 | `max_confirmed_size` |
   |---|---|---|
   | `ok` | 已确认最大可用负载 | 确认值（等于 `max_size` 时 `reached_range_max=true`，实际上限可能更高） |
   | `below_range` | 链路正常，但范围下限都确认不了 | `null` |
   | `undetermined` | 大包失败后小包复核也失败，**链路不确定** | 此前已确认的下界（无则 `null`），**绝不把故障当作尺寸上限** |
   | `invalidated` | 探测期间回显端配置被修改，**本次结论作废** | `null` |

   `attempts[]` 列出每次探测（`probe`）与小包复核（`link-verify`）的尺寸、结果与 RTT。
4. 历史结论：`GET /probes`、`GET /probe/{probe_id}`（内存保留最近 200 条）。

## 判定规则与需求对应

- **禁止 IP 分片**：探测与回显 socket 均设置 `IP_MTU_DISCOVER/IP_PMTUDISC_DO`（DF=1），
  结果中 `df_enabled` 如实上报；超过路径 MTU 时发送直接失败（EMSGSIZE），按发送失败处理。
- **报文带本次探测编号**：每次运行生成 UUID，连同序号写入 28 字节报文头
  （`magic | UUID | seq | size | 填充`）；只有 magic/编号/序号/长度**全部对应**的回包才算成功。
- **大包失败小包复核**：大包超时或发送失败 → 立即用 `small_size`（默认 64B）复核链路；
  小包通 = 确为尺寸受限，继续二分；小包也不通 = `undetermined`，故障不记为尺寸上限。
- **配置改变结论作废**：回显端配置带单调递增的 `epoch`，探测开始/每步/结束比对，
  不一致即 `invalidated`。
- **并发与迟到回包隔离**：每次探测运行使用独立临时端口 socket 并 connect 到回显端，
  其他运行的回包在内核层就被过滤；迟到的本次回包按序号拒收并计入 `stray_replies`。
- **配置失败保留原状态**：配置先经 Pydantic 校验，通过才原子替换并递增 epoch。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `ECHO_HOST` | `0.0.0.0` | 回显端监听地址 |
| `ECHO_PORT` | `9999` | 回显端 UDP 端口 |
| `PROBE_TARGET_HOST` | `127.0.0.1` | 探测默认目标（`POST /probe` 可用 `target_host/target_port` 覆盖，指向真实网关） |

## 项目结构

```
app/
  main.py        # FastAPI 路由与生命周期
  echo_server.py # 本地回显端（阈值丢弃/断联，epoch）
  prober.py      # 二分探测引擎（DF、探测编号、小包复核、作废判定）
  packets.py     # 探测报文编解码
  netutil.py     # DF 位设置
tests/test_api.py
Dockerfile / docker-compose.yml
```
