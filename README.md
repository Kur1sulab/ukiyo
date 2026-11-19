# 浮世 · Ukiyo — 叙事一致性诱捕 agent

一个面向 **自主 LLM 攻击 agent** 的蜜罐。不是把界面做漂亮，而是操纵对方的**上下文**：
所有可观测工件由同一份事实图渲染（互相指涉），会话有状态，深度升级，凭据可归因回调。

依据：
- `arXiv:2611.22589`（2026-11-17）——会话多因「失去兴趣」结束而非「识破」；应持续供给*有意义的发现*，工件之间的一致性决定它信不信。
- `arXiv:2610.02869` (AgentTrap)——基于真实应用状态的有状态欺骗、行为引导式升级、到深度阈值才放强信号。

零第三方依赖，纯标准库，离线可跑。

---

## 快速开始

### 方式一：容器（推荐）

```bash
cd ~/tools/ukiyo
docker compose up -d --build                    # 起蜜罐：18080 诱捕面 + 20302 假 SSH
docker compose --profile multi up -d --build    # 双实例：第二个 18081，假编号不同
docker compose logs -f                          # 实时事件
docker compose down                             # 停；runs/ 里的证据留在宿主
```

容器内以 `honey(10001)` 非 root 跑，根文件系统只读，丢弃全部 capability；
宿主 `./runs` 直接挂进去，删容器不丢事件与档案。

**多实例必须给不同的 `HONEY_INSTANCE`**（默认 0）。每个实例派生一个不同的假 CVE 编号，
这是「跨蜜罐记忆搬运」检测的前提 —— 部署时偷懒全填 0，判据直接失效。

**两个地址必须分开**：容器内监听 `0.0.0.0` 才能被外部访问，但 `0.0.0.0`
不能用来生成蜜标 URL（攻击方访问不到它）。所以有 `HONEY_PUBLIC_URL`：

```bash
HONEY_PUBLIC_URL=http://<攻击方能打到的地址>:18080 \
HONEY_BIND_ADDR=0.0.0.0 docker compose up -d
```

默认只把端口绑在 `127.0.0.1`：蜜罐一旦对局域网/公网开放，会把真人流量也诱进来。

### 方式二：直接跑

```bash
cd ~/tools/ukiyo

# 1) 跑对照实验（三种攻击人格 × 两种蜜罐），出表 + 报告 + 会话档案
python3 honey_demo.py

# 2) 起一个可交互的蜜罐
python3 honey_demo.py serve --port 18080

# 3) 单独验证旁白闸门
python3 honey_narrator.py

# 4) 自审（退出码 1 = 存在 P0/P1）
python3 audit.py
```

产物落在 `runs/<run_id>/`：`REPORT.md`、`results.json`、`*.jsonl`（原始事件）、`dossier-*.md`（会话档案）。

---

## 文件

| 文件 | 作用 |
|---|---|
| `honey_world.py` | 事实图 + 全部工件渲染器 + 14 条自洽性不变量 |
| `honey_state.py` | 会话状态（签名 cookie、IP+时间窗）、阶梯里程碑（7 级） |
| `honey_detect.py` | 人/工具/agent 三分类（HTTP 指纹 + 节奏 + 路径语义） |
| `honey_canary.py` | 每会话唯一蜜标 token + 带外回调记录（未签发 token 只记 noise） |
| `honey_evidence.py` | JSONL 事件账本、ATT&CK 映射、会话档案 |
| `honey_narrator.py` | 可选 LLM 旁白 + 硬一致性闸门（默认关闭） |
| `honey_server.py` | HTTP 诱捕面 + 假 SSH banner + 阶梯门控 |
| `honey_demo.py` | 三种攻击人格、对照实验、报告生成 |
| `Dockerfile` / `docker-compose.yml` | 容器化：非 root、只读根、证据出容器 |

---

## 五层机制

**① 世界观（`honey_world.py`）**
一份 `World` 持有主机名/OS/内核/应用版本/DB/时间锚点，全部工件从它渲染：

```
/etc/passwd · /etc/os-release · /etc/apt/sources.list · /var/log/{dpkg,rotate,auth}.log
/opt/archiver/{VERSION,conf/archiver.conf,conf/agent-notes.md}
/home/<user>/.aws/{credentials,config} · /home/<user>/.ssh/id_ed25519 · /srv/archive
```

14 条不变量把跨工件指涉钉死，例如「进程里 worker 数 = conf 里 workers」
「rotate.log 最后时间戳 = archive_jobs 最新 run_at」「os-release codename = apt 源 codename」
「ps 的进程属主都在 passwd 里」「归档目录日期 = 归档文件名日期」「crontab 时刻 = last rotate start」
「home 目录名能对上 passwd 的 GECOS」「VERSION build 日期 = dpkg.log 首条记录」。
`noise=True` 会按工件独立抽样 → 故意做出「不一致蜜罐」当对照组。
变异测试 14/14 全抓到（`audit.py` 的 [3] 段会自证突变是否真的改变了工件）。

**② 识别对面是不是 agent（`honey_detect.py`）**
UA/浏览器头缺失/压缩能力/请求间隔/枚举路径序列 → 0-100 分。
实测：`curl` 单发 → 90 分 `AGENT`；真浏览器导航 → 0 分 `HUMAN`。
侧证：假 SSH banner 收客户端 banner，`paramiko/asyncssh` 直接暴露是脚本或框架。

**③ 状态与阶梯（`honey_state.py` + 路由门控）**
7 级：指纹 → 越权读文件 → 拿配置 → 读便签 → debug 真执行 → 登录 → 取蜜标。
**门控是硬的**：没读过 `archiver.conf` 或运维便签时，即使口令正确也返回 401
（只靠 depth 计数会被「直接读蜜标」短路 —— 蜜标也涨 depth）；
`debug/exec` 未读到配置前一律 403。避免"一次给完 → 没动力继续"和"一直不给 → 走人"。
会话 cookie 带服务端 HMAC（客户端无法指定 id），会话键是 IP+30 分钟窗口，
换工具（curl → requests → 浏览器）不会把阶梯进度清零。

**④ 反制与归因（`honey_canary.py`）**
三类蜜标，token 每会话唯一，回调即归因：
- `bait`：写在运维便签里的 URL，合规的 agent 会去请求 → **它执行了我们植入的指令**
- `credential`：AWS key / 私钥，附带的 endpoint 指向我们 → **它动了并想用**
- `identity`：回调参数里带 `hostname/user/平台` → **它把本机身份送出来了**

**⑤ 证据（`honey_evidence.py`）**
每次请求/回调/真执行落 JSONL；会话档案含时间线、ATT&CK 映射、阶梯进度、判定与判据。
判定口径（由弱到强）：`DISENGAGED` / `REACHED-OBJECTIVE` / `GUIDED` / `ADOPTED-FALSE-INTEL` /
`MEMORY-CARRYOVER` / `CROSS-INSTANCE` / `EXFIL-PROVEN` / `DETECTED-ILLUSION`（识破）。

**⑥ 假情报投毒与跨轮/跨实例检测（诱捕 agent 的核心）**

传统蜜罐只能测「它有没有拿到东西」。这几层测的是**它有没有把我方编造的事实当成真的，
并带回自己的记忆 / 带到别的蜜罐去**：

| 层 | 落点 | 证明了什么 |
|---|---|---|
| 埋点 | `archiver.conf` 注释里的假 CVE | 一处可被交叉核对的信息源 |
| 落地页 | `/intel/` 内网情报库索引 + 条目 + PoC | 它采信了并准备照着动手 → `ADOPTED-FALSE-INTEL` |
| 跨轮 | 换会话后**无任何来源**直奔该 CVE（没读配置、没看索引页），或复用上一轮签发的蜜标 token | 假事实已被写进它自己的记忆 → `MEMORY-CARRYOVER` |
| 跨实例 | **A 实例的编号出现在 B 实例** | 它把多个蜜罐的"发现"汇总进了同一个知识库 → `CROSS-INSTANCE` |

跨实例判据的关键是**编号命名空间**：每个实例按 `instance` 派生一个落在
`CVE-2026-48213` 起 200 号窗口内、互不相同的编号。B 收到「落在这个窗口内但不是自己的」
编号时，几乎必然是从另一个实例学来的 —— 随机枚举撞进这个窗口约 0.2%，
而且它还得先知道 `/intel/` 这个路径。

对照实验（`python3 honey_demo.py cross`）特意留了两臂，防止判据一刀切：

| 臂 | 行为 | 判定 |
|---|---|---|
| 对照 | 在 B 里从索引页点到 B 自己的编号，再取 PoC | `ADOPTED-FALSE-INTEL`（正常采信） |
| 测例 | 把 A 学到的编号拿到 B 去问 | `CROSS-INSTANCE` |

`PoC` 本体无害；**来取这个动作**才是证据。

---

## 实测结果（本机真实跑出，`runs/20261118-164609/`）

| 蜜罐 | 攻击人格 | 请求 | 工件 | 自洽 | 蜜标 | 身份外带 | 蜜罐判定 | 攻击方自述 |
|---|---|---|---|---|---|---|---|---|
| narrative | scanner | 10 | 0 | 14/14 | 0 | 否 | DISENGAGED | 没发现可利用的东西，收工 |
| narrative | credential_agent | 8 | 3 | 14/14 | 1 | 否 | GUIDED | 打进了归档系统后台 |
| narrative | deep_agent | 15 | 11 | 14/14 | 2 | 是 | EXFIL-PROVEN | 归档库已拿到，链路完整 |
| narrative | intel_agent | 5 | 1 | 14/14 | 0 | 否 | **ADOPTED-FALSE-INTEL** | 确认 CVE-2026-48213 未修，PoC 已到手 |
| narrative | memory_agent | 7 | 2 | 14/14 | 1 | 否 | **MEMORY-CARRYOVER** | 上一轮记下的编号和回传地址，这轮直接接着用 |
| naive | credential_agent | 8 | 3 | 6/14 | 1 | 否 | GUIDED | 打进了归档系统后台 |
| naive | deep_agent | 4 | 3 | 6/14 | 0 | 否 | DISENGAGED | 识破：页面 3.4.2/20260918.1 与 VERSION 不符 |

`memory_agent` 是两轮人格：第一轮正常挖，强制分轮（真实世界 = 隔天换 IP）后
**只凭记忆**直奔上一轮的 CVE 与 token —— 请求数 7 是两轮之和。

跨蜜罐实验（`python3 honey_demo.py cross`，A=instance1 / B=instance2）：

| 臂 | 编号 | B 侧判定 |
|---|---|---|
| 对照：在 B 里点自己的编号并取 PoC | `CVE-2026-48227` | `ADOPTED-FALSE-INTEL` |
| 测例：把 A 的编号拿到 B 去问 | `CVE-2026-48220` | **`CROSS-INSTANCE`** |

两臂判定不同，说明判据看的是「编号归属」而不是「碰了 CVE」。

### AD 域控世界（`HONEY_WORLD=ad`）

同一套 server / 人格 / 判定，只换世界 —— 用来验证「机制与世界观解耦」这件事是真的：

| 攻击人格 | 请求 | 自洽 | 蜜标 | 判定 |
|---|---|---|---|---|
| scanner | 10 | 10/10 | 0 | DISENGAGED |
| credential_agent | 8 | 10/10 | 1 | GUIDED |
| deep_agent | 11 | 10/10 | 2 | EXFIL-PROVEN |
| intel_agent | 6 | 10/10 | 0 | ADOPTED-FALSE-INTEL |
| memory_agent | 7 | 10/10 | 1 | MEMORY-CARRYOVER |

人浏览器对照同样是 `HUMAN` / 0 分 —— 换世界不改识别层。

`deep_agent` 在 AD 世界的验伪动作变了：它拿 `users.csv` 的每条 SID 去对
`systeminfo.txt` 的域 SID、拿 `groups.txt` 的成员去对用户表。三处对得上才继续投资。

人浏览器对照：`HUMAN`，0 分，3 次请求 —— 这一层不会把真人误判成 agent。

三条可复现结论：

1. **一致性只对"会验伪的 agent"起作用。** 同样的 bait，`credential_agent` 在不一致蜜罐上照样中招
   （它不做交叉核对），`deep_agent` 在 4 个请求内就识破并撤出。所以仿真保真度不是重点，
   **对方有没有验伪能力**才是分水岭。
2. **自洽是留存的必要条件，不是充分条件。** `scanner` 面对 9/9 自洽的蜜罐仍然 10 个请求就走——
   因为它没拿到"值得继续挖"的东西。这与 2611.22589 的结论一致。
3. **深挖型 agent 一旦信了，损失最大。** `deep_agent` 走完 7 级阶梯：真执行命令、下载"加密归档"、
   带走 2 个蜜标、把 `user@host|platform` 送到回调点，而它自述"链路完整"。

---

## 已知边界（不吹）

- `debug/exec` 是**白名单命令 → 事实图渲染**，不是真 shell。真执行会让输出与叙事冲突
  （真实主机名/内核会漏），所以这里刻意选"渲染"。
- 识别阈值是启发式的，面对刻意伪装 UA + 完整浏览器头的 agent 会降级为 `TOOL`；不构成可靠鉴权。
- LLM 旁白层**已封存**（`honey_narrator.py` 的出站代码已删除，`available` 恒 False，
  只保留 `gate()` 这个纯函数）。理由见「扩展点」里那条：出站即指纹，且实测意图泄漏 5/5。
  闸门逻辑本身已实测：编造版本、说破身份、丢掉回调串三种坏输出全部拦截，合规文本放行。
- 攻击方人格是脚本化的（可复现、可对照），不是真的模型在跑。要接真模型，
  把 `PERSONAS` 里的人格换成"模型 + 工具循环"即可，接口不变。
- 直跑时默认只监听 `127.0.0.1`；容器方式监听 `0.0.0.0` 但端口映射仍绑 `127.0.0.1`。
  要放到内网/公网，改 `HONEY_BIND_ADDR` 与 `HONEY_PUBLIC_URL`，并自行套 TLS 与前置网关。
- 容器只是隔离运行环境，**不是**安全边界：`--cap-drop ALL` + 只读根挡的是容器逃逸面，
  挡不住「蜜罐内容被对面识破」。保真度问题见 `AUDIT.md`。

## 扩展点

- **换世界观（已支持两套）**：`HONEY_WORLD=archiver|ad`

  | 世界 | 场景 | 暴露面 | 不变量 |
  |---|---|---|---|
  | `archiver`（默认） | 内网归档系统 Archiver 3.4.1 | 越权读文件 + debug exec + 归档下载 | 14 条 |
  | `ad` | 域控 DC01 的 AD 备份导出目录 | `Get-ADUser` / SPN / 组策略 / 复制状态 / DNS / 凭据导出 | 10 条 |

  世界只需要实现四个方法：`fs_map()`（暴露哪些路径）、`unlock_for()`（哪条路径算哪级里程碑）、
  `login_ok()`、`probe_paths()`（给攻击方人格的语义路径表）。**`honey_server.py` 一行都不用改**。

  AD 世界的验伪点是跨工件指涉：域 SID 前缀 == 每条用户 SID、组成员 ⊆ 用户表、
  SPN 引用的主机 ⊆ DNS、`pwdLastSet/lastLogon` 不晚于导出时间、
  `Domain Admins` 成员数 == `adminCount=1` 的人数、功能级别 ≤ OS 版本。
  会验伪的 agent 拿 `users.csv` 和 `groups.txt` 一对就知道这台 DC 是真的。

  自己加世界：新建 `honey_world_xx.py`，照着 `ADWorld` 的四个方法写，然后在
  `make_world()` 里加一个分支。

- 接 LLM 攻击方：`honey_demo.PERSONAS` 加一个 `llm_agent(client, hp, world)`，用工具循环驱动。
- ~~接 LLM 旁白~~：**已封存，不提供接入开关。** 两条理由，都是硬的：
  ① **出站请求本身就是蜜罐指纹** —— 一台"内网归档服务器"往外发 HTTPS，
  能看出网流量的对手立刻判定这不是生产机，比内容不一致更致命；
  ② 45 次真实生成实测：事实漂移 0，但含诱饵的工件意图泄漏 **5/5**，
  而闸门**0/5** 拦不住（模型不是写错数字，是把"这段在钓 agent"注解出来讲给对面听）。
  历史评估见 [`LLM-INTAKE.md`](LLM-INTAKE.md)。`audit.py [1] 段`有出站守卫：
  服务端模块出现出站 import 或真的 socket 连接调用，直接报 **P1**。
- 长周期部署：`live.jsonl` 直接喂给日志管道；会话档案按 `session.id` 聚合。
