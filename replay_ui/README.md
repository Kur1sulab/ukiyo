# 浮世 Ukiyo · 诱捕回放界面（只读运营层）

回答一个问题：**「对方信到第几层、在哪一步转折、我怎么把它骗到那里的」**。

此前仓库只有给攻击者看的诱饵页（`honey_world.py:112 login_html`、`:319 intel_index_html`、
`:337 intel_advisory_html`，由 `honey_server.py:255/295/330` 送出），运营者看账本只能手动
`cat runs/*/`。本目录 + `honey_replay.py` 补上运营侧的只读回放界面。

## 起法

```bash
python3 honey_replay.py                 # http://127.0.0.1:18099
python3 honey_replay.py --port 18099 --run stress-100-final
python3 honey_replay.py --selfcheck     # 全量复算判定，与 runs 快照核对
```

- 纯标准库 `http.server`，零第三方依赖。
- **只绑 127.0.0.1**（`BIND` 写死，无改绑参数）；蜜罐数据不出本机。
- **只读**：仅处理 GET；文件一律 `open(..., "r")`；不实例化 `CanaryVault`、不签发蜜标、不写任何文件。
- 默认端口 18099，避开正在跑的 18080/18081 容器。
- 蜜罐本体（honey_server / honey_world / honey_detect / honey_state / honey_evidence /
  honey_demo / honey_canary）一行未改。

## 判定从哪来（不另写一套）

回放判定直接调 `honey_demo.server_verdict`（`honey_demo.py:333`），输入只有磁盘账本 +
从账本重建的 `_LedgerVaultView`（蜜标命中/身份外带规则复刻 `honey_canary.leaked_identity`），
与 `_selftest_verdict_replay.py` 的「重启后仅凭账本重放」同源。阶梯深度 = 已解锁里程碑个数
（`honey_state.py:57` 的 depth 由 flags 派生，重建时喂 `s.flags`）。

`--selfcheck` 对 6 个 stress run 共 340 个会话全量复算，与快照 100% 一致。

## 界面

- 左栏：run 切换 + 会话列表（深度/判定/事件数，可按判定过滤）+ 黑/白主题切换（仅两套）。
- 头部：判定徽章（随回放位置变化）+ 七级信任阶梯（点亮/未解锁/跳级解锁如实标注）。
- 回放视图：时间线（过去/未来以几何+灰度区分）+ 归因链（每一步「它做了什么 → 我们给了什么」，
  断链有横幅；横幅随回放位置变化，中途不提前宣布终态）+ 播放/步进/倍速/拖动。
- 档案视图：渲染 `dossiers/dossier-*.md` 真实档案。
- 深链：`#run=<id>&sid=<sid>` 直达某会话。
- 枚举中文全部来自 `/api/meta`（后端单一事实源），前端不写死词表。

## 数据布局（两种都支持）

- A：`runs/<id>/live.jsonl` + `server_sessions.json` + `dossiers/dossier-<sid>.md`
- B：`runs/<id>/<arm>.jsonl` + `dossier-<arm>.md`（含 `(arm-unattributed)` 会话）

## 设计依据

`~/.hermes/skills/ui-design/` 的 desktop-ui-design（哥哥专属规范）与 design-review（验收）。
要点：黑白灰中性色阶承载信息；语义色只出现在圆点、1px 边框、极淡判定底色、数字着色——
无大面积彩色填充；结构 token 在 `:root`，颜色全走语义变量（组件内零字面色值）；
`<head>` 内联脚本防主题闪烁；版本号来自 `/api/meta`；长 token 截断 + title。

## audit/ — 验收证据

- `contrast-dark.md` / `contrast-light.md`：contrast.py 实测两张表（各 40 对，全过）。
- `gen_pairs.py`：从 replay.css 真实 token 生成色对（半透明先合成到承载背景）。
  复跑：`python3 gen_pairs.py && contrast.py --batch pairs-dark.txt`。
  注意 contrast.py 批处理把 `#` 开头行当注释，故色对用 `rgb()` 格式。
- `final-audit.json`：活 DOM 对比度审计（双主题独立加载，含检查基数）+ 几何溢出取证，0 失败。
- `shots/`：真实账本渲染截图（stress-100-final 与 20261119-104811，非造数据）。

## 验收记录（2026-11-19）

- `python3 audit.py` → P0=0 P1=0 P2=0
- `python3 _selftest_verdict_replay.py` → 6/6
- `python3 honey_replay.py --selfcheck` → 340/340 判定与快照一致
- 活 DOM 对比度：黑/白 × 全貌/中途/档案/演示 run，0 失败（基数 667/668/561/300）
- 几何取证：0 溢出，页面无横向滚动
- `git status`：仅新增 `honey_replay.py` + `replay_ui/`，本体零改动；未 commit/push