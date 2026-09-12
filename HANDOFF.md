# Smart7z 离线交接索引

本文件是**离线交接的唯一入口**：拿到这个工作空间后，按本文顺序读，不会缺东西、不会走错门。

日期：2026-09-12。适用于本工作空间当前状态。

---

## 一、先看这三行

1. **对外发布版本仍是 1.0.3。**
2. **1.0.4 已构建完成，但 2026-09-11 的全业务审查建议「暂缓发布」**——已确认 3 项 P1 数据安全问题（见下）。
3. 接手时**先读审查报告**：[REVIEW_2026-09-11.md](.sandbox-test/portable-fulltest/REVIEW_2026-09-11.md)，再读 [MAINTENANCE.md](MAINTENANCE.md) 的「待决事项」。

---

## 二、当前状态一页纸

| 项目 | 状态 |
| --- | --- |
| 对外发布版本 | **1.0.3**（`release/Smart7z-1.0.3-*`） |
| 1.0.4 候选 | 三件产物已构建，SHA-256 与 `release/SHA256SUMS-1.0.4.txt` 一致；**审查建议修完 P1 再发** |
| 源码全量测试 | 460 项通过，0 失败／0 错误／0 跳过（`resumed-source/test-full-latest.json`） |
| 成品场景矩阵 | 9 通过／0 失败／4 待定（`resumed-20260911-205503/review-evidence.json`） |
| 工作树 | **2026-09-12 已开始落库**：`dd5f319`（ignore）／`4b92c66`（行尾策略）／`9cff198`（旧交付目录退役）＋ 四份核心文档提交。剩下的 1.0.4 代码改动仍需按分组口径提交，见 `MAINTENANCE.md`「仓库整洁化与提交计划」 |
| 审查报告 | `.sandbox-test/portable-fulltest/REVIEW_2026-09-11.md`（R01–R14、S01–S02） |

### 必须先知道的 3 项 P1（均为真实成品复现，非模拟）

| 编号 | 问题 | 后果 |
| --- | --- | --- |
| R01 | 只提交独立 `book.z01`，执行时却解出同名 `book.zip` 的内容 | 解出错的包；选「并删除」时**两个文件都被删**，程序还返回成功 |
| R02 | 修改任意无关设置（如「嵌套解压」），会把未完成任务的「保留源包」重写成**永久删除** | 源包被误删 |
| R03 | 成功密码回写会截断超限密码本 | 4,194,324 字节的密码本被写成 **24 字节** |

---

## 三、目录地图：每样东西是什么、该不该装进交接包

总计约 **5.9 GB**，不可能整体打包。按下面取舍。

| 路径 | 是什么 | 体积 | 打包建议 |
| --- | --- | --- | --- |
| `README.md` / `CHANGELOG.md` / `MAINTENANCE.md` / `smart7z_user_manual.html` | 四份核心文档 | 190 KB | **必带** |
| `.sandbox-test/portable-fulltest/` 的结论与脚本（见第四节清单） | 本轮审查的报告＋证据＋复跑脚本 | **284 KB** | **必带** |
| `.sandbox-test/portable-fulltest/session-handoff-20260911/` | 审查过程存档（含原始会话 rollout 4.7 MB） | 4.6 MB | 建议带 |
| `01_MainProgram/smart7z/` 源码、`tests/`、`build_assets/`、构建脚本 | 产品源码与测试 | 约 60 MB | **必带** |
| `01_MainProgram/smart7z/release/Smart7z-1.0.4-*` | 1.0.4 三件产物＋已解压便携目录 | 约 154 MB | 要复现问题就带 |
| `01_MainProgram/smart7z/release/` 里 1.0.2／1.0.3 产物 | 历史版本 | 其余约 470 MB | 按需，通常不带 |
| `01_MainProgram/smart7z/.build-venv/` | **已失效** 的构建虚拟环境 | 701 MB | **不要带** |
| `.sandbox-test/portable-fulltest/` 下 7 个隔离运行目录 | 每个含一份 64 MB 的成品副本＋原始结果 | 约 449 MB | 只带 JSON 结果即可（已在核心清单） |
| `.sandbox-test/corpus/` | 回归语料（`github/` 占 2.0 GB） | 2.0 GB | 按需，通常不带 |
| `.sandbox-test/out/` | 旧批次跑测输出 | 768 MB | 不带 |
| `.sandbox-test/report/`、`startup-phases/`、`final-verification/`、`app/` | 更早几轮测试工程 | 约 430 MB | 只带其中的报告 `.md` |
| `.git/` | 仓库历史 | 720 MB | 按需 |
| `.codegraph/` | 代码检索索引，可重建 | 91 MB | 不带 |
| `发行版/`、`源码/` | **2026-09-12 已从版本库与工作区移除**的 1.0.2 旧交付目录（文件在回收站） | 0（原 44 MB + 100 MB） | 无需再考虑 |

### 最小可交接组合（约 65 MB）

四份核心文档 ＋ `.sandbox-test/portable-fulltest/` 结论与脚本（284 KB）＋ `session-handoff-20260911/`（4.6 MB）＋ `01_MainProgram/smart7z/` 源码与测试（约 60 MB，剔除 `.build-venv`、`release/`、`__pycache__`）。

**只做结论交接**（不带源码）时，前两项合计不到 **5 MB** 就能把话说完。

---

## 四、审查包核心清单（`.sandbox-test/portable-fulltest/`）

| 文件 | 内容 |
| --- | --- |
| `REVIEW_2026-09-11.md` | **主报告**：R01–R14 缺陷与风险、S01–S02 启动结论复核、修复顺序 |
| `business-review-evidence.json` | 业务／UI 探针结果（R02、R04–R09 等） |
| `resumed-20260911-205503/review-evidence.json` | 成品场景矩阵判定：9／0／4 |
| `resumed-20260911-205503/portable-fulltest.json` | 场景矩阵原始输出 |
| `resumed-source/test-full-latest.json` | 源码全量测试：460 项通过 |
| `frozen-business-20260911-211106/results.json` | **R01 成品复现原始证据**（错解＋双删） |
| `startup-review-20260911-210444/results.json` | 有效启动测量（暖启动） |
| `startup-review-20260911-210329/results.json` | 跨时钟失效样本，**报告已标为无效**，保留备查 |
| `review_business.py` / `review_frozen.py` / `review_startup.py` / `resume_verification.py` | 可复跑脚本 |
| `build_fixtures.py` / `run_scenarios.py` / `run_portable_fulltest.py` 等 | 原有成品补测工装 |
| `review-ui.png` | offscreen 截图，**字体显示异常，不作为真实桌面视觉证据** |

---

## 五、环境清单（离线必读）

| 项目 | 已验证可用 | 说明 |
| --- | --- | --- |
| 操作系统 | Windows 11（build 26200） | 回收站、右键菜单、单实例 IPC 均依赖 Windows 行为 |
| 源码／CLI 测试解释器 | Python **3.12.3**（`C:\Users\IO\AppData\Local\Programs\Python\Python312\python.exe`） | 已装 PySide6 6.11.1 |
| GUI 探针解释器 | 同上 | 需 PySide6；**必须显式指定**，见下 |
| 另一可用解释器 | Python 3.13.12（`C:\Users\IO\.workbuddy\binaries\python\versions\3.13.12\python.exe`） | **未装 PySide6**，只能跑 CLI 部分 |
| 7-Zip | 成品自带 `7z.exe` 26.02 | 源码运行需系统安装或把 `7z.exe` 放源码根 |
| 打包 | PyInstaller 6.12.0 | 仅重新构建时需要 |

GUI 探针没有默认可用环境，**跑之前先设这一句**（否则会去找不存在的 venv 并失败）：

```powershell
$env:SMART7Z_GUI_PYTHON = "C:\Users\IO\AppData\Local\Programs\Python\Python312\python.exe"
```

---

## 六、复跑入口

```powershell
# 1) 源码全量测试（460 项）
Set-Location 01_MainProgram\smart7z
& "C:\Users\IO\AppData\Local\Programs\Python\Python312\python.exe" -X utf8 verify_project.py --report-dir F:\Smart7z\.sandbox-test\portable-fulltest\resumed-source

# 2) 成品场景矩阵 + 判定复核
Set-Location F:\Smart7z
& "C:\Users\IO\AppData\Local\Programs\Python\Python312\python.exe" -X utf8 .sandbox-test\portable-fulltest\resume_verification.py

# 3) 业务／UI 探针、启动测量、成品缺陷复现
& "C:\Users\IO\AppData\Local\Programs\Python\Python312\python.exe" -X utf8 .sandbox-test\portable-fulltest\review_business.py
& "C:\Users\IO\AppData\Local\Programs\Python\Python312\python.exe" -X utf8 .sandbox-test\portable-fulltest\review_startup.py
& "C:\Users\IO\AppData\Local\Programs\Python\Python312\python.exe" -X utf8 .sandbox-test\portable-fulltest\review_frozen.py
```

跑之前确认**没有残留** `Smart7z.exe` / `7z.exe` 进程；脚本内部会新建隔离样本，不会碰你手上的真实压缩包。

---

## 七、离线会踩的 5 个坑

1. **`.build-venv/` 是死的**（701 MB）。`pyvenv.cfg` 指向另一台机器的 `C:\Users\23700\AppData\Local\Python\pythoncore-3.14-64`。不要用它，直接用上面的 3.12。
2. **一批旧脚本硬编码了另一台机器的路径** `C:\Users\23700\WorkBuddy\11111\Smart7z`，在本机和离线环境都跑不通——分布在 `.sandbox-test/report/`、`startup-phases/`、`final-verification/`。这些是历史轮次的工装，**当资料看，不要指望能直接跑**。
   - 例外：`portable-fulltest/probe_gui_conclusions.py` 里那串 `C:/Users/23700/...` 只是**超长路径测试用的字符串样本**，不读真实文件，不影响运行。
3. **GUI 探针默认环境不存在**：脚本首选 `~/.workbuddy/binaries/python/envs/smart7z/`，本机没有这个环境，必须按第五节设 `SMART7Z_GUI_PYTHON`。
4. **`MAINTENANCE.md` 提到的 5.6 GB 备份不在本机**（`C:\Users\23700\Smart7z-backup-20260910-1803`）。本机不存在 `C:\Users\23700`，交接时不要承诺有这份备份。
5. **外部网络依赖**：`.sandbox-test/corpus/` 的语料曾通过本机代理 `http://127.0.0.1:7897` 下载，部分站点已失效。离线环境**无法重新获取语料**，要用就整目录带走。

---

## 八、文档口径冲突（交接前必须知道）

`MAINTENANCE.md` 第 9 行仍写着任务列表创建的波动「**已结案：该阶段没有可修的启动代码缺陷，不必再优化**」，`.sandbox-test/startup-phases/REPORT.md` 第 7 行同口径。

**2026-09-11 的审查（S02）认定这句话结论过度**：报告自己承认 Qt 内部变慢机制未定位，而「未定位」不等于「无缺陷、无需优化」。本轮实测有效数据是暖启动 show 中位数约 0.49–0.69 秒、ready 约 0.59–0.78 秒，连续启动中出现过一次 216 毫秒的间歇波动。

**口径未改，是刻意留给你拍板的**（见第九节）。在此之前，请以 `REVIEW_2026-09-11.md` 的 S02 为准，不要引用 `MAINTENANCE.md` 那句「已结案」。

---

## 九、待决事项

沿用 `MAINTENANCE.md`「待决事项」的 6 条（备份去留、剩余代码改动如何分组提交、是否做历史瘦身、`.sandbox-test/` 大件、1.0.4 是否发布、包内手册旧说法），其中**第 5 条现在多了硬输入**：审查建议修完 R01/R02/R03 再发布。

**2026-09-12 起有两处已经不再是待决项**（已执行，本地提交，未推送）：四份核心文档已进版本库；`发行版/`、`源码/` 已移出跟踪并移入回收站。旧的「是否提交 git」现在只剩代码改动的分组口径。

本次整理新增 2 条：

| # | 事项 | 需要你决定什么 |
| --- | --- | --- |
| 7 | **文档口径是否改写** | `MAINTENANCE.md:9` 与 `startup-phases/REPORT.md:7` 的「已结案／无缺陷」是否按审查 S02 改写 |
| 8 | **1.0.4 发布门槛** | 是「先修 3 项 P1 再发」，还是「带已知 P1 发布并在发行说明里披露」 |

---

## 十、校验

| 文件 | SHA-256 |
| --- | --- |
| `REVIEW_2026-09-11.md` | `8a15452fe39ef1ed0a43bc0639830070f36fab512fe708c708f3eaaf2797aa2e` |
| `business-review-evidence.json` | `7bfac273b0760834b302ee8d840585fa310eb6cba8c35cd7b259a52dfa0f7d33` |
| `resumed-source/test-full-latest.json` | `ee84b860a60be9e83e4831e476835182f4db86fe4f42cf38f577b0890a5602fa` |
| `resumed-20260911-205503/review-evidence.json` | `09d3eb1b5fbc0420b83c4a95b6456348aa38a88de223c6d2248040682ea3a8ab` |
| `frozen-business-20260911-211106/results.json` | `672571fba2856f4e7309983bcba902a9812c67c0c0bde030a91a4edfa9ef89c0` |
| `startup-review-20260911-210444/results.json` | `90884b94b447252230af6bded6e1cd3dcdbc248b155e773a8a1d9df1cc5331a6` |
| `session-handoff-20260911/raw-session-rollout.jsonl` | `82df85b56936711ddd92e628fd2905c4f3ea0bb1dba2b77bf028584d05bb0e11` |

1.0.4 三件产物的 SHA-256 见 `01_MainProgram/smart7z/release/SHA256SUMS-1.0.4.txt`。

---

## 十一、接手后建议的顺序

1. 读 `REVIEW_2026-09-11.md`，确认 3 项 P1 的复现条件。
2. 跑第六节第 2、3 条命令，确认结论可复现（不需要先改任何代码）。
3. 拍板第八、九节的口径与发布门槛。
4. 再动产品代码：按报告「后续顺序」先修 R01/R02/R03，并用真实成品回验误删与密码本保留。
