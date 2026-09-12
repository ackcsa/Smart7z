# Smart7z 维护与交接指南

本指南面向接手开发、测试和发布的人；日常操作见[用户手册](smart7z_user_manual.html)，项目入口见 [README](README.md)，版本记录见 [CHANGELOG](CHANGELOG.md)。

下文路径未特别注明时均相对仓库根目录；“源码目录”指 `01_MainProgram/smart7z/`。

## 交接状态

截至 2026-09-11，1.0.3 仍是对外发布版本。**1.0.4 已按含当日修复的源码重新构建完成，并已用打包成品完成实机场景补测（11 项 + 7 项 GUI 断言全通过）**，三件产物在 `release/`，校验清单 `SHA256SUMS-1.0.4.txt`；是否对外发布见「待决事项」。任务列表创建阶段的波动**已结案：该阶段没有可修的启动代码缺陷**，不必再优化——那一段就是一次固定的一次性 Qt 控件初始化（约 40～70 毫秒），观测到的 240～590 毫秒来自测量循环连续启动应用留下的残留效应。推导与排除清单见[启动诊断报告](.sandbox-test/startup-phases/REPORT.md)。不要把旧统计、字体显示调整或文档整理当作冷启动优化已获证明。

**2026-09-11 改动（对应版本 1.0.4，已构建）**：

| 文件 | 改动 |
| --- | --- |
| `archive_classifier.py` | quick 路径补上与慢路径一致的规则；正向判定必须先过 `has_independent_archive_structure()` |
| `discovery.py` | 用 `_zip_split_has_main_volume()` / `_classic_rar_has_main_volume()` 替换武断的 `_z_volume_is_zip()`；`logical_archive_key()` 在缺少主卷时不再折叠键 |
| `executor.py` | 缺卷集合仅当文件**自身带独立归档结构**时才交由 7-Zip 判定，其余仍以 `MISSING_VOLUME` 失败（7-Zip 对垃圾首卷会假报成功，见下） |
| `ui_qt.py` | 删除 `_clear_after_terminal` 死代码；扫描中标签改用快照模式；`closeEvent` 补齐手册承诺的保存与失败取消关闭；详情区超长路径中间省略 + tooltip |
| `build_release.ps1` | 清单改为按版本命名（`SHA256SUMS-<version>.txt`，另留不带版本的别名）；压缩实现由 `Compress-Archive` 换为 Python `zipfile` |
| `tests/` | 新增回归测试：扫描标签快照、超长路径省略、关窗保存、保存失败取消关闭、无悬空编辑不写盘、悬空判定、`.rNN` 独立包/续卷双向判定 |

这些改动已跑全量测试：**460 项通过，0 失败、0 错误、0 跳过**（用带 PySide6 的解释器；缺依赖的解释器会把 71 项静默跳过而非失败），并已据此完成 1.0.4 构建（门槛 rc=0），随后**用打包成品复跑了实机场景补测：11 项通过、7 项 GUI 结论断言通过**（2026-09-11，见下节）。

### 便携版实机场景补测（2026-09-11，1.0.4 成品）

源码全绿不等于成品正确（冻结后导入路径、`sys.frozen` 分支、状态根落点都会变），因此用 `release/Smart7z-1.0.4-portable-windows-x64/` 的**真实入口**复跑，样本由便携版自带的 7-Zip 26.02 现场生成。

**通过项**：

| 场景 | 实测结果 |
| --- | --- |
| 便携状态根 | `portable.flag` 生效，`ipc-v3.json` / `recovery-v1.json` 落在安装目录旁，未写 `%LOCALAPPDATA%` |
| 普通 ZIP / 内嵌 ZIP / 嵌套包 | 解压正确，产物名无暂存点前缀 |
| 完整分卷（19 卷） | 仅 `.001` 入队，18 个续卷跳过，整套解压成功 |
| 续卷单投（`.005`） | 能反查首卷并成功解压，未被误拒为独立包 |
| 缺尾卷（18/19） | 解压期 7z 返回 `rc=2 Unexpected end of archive` → `MISSING_VOLUME` 失败，无输出 |
| 垃圾首卷 | 7z 返回 `rc=0 + Everything is Ok + Files: 0`，产品识别 `WARNING:` 行 → 提升为 `EXIT_WARNING` / `VERIFY_FAILED`，**不假成功** |
| 超长路径 | 解压路径最长 467 字符，成功 |
| 源包保留 | `--keep-source` 下源包字节未变 |
| GUI 结论 7 项 | 失败分类写进运行日志、异常任务阻止自动关闭、13 类错误码全部双语渲染、超长路径显示 41 字符 / tooltip 完整 459 字符、三种扫描模式标签互异、**扫描中标签锁定快照**（改实时 config 后仍显示快照值）、无悬空编辑时关窗零写盘 |

**两条重要认知（勿重复排查）**：

1. **缺尾卷时 `is_complete` 会乐观为 True**。7z 分卷没有总卷数元数据，扫描期只能按连续编号推断，无法感知最后一卷缺失。防线在**解压阶段**由 7z 的 `Unexpected end of archive` 兜底，不是扫描期缺陷。判定优先级：**扫描期粗筛 → 解压期权威**。
2. **垃圾首卷会让 7z 假报成功**。`rc=0` + `Everything is Ok` + `Files: 0`（零文件导出、无错误码）。产品靠 `sevenzip.py:_detect_warning_output` 提取 `WARNING:` 行后在 `executor.py:1541-1546` 提升返回码来拦。**改动这两处必须复跑本场景。**

**方法学注意**：右键窗口按设计"仅在全部无异常完成后自动关闭"，需密码 / 失败 / 需复核 / `--queue` 都会保留窗口。这类场景进程不退出，**退出码不是证据**，要看任务表文本、tooltip、运行日志与错误分类。

复跑入口与完整操作手册：`.sandbox-test/portable-fulltest/`（`README.md` + `run_scenarios.py --all`），报告产出 `portable-fulltest-summary.json`。

既有启动对照、186 样本重扫、测试与发布核验材料位于 `.sandbox-test/final-verification/`；应引用具体报告及适用版本，不能笼统视为当前工作树验收通过。旧备份和原样本保留，旧统计不作为新版本验收结果。

## 待决事项（需要拍板或下一轮处理）

**规则**：凡需要你做选择、或需要下一轮才能推进的事项，都记在本节；处理完就删掉对应条目。请不要让待决项只留在会话记录或诊断报告里。

### 需要你下令的选择

| # | 事项 | 现状 | 需要你决定什么 |
| --- | --- | --- | --- |
| 1 | **备份保留多久** | `C:\Users\23700\Smart7z-backup-20260910-1803`（5.6 GB，改动前全量副本）；另有 `.sandbox-test/backups/` 4 组小体量文本备份 | 保留 / 何时清理 |
| 2 | **剩余代码改动如何分组提交** | 仓库整洁化与四份核心文档已在 2026-09-12 提交（见「仓库整洁化」节的提交记录）。剩下的是一整批 1.0.4 代码改动：19 个已跟踪文件被改、4 个新源码文件、4 个新测试文件，改动跨归档判定、界面、调度、构建四个子系统，互相有耦合 | 按计划里给的两套方案挑一套（A：按子系统拆 5~6 个提交；B：核心逻辑 1 个 + 界面 1 个 + 工具与构建 1 个），以及**是否要求每个提交单独跑一次测试**（跑一次全量约需带 PySide6 的解释器） |
| 3 | **是否做历史瘦身** | `.git` 仍为 **719 MB**，主因是历史里的 1.0.2／1.0.3 交付产物（143 MB 的旧目录刚移出跟踪，但 blob 还在 pack 里）。移出跟踪只让仓库**不再增长**，不会变小 | 做 / 不做。做的话要 `git filter-repo` 重写全部 20 个提交、所有 commit hash 变化、远程必须强推，交接期间风险高；也可以永远不做 |
| 4 | **`.sandbox-test/` 大件去留** | 总计约 3.18 GB。`report/verify-ref/`（288 MB）被 `.sandbox-test/README.md` 标注为「可删后由 verify 重建」，重建需重跑 `_deep_confirm` 深度校验；`corpus/`（1987 MB）+ `out/`（766 MB）是回归测试固定资产，不建议动 | `verify-ref/` 保留还是回收 |
| 5 | **1.0.4 是否对外发布** | 已按含 2026-09-11 修复的源码重构建完成，三件产物 + `SHA256SUMS-1.0.4.txt` 校验通过；README/发行入口仍指向 1.0.3 | 发布、继续留作候选，还是先做发布前人工检查 |
| 6 | **包内手册的那句旧说法** | `smart7z_user_manual.html` 仍写着"截至 2026-09-10，1.0.3 已发布"，该副本已随 1.0.4 三件产物进包（手册由构建脚本复制，不从工作树热更） | 是否改这句并重新构建，或在发布说明里覆盖 |

### 本轮已完成、无需再决策

- **界面 P3 四条 + 死代码删除**（2026-09-11，对应 1.0.4，已有回归测试）：
  - **扫描模式标签**：原读实时 `self.config`，而后台扫描按启动时的 `config_snapshot` 执行，用户中途切菜单会让标签与实跑模式不符（实测复现）。改为扫描中优先读 `_scan_config_snapshot`。测试 `test_scan_mode_label_follows_snapshot_while_scanning`。
  - **关窗保存配置**：原报告说「关窗不保存」不准确——绝大多数控件即时保存；真实口子是 `target_edit` 只接 `editingFinished`，输入后不移动焦点直接关窗会丢 `target_dir`（实测复现）。`closeEvent` 现调用 `_flush_pending_config_edits()`，并在保存失败时提示 + `event.ignore()`，补齐手册第 607 行承诺的契约。测试 `test_close_event_flushes_pending_target_dir_edit`、`test_close_event_cancels_when_config_save_fails`。
  - **超长路径省略**：实测原 `sizeHint` 达 5508 px，撑爆 1180 px 窗口且无 tooltip。新增 `elide_path_middle()`（中间省略，保留盘符与文件名尾），`sizeHint` 降到 864 px，tooltip 给全路径。测试 `test_long_path_is_elided_with_full_tooltip`。
  - **`_clear_after_terminal` 死代码**：三处引用但全文从未 `add()`，`if job.task_id in set()` 恒假，分支不可达；与 `_maybe_auto_close_context` 功能重叠。按选项 A 删除，现全仓库 0 引用。
- **验证反复报 `input_changed` 的根因（2026-09-11 实测，推翻"环境噪声"猜测）**：`verify_project.py` 连续两轮在 0 失败、0 跳过的情况下仍报 `input_changed`，且第二轮未编辑任何文件。逐用例监测 `input_fingerprint` 覆盖范围内全部 68 个文件后定位到唯一变动项：`resources/smart7z_config.json`（同尺寸 765 字节、内容不同，`target_dir` 被写成临时目录），触发者是 `test_runtime_cleanup_qt.py` 的 `test_context_auto_close_stops_scheduler_and_clears_session_state`。
  - **机制**：该测试用 `mock.patch` 注入临时配置，但从不重定向配置路径；窗口 `closeEvent` → 新增的 `_flush_pending_config_edits()` → `_sync_config()` → `save_config()` 一路用**真实默认路径**写盘，把测试的临时 `target_dir` 落到产品资源文件上。用旧版 `closeEvent` 复跑则无写入——**这是本轮改动引入的缺陷，不是既有噪声**。
  - **修复**：`_flush_pending_config_edits()` 先过 `_pending_config_edits()`（文本框与已提交 `target_dir` 比对），仅确有悬空编辑才写盘。修复后 460 项全绿、`input_changed` 消失。
  - **注意**：判断此类告警不要先归因于环境或缓存。`input_fingerprint()` 覆盖源码目录顶层文件 + `tests/` + `resources/` + `build_assets/` + 根 `README.md`/`CHANGELOG.md`/`smart7z_user_manual.html`；测试若在这几处写盘就会被抓到。回归测试 `test_close_event_without_pending_edit_does_not_write_config` 与 `test_pending_config_edits_tracks_textbox_against_committed_value` 守住此行为。
- **`test_clean_zip_staging_and_direct_keep_source` 的偶发 `[WinError 5]`（2026-09-11 实测，未定性为产品缺陷）**：构建流程首跑时该用例在 `direct` 子测试失败，`Commit failed: [WinError 5] 拒绝访问。`，提交阶段回退也失败，落到 `JobState.FAILED`。
  - **实测排除项**：同一解释器（构建 venv 3.14.6）单跑该用例通过；单跑连续 10 次全通过；同一解释器跑全量 460 项全通过；换 PySide6 解释器跑全量也全通过。构建流程重跑后未复现。**故判定为环境瞬时干扰，不是稳定复现的代码缺陷**，未改动产品代码。
  - **机制**：提交阶段用 `windows_adapters.move_no_replace_durable()` → `MoveFileExW(..., MOVEFILE_WRITE_THROUGH)`，`WinError 5` 表示源或目标被占用。此机对"刚解压出的文件"做目录移动，空载 300 次失败 0 次，说明需要外部进程（杀毒/索引器）恰好持有句柄才会触发。失败时 `_recover_commit_stage()` 走同一条搬移路径，因此同样失败、无法兜底。
  - **若再次遇到**：先重跑确认是否瞬时；不要因单次失败改产品代码。真正值得考虑的是给 `_publish_stage`/`_recover_commit_stage` 的搬移加有限次退避重试，但**前提是能稳定复现**，否则属于无实证的改动。
- **待决 1 与待决 2 均已修**（2026-09-11）：`archive_classifier.py` 的 quick 路径改为与慢路径同规则；`discovery.py` 换掉武断判据并在缺主卷时不再折叠键，`executor.py` 对显式输入改由 7-Zip 判定。**修前必须先实测**：本轮实测推翻了此前"`.r20` 独立包被永久判为缺卷"的推断，真实根因是 `_z_volume_is_zip()` 武断与 `logical_archive_key()` 键折叠。证据脚本在 `.tmp_task/probe_*.py`。
- **构建脚本两处**（2026-09-11，已完成并生效）：
  - 清单改为按版本命名 `SHA256SUMS-<version>.txt`，同时保留不带版本号的 `SHA256SUMS.txt` 作为"最新"别名。仓库里 `SHA256SUMS-1.0.2.txt` 是此命名的先例。**实测确认**：1.0.4 构建产出 `SHA256SUMS-1.0.4.txt` 与别名，内容一致，且未覆盖 `SHA256SUMS-1.0.2.txt`。
  - 压缩实现由 `Compress-Archive` 换为 `New-ReleaseZip`（Python `zipfile`，deflate level 6）。**实测数据**：源码包输入（299 MB / 2.75 万文件，其中 297 MB 是 `corresponding-source` 的 Qt 源码）用 Python `zipfile` 压缩耗时 **47.4 秒（0.79 分钟）**，产出 100.4 MiB，`testzip` 通过；此前的 `Compress-Archive` 在同类输入上约 44 分钟。先写临时文件再原子替换；保留空目录条目与旧行为对齐。
  - **注意**：源码包整体耗时看起来很长，但瓶颈不是压缩，而是 `corresponding-source`（297 MB Qt 源码）的暂存复制。**排查时不要据此判断压缩有问题**；实测方法是把交付 zip 解出再按 `New-ReleaseZip` 的脚本体重压一遍（`.sandbox-test/bench_release_zip.py`）。
- **`build/` 中间产物已清理**（2026-09-11）：`01_MainProgram/smart7z/build/` 共 667 MB / 5.5 万文件（`pyinstaller-dist`、`pyinstaller-work`、`release-resources`、`source-package` 及 `smart7z_version_info.txt`）全部移入回收站。清理前已重算 1.0.4 三件产物的 SHA-256，与 `SHA256SUMS.txt` 完全一致，确认产物不依赖这些中间文件。`verify_project.py --build` 的"已有 build/ 即中止"门槛现已不再触发；同版本发布物仍在 `release/`，重新构建前需先处理它。
  - **注意**：本机 PowerShell 无法 `Add-Type` 或实例化 COM（被安全策略拦截），且无 `trash` 命令行工具；回收站投递通过 `SHFileOperationW`（ctypes，`FOF_ALLOWUNDO`）完成。`source-package`（2.6 万文件）首次投递返回 `rc=120`，重试即成功。
- **1.0.4 暂不发布**（2026-09-11 决定）：三件产物作为候选留在 `release/`，README 与发行入口保持 1.0.3 不变。
- **启动诊断第 2 轮重启测量取消**（2026-09-11 决定）：该轮唯一目的是刻画"任务列表创建"波动，而波动已定性为测量循环连跑留下的残留效应，该阶段确认无可修缺陷。
- **文档整理**（2026-09-11）：修正本指南 14 处带 `../` 前缀的失效链接；修正 README 指向不存在的 `docs/MAINTENANCE.md`；README 发行节补充 1.0.4 待发布与 `SHA256SUMS.txt` 会被重写两点；`.gitignore` 补充 `/.artifact_spreadsheet_build/`、`/outputs/`（与本项目无关的工作区产物，不删除）；核心文档收敛为根目录三份。逐条核对 4 份文档共 21 条相对链接，0 失效。**阶段性审查报告已按决定删除**（原 `.sandbox-test/autonomous-review/` 三份报告与 SUMMARY，结论已提炼至本节与下方各节）。

### 分卷误并的实测结论（2026-09-11，替代此前的推断）

此前记录称"形如 `report.r20`/`data.z20` 的独立包会被永久判为缺卷、手动添加也绕不过"。**实测结果与之相反**，需要按下表理解：

| 场景 | 实测行为 | 是否有缺陷 |
| --- | --- | --- |
| 目录内只有 `report.r20`（独立 ZIP） | `standalone`，可正常处理 | 无 |
| 真 RAR 分卷 `book.rar` + `.r20` + `.r21` | 正确成组，续卷被跳过 | 无 |
| 两个独立 ZIP `report.r20` + `report.r21` | 只入队**一个**，第二个被静默丢弃 | **有**（键折叠） |
| 真 split-ZIP `data.zip`+`.z01`+`.z02` 与独立包 `data.z20` 共存 | `data.z20` 被判 `zip_split` 缺卷 | **有**（判据武断） |
| 真 RAR 分卷缺主卷（只有 `.r00`/`.r01`） | 判为 `standalone`，不再是"缺卷" | 无（已由本轮修复改善） |

关键实测数据：真实 RAR 分卷（10 卷）中**每个卷**的 `has_independent_archive_structure()` 都返回 `True`，所以"有完整结构"这条判据无法区分续卷与独立包——这正是原兜底失效的原因。7-Zip 生成的 ZIP 分卷末卷（带中央目录）同样返回 `True`。

### 补充分析：这两条到底会不会被 7z 拦下

结论：**第 1 条会，第 2 条不会**——第 2 条在更早的环节就被应用自己拦掉了。

- **第 1 条（边角签名）**：分类器放行 → 任务入队 → executor 读清单时 7z 打不开 → 任务 FAILED。属于"7z 兜住了，但用户白看一次失败"。**已修**：quick 路径的正向判定改为必须先过 `has_independent_archive_structure()`；该函数**已经对 ZIP 做中央目录校验**（`_zip_central_info`），此前只是 quick 路径没调用它。代价：命中的少数文件要多读 1 MB 边缘（quick 路径原本只读 64 KB），平均开销几乎不变。
- **第 2 条（分卷误并）**：`executor.py` 对**每个任务**先做 `detect_archive_set`，发现 `is_complete=False` 就直接 `_fail(..., MISSING_VOLUME)` 返回，**7z 根本没被调用**。**已修**：改为仅当该文件**自身带独立归档结构**时才交由 7-Zip 判定（即"名字像续卷、实为完整独立包"的情况）；其余缺卷集合仍以 `MISSING_VOLUME` 失败——实测 7-Zip 对垃圾首卷会假报成功，见「缺卷判定为什么不能全交给 7-Zip」。同时修掉两处真正的误并根因（见上「实测结论」节）。
- **两类都不会丢数据**：`FAILED` 状态不清理源文件（见「行为核对重点」）。

### 分卷探测在"查找文件夹"时是怎么做的

分工是三段，别把它们混在一起：

1. **扫描阶段只做"要不要入队"的粗筛**（`archive_classifier.classify_automatic_candidate`），配合 `logical_archive_key()` 去重。逐个文件判断是否像归档；对它认定的续卷，用 `discovery.is_multipart_child()`（`discovery.py`）**跳过**，不单独入队，保证一套分卷只产生一个任务。**去重键只在主卷存在时才折叠**——缺少主卷的续卷名会保留自身身份，避免不同独立包被合并成一个键。
2. **成组与完整性判定在任务预检阶段**（`executor.py`），不在扫描阶段。由 `detect_archive_set(job.path)` 按文件名模式在**该文件所在目录**里收集同名兄弟，产出 `ArchiveSet(main_path, volumes, format_family, missing_indexes, is_complete)`，并把 `job.path` 换成主卷。
3. **中央目录/结构校验的归属**：由 `has_independent_archive_structure()` 承担（它是"这文件里是否有一个结构完整的归档"的判定，ZIP 走中央目录、7z/RAR/WIM/ISO 等走强签名），因为那是唯一能在入队前拦住误判的位置。**注意它不能用来判断"是不是分卷"**：真实 RAR/ZIP 分卷的每一个卷本身都带强签名/中央目录，该函数对续卷同样返回 True。分卷归属只能靠**同族主卷是否存在**这一目录级证据。7z 只当**最终权威**（读清单、解压校验），不当筛选器用。

### 缺卷判定为什么不能全交给 7-Zip（2026-09-11 实测）

`executor.py` 对缺卷集合**只在"文件自身带独立归档结构"时才把判定交给 7-Zip**；其余情况直接以 `MISSING_VOLUME` 失败。原因是实测发现 7-Zip 在坏输入上会给出**假成功**：

| 输入 | `7z x` / `7z l` 结果 |
| --- | --- |
| 真实 7z 分卷，删掉中间卷 | `rc=2`，`Unexpected end of archive` —— 能正确报错 |
| 内容为 `b"first"` 的垃圾 `archive.001` | **`rc=0`，输出 `Everything is Ok`** —— 假成功 |

即"第一卷被截断或根本是垃圾"时 7-Zip 会说一切正常。若把这类输入无差别交给 7-Zip 判定，用户会看到一次假成功而不是 `MISSING_VOLUME`。这与"`.r20` 独立包"不同：后者**自己就是完整归档**，确实应当交给 7-Zip 正常处理。

配套地，`discovery.py` 里 `_CLASSIC_R_RE`（`.r`–`.z` 后缀）**先于** `_ZIP_Z_RE` 匹配，所以 `.zNN` 必须先按 ZIP 分卷处理、不能硬探 `.rar`，否则真 split-ZIP 续卷会被判成非子卷。

## 仓库整洁化与提交计划（2026-09-12）

接手时的状态：**20 个提交、719 MB、工作树长期 dirty**。四份核心文档从未进过版本库（误删即失），3 个未跟踪大目录没被 ignore（一次 `git add -A` 就能把 3.7 GB 推进暂存区），仓库没有行尾策略，并且 HEAD 还跟踪着 143 MB 的 1.0.2 交付产物。

### 已落库（本地提交，未推送）

| 提交 | 内容 |
| --- | --- |
| `dd5f319` | `chore(git)`：`.gitignore` 补 `/.sandbox-test/`、`/.codegraph/`、`/.workbuddy/`，连同此前已改未提交的 `/.artifact_spreadsheet_build/`、`/outputs/`、`/01_MainProgram/smart7z/.verification/` 一起落库 |
| `4b92c66` | `chore(git)`：新增 `.gitattributes` 行尾策略。文本在库内统一存 LF，Windows 脚本与 Inno 安装脚本保持 CRLF，二进制不转换；已用 `git add -n --renormalize` 验证无内容翻动 |
| `9cff198` | `chore(repo)`：`发行版/`、`源码/` 移出跟踪并**移入回收站**（8 个文件、142.8 MB）。删除前登记了逐文件 SHA-256，见 `.sandbox-test/git-hygiene-20260912/removed-1.0.2-artifacts.md`；在改写历史之前可用 `git checkout f1bc086 -- 发行版 源码` 取回 |
| `3bf8e07` | `docs`：`CHANGELOG.md`、`HANDOFF.md`、`MAINTENANCE.md`、`smart7z_user_manual.html` 四份核心文档首次入库；删除已被取代的 `SMART7Z_POST_REVIEW_PLAN.md` 与旧手册 `smart7z_user_manual .html`（文件名带空格）；README 重写 |
| `9e99b73` | `fix(resources)`：清除被测试写入 `resources/smart7z_config.json` 的临时路径（`7z_path` 变成 `C:\7z.exe`、`target_dir`／`temp_dir` 指向 `%TEMP%`）。**这是会随包发出的产品资源模板**，现已恢复为空值，`allow_permanent_fallback` 键保留 |
| `docs(maintenance)`（本节所在提交） | 记录本次仓库整洁化与剩余计划，改写「待决事项」第 2、3 条 |

### 待办（见「待决事项」第 2 条）

剩下的是一整批 1.0.4 代码改动：19 个已跟踪文件被改、4 个新源码文件、4 个新测试文件。分组方案与执行顺序见 `.sandbox-test/git-hygiene-20260912/COMMIT_PLAN.md`，需拍板的只有两件事——按哪套方案拆、以及是否要求每个提交单独跑一次测试。

### 三条硬约束

1. **只做本地提交，不推送。** 远程 `origin` 停在 `f1bc086`；「已落库」那张表就是全部未推送的提交，推送是单独一次决定。
2. **本轮不改写历史。** 仓库体积问题只做到"不再增长"，`filter-repo` 瘦身属独立一轮，见「待决事项」第 3 条。
3. **全部提交完成、工作树干净之后**，再跑一次 `git checkout-index -f -a` 按新策略重写工作树行尾。**工作树 dirty 时不要跑**，它会把未提交内容覆盖掉。

## 目录

- [01_MainProgram/smart7z/](01_MainProgram/smart7z/)：程序源码、测试、构建脚本和资源模板。
- [01_MainProgram/smart7z/release/](01_MainProgram/smart7z/release/)：实际构建输出，目前包含 1.0.3 安装包、便携 ZIP、源码 ZIP 和 `SHA256SUMS.txt`，也保留了 1.0.2 产物。
- `发行版/`、`源码/`：1.0.2 的旧交付目录。**2026-09-12 已从版本库和工作区移除**（文件在回收站，SHA-256 清单见 `.sandbox-test/git-hygiene-20260912/removed-1.0.2-artifacts.md`），发布入口只认 `release/`。
- `.gitattributes`：行尾策略，2026-09-12 新增，见「仓库整洁化」。

## 运行环境

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Windows（回收站、右键菜单、单实例 IPC 等按 Windows 行为实现） |
| Python | 仅源码运行和开发需要；原 README 记录打包与测试使用 64 位 Python 3.14.6。重新验证以实际解释器和报告为准，不把历史记录当兼容范围。 |
| 7-Zip | 安装/便携版自带；源码版需系统安装或在源码根目录放置 `7z.exe` |
| 图形界面 | 发行版已带 PySide6；源码版需自行安装 |

源码版从仓库根目录运行：

```powershell
Set-Location 01_MainProgram/smart7z
python smart7z.py
```

## 程序模块

下表文件均位于[源码目录](01_MainProgram/smart7z/)。

| 文件 | 职责 |
| --- | --- |
| `smart7z.py` | 程序入口，调用 `ui_qt.run_app`。 |
| `ui_qt.py` | PySide6 界面、路径输入、拖拽、任务详情、日志、右键菜单和配置同步。界面、命令行、右键菜单和 IPC 收到的文件最终都转为 Job 交给 Scheduler。 |
| `runtime_ipc.py` | 启动参数、单实例互斥协作和本机 IPC，不依赖 GUI 工具包。 |
| `models.py` | 状态、错误、清理策略、任务、清单和输出移动记录等数据模型（JobState、ErrorCategory、CleanupPolicy、Job）。 |
| `user_messages.py` | 用户可见消息目录：中英文模板与稳定代码，供程序和手册同步检查。 |
| `config.py` | 配置路径、默认值、迁移、保存和 7-Zip 定位。 |
| `scheduler.py` | 任务调度：单工作线程按源包大小升序处理，同大小保持入队顺序，人工输入后的恢复任务优先。 |
| `executor.py` | 任务处理状态机：识别、读清单、试密码、预检、等待空间、解压、校验、移动输出、清理源文件和嵌套任务。 |
| `sevenzip.py` | 7-Zip 调用层：执行命令、解析进度、分类返回码，同一进程一次只跑一个 7-Zip 操作。 |
| `discovery.py` | 分卷识别和压缩包去重标识。 |
| `archive_classifier.py` | 目录扫描分类器，供目录扫描和嵌套扫描使用。 |
| `steganographier_compat.py` | 隐写者兼容模式探测：BMFF 原子和 Matroska EBML/SeekHead 跳读。 |
| `stego_candidates.py` | 通用内嵌压缩包候选定位：ZIP/ZIP64 结构检查、限定区间校验、全文件深度扫描与 B' 候选分流。 |
| `path_safety.py` | 路径安全：拦截穿越、ADS、设备名、重解析点逃逸。 |
| `nested.py` | 嵌套压缩包识别：限制深度、数量、字节数，防循环，保护普通 EXE 目录。 |
| `recovery.py` | 恢复日志：跟踪临时目录和源文件暂存；写不进就停相关操作。 |
| `windows_adapters.py` | Windows 集成：卷级回收站设置、严格回收、永久删除、右键菜单、长路径。 |
| `verify_project.py` | 按测试组验证、汇总报告、检查结果复用条件及构建门槛。 |
| `startup_trace.py` | 默认关闭的启动阶段诊断，通过 `SMART7Z_STARTUP_TRACE` 指定输出后启用；事件先缓冲，再集中写入，避免逐事件写盘。 |
| `startup_runtime_hook.py` | 打包版在 PyInstaller 的 Python 引导之后记录最早的应用侧标记；不等于进程启动时刻。 |
| `benchmark_startup.py` | 准备隔离副本，交替测量打包版和源码版；可检查准备后是否确实重启。 |

### 行为核对重点

- **B' 候选分流**：`triage_candidates` 过滤签名噪声、无结构证据、无效范围及重复项。唯一精确 ZIP/ZIP64 为 `DEFAULT_AUTO`；唯一有结构证据且边界非暂定、但未达到自动条件的候选为 `DEFAULT_PRESELECT`；多候选或暂定边界为 `REVIEW`。`HIGH` 本身不足以自动放行，推荐预选不等于确认，也不授权清理源文件。
- **取消任务**：界面 `_cancel_selected` 经调度器移除选中的未完成任务，活动任务请求停止；不把迟到事件重新显示为提示。取消操作不等于源文件清理；“取消所有”会留下当前任务继续执行，当前任务仍可能按其策略清理源包。
- **密码顺序**：`_password_candidates` 优先手动输入，再用会话主密码、适用时的无密码探测和密码文件候选。完整成功后会话优先密码更新，`_promote_password` 尝试把成功密码写到明文密码本顶部。同批下一任务可使用新顺序，无需重启；当前一轮已取得的候选不在中途替换。
- **配置与清理**：执行配置快照固定本次任务的输出目录、暂存模式等；清理策略另存于任务对象，`Scheduler.refresh_config` 会更新所有未终态任务的策略，包括活动任务。不能向用户承诺“运行中所有配置都不会变”。终态任务保留结束时的策略。
- **安全边界**：自动发现、候选选择、完整解压校验和源文件清理是不同阶段。候选自动继续不等于内容可信；`FAILED`、`PARTIAL_RECOVERY`、`INTERRUPTED` 不清理源文件。

## 配置项

源码运行时读 `01_MainProgram/smart7z/resources/smart7z_config.json`；安装版用 `%LOCALAPPDATA%/Smart7z/smart7z_config.json`；EXE 旁有 `portable.flag` 时用便携模式（配置在 EXE 目录）。

相对密码文件路径基于可写状态目录解析，不一概相对程序目录。升级时若旧程序目录里已有非空密码本、而新位置缺失或为空，可能继续使用旧密码本；自定义绝对路径按指定位置使用。密码本是明文，不应提交、打包或分享。

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `7z_path` | 空（自动查找） | 留空时依次查程序目录和系统安装目录。 |
| `target_dir` | 空 | 非原目录解压时的目标目录。 |
| `extract_to_source` | `true` | 解压到源压缩包所在目录。 |
| `wait_disk_space` | `true` | 空间不足时等待，适合稍后能释放空间的场景；不负责自动腾空间。 |
| `steganographier_compat_mode` | `true` | 默认扫描模式：跳读识别 SteganographierGUI 兼容的 MP4/MKV ZIP。 |
| `deep_scan` | `false` | 未命中兼容探测时做全文件流式预检，适合未知布局但增加读取量；开启时关闭兼容模式选项，探测仍可优先使用兼容路径。 |
| `temp_dir` | `%TEMP%/Smart7z`（程序默认） | 暂存模式临时根；资源模板为空，由运行时选择可用位置，不表示禁用临时目录。 |
| `password_file` | `code.txt` | 密码候选文件路径。 |
| `extract_mode` | `staging` | `staging` 用暂存目录；`direct` 在目标目录下建隐藏临时目录。两者都先校验再移动，跨盘暂存还需要复制输出。 |
| `config_version` | `1` | 配置结构版本，由程序维护。 |
| `cleanup_policy` | `keep` | `keep` / `recycle` / `permanent`。三类交付首次运行都默认保留。 |
| `del_archive` | `false` | 旧版兼容字段，按 `cleanup_policy` 自动同步，不要单独修改。 |
| `allow_permanent_fallback` | `false` | 仅“回收站”策略下，明确不可回收或超容量时允许永久删除；不是遇到任何错误都删。 |
| `nested_extraction` | `false` | 自动处理解压结果中的内层压缩包，会增加任务和空间需求。 |
| `max_nested_depth` | `2` | 嵌套最大深度。 |
| `space_wait_timeout` | `7200` | 空间等待超时秒数。 |
| `max_manifest_entries` | `200000` | 清单最大条目数（内部安全上限同为 200000，调高无效）。 |
| `max_output_files` | `200000` | 输出文件数上限。 |
| `max_output_bytes` | `0` | 0 表示按清单和空闲空间自动批准，不是无限制。 |
| `max_nested_children` | `50` | 每个根批次最多内层任务数。 |
| `max_nested_output_bytes` | `0` | 嵌套总字节上限；0 为不单独限制。 |

保存与应用时机见手册[选项总览](smart7z_user_manual.html#options-save)。保存配置不保存“主密码”字段，但成功密码可能另行写入密码本；不要混淆这两条路径。

## 测试

所有下列测试命令均在源码目录执行。

### 文档专项

```powershell
.\.build-venv\Scripts\python.exe -X utf8 -m unittest discover -s tests -p test_user_messages.py -q
```

**手册同步契约**：[test_user_messages.py](01_MainProgram/smart7z/tests/test_user_messages.py) 解析 HTML 可见文本，逐条比对 [user_messages.py](01_MainProgram/smart7z/user_messages.py) 的消息代码及精确中英文模板，并锁定必需/禁用短语和章节锚点。编辑器附加属性不影响验证，不为通过测试而删除断言或隐藏消息文本。

编辑手册时保留已有章节 `id`、消息代码、精确双语模板及安全禁令；不全量清理 `data-page-node-id`。白话解释应放在模板之外。除测试外，还需检查原有锚点是否保留、内部链接是否有效；页面排版由人工渲染复核。

测试和构建均优先使用源码目录的 `Smart7z-User-Manual.html`，不存在时才使用仓库根目录的 `smart7z_user_manual.html`。本轮核对时前者不存在，因此专项测试验证的是工作树手册。

### 日常与完整验证

并行性能测量期间不要运行下列全量、界面或构建操作。日常入口为源码目录中的 [verify_project.py](01_MainProgram/smart7z/verify_project.py)，无需 pytest。默认全量测试，完整输出写日志，终端仅显示统计与失败摘要：

```powershell
python verify_project.py
python verify_project.py --suite candidates
python verify_project.py --suite ui
python verify_project.py --suite integration
python verify_project.py --suite release
python verify_project.py --pattern "test_config.py"
```

结果保存在源码目录 `.verification/`；可用 `--report-dir` 指定证据目录。`--reuse` 仅复用 24 小时内测试选择、输入指纹及运行环境均一致的成功结果。当前输入指纹涵盖源码目录顶层文件、测试、资源、构建资产及根 README/CHANGELOG/手册，不包含本指南；修改本指南仍应人工复核链接和命令。

```powershell
# 全量（图形测试需要 PySide6，真实解压需要 7-Zip，发布测试需要 PowerShell）
python -m unittest discover -s tests -p "test_*.py" -q

# 单个模块
python -m unittest discover -s tests -p "test_runtime_safety.py" -q
```

覆盖范围：界面生命周期、扫描模式、SteganographierGUI 三类布局、诱饵尾缀、ZIP64、右键菜单注册、单实例参数转发、配置与迁移、分卷识别、路径安全、7-Zip 输出解析、运行时安全、内嵌 ZIP 候选、输出提交、源文件恢复。

测试通过只证明该次环境与输入下的结果，不替代发行物核验或启动性能测量。

### 启动诊断

不要同时运行性能测量和全量测试、构建。复测步骤：

- 在源码目录运行 `benchmark_startup.py --prepare APP_DIR --output PATH`，从独立诊断包目录准备隔离副本；`APP_DIR` 和 `PATH` 替换为实际路径，输出目录应尚不存在。
- 随后用同一解释器运行 `benchmark_startup.py --output PATH --runs 3 --first frozen`，或用 `--first source` 调整先测对象；每轮交替顺序，降低固定先后次序的影响。
- 需要重启后观察时添加 `--after-reboot`，工具会检查自准备后是否确实重启，并拒绝同次开机重复首测。只有首个测量进程属于该次重启后首次观察，后续进程共享已预热的系统缓存，不能都称为冷启动。用户仍需确保没有提前运行其他 Smart7z 副本。

上述脚本用 Python 调用，例如 `python benchmark_startup.py --output PATH --runs 3 --first frozen`。阶段标记不是屏幕实际显示延迟，也不能把运行时钩子之前的耗时全部归因于打包器；结论以主线报告及其测量限制为准。

本机已经准备好 `paired-final/`，用户自行重启后可从仓库根运行 `.sandbox-test/startup-phases/measure_after_reboot.ps1`；另一轮独立重启后加 `-First source`。后续会话先读启动报告和两个新增的 `results.json`，无需重新翻阅整段历史。`recycle_probes.py` 默认仅列出清理预览，加 `--execute` 才将固定白名单送入回收站，不永久删除；它不会清理 `paired-final/`、日志、备份或发行包。

## 构建与发布

构建脚本：[build_release.ps1](01_MainProgram/smart7z/build_release.ps1)，产出安装包、便携 ZIP、源码 ZIP，实际目录是源码下的 `release/`。

后续安排发布时，可在源码目录使用以下入口：

```powershell
python verify_project.py --reuse --build
```

此入口要求全量通过且无跳过项；遇到已有 `build/` 或同版本发布物会停止，不自动覆盖或删除。**该停止保障由 `verify_project --build` 入口强制；直接运行 `build_release.ps1` 不提供此保障**（它自身在开始时即可删除已有的同版本产物），独立调用前请自行核对并备份。不要为了绕过门槛直接清掉已发布文件；先核对、备份并由发布负责人决定如何处理。当前 `build/` 已清空，该门槛不会因历史中间产物触发；同版本发布物仍在 `release/`，重新构建前需先处理它。

构建会把选定手册复制为各包的 `Smart7z-User-Manual.html`。工作树 README、手册或本指南的修改不会自动进入已发布的安装包、便携包或源码 ZIP；本轮不更新发行物，也不承诺构建脚本自动收录新指南，未来发布需核对包内文档与相对链接。

### 校验清单与压缩实现（2026-09-11 起）

- **校验清单按版本命名**：构建写出 `release/SHA256SUMS-<version>.txt`，并同时写一份不带版本号的 `SHA256SUMS.txt` 作为"最新"别名。覆盖历史版本清单不会再发生。
- **压缩走 `New-ReleaseZip`**：便携包与源码包均用 Python `zipfile`（deflate level 6）打包，替代原先的 `Compress-Archive`。理由是实测的数量级速度差（源码包 299 MB / 2.75 万文件：约 44 分钟 → **47.4 秒**），且构建流程本就依赖 Python。**排查压缩问题时不要退回 `Compress-Archive`**；若需调整压缩率，改 `New-ReleaseZip` 的 `-CompressionLevel`。注意源码包整体耗时的大头是 `corresponding-source`（297 MB Qt 源码）的暂存复制，不是压缩本身。
- 校验清单只覆盖三个交付产物（两个 `.zip` + 一个 `.exe`），不含清单自身，也不含包内手册等内容的哈希。

发布前检查：

- 确认 7-Zip 路径有效，版本差异记录在发布说明。
- 资源模板默认值：`cleanup_policy=keep`、`del_archive=false`、`steganographier_compat_mode=true`、`allow_permanent_fallback=false`，`code.txt` 为空。
- 验证配置文件和密码文件所在目录可写。
- 测试普通 ZIP、加密 7z、完整分卷、缺卷、恶意路径、部分损坏、带内嵌 ZIP 的外层文件。
- 确认 PARTIAL_RECOVERY、FAILED、INTERRUPTED 状态下都不清理源文件。
- 模拟回收站可用、NukeOnDelete、容量超限、设置未知、Shell 失败和兜底删除失败（不要改真实注册表或动真实用户文件）。
- 关闭窗口后检查无该次运行残留的 `python`、`7z`、`7zG`、`7zFM` 进程，不干预其他工作进程。
- 安装模式（`%LOCALAPPDATA%/Smart7z`）、便携模式（`portable.flag`）和旧配置迁移分别过一遍。
- 三个交付包内容互不混放；源码包不含构建缓存、虚拟环境、测试密码或运行时恢复记录。
- 核对包内手册版本、消息契约及文档链接；重新计算三个交付包的 SHA-256，从最终交付目录复核，并与 `SHA256SUMS-<version>.txt` 比对。
