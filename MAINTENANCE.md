# Smart7z 维护指南

本指南面向开发、测试和发布维护者。日常操作见[用户手册](smart7z_user_manual.html)，项目入口见 [README](README.md)，产品变更见 [CHANGELOG](CHANGELOG.md)。

下文路径相对仓库根目录；“源码目录”指 `01_MainProgram/smart7z/`。指南只保留当前规则和可重复的操作，阶段性修复记录、机器路径和测试证据保存在本地 `.sandbox-test/`，不作为正式发行状态。

## 文档与目录

| 路径 | 职责 |
| --- | --- |
| `README.md` | 下载、快速上手和文档导航。 |
| `smart7z_user_manual.html` | 用户操作、安全边界、消息代码与双语模板；打包为 `Smart7z-User-Manual.html`。 |
| `CHANGELOG.md` | 唯一的产品变更记录，随三种发行包分发。 |
| `MAINTENANCE.md` | 开发和维护流程；原交接指南中仍有效的内容已合并到这里。 |
| `01_MainProgram/smart7z/` | 一方源码、测试、构建脚本、资源与第三方声明。 |
| `01_MainProgram/smart7z/release/` | 本地构建输出，不进版本控制；可能包含未发布候选。 |
| `.sandbox-test/` | 隔离语料、历史报告和验证证据，不打包，不提交。 |
| `.codegraph/` | 本地代码检索索引，可重建，不随源码包分发。 |

不要把开发过程不断追加到用户手册或更新日志。修改现有行为时同步对应文档；不重复抄写整轮测试日志。删除或合并历史文档前先保留可校验的本地归档。许可证、原始失败证据和用户语料不属于文档清理范围。

## 开发环境

| 项目 | 说明 |
| --- | --- |
| 系统 | 64 位 Windows；发行目标为 Windows 10 1809 及以上版本、Windows 11。回收站、右键菜单和 IPC 必须在 Windows 验证。 |
| Python | 本轮验证基线为 64 位 Python 3.14.6；这不是对其他版本兼容性的承诺。 |
| PySide6 | 构建基线 6.11.1；安装版和便携版已带运行依赖。 |
| 7-Zip | 发行包自带完整命令行组件；源码运行需系统安装或在源码根放置 `7z.exe`。 |
| 构建工具 | PowerShell 7、Inno Setup、64 位 .NET Framework C# 编译器，完整 7-Zip 发行文件及经哈希验证的 Qt/PySide 源码归档。 |

从仓库根目录准备开发环境：

```powershell
Set-Location 01_MainProgram/smart7z
python -m venv .build-venv
.\.build-venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.build-venv\Scripts\python.exe smart7z.py
```

`requirements-build.txt` 固定构建依赖版本；只运行程序时不需要全部打包工具。不要跨机器复制虚拟环境。下文用 `python` 简写已选定的环境解释器，执行前确认实际路径。

## 模块

以下文件均位于[源码目录](01_MainProgram/smart7z/)。

| 文件 | 职责 |
| --- | --- |
| `smart7z.py` | 入口与轻量实例转发，随后调用 Qt 界面。 |
| `ui_qt.py` | 界面、输入、拖拽、任务表、详情、日志、配置同步和关闭流程。 |
| `launch_ipc.py` / `runtime_ipc.py` | 无 Qt 的轻量客户端、共享实例发现路径，以及有界本机服务端和界面事件映射。 |
| `runtime_startup.py` | 后台初始化、结果归属、取消和未交接资源释放，不依赖 Qt。 |
| `models.py` / `user_messages.py` | 任务状态与数据模型；稳定消息代码及精确双语模板。 |
| `config.py` / `password_book.py` | 配置路径、默认值、迁移与保存；有界密码候选读取和完整密码本回写。 |
| `scheduler.py` | 单工作线程调度，小包优先、同大小按接收顺序，人工输入后的恢复任务优先。 |
| `executor.py` | 识别、清单、密码、预检、空间等待、解压、校验、提交、清理和嵌套任务。 |
| `sevenzip.py` | 7-Zip 进程、流式清单解析、进度与错误分类。 |
| `discovery.py` / `archive_classifier.py` | 分卷和去重身份；目录及嵌套扫描分类。 |
| `steganographier_compat.py` / `stego_candidates.py` | 容器跳读、ZIP/ZIP64 结构校验、深度扫描及候选分流。 |
| `path_safety.py` / `nested.py` | 路径边界，嵌套深度、数量、字节与循环限制，普通 EXE 目录保护。 |
| `recovery.py` / `windows_adapters.py` | 恢复日志与临时目录所有权；回收站、删除、菜单和长路径集成。 |
| `verify_project.py` | 测试分组、指纹、结果复用和构建门禁。 |
| `startup_trace.py` / `startup_runtime_hook.py` / `benchmark_startup.py` | 可选启动计时、打包运行时标记和隔离测量。 |

## 不应改变的规则

- **清理策略在接收时冻结**：设置切换不改变任何已接收任务，包括待接纳、排队、等待和执行中任务；外部请求明确指定的策略和嵌套继承策略不被全局设置覆盖。
- **清理需要独立证明**：自动发现、候选选择、完整校验与源文件清理是不同阶段。失败、中断和部分恢复不清理源文件；多卷清理还需有效且数量一致的卷元数据，名字相似不是许可。
- **完整独立包优先**：分卷身份不只看扩展名。7z 检查完整头部及边界，RAR 检查主头 CRC 和卷标志，split-ZIP 检查跨盘结构。
- **候选推荐不是确认**：唯一精确 ZIP/ZIP64 可自动继续；唯一非临时结构候选可预选；多候选或暂定边界需要复核。高置信度本身不授权自动解压或清理。
- **密码本不能因尝试上限被截断**：候选数量和行长限制只限制尝试。超过 4 MiB、读取不完整、编码无法无损保存或写前发现外部修改时跳过回写；保留密码首尾空格。
- **取消不是删除源包**：“取消选中”移除所选未完成任务并请求停止活动任务；“取消所有待处理”不停止当前任务，当前任务仍按自身策略执行。
- **未完成工作都需要关闭确认**：UI 待处理输入与加锁的 `Scheduler.has_unfinished_jobs()` 共同判定，不能仅看当前任务或队列长度。确认默认不退出，防止自动关闭重入；拒绝退出后工作继续。
- **恢复数据先保全**：恢复记录写入失败时停止相关操作；提交失败后需要人工恢复的目录不能被通用临时清理删除。初始化失败及取消释放未交接的日志锁和会话目录。
- **同会话一个窗口**：安装、便携和源码副本共用窗口和队列，本版本没有多实例开关。只共享 IPC 连接信息，不合并其他用户数据。

## 配置与数据

| 运行方式 | 配置与恢复状态 |
| --- | --- |
| 源码 | 配置在 `resources/smart7z_config.json`，状态按源码模式保存。 |
| 安装 | `%LOCALAPPDATA%/Smart7z/`。 |
| 便携 | EXE 旁存在 `portable.flag` 时，保存到 EXE 所在目录。 |

IPC 是例外：所有副本使用 `%LOCALAPPDATA%/Smart7z/ipc-v3.json`；缺少 `LOCALAPPDATA` 时依次回退到 `TEMP`、`TMP` 或系统临时目录下的 `Smart7z`。这里只存本机端口及随机认证信息。升级前关闭旧版窗口，旧便携版的私有 IPC 文件不能从任意位置自动发现。

相对密码本路径基于可写状态目录解析。旧程序目录已有非空密码本而新位置缺失或为空时，可能继续使用旧地址。密码本是明文，不能提交、打包或分享。卸载保留配置、密码本和恢复数据。

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `7z_path` | 空 | 自动查找程序目录和系统安装目录。 |
| `target_dir` | 空 | 非原目录解压时的目标目录。 |
| `extract_to_source` | `true` | 解压到源包旁边。 |
| `wait_disk_space` | `true` | 空间不足时等待，不自动腾空间。 |
| `steganographier_compat_mode` | `true` | 默认跳读兼容的 MP4/MKV ZIP 布局。 |
| `deep_scan` | `false` | 全文件流式预检；增加读取量，与兼容模式菜单项互斥。 |
| `temp_dir` | `%TEMP%/Smart7z` | 资源模板为空，由运行时选择临时位置，不表示禁用暂存。 |
| `password_file` | `code.txt` | 一行一个候选。 |
| `extract_mode` | `staging` | `staging` 用暂存目录；`direct` 在目标盘临时目录解压，两者均校验后提交。 |
| `config_version` | `1` | 由程序维护。 |
| `cleanup_policy` | `keep` | `keep` / `recycle` / `permanent`。 |
| `del_archive` | `false` | 旧版兼容字段，随清理策略同步。 |
| `allow_permanent_fallback` | `false` | 仅回收策略下明确不可回收或超容量时允许永久删除，不是任意错误都删除。 |
| `nested_extraction` | `false` | 自动处理内层归档。 |
| `max_nested_depth` | `2` | 嵌套深度上限。 |
| `space_wait_timeout` | `7200` | 空间等待超时秒数。 |
| `max_manifest_entries` | `200000` | 清单上限，不能超过内部安全上限。 |
| `max_output_files` | `200000` | 输出文件数上限。 |
| `max_output_bytes` | `0` | 0 表示按清单和空闲空间批准，不是无限制。 |
| `max_nested_children` | `50` | 每个根批次的内层任务数上限。 |
| `max_nested_output_bytes` | `0` | 嵌套总字节上限；0 为不单独限制。 |

保存与应用时机见手册[选项总览](smart7z_user_manual.html#options-save)。主密码不写配置，但成功密码可能另行写入密码本，不要混淆两条路径。

## 测试

在源码目录运行：

```powershell
python verify_project.py
python verify_project.py --suite candidates
python verify_project.py --suite ui
python verify_project.py --suite integration
python verify_project.py --suite release
python verify_project.py --pattern "test_runtime_safety.py"
```

默认是 `test_*.py` 全量测试，图形用例需要 PySide6，真实解压需要 7-Zip，发布测试需要 Windows PowerShell。摘要和详细日志默认写入 `.verification/`；使用 `--report-dir` 指定隔离证据目录。

`--reuse` 只接受 24 小时内、测试选择、输入指纹和环境均一致的成功结果。指纹涵盖源码顶层文件、测试、资源、构建资产及根 README/CHANGELOG/手册。测试期间不要编辑这些输入；出现 `input_changed` 时先检查测试是否写坏了真实资源模板，不直接归因于环境噪声。

### 文档契约

[test_user_messages.py](01_MainProgram/smart7z/tests/test_user_messages.py) 解析手册可见文本，逐条比对消息代码和精确中英文模板，并锁定安全说明和章节锚点。

编辑手册应保留既有 `id`、消息代码和模板；解释性改写放在模板外，不为通过测试删断言，也不批量清除编辑器附加属性。专项测试：

```powershell
python -m unittest discover -s tests -p test_user_messages.py -q
```

测试和构建优先使用源码目录的 `Smart7z-User-Manual.html`，不存在时使用仓库根手册；更新日志也优先使用源码包根的 `CHANGELOG.md`，否则使用仓库根版本。另需检查相对链接和渲染结果。

### 实际场景

用新建隔离目录和最终成品测试，不覆盖旧报告或使用真实用户密码本。至少覆盖普通包、加密包、完整分卷与续卷入口、缺卷、相似卷名独立包、内嵌 ZIP、恶意路径、损坏输出、嵌套包及源包策略。

成功必须核对输出路径、内容哈希和源包状态；异常必须核对明确错误/等待状态和源包完整性。进程超时不代表成功。右键窗口只有全部无异常完成才自动关闭，需密码、候选复核或失败时保留窗口，不能用“没退出”判断业务结果。

缺尾卷不一定在预检报 `MISSING_VOLUME`，也可能在清单阶段报 `CORRUPT_HEADER`。7-Zip 对某些垃圾首卷可能返回成功码和零文件，仍须检查警告及完整性，不能只看退出码。

安装、覆盖升级和卸载验证会改变当前用户的安装登记与菜单。先取得授权，记录原状态并在隔离安装目录测试，最后精确恢复原状态；不要改真实回收站配置来制造失败。

### 启动测量

性能测量与全量测试、构建分开运行。`SMART7Z_STARTUP_TRACE` 默认关闭，指定输出路径才启用：

```powershell
python benchmark_startup.py --prepare APP_DIR --output NEW_DIRECTORY
python benchmark_startup.py --output NEW_DIRECTORY --runs 3 --first frozen
```

用实际独立成品目录和新输出目录替换占位参数。`--first source` 调整交替顺序；只有明确安排重启后才使用 `--after-reboot`。工具核对父子时钟、平台及父进程总时长，缺少时钟元数据的旧日志不自动接受。

阶段标记不是屏幕实际呈现时间，运行时钩子前的全部耗时也不能一概归因于打包器。暖启动不能代表冷启动，重启后只有首个测量进程属于首次观察。后台初始化响应性和整体启动速度分别评价，不从少量波动样本推导“无法优化”或固定提速比例。

## 构建与发布

版本在 `ui_qt.py`、`build_release.ps1`、`smart7z_installer.iss` 中保持一致。更新文档后再做最终完整测试：

```powershell
python verify_project.py --report-dir .verification/release
python verify_project.py --report-dir .verification/release --reuse --build
```

该入口要求全量通过且零跳过；遇到已有 `build/` 或同版本 `Smart7z-<版本>-*` 会停止。先核对并归档旧产物及校验清单，不覆盖已发布附件。直接运行 `build_release.ps1` 不具备这一保护，会清理相应输出，不能用来绕过门禁。

构建还会自行验证测试、固定依赖、最小 Qt 运行时、源码归档哈希、许可证、空密码模板和默认保留策略。Qt/PySide 源码缓存使用 `.license-cache/` 或 `.build-tools/qt-source/` 中的两个匹配归档；名称和固定哈希见构建脚本。源码包中的 `corresponding-source/` 是供阅读及许可证合规使用的展开源码，不代替构建所需的原始归档。

### 产物

- `Smart7z-<版本>-setup-windows-x64.exe`：安装器。
- `Smart7z-<版本>-portable-windows-x64.zip`：完整便携目录。
- `Smart7z-<版本>-source.zip`：平铺的一方源码、测试、资源、构建文件、手册、更新日志及第三方材料，不是整个 Git 仓库。
- `SHA256SUMS-<版本>.txt`：以上三个文件的 SHA-256；`SHA256SUMS.txt` 是本次构建别名。

三类包的 `README.txt` 只说明各自的运行和数据位置，详细操作共用手册，变更共用更新日志。仓库维护指南不直接装入平铺源码包，包内 README 提供可独立执行的测试和构建说明，避免失效的仓库相对链接。

### 发布检查

1. 核对版本、Git 工作树和远端标签；保留已有工作，不改写历史、不强推。
2. 全量测试零失败、零错误、零跳过；记录输入指纹、依赖和 7-Zip 版本。
3. 构建三个新产物，核对包内手册/更新日志、许可证、空 `code.txt` 和默认安全配置。
4. 用最终 EXE 做实际场景，单独记录安装、升级、卸载与界面检查的覆盖范围及未测项。
5. 复算哈希，确认包内没有密码、个人配置、IPC 凭据、恢复日志、虚拟环境、缓存或测试语料。
6. 提交已验证的一方源码和文档，将版本标签指向对应提交。先准备 Release 草稿，上传三个产物与版本校验清单；复核远端附件后再发布。
7. 发布后核对标签提交、Release 状态、附件大小与哈希，记录证据。保持仓库原有可见性，不顺带改权限或清理旧 Release。

测试数量、耗时和验收结论写入该次发布记录，不把历史通过数当作新版本结果。工作树文档修改不会热更新旧包内副本。
