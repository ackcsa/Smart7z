Smart 7z Ultra __VERSION__ 源码版
================================

内容
----
- 包含 Smart7z 一方 Python 源码、测试、构建脚本、资源模板和用户手册。
- `licenses/` 包含 Qt 6.11.1、PySide6 6.11.1 和 Shiboken6 6.11.1 对应的 LGPL/GPL 正文及 Qt GPL exception；`licenses/Qt-PySide6-source-manifest.json` 记录版本、组件、许可来源和归档 SHA256。
- `corresponding-source/` 包含从已校验的 qtbase-everywhere-src-6.11.1.tar.xz 与 pyside-setup-everywhere-src-6.11.1.tar.xz 解出的对应源代码树，位置和完整性信息也见 `Qt-PySide6-CORRESPONDING_SOURCE.txt`。
- 不包含 build、release、虚拟环境、离线构建工具、缓存或运行时恢复记录。
- resources/code.txt 为空，resources/smart7z_config.json 默认保留源压缩包。

本次更新
--------
<<<<<<< HEAD
- 修复 7-Zip SLT 清单的空路径根目录元记录被当成实际成员、导致部分 ZIP 以 INTERNAL_ERROR 失败的问题，并增加解析与真实解压回归。
- 修复 Qt 菜单栏固定高度造成的文字裁切，补充菜单几何、文件和目录拖放测试。
- 新增 `launch_ipc.py` 作为无 Qt、无完整运行时模型的轻量转发边界；无实例时用命名互斥量快速退出探测，异常诊断依赖改为按需导入。
- 启动参数延后到 IPC 成功监听后激活；关闭结果传播调度器与 IPC 的真实停止状态，待分发 ticket 会在关闭时取消。
- 首次右键窗口的启动置前不再解除自动关闭；后续外部激活仍会解除，保持用户主动查看时不自动退出。
- 修复嵌套深度 0、一次性密码清理、源包大小升序、输入选中态和深度步进器样式等回归。
- 菜单栏新增“文件扫描模式”三级互斥对钩菜单与“选项 → 空间不足时等待”，并删除工具栏重复按钮；默认选择 SteganographierGUI 兼容模式。
=======
- 图形界面真源为 PySide6 的 ui_qt.py。顶部提供“右键菜单”“文件扫描模式”和“选项”；三种扫描模式互斥选择，默认选择 SteganographierGUI 兼容模式。
- 主界面直接切换“嵌套解压”；“选项”对话框设置暂存目录、密码文件、最大嵌套深度和“空间不足时等待”。
>>>>>>> origin/main
- 兼容探测器支持普通 MP4 追加 ZIP、ZArchiver free 原子和 MKV ZIP 附件；通过 BMFF/EBML 跳读与限定区间 ZIP 校验避免全文件读取。
- 严格校验非饱和经典字段 ZIP64 的记录、定位器和中央目录几何；深度扫描与直接输入优先复用兼容候选，屏蔽随机 RAR/7z/ZIP 诱饵。
- 修复兼容模式扫描任务丢弃预计算候选的执行器准入缺口；已确认的候选现在直接进入安全切割，超过 4 GB 的 MP4 载体不会再以 NOT_ARCHIVE 结束。
- 深度扫描改为单轮流式候选预检和复用；扫描、密码和隐写候选共用非常驻活动栏。
- 任务队列与“任务详情 / 运行日志”使用可拖动的垂直分隔条，并支持显示或隐藏详情；任务默认按源包大小升序执行，密码提示完成后自动恢复布局。
- 自动候选耗尽后的手动密码重试只使用本次输入，不再重复读取会话密码和密码本。
- 修复隐写候选处理后可能遗留空 stego 会话目录的问题，并保持对未登记内容、链接和重解析点的保留策略。
- 安装模式可继续使用旧安装地址中的非空密码本，不会被新位置的空占位替代。
- 嵌套扫描增加普通 PE 目录保护，并为改名压缩包及高置信度 ZIP/7z SFX 保留内容优先例外。
- 单实例启动优先转交请求；现有实例关闭中时，新进程有界等待重新转交或取得启动互斥量后接管，不创建并行窗口、调度器或恢复日志。
- 复用完整加密清单，优先本批次成功密码，并避免已确认加密包的无密码解压尝试。
- 使用有界流式 SLT 解析，在条目超限时提前终止 7-Zip；内部解析安全上限为 200000，配置更高也不会绕过；保留完整安全预检语义。
- 增加列表、解析、预检、解压、输出扫描和总耗时指标。
- 收窄格式回退：自动识别失败后只做一次有签名或扩展名依据的 ZIP/RAR/7z 重试。

运行
----
1. 使用 64 位 Python 3.12，并安装 PySide6。
2. 安装 7-Zip，或把 7z.exe 放在源码根目录。
3. 在源码根目录运行 python smart7z.py。
4. 图形界面使用 PySide6，拖拽由 Qt 原生支持。

验证与构建
----------
- 全量测试：python -m unittest discover -s tests -v
- 真实 7-Zip 集成测试：python -m unittest tests.test_integration_real7z -v
- 构建依赖：python -m pip install -r requirements-build.txt
- 构建：powershell -ExecutionPolicy Bypass -File .\build_release.ps1

完整中文说明见 Smart7z-User-Manual.html。
