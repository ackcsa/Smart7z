Smart 7z Ultra __VERSION__ 源码版
================================

内容
----
- 包含 Smart7z 一方 Python 源码、测试、构建脚本、资源模板和用户手册。
- 不包含 build、release、虚拟环境、离线构建工具、缓存或运行时恢复记录。
- resources/code.txt 为空，resources/smart7z_config.json 默认保留源压缩包。

本次更新
--------
- 菜单栏新增“文件扫描模式”三级互斥对钩菜单与“选项 → 空间不足时等待”，并删除工具栏重复按钮；默认选择 SteganographierGUI 兼容模式。
- 兼容探测器支持普通 MP4 追加 ZIP、ZArchiver free 原子和 MKV ZIP 附件；通过 BMFF/EBML 跳读与限定区间 ZIP 校验避免全文件读取。
- 严格校验非饱和经典字段 ZIP64 的记录、定位器和中央目录几何；深度扫描与直接输入优先复用兼容候选，屏蔽随机 RAR/7z/ZIP 诱饵。
- 深度扫描改为单轮流式候选预检和复用，并增加非常驻文件扫描进度。
- 任务详情区可调高度，任务默认按源包大小升序执行，密码提示完成后自动恢复布局。
- 自动候选耗尽后的手动密码重试只使用本次输入，不再重复读取会话密码和密码本。
- 修复隐写候选处理后可能遗留空 stego 会话目录的问题，并保持对未登记内容、链接和重解析点的保留策略。
- 安装模式可继续使用旧安装地址中的非空密码本，不会被新位置的空占位替代。
- 嵌套扫描增加普通 PE 目录保护，并为改名压缩包及高置信度 ZIP/7z SFX 保留内容优先例外。
- 修复关闭阶段右键请求与单实例恢复日志锁的接管竞态。
- 复用完整加密清单，优先本批次成功密码，并避免已确认加密包的无密码解压尝试。
- 使用有界流式 SLT 解析，在条目超限时提前终止 7-Zip；内部解析安全上限为 200000，配置更高也不会绕过；保留完整安全预检语义。
- 增加列表、解析、预检、解压、输出扫描和总耗时指标。
- 收窄格式回退：自动识别失败后只做一次有签名或扩展名依据的 ZIP/RAR/7z 重试。

运行
----
1. 使用 64 位 Python 3.12（含 Tkinter）。
2. 安装 7-Zip，或把 7z.exe 放在源码根目录。
3. 在源码根目录运行 python smart7z.py。
4. tkinterdnd2 仅用于拖拽；未安装时按钮和命令行仍可使用。

验证与构建
----------
- 全量测试：python -m unittest discover -s tests -v
- 真实 7-Zip 集成测试：python -m unittest tests.test_integration_real7z -v
- 构建依赖：python -m pip install -r requirements-build.txt
- 构建：powershell -ExecutionPolicy Bypass -File .\build_release.ps1

完整中文说明见 Smart7z-User-Manual.html。
