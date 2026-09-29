Smart7z __VERSION__ 源码版
========================

内容
----
- 平铺的一方 Python 源码、tests、构建文件、资源模板、用户手册和 CHANGELOG.md，不是完整 Git 仓库。
- licenses 与 corresponding-source 保存第三方许可证和对应源码，另见 THIRD_PARTY_NOTICES.txt。
- 不含 build、release、虚拟环境、离线构建工具、个人配置、密码或恢复记录。
- resources/code.txt 为空；resources/smart7z_config.json 默认保留源包。

运行
----
在 Windows 上使用 64 位 Python。本版开发基线为 Python 3.14.6、PySide6 6.11.1。
在本文件所在目录执行：

    python -m venv .build-venv
    .\.build-venv\Scripts\python.exe -m pip install -r requirements-build.txt
    .\.build-venv\Scripts\python.exe smart7z.py

安装 7-Zip，或把 7z.exe 放在源码根目录。仅运行程序不需要 Inno Setup 等打包工具。
下面用 python 简写已选定环境中的解释器。

验证
----
    python verify_project.py
    python verify_project.py --suite integration
    python verify_project.py --suite ui
    python verify_project.py --suite release

摘要和日志写入 .verification，可用 --report-dir 指定目录。
--reuse 只复用 24 小时内输入、环境和测试选择一致的成功结果；测试数量以当前报告为准。
Qt 测试需要 PySide6，真实解压需要 7-Zip，发布测试需要 Windows PowerShell。
安装器编译与隔离逻辑测试还需 Inno Setup；可通过 INNO_SETUP_COMPILER 指定 ISCC.exe。
逻辑测试不修改真实安装登记，不能替代实际安装、升级和卸载验收。

构建
----
    python verify_project.py --reuse --build

- 入口要求全量测试通过且零跳过。已有 build 或同版本发布物时会停止，先核对并归档旧产物及校验清单。
- 不要用直接调用 build_release.ps1 绕过保护，它会清理对应的已有输出。
- 还需 PowerShell 7、Inno Setup、64 位 .NET Framework C# 编译器，以及完整 7-Zip 发行目录（7z.exe、7z.dll、License.txt）。
- Qt/PySide 官方源码归档放入 .license-cache 或 .build-tools\qt-source，固定名称与 SHA-256 见 build_release.ps1。
- 7-Zip 26.03 官方源码归档放入 .license-cache\7z2603-src.tar.xz；
  可从本源码包 corresponding-source 中复制该原始归档，哈希见 THIRD_PARTY_NOTICES.txt。
- corresponding-source 中的展开源码供阅读和许可证合规使用，不能替代上述原始归档。
- 构建输出为 release 中的安装器、便携 ZIP、源码 ZIP 和 SHA256SUMS-<版本>.txt。
- 先更新代码、手册和 CHANGELOG.md，再验证、构建；旧发行物不会随文档修改自动更新。

数据与行为
----------
- 源码配置模板在 resources；测试应使用独立临时目录，不写真实配置、密码本或恢复数据。
- 清理策略在任务接收时固定；切换设置不影响任何已有任务。
- 排队、等待和扫描也需要关闭确认，退出后未完成任务需要重新添加。
- 安装、便携和源码副本在当前用户登录会话内共用窗口和队列；只有 IPC 连接信息共享，不合并其他数据。本版本没有多实例开关。
- 启动失败可修正设置后重试；启动诊断默认关闭，暖启动结果不代表冷启动性能。

文档
----
- 操作和错误说明：Smart7z-User-Manual.html
- 版本变更：CHANGELOG.md
- 仓库维护指南：https://github.com/ackcsa/Smart7z/blob/v__VERSION__/MAINTENANCE.md
- 发行与校验清单：https://github.com/ackcsa/Smart7z/releases
