Smart 7z Ultra __VERSION__ 源码版
================================

内容
----
- 包含 Smart7z 一方 Python 源码、测试、构建脚本、资源模板和用户手册。
- 不包含 build、release、虚拟环境、离线构建工具、缓存或运行时恢复记录。
- resources/code.txt 为空，resources/smart7z_config.json 默认保留源压缩包。

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
