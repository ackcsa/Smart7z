# Smart7z

Smart7z 是面向 Windows 的图形化压缩包发现、预检、解压、校验和源文件清理工具。发行版内置 7-Zip，源码使用 Python 3.12 和 Tkinter。

## 目录

- `01_MainProgram/smart7z/`：程序源码、测试、构建脚本和资源模板。
- `发行版/安装版/`：Windows x64 安装包。
- `发行版/便携版/`：Windows x64 便携包。
- `源码/`：对外源码 ZIP 和校验文件。
- `smart7z_user_manual .html`：当前用户手册，也是构建脚本的手册来源。

`shuorenhua/` 和根目录下的用户脚本不是 Smart7z 的组成部分，已从本仓库排除。

## 测试

在 `01_MainProgram/smart7z/` 中运行：

```powershell
python -m unittest discover -s tests -v
```

完整测试包含真实 7-Zip 集成用例。离线构建环境存在时，也可使用 `.build-tools/python312/python.exe` 执行同一命令。

## 构建

在 `01_MainProgram/smart7z/` 中运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\build_release.ps1
```

构建完成后需要同步安装版、便携版、源码 ZIP、当前手册、发行说明和 SHA-256 清单。

## 入库边界

- `01_MainProgram/smart7z/resources/code.txt` 是空密码本模板，提交前必须保持为空。
- 不提交恢复日志、IPC 状态、启动锁、临时会话、虚拟环境或离线构建工具链。
- 发布物没有代码签名；下载和安装时 Windows 可能显示信誉提示。
