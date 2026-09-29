import ast
import string
import unittest
from html.parser import HTMLParser
from pathlib import Path

from user_messages import (
    USER_MESSAGE_TEMPLATES,
    format_user_message,
    user_message_code,
    user_message_red_spans,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGED_MANUAL_PATH = PROJECT_ROOT / "Smart7z-User-Manual.html"
WORKSPACE_MANUAL_PATH = PROJECT_ROOT.parents[1] / "smart7z_user_manual.html"
MANUAL_PATH = (
    PACKAGED_MANUAL_PATH
    if PACKAGED_MANUAL_PATH.is_file()
    else WORKSPACE_MANUAL_PATH
)
UI_PATH = PROJECT_ROOT / "ui_qt.py"
EXECUTOR_PATH = PROJECT_ROOT / "executor.py"


class ManualContent(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.codes = []
        self.anchors = set()
        self.links = []
        self.images = []
        self._code = None
        self._hidden = 0
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag in {"style", "script"}:
            self._hidden += 1
        if self._hidden:
            return
        attributes = dict(attrs)
        if "id" in attributes:
            self.anchors.add(attributes["id"])
        if tag == "a" and "href" in attributes:
            self.links.append(attributes["href"])
        if tag == "img":
            self.images.append(attributes)
        if tag == "code":
            self._code = []

    def handle_endtag(self, tag):
        if tag in {"style", "script"}:
            self._hidden = max(0, self._hidden - 1)
        elif tag == "code" and self._code is not None:
            self.codes.append("".join(self._code))
            self._code = None

    def handle_data(self, data):
        if not self._hidden:
            self.text.append(data)
            if self._code is not None:
                self._code.append(data)


class TestUserMessageCatalog(unittest.TestCase):
    def test_manual_internal_links_and_offline_preview(self):
        content = ManualContent(MANUAL_PATH.read_text(encoding="utf-8"))
        for link in content.links:
            if link.startswith("#"):
                with self.subTest(link=link):
                    self.assertIn(link[1:], content.anchors)
        self.assertTrue(content.images)
        for image in content.images:
            self.assertTrue(image["src"].startswith("data:image/png;base64,"))
            self.assertTrue(image.get("alt"))
            self.assertGreater(int(image["width"]), 0)
            self.assertGreater(int(image["height"]), 0)

    def test_manual_palette_matches_qt_semantic_colors(self):
        names = {
            "COLOR_ACCENT": "--accent",
            "COLOR_ACCENT_HOVER": "--accent-hover",
            "COLOR_ACCENT_SOFT": "--soft",
            "COLOR_TEXT": "--ink",
            "COLOR_MUTED": "--muted",
            "COLOR_BORDER": "--line",
            "COLOR_PROCESSING": "--accent-2",
            "COLOR_SUCCESS": "--ok",
            "COLOR_WARNING": "--warn",
            "COLOR_DANGER": "--danger",
        }
        manual = MANUAL_PATH.read_text(encoding="utf-8").lower()
        matched = set()
        for node in ast.parse(UI_PATH.read_text(encoding="utf-8")).body:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in names:
                    color = ast.literal_eval(node.value.args[0]).lower()
                    self.assertIn(f"{names[target.id]}: {color};", manual)
                    matched.add(target.id)
        self.assertEqual(matched, set(names))

    def test_manual_parser_checks_visible_content_despite_editor_attributes(self):
        content = ManualContent(
            '<section id="s" data-page-node-id="x">'
            '<code class="label">CODE</code>A &amp; B</section>'
            '<!-- FAKE --><script>HIDDEN</script><style>CSS</style>'
        )
        self.assertEqual(content.anchors, {"s"})
        self.assertEqual(content.codes, ["CODE"])
        self.assertEqual("".join(content.text), "CODEA & B")

    def test_abnormal_message_emphasis_is_explicit(self):
        whole_line_codes = {
            code
            for code, template in USER_MESSAGE_TEMPLATES.items()
            if template.whole_line_red
        }
        keyword_codes = {
            code
            for code, template in USER_MESSAGE_TEMPLATES.items()
            if template.red_terms
        }

        self.assertEqual(
            whole_line_codes,
            {
                "JOB_FAILED",
                "ARCHIVE_BLOCKED",
                "CONFIG_SYNC_FAILED",
                "CONFIG_APPLY_FAILED",
                "RECYCLE_FAILED",
                "RECYCLE_FALLBACK_DELETE_FAILED",
            },
        )
        self.assertEqual(
            keyword_codes,
            {
                "RECOVERY_REVIEW",
                "INTAKE_FULL",
                "JOB_PARTIAL_RECOVERY",
                "JOB_INTERRUPTED",
                "JOB_PASSWORD_REQUIRED",
                "SCAN_FAILED",
                "USER_NOTICE",
                "RECYCLE_FALLBACK_UNAVAILABLE",
                "RECYCLE_FALLBACK_TOO_LARGE",
                "RECYCLE_FALLBACK_DISABLED",
            },
        )
        self.assertFalse(whole_line_codes & keyword_codes)
        for code in keyword_codes:
            template = USER_MESSAGE_TEMPLATES[code]
            catalog_text = f"{template.zh} {template.en}"
            for term in template.red_terms:
                with self.subTest(code=code, term=term):
                    self.assertIn(term, catalog_text)

    def test_red_spans_follow_the_rendered_catalog_message(self):
        message = format_user_message(
            "SCAN_FAILED",
            count=2,
            detail="Access is denied",
        )
        self.assertEqual(user_message_code(message), "SCAN_FAILED")
        whole_line, spans = user_message_red_spans(message)
        highlighted = " ".join(message[start:end] for start, end in spans)

        self.assertFalse(whole_line)
        self.assertIn("目录扫描失败", highlighted)
        self.assertIn("Folder scan failed", highlighted)
        self.assertNotIn("Access is denied", highlighted)

        severe = format_user_message("JOB_FAILED", category="INTERNAL_ERROR")
        whole_line, spans = user_message_red_spans(severe)
        self.assertTrue(whole_line)
        self.assertEqual(spans, ((0, len(severe)),))

    def test_every_template_renders_bilingual_text_and_stable_code(self):
        formatter = string.Formatter()
        for code, template in USER_MESSAGE_TEMPLATES.items():
            with self.subTest(code=code):
                field_names = {
                    field_name
                    for text in (template.zh, template.en)
                    for _literal, field_name, _spec, _conversion in formatter.parse(text)
                    if field_name
                }
                values = {field_name: 1 for field_name in field_names}
                rendered = format_user_message(code, **values)

                self.assertIn(" / ", rendered)
                self.assertTrue(rendered.endswith(f"[{code}]"))
                self.assertRegex(template.zh, r"[\u4e00-\u9fff]")
                self.assertRegex(template.en, r"[A-Za-z]")

    def test_manual_contains_every_exact_chinese_and_english_template(self):
        content = ManualContent(MANUAL_PATH.read_text(encoding="utf-8"))
        manual = "".join(content.text)
        for code, template in USER_MESSAGE_TEMPLATES.items():
            with self.subTest(code=code):
                self.assertIn(code, content.codes)
                self.assertIn(template.zh, manual, f"Missing Chinese template: {code}")
                self.assertIn(template.en, manual, f"Missing English template: {code}")

    def test_manual_documents_config_commit_and_archive_safety_boundaries(self):
        content = ManualContent(MANUAL_PATH.read_text(encoding="utf-8"))
        manual = "".join(content.text)
        self.assertTrue({"options-save", "options-safety"} <= content.anchors)
        for code in ("max_manifest_entries", "max_output_files", "ARCHIVE_BLOCKED", "7200"):
            self.assertIn(code, content.codes)
        for expected in (
            "不再提供单独的“保存配置”菜单项",
            "正常关闭窗口",
            "取消本次关闭",
            "即使只是排队或等待也需要关闭确认",
            "未完成任务需要重新添加",
            "主密码不会落盘",
            "只读取已经提交的配置",
            "正常压缩包不会因名称中含空格、中文、点文件",
            "路径穿越",
            "Windows 保留设备名",
            "NTFS 备用数据流",
            "符号链接或硬链接",
            "反向删除条目",
            "Windows 路径冲突",
            "Windows 不兼容路径",
            "7200 秒（2 小时）",
            "工具栏不再提供手动暂停接收入口",
            "右键菜单 → 添加右键菜单",
            "界面不再提供状态过滤按钮",
            "中断、部分恢复、失败、需密码、等待中、处理中、完成",
            "取消所有",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, manual, f"Missing manual text: {expected}")
        self.assertNotIn("可信输入", manual)
        self.assertNotIn("trusted_input", manual)
        self.assertNotIn("暂停输入", manual)
        self.assertNotIn("取消剩余", manual)
        self.assertNotIn("工具 → 注册右键菜单", manual)

    def test_executor_user_notices_are_catalog_messages(self):
        tree = ast.parse(EXECUTOR_PATH.read_text(encoding="utf-8"))
        notice_calls = []
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            function = call.func
            if isinstance(function, ast.Attribute) and function.attr == "_notify_user":
                notice_calls.append(call)

        self.assertTrue(notice_calls)
        for call in notice_calls:
            with self.subTest(line=call.lineno):
                self.assertGreaterEqual(len(call.args), 2)
                message_call = call.args[1]
                self.assertIsInstance(message_call, ast.Call)
                self.assertIsInstance(message_call.func, ast.Name)
                self.assertEqual(message_call.func.id, "format_user_message")

    def test_ui_log_events_use_catalog_codes(self):
        tree = ast.parse(UI_PATH.read_text(encoding="utf-8"))
        seen_codes = set()
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            function = call.func
            if not isinstance(function, ast.Attribute) or function.attr != "log_event":
                continue
            self.assertTrue(call.args)
            self.assertIsInstance(call.args[0], ast.Constant)
            code = call.args[0].value
            self.assertIn(code, USER_MESSAGE_TEMPLATES)
            seen_codes.add(code)
        self.assertTrue(seen_codes)

    def test_every_catalog_message_has_a_runtime_callsite(self):
        used_codes = set()
        for path, function_names in (
            (EXECUTOR_PATH, {"format_user_message"}),
            (UI_PATH, {"log_event"}),
        ):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
                function = call.func
                name = (
                    function.attr
                    if isinstance(function, ast.Attribute)
                    else function.id
                    if isinstance(function, ast.Name)
                    else ""
                )
                if (
                    name in function_names
                    and call.args
                    and isinstance(call.args[0], ast.Constant)
                ):
                    used_codes.add(call.args[0].value)

        self.assertEqual(set(USER_MESSAGE_TEMPLATES), used_codes)


if __name__ == "__main__":
    unittest.main()
