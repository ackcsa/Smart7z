import os
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import zipfile
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

import ui_app
import windows_adapters
from archive_classifier import AutoDiscoveryDecision
from config import DEFAULT_CONFIG
from models import ArchiveCandidate, Confidence, ErrorCategory, Job, JobState
from user_messages import format_user_message


class _FakeVar:
    def __init__(self, master=None, value=None, **_kwargs):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class _FakeWidget:
    _next_id = 0

    def __init__(self, *args, **kwargs):
        self.master = args[0] if args else None
        self.options = dict(kwargs)
        self.value = ""
        self.rows = {}
        self.selected = ()
        self.items = []
        self.children_added = []
        self.tag_options = {}
        self.tagged_inserts = []
        self.menu_commands = []
        self.menu_cascades = []
        self.headings = {}
        self.row_order = []
        self.packed = False
        self.pack_options = {}

    def pack(self, **kwargs):
        self.packed = True
        self.pack_options = dict(kwargs)
        return None

    def pack_forget(self):
        self.packed = False
        return None

    def config(self, **kwargs):
        self.options.update(kwargs)

    configure = config

    def insert(self, *args, **kwargs):
        if "values" in kwargs:
            type(self)._next_id += 1
            item = f"item-{type(self)._next_id}"
            self.rows[item] = kwargs["values"]
            self.row_order.append(item)
            return item
        if len(args) >= 2:
            text = str(args[1])
            self.value += text
            self.items.append(text)
            self.tagged_inserts.append((text, tuple(str(tag) for tag in args[2:])))
        return None

    def delete(self, *args):
        if args and args[0] in self.rows:
            self.rows.pop(args[0], None)
            if args[0] in self.row_order:
                self.row_order.remove(args[0])
            return
        self.value = ""
        self.items.clear()
        self.tagged_inserts.clear()

    def tag_configure(self, tag, **kwargs):
        self.tag_options[str(tag)] = dict(kwargs)

    def get(self):
        return self.value

    def focus_set(self):
        return None

    def heading(self, column, **kwargs):
        if kwargs:
            self.headings[column] = dict(kwargs)
        return self.headings.get(column, {})

    def column(self, *_args, **_kwargs):
        return None

    def bind(self, *_args, **_kwargs):
        return None

    def yview(self, *_args, **_kwargs):
        return None

    def set(self, *_args, **_kwargs):
        return None

    def see(self, *_args, **_kwargs):
        return None

    def item(self, item, **kwargs):
        if "values" in kwargs:
            self.rows[item] = kwargs["values"]
        return {"values": self.rows.get(item, ())}

    def move(self, item, _parent, index):
        if item in self.row_order:
            self.row_order.remove(item)
        self.row_order.insert(index, item)

    def selection(self):
        return tuple(self.selected)

    def curselection(self):
        return tuple(self.selected)

    def reattach(self, *_args, **_kwargs):
        return None

    def detach(self, *_args, **_kwargs):
        return None

    def add_command(self, **_kwargs):
        self.menu_commands.append(dict(_kwargs))
        return None

    def add_separator(self):
        return None

    def add_cascade(self, **_kwargs):
        self.menu_cascades.append(dict(_kwargs))
        return None

    def add_checkbutton(self, **_kwargs):
        self.menu_commands.append(dict(_kwargs))
        return None

    def add(self, child, **kwargs):
        self.children_added.append((child, dict(kwargs)))
        return None

    def winfo_children(self):
        return [child for child, _options in self.children_added]

    def __setitem__(self, key, value):
        self.options[key] = value

    def __getitem__(self, key):
        return self.options.get(key)


class _FakeRoot(_FakeWidget):
    def __init__(self, mainloop_error=None):
        super().__init__()
        self.destroyed = False
        self.mainloop_error = mainloop_error
        self.protocols = {}
        self.after_calls = 0
        self.deferred_after = {}
        self.dnd_registered = False
        self.tk = types.SimpleNamespace(splitlist=lambda value: [value])

    def title(self, value):
        self.options["title"] = value

    def geometry(self, value):
        self.options["geometry"] = value

    def minsize(self, width, height):
        self.options["minsize"] = (width, height)

    def deiconify(self):
        self.options["deiconified"] = True

    def lift(self):
        self.options["lifted"] = True

    def focus_force(self):
        self.options["focused"] = True

    def after(self, _delay, callback=None, *args):
        if self.destroyed:
            raise ui_app.tk.TclError("root destroyed")
        self.after_calls += 1
        if callback is not None:
            name = getattr(callback, "__name__", "")
            if name in {
                "_drain_tk_queue",
                "_poll_shutdown",
                "_maybe_auto_close_context_window",
            }:
                self.deferred_after[name] = (callback, args)
            else:
                callback(*args)
        return f"after-{self.after_calls}"

    def run_deferred(self, name):
        callback, args = self.deferred_after.pop(name)
        callback(*args)

    def protocol(self, name, callback):
        self.protocols[name] = callback

    def destroy(self):
        self.destroyed = True

    def mainloop(self):
        if self.mainloop_error is not None:
            raise self.mainloop_error

    def drop_target_register(self, *_args):
        self.dnd_registered = True

    def dnd_bind(self, *_args):
        self.dnd_registered = True


class _FakeRunner:
    def supported_formats(self, timeout=15):
        return {".zip", ".7z"}


class _FakeScheduler:
    instances = []

    def __init__(self, sevenzip_path, config, event_cb=None):
        self.sevenzip_path = sevenzip_path
        self.config = dict(config)
        self.event_cb = event_cb or (lambda *_args, **_kwargs: None)
        self.runner = _FakeRunner()
        self.current_job = None
        self.jobs = []
        self.start_count = 0
        self.stop_count = 0
        self.enable_count = 0
        self.refresh_count = 0
        self.password_responses = []
        self.skipped_password_jobs = []
        self.stego_selections = []
        self.recovery_messages = []
        self.recovery_journal = types.SimpleNamespace(
            protected_session_paths=lambda: []
        )
        type(self).instances.append(self)

    def start(self):
        self.start_count += 1

    def stop(self):
        self.stop_count += 1
        return True

    def submit(self, job):
        self.jobs.append(job)
        self.event_cb("job_submitted", job)
        return True

    def enable_processing(self):
        self.enable_count += 1

    def is_io_busy(self):
        return False

    def resume_intake(self):
        return 0

    def pause_intake(self):
        return None

    def deferred_intake_size(self):
        return 0

    def refresh_config(self, config):
        self.config = dict(config)
        self.refresh_count += 1

    def set_session_main_password(self, _password):
        return None

    def submit_password_response(self, job, password):
        self.password_responses.append((job, password))

    def skip_password_job(self, job):
        self.skipped_password_jobs.append(job)

    def submit_stego_selection(self, job, candidate_index):
        self.stego_selections.append((job, candidate_index))

    def clear_finished(self, _task_ids=None):
        return []

    def cancel_remaining(self):
        return None

    def cancel_jobs(self, _task_ids):
        return []

    def has_job(self, task_id):
        return any(job.task_id == task_id for job in self.jobs)


def _test_config(temp_dir):
    config = dict(DEFAULT_CONFIG)
    config.update(
        {
            "temp_dir": str(temp_dir),
            "target_dir": str(temp_dir),
            "password_file": str(Path(temp_dir) / "passwords.txt"),
        }
    )
    return config


@contextmanager
def _patched_ui(config, sevenzip_path=r"C:\Program Files\7-Zip\7z.exe"):
    _FakeScheduler.instances.clear()
    widget_names = (
        "Frame",
        "Button",
        "Checkbutton",
        "Label",
        "Radiobutton",
        "LabelFrame",
        "Entry",
        "Spinbox",
        "Listbox",
        "Menu",
        "PanedWindow",
    )
    with ExitStack() as stack:
        for name in widget_names:
            stack.enter_context(mock.patch.object(ui_app.tk, name, _FakeWidget))
        stack.enter_context(mock.patch.object(ui_app.tk, "BooleanVar", _FakeVar))
        stack.enter_context(mock.patch.object(ui_app.tk, "StringVar", _FakeVar))
        for name in ("Treeview", "Scrollbar", "Progressbar", "Notebook"):
            stack.enter_context(mock.patch.object(ui_app.ttk, name, _FakeWidget))
        stack.enter_context(
            mock.patch.object(ui_app.scrolledtext, "ScrolledText", _FakeWidget)
        )
        stack.enter_context(mock.patch.object(ui_app, "Scheduler", _FakeScheduler))
        stack.enter_context(mock.patch.object(ui_app, "load_config", return_value=dict(config)))
        stack.enter_context(mock.patch.object(ui_app, "save_config"))
        stack.enter_context(
            mock.patch.object(ui_app, "find_sevenzip", return_value=sevenzip_path)
        )
        stack.enter_context(mock.patch.object(ui_app, "cleanup_stale_sessions"))
        stack.enter_context(mock.patch.object(ui_app, "create_mutex", return_value=object()))
        stack.enter_context(mock.patch.object(ui_app, "close_mutex", return_value=True))
        stack.enter_context(mock.patch.object(ui_app, "DND_AVAILABLE", False))
        stack.enter_context(mock.patch.object(ui_app.messagebox, "showwarning"))
        stack.enter_context(mock.patch.object(ui_app.messagebox, "showerror"))
        yield


class TestHeadlessUiLifecycle(unittest.TestCase):
    def test_context_menu_is_top_level_menu_without_duplicate_buttons(self):
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())

                labels = [
                    item.get("label")
                    for item in app.context_menu_menu.menu_commands
                ]
                self.assertEqual(labels, ["添加右键菜单", "删除右键菜单"])
                self.assertNotIn("保存配置", labels)
                self.assertEqual(
                    [item.get("label") for item in app.menubar.menu_cascades],
                    ["右键菜单", "文件扫描模式", "选项"],
                )
                self.assertEqual(
                    [
                        item.get("label")
                        for item in app.file_scan_mode_menu.menu_commands
                    ],
                    [
                        "深度扫描模式（全文件读取）",
                        "仅兼容隐写者模式（非全读取）",
                        "普通模式",
                    ],
                )
                self.assertEqual(
                    [
                        item.get("label")
                        for item in app.options_menu.menu_commands
                    ],
                    ["空间不足时等待"],
                )
                self.assertTrue(app.var_steganographier_compat.get())
                self.assertTrue(app.var_scan_steganographier_mode.get())
                self.assertFalse(app.var_scan_deep_mode.get())
                self.assertFalse(app.var_scan_normal_mode.get())
                self.assertFalse(hasattr(app, "context_menu_controls"))
                self.assertFalse(hasattr(app, "btn_add_context_menu"))
                self.assertFalse(hasattr(app, "btn_remove_context_menu"))
                app._on_closing()

    def test_scan_modes_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                self.assertTrue(app.var_steganographier_compat.get())
                self.assertFalse(app.var_deep_scan.get())

                app._select_scan_mode(ui_app.SCAN_MODE_DEEP)
                self.assertFalse(app.var_steganographier_compat.get())
                self.assertTrue(app.var_scan_deep_mode.get())

                app._select_scan_mode(ui_app.SCAN_MODE_STEGANOGRAPHIER)
                self.assertFalse(app.var_deep_scan.get())
                self.assertTrue(app.var_scan_steganographier_mode.get())

                app._select_scan_mode(ui_app.SCAN_MODE_NORMAL)
                self.assertFalse(app.var_deep_scan.get())
                self.assertFalse(app.var_steganographier_compat.get())
                self.assertTrue(app.var_scan_normal_mode.get())
                app._on_closing()

    def test_close_saves_current_controls_before_shutdown(self):
        with tempfile.TemporaryDirectory() as temp:
            root = _FakeRoot()
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(root)
                app._select_scan_mode(ui_app.SCAN_MODE_DEEP)
                app.entry_target.delete(0, ui_app.tk.END)
                app.entry_target.insert(0, str(Path(temp) / "new-target"))

                self.assertTrue(app._on_closing())

                ui_app.save_config.assert_called_once()
                saved = ui_app.save_config.call_args.args[0]
                self.assertNotIn("trusted_input", saved)
                self.assertTrue(saved["deep_scan"])
                self.assertEqual(saved["target_dir"], str(Path(temp) / "new-target"))
                self.assertTrue(app._closing)
                app._wait_for_shutdown_without_mainloop()
                self.assertTrue(root.destroyed)

    def test_close_save_failure_keeps_window_open(self):
        with tempfile.TemporaryDirectory() as temp:
            root = _FakeRoot()
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(root)
                scheduler = _FakeScheduler.instances[-1]
                ui_app.save_config.side_effect = OSError("read only")

                self.assertFalse(app._on_closing())

                self.assertFalse(app._closing)
                self.assertFalse(root.destroyed)
                self.assertEqual(scheduler.stop_count, 0)
                ui_app.messagebox.showerror.assert_called_with(
                    "配置保存失败", "read only"
                )

                ui_app.save_config.side_effect = None
                ui_app.save_config.reset_mock()
                self.assertTrue(app._on_closing())
                app._wait_for_shutdown_without_mainloop()

    def test_primary_options_and_queue_action_rows_follow_requested_layout(self):
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())

                self.assertEqual(
                    [
                        app.btn_add_files["text"],
                        app.btn_scan_folder["text"],
                        app.btn_start["text"],
                    ],
                    ["添加文件", "扫描文件夹", "开始"],
                )
                self.assertTrue(
                    all(
                        button.master is app.primary_toolbar
                        for button in (
                            app.btn_add_files,
                            app.btn_scan_folder,
                            app.btn_start,
                        )
                    )
                )
                self.assertIsNone(app.btn_start["height"])
                self.assertGreater(
                    app.btn_start["width"], app.btn_add_files["width"]
                )
                self.assertTrue(app.extract_options_frame.packed)
                self.assertEqual(
                    [control["text"] for control in app.extract_option_controls],
                    [
                        "解压到原目录",
                        "暂存模式",
                        "嵌套解压",
                    ],
                )
                self.assertEqual(
                    [control["text"] for control in app.cleanup_policy_controls],
                    ["保留", "回收站", "永久删除"],
                )
                self.assertTrue(
                    all(
                        control.master is app.extract_options_frame
                        for control in (
                            app.extract_option_controls
                            + app.cleanup_policy_controls
                        )
                    )
                )
                self.assertEqual(
                    [
                        app.btn_cancel_current["text"],
                        app.btn_cancel_all["text"],
                        app.btn_clear_selected["text"],
                        app.btn_clear_finished["text"],
                    ],
                    ["取消当前", "取消所有", "清除所选", "清除已完成"],
                )
                self.assertTrue(
                    all(
                        button.master is app.queue_actions_frame
                        for button in (
                            app.btn_cancel_current,
                            app.btn_cancel_all,
                            app.btn_clear_selected,
                            app.btn_clear_finished,
                        )
                    )
                )
                self.assertFalse(hasattr(app, "var_filter"))
                app._on_closing()

    def test_context_menu_commands_report_success_and_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            with (
                _patched_ui(_test_config(temp)),
                mock.patch.object(ui_app, "register_context_menu", return_value=True),
                mock.patch.object(ui_app, "unregister_context_menu", return_value=False),
                mock.patch.object(ui_app.messagebox, "showinfo") as showinfo,
                mock.patch.object(ui_app.messagebox, "showerror") as showerror,
            ):
                app = ui_app.Smart7zAppModern(_FakeRoot())

                app._register_menu()
                app._unregister_menu()

                showinfo.assert_called_once_with("成功", "右键菜单已添加。")
                showerror.assert_called_once_with("失败", "删除右键菜单失败。")
                app._on_closing()

    def test_compact_progress_and_tabbed_inspector(self):
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())

                self.assertEqual(app.tree["height"], 5)
                self.assertEqual(app.tree.headings["size"]["text"], "大小 ▲")
                self.assertEqual(ui_app.TREE_COLUMNS[-1][1], "源包处理")
                self.assertIs(app.file_progress.master, app.progress_frame)
                self.assertIs(app.total_progress.master, app.progress_frame)
                self.assertEqual(app.file_progress.pack_options["side"], ui_app.tk.LEFT)
                self.assertEqual(app.total_progress.pack_options["side"], ui_app.tk.LEFT)
                self.assertIs(app.queue_panel.master, app.work_pane)
                self.assertIs(app.details_frame.master, app.inspector_tabs)
                self.assertIs(app.log_frame.master, app.inspector_tabs)
                self.assertEqual(
                    [options["text"] for _child, options in app.inspector_tabs.children_added],
                    ["任务详情", "运行日志"],
                )
                self.assertEqual(app.details_text["height"], 3)
                self.assertEqual(app.log_text["height"], 3)
                self.assertEqual(
                    [child for child, _options in app.work_pane.children_added],
                    [app.queue_panel, app.inspector_tabs],
                )
                self.assertTrue(app.work_pane.packed)
                self.assertFalse(app.scan_progress_frame.packed)
                app._on_closing()

    def test_scan_progress_is_visible_only_for_the_active_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                generation = app._scan_generation + 1
                app._scan_generation = generation

                app._show_scan_progress(generation)
                app._update_scan_progress(
                    generation,
                    4,
                    2,
                    str(Path(temp) / "archive.zip"),
                    55,
                )

                self.assertTrue(app.scan_progress_frame.packed)
                self.assertEqual(app.scan_progress["value"], 55)
                self.assertIn("已发现 2", app.scan_progress_label["text"])

                app._hide_scan_progress(generation - 1)
                self.assertTrue(app.scan_progress_frame.packed)
                app._hide_scan_progress(generation)
                self.assertFalse(app.scan_progress_frame.packed)
                app._on_closing()

    def test_state_column_uses_requested_priority_and_tracks_updates(self):
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                states = (
                    JobState.COMPLETE,
                    JobState.EXTRACTING,
                    JobState.QUEUED,
                    JobState.PASSWORD_REQUIRED,
                    JobState.FAILED,
                    JobState.PARTIAL_RECOVERY,
                    JobState.INTERRUPTED,
                )
                jobs = []
                for index, state in enumerate(states):
                    job = Job(path=str(Path(temp) / f"job-{index}.zip"), state=state)
                    jobs.append(job)
                    app._add_job_to_tree(job)

                app._sort_tree("state")

                self.assertEqual(
                    [app.tree.rows[item][2] for item in app.tree.row_order],
                    [
                        "中断",
                        "部分恢复",
                        "失败",
                        "需密码",
                        "等待中",
                        "解压中",
                        "完成",
                    ],
                )
                self.assertEqual(app.tree.headings["state"]["text"], "状态 ▲")
                self.assertTrue(
                    all(
                        callable(app.tree.headings[column]["command"])
                        for column, _label, _width in ui_app.TREE_COLUMNS
                    )
                )

                jobs[0].record_state(JobState.INTERRUPTED)
                app._update_job_in_tree(jobs[0])
                self.assertEqual(
                    app.tree.row_order[0], app.job_tree_ids[jobs[0].task_id]
                )
                app._on_closing()

    def test_file_and_progress_columns_sort_text_and_numbers(self):
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                jobs = []
                for name, progress in (
                    ("zeta.zip", 2),
                    ("Alpha.zip", 10),
                    ("beta.zip", 1),
                ):
                    job = Job(path=str(Path(temp) / name), progress=progress)
                    jobs.append(job)
                    app._add_job_to_tree(job)

                app._sort_tree("file")
                self.assertEqual(
                    [app.tree.rows[item][0] for item in app.tree.row_order],
                    ["Alpha.zip", "beta.zip", "zeta.zip"],
                )
                app._sort_tree("progress")
                self.assertEqual(
                    [app.tree.rows[item][3] for item in app.tree.row_order],
                    ["1%", "2%", "10%"],
                )
                app._sort_tree("progress")
                self.assertEqual(
                    [app.tree.rows[item][3] for item in app.tree.row_order],
                    ["10%", "2%", "1%"],
                )
                self.assertEqual(app.tree.headings["progress"]["text"], "进度 ▼")
                app._on_closing()

    def test_user_notice_appears_in_task_details_and_run_log(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "archive.zip"
            archive.write_bytes(b"source")
            message = (
                "回收站不可用，已永久删除 1 个源文件 / "
                "Recycle Bin unavailable; permanently deleted 1 source item(s) "
                "[RECYCLE_FALLBACK_UNAVAILABLE]"
            )
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                job = Job(path=str(archive), user_notices=[message])
                app._handle_event("job_submitted", job)

                app._handle_event("user_notice", job, message)
                app._drain_tk_queue()

                self.assertIn(message, app.details_text.value)
                self.assertIn(message, app.log_text.value)
                self.assertEqual(app.log_text.value.count(message), 1)
                app._on_closing()

    def test_routine_per_job_events_do_not_fill_run_log(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "routine.zip"
            archive.write_bytes(b"source")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                app._drain_tk_queue()
                job = Job(path=str(archive))
                app._handle_event("job_submitted", job)

                for _index in range(50):
                    app._handle_event("job_deferred", job)
                    app._handle_event("job_duplicate", job)
                    app._handle_event("job_resubmitted", job)
                    app._handle_event(
                        "state_change",
                        job,
                        JobState.COMPLETE,
                        "Verified output committed",
                        100,
                    )
                app._drain_tk_queue()

                self.assertEqual(app.log_lines, 1)
                self.assertEqual(app.log_text.value.count("[APP_READY]"), 1)
                self.assertNotIn("routine.zip", app.log_text.value)
                app._on_closing()

    def test_failed_job_log_is_bilingual_without_internal_detail(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "failed.zip"
            archive.write_bytes(b"source")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                job = Job(path=str(archive))
                job.error_category = ErrorCategory.INTERNAL_ERROR
                app._handle_event("job_submitted", job)
                app._handle_event(
                    "state_change",
                    job,
                    JobState.FAILED,
                    "low-level executor detail",
                    -1,
                )
                app._drain_tk_queue()

                self.assertIn("任务失败，请查看任务详情", app.log_text.value)
                self.assertIn("Job failed; see task details", app.log_text.value)
                self.assertIn("INTERNAL_ERROR", app.log_text.value)
                self.assertIn("[JOB_FAILED]", app.log_text.value)
                self.assertNotIn("low-level executor detail", app.log_text.value)
                app._on_closing()

    def test_archive_safety_block_logs_dedicated_reason(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "unsafe.zip"
            archive.write_bytes(b"source")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                job = Job(path=str(archive))
                job.error_category = ErrorCategory.UNSAFE_PATH
                job.error_message = (
                    "安全拦截：压缩包包含路径穿越条目；已跳过且未解压。"
                )
                job.source_retention_reason = "unsafe_path_traversal"
                app._handle_event("job_submitted", job)

                app._handle_event(
                    "state_change",
                    job,
                    JobState.FAILED,
                    job.error_message,
                    -1,
                )
                app._drain_tk_queue()

                self.assertIn("[ARCHIVE_BLOCKED]", app.log_text.value)
                self.assertIn(job.error_message, app.log_text.value)
                self.assertNotIn("[JOB_FAILED]", app.log_text.value)
                app._on_closing()

    def test_run_log_marks_keywords_and_severe_messages_red(self):
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                app.log_event("SCAN_FAILED", count=2, detail="Access is denied")
                app.log_event(
                    "JOB_FAILED",
                    context="broken.zip",
                    category="INTERNAL_ERROR",
                )
                app.log_event("SCAN_COMPLETE", count=1)
                app._drain_tk_queue()

                keyword_text = "".join(
                    text
                    for text, tags in app.log_text.tagged_inserts
                    if ui_app.LOG_RED_KEYWORD_TAG in tags
                )
                severe_text = "".join(
                    text
                    for text, tags in app.log_text.tagged_inserts
                    if ui_app.LOG_RED_LINE_TAG in tags
                )

                self.assertIn("目录扫描失败", keyword_text)
                self.assertIn("Folder scan failed", keyword_text)
                self.assertNotIn("Access is denied", keyword_text)
                self.assertIn("broken.zip: 任务失败", severe_text)
                self.assertIn("[JOB_FAILED]", severe_text)
                self.assertNotIn("[SCAN_COMPLETE]", keyword_text + severe_text)
                self.assertEqual(
                    app.log_text.tag_options[ui_app.LOG_RED_KEYWORD_TAG]["foreground"],
                    ui_app.LOG_RED_COLOR,
                )
                self.assertEqual(
                    app.log_text.tag_options[ui_app.LOG_RED_LINE_TAG]["foreground"],
                    ui_app.LOG_RED_COLOR,
                )
                app._on_closing()

    def test_recovery_review_details_are_capped_but_conflicts_remain_visible(self):
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                journal_path = str(Path(temp) / "recovery-v1.json")
                app.scheduler.recovery_journal.path = journal_path
                messages = [
                    f"Recovery deferred for item-{index}: locked"
                    for index in range(12)
                ]
                messages.append(
                    "Source recovery conflict retained at: C:\\visible\\archive.zip"
                )
                with mock.patch.object(ui_app.logger, "warning"):
                    app._log_recovery_messages(messages)
                app._drain_tk_queue()

                self.assertEqual(
                    app.log_text.value.count("[RECOVERY_REVIEW]"),
                    ui_app.MAX_RECOVERY_LOG_DETAILS + 1,
                )
                self.assertEqual(
                    app.log_text.value.count("[RECOVERY_MORE]"), 1
                )
                self.assertIn("C:\\visible\\archive.zip", app.log_text.value)
                self.assertIn(journal_path, app.log_text.value)
                self.assertNotIn("item-8", app.log_text.value)
                app._on_closing()

    def test_run_log_flattens_and_caps_dynamic_detail(self):
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                app.log_event(
                    "USER_NOTICE",
                    detail="first line\nsecond line\t" + ("x" * 2000),
                )
                app._drain_tk_queue()

                line = next(
                    value
                    for value in app.log_text.value.splitlines()
                    if "[USER_NOTICE]" in value
                )
                self.assertIn("first line second line", line)
                self.assertLessEqual(
                    len(line), ui_app.MAX_UI_LOG_CHARS + len("[00:00:00] ")
                )
                self.assertTrue(line.endswith(" ..."))
                app._on_closing()

    def test_extract_options_row_is_always_visible_and_preserves_values(self):
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())

                self.assertTrue(app.extract_options_frame.packed)
                self.assertEqual(
                    app.extract_options_frame.pack_options["fill"], ui_app.tk.X
                )
                self.assertEqual(
                    [control["text"] for control in app.extract_option_controls],
                    [
                        "解压到原目录",
                        "暂存模式",
                        "嵌套解压",
                    ],
                )
                self.assertFalse(hasattr(app, "var_trusted"))
                self.assertFalse(hasattr(app, "btn_pause"))
                self.assertEqual(
                    [control["text"] for control in app.cleanup_policy_controls],
                    ["保留", "回收站", "永久删除"],
                )
                self.assertTrue(
                    all(
                        control.master is app.extract_options_frame
                        for control in (
                            app.extract_option_controls
                            + app.cleanup_policy_controls
                        )
                    )
                )

                app._select_scan_mode(ui_app.SCAN_MODE_DEEP)
                app.var_cleanup_policy.set("recycle")
                self.assertTrue(app.var_deep_scan.get())
                self.assertEqual(app.var_cleanup_policy.get(), "recycle")
                self.assertFalse(hasattr(app, "btn_extract_options"))
                app._on_closing()

    def test_password_prompt_is_transient_and_advances_fifo(self):
        with tempfile.TemporaryDirectory() as temp:
            root = _FakeRoot()
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(root)
                scheduler = _FakeScheduler.instances[-1]
                first = Job(path=str(Path(temp) / "first-encrypted.rar"))
                second = Job(path=str(Path(temp) / "second-encrypted.rar"))

                self.assertEqual(root.options["minsize"], (800, 600))
                self.assertFalse(app.prompt_host.packed)
                self.assertIs(app.pwd_frame.master, app.prompt_host)
                self.assertIs(app.stego_frame.master, app.prompt_host)
                self.assertIs(app.pwd_entry.master, app.pwd_input_row)

                app._show_password_prompt(first)
                self.assertTrue(app.pwd_frame.packed)
                self.assertTrue(app.prompt_host.packed)
                self.assertIs(app.current_pwd_job, first)
                self.assertIn("first-encrypted.rar", app.pwd_label["text"])

                app._show_password_prompt(second)
                self.assertEqual(app.pending_pwd_jobs, [second])

                app.pwd_entry.insert(0, "stale-password")
                app._dismiss_prompts_for_job(first)
                self.assertTrue(app.pwd_frame.packed)
                self.assertIs(app.current_pwd_job, second)
                self.assertEqual(app.pending_pwd_jobs, [])
                self.assertEqual(app.pwd_entry.get(), "")
                self.assertIn("second-encrypted.rar", app.pwd_label["text"])

                app.pwd_entry.insert(0, "manual-password")
                app._submit_password()

                self.assertEqual(
                    scheduler.password_responses,
                    [(second, "manual-password")],
                )
                self.assertIsNone(app.current_pwd_job)
                self.assertEqual(app.pwd_entry.get(), "")
                self.assertFalse(app.pwd_frame.packed)
                self.assertFalse(app.prompt_host.packed)
                app._on_closing()

    def test_constructor_cli_autostart_and_idempotent_close(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "sample.zip"
            archive.write_bytes(b"not-opened-by-this-test")
            root = _FakeRoot()
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(root, startup_args=[str(archive)])

                scheduler = _FakeScheduler.instances[-1]
                self.assertEqual(scheduler.start_count, 1)
                self.assertEqual([job.path for job in scheduler.jobs], [str(archive)])
                self.assertEqual(scheduler.enable_count, 1)
                self.assertIn("WM_DELETE_WINDOW", root.protocols)

                app._on_closing()
                app._on_closing()
                app._wait_for_shutdown_without_mainloop()

                self.assertTrue(root.destroyed)
                self.assertEqual(scheduler.stop_count, 1)
                self.assertFalse(app._post_to_tk(lambda: None))

    def test_constructor_cli_queue_mode_waits_for_start(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "queued-from-cli.zip"
            archive.write_bytes(b"not-opened-by-this-test")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(
                    _FakeRoot(),
                    startup_args=[str(archive)],
                    startup_auto_start=False,
                )
                scheduler = _FakeScheduler.instances[-1]

                self.assertEqual([job.path for job in scheduler.jobs], [str(archive)])
                self.assertEqual(scheduler.enable_count, 0)
                app._on_closing()

    def test_constructor_cli_delete_extracts_beside_source(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "delete-from-context-menu.zip"
            archive.write_bytes(b"not-opened-by-this-test")
            config = _test_config(temp)
            config["extract_to_source"] = False
            with _patched_ui(config):
                app = ui_app.Smart7zAppModern(
                    _FakeRoot(),
                    startup_args=[str(archive)],
                    startup_cleanup_policy="permanent",
                    startup_extract_to_source=True,
                )
                job = _FakeScheduler.instances[-1].jobs[0]

                self.assertEqual(job.cleanup_policy_snapshot, "permanent")
                self.assertTrue(job.extract_to_source_override)
                app._on_closing()

    def test_context_menu_window_closes_only_after_every_job_completes(self):
        with tempfile.TemporaryDirectory() as temp:
            first = Path(temp) / "first.zip"
            second = Path(temp) / "second.zip"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            root = _FakeRoot()
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(
                    root,
                    startup_args=[str(first), str(second)],
                    startup_context_menu=True,
                )
                root.run_deferred("_drain_tk_queue")
                jobs = _FakeScheduler.instances[-1].jobs

                jobs[0].record_state(JobState.COMPLETE)
                app._handle_event("job_complete", jobs[0])
                root.run_deferred("_maybe_auto_close_context_window")
                self.assertFalse(app._closing)

                jobs[1].record_state(JobState.COMPLETE)
                app._handle_event("job_complete", jobs[1])
                root.run_deferred("_maybe_auto_close_context_window")
                self.assertTrue(app._closing)
                app._wait_for_shutdown_without_mainloop()

    def test_context_menu_request_never_arms_an_existing_regular_window(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "regular-window.zip"
            archive.write_bytes(b"payload")
            root = _FakeRoot()
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(root)

                self.assertTrue(
                    app.process_ipc_args(
                        [str(archive)],
                        context_menu=True,
                    )
                )
                job = _FakeScheduler.instances[-1].jobs[0]
                job.record_state(JobState.COMPLETE)
                app._handle_event("job_complete", job)

                self.assertFalse(app._context_auto_close_armed)
                self.assertNotIn(
                    "_maybe_auto_close_context_window", root.deferred_after
                )
                self.assertFalse(app._closing)
                app._on_closing()

    def test_double_click_activation_cancels_context_window_auto_close(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "activated.zip"
            archive.write_bytes(b"payload")
            root = _FakeRoot()
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(
                    root,
                    startup_args=[str(archive)],
                    startup_context_menu=True,
                )
                stale_generation = app._context_auto_close_generation

                self.assertTrue(app.activate_window())
                job = _FakeScheduler.instances[-1].jobs[0]
                job.record_state(JobState.COMPLETE)
                app._handle_event("job_complete", job)
                app._maybe_auto_close_context_window(stale_generation)

                self.assertFalse(app._context_auto_close_armed)
                self.assertFalse(app._closing)
                self.assertTrue(root.options["focused"])
                app._on_closing()

    def test_non_context_ipc_request_cancels_context_window_auto_close(self):
        with tempfile.TemporaryDirectory() as temp:
            first = Path(temp) / "context.zip"
            second = Path(temp) / "command-line.zip"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(
                    _FakeRoot(),
                    startup_args=[str(first)],
                    startup_context_menu=True,
                )

                self.assertTrue(
                    app.process_ipc_args(
                        [str(second)],
                        context_menu=False,
                    )
                )
                self.assertFalse(app._context_auto_close_armed)
                app._on_closing()

    def test_new_context_request_invalidates_older_close_check(self):
        with tempfile.TemporaryDirectory() as temp:
            first = Path(temp) / "first.zip"
            second = Path(temp) / "second.zip"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(
                    _FakeRoot(),
                    startup_args=[str(first)],
                    startup_context_menu=True,
                )
                old_generation = app._context_auto_close_generation
                self.assertTrue(
                    app.process_ipc_args(
                        [str(second)],
                        context_menu=True,
                    )
                )
                current_generation = app._context_auto_close_generation
                self.assertGreater(current_generation, old_generation)

                for job in _FakeScheduler.instances[-1].jobs:
                    job.record_state(JobState.COMPLETE)
                    app._handle_event("job_complete", job)
                app._maybe_auto_close_context_window(old_generation)
                self.assertFalse(app._closing)

                app._maybe_auto_close_context_window(current_generation)
                self.assertTrue(app._closing)
                app._wait_for_shutdown_without_mainloop()

    def test_context_window_waits_for_all_intake_and_prompt_blockers(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "blocked.zip"
            archive.write_bytes(b"payload")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(
                    _FakeRoot(),
                    startup_args=[str(archive)],
                    startup_context_menu=True,
                )
                app.root.run_deferred("_drain_tk_queue")
                scheduler = _FakeScheduler.instances[-1]
                job = scheduler.jobs[0]
                job.record_state(JobState.COMPLETE)
                generation = app._context_auto_close_generation

                blockers = [
                    ("_pending_intake", [("file",)]),
                    ("_scan_thread", threading.current_thread()),
                    ("current_pwd_job", job),
                    ("pending_pwd_jobs", [job]),
                    ("current_stego_job", job),
                    ("pending_stego_jobs", [job]),
                ]
                defaults = {
                    "_pending_intake": [],
                    "_scan_thread": None,
                    "current_pwd_job": None,
                    "pending_pwd_jobs": [],
                    "current_stego_job": None,
                    "pending_stego_jobs": [],
                }
                for attribute, value in blockers:
                    with self.subTest(attribute=attribute):
                        setattr(app, attribute, value)
                        app._maybe_auto_close_context_window(generation)
                        self.assertFalse(app._closing)
                        setattr(app, attribute, defaults[attribute])

                app._scan_threads.add(threading.current_thread())
                app._maybe_auto_close_context_window(generation)
                self.assertFalse(app._closing)
                app._scan_threads.clear()

                scheduler.current_job = job
                app._maybe_auto_close_context_window(generation)
                self.assertFalse(app._closing)
                scheduler.current_job = None
                with mock.patch.object(scheduler, "is_io_busy", return_value=True):
                    app._maybe_auto_close_context_window(generation)
                    self.assertFalse(app._closing)
                with mock.patch.object(
                    scheduler, "deferred_intake_size", return_value=1
                ):
                    app._maybe_auto_close_context_window(generation)
                    self.assertFalse(app._closing)

                app._maybe_auto_close_context_window(generation)
                self.assertTrue(app._closing)
                app._wait_for_shutdown_without_mainloop()

    def test_any_abnormal_job_event_keeps_context_window_open(self):
        abnormal_events = (
            "intake_full",
            "user_notice",
            "password_required",
            "stego_review_required",
            "job_partial",
            "job_failed",
            "job_interrupted",
            "job_skipped",
            "job_duplicate",
        )
        for event_type in abnormal_events:
            with self.subTest(event_type=event_type):
                with tempfile.TemporaryDirectory() as temp:
                    archive = Path(temp) / f"{event_type}.zip"
                    archive.write_bytes(b"payload")
                    with _patched_ui(_test_config(temp)):
                        app = ui_app.Smart7zAppModern(
                            _FakeRoot(),
                            startup_args=[str(archive)],
                            startup_context_menu=True,
                        )
                        job = _FakeScheduler.instances[-1].jobs[0]

                        app._handle_event(event_type, job)

                        self.assertTrue(app._context_auto_close_abnormal)
                        self.assertFalse(app._context_auto_close_armed)
                        self.assertFalse(app._closing)
                        app._on_closing()

    def test_scan_failure_and_recovery_review_keep_context_window_open(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "scan-failure.zip"
            archive.write_bytes(b"payload")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(
                    _FakeRoot(),
                    startup_args=[str(archive)],
                    startup_context_menu=True,
                )
                scan_thread = threading.Thread(target=lambda: None)
                app._scan_thread = scan_thread
                app._scan_threads.add(scan_thread)
                app._finish_background_scan(
                    app._scan_generation,
                    0,
                    scan_thread,
                    "PermissionError: denied",
                )

                self.assertTrue(app._context_auto_close_abnormal)
                self.assertFalse(app._context_auto_close_armed)
                app._on_closing()

            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(
                    _FakeRoot(),
                    startup_args=[str(archive)],
                    startup_context_menu=True,
                )
                app._log_recovery_messages(["Recovery deferred: locked"])

                self.assertTrue(app._context_auto_close_abnormal)
                self.assertFalse(app._context_auto_close_armed)
                app._on_closing()

    def test_unexpected_tk_callback_error_keeps_context_window_open(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "callback-error.zip"
            archive.write_bytes(b"payload")
            root = _FakeRoot()
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(
                    root,
                    startup_args=[str(archive)],
                    startup_context_menu=True,
                )

                def fail_callback():
                    raise ValueError("unexpected callback failure")

                app._post_to_tk(fail_callback)
                with self.assertLogs(ui_app.logger, level="ERROR"):
                    root.run_deferred("_drain_tk_queue")

                self.assertTrue(app._context_auto_close_abnormal)
                self.assertFalse(app._context_auto_close_armed)
                self.assertFalse(app._closing)
                app._on_closing()

    def test_unexpected_close_error_keeps_context_window_open(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "close-error.zip"
            archive.write_bytes(b"payload")
            root = _FakeRoot()
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(
                    root,
                    startup_args=[str(archive)],
                    startup_context_menu=True,
                )
                root.run_deferred("_drain_tk_queue")
                job = _FakeScheduler.instances[-1].jobs[0]
                job.record_state(JobState.COMPLETE)
                generation = app._context_auto_close_generation

                with (
                    mock.patch.object(
                        app,
                        "_on_closing",
                        side_effect=RuntimeError("unexpected close failure"),
                    ),
                    self.assertLogs(ui_app.logger, level="ERROR"),
                ):
                    app._maybe_auto_close_context_window(generation)

                self.assertTrue(app._context_auto_close_abnormal)
                self.assertFalse(app._context_auto_close_armed)
                self.assertFalse(app._closing)
                app._on_closing()

    def test_launch_args_support_default_start_and_explicit_queue(self):
        archive = r"C:\input\archive.zip"

        self.assertEqual(
            ui_app.parse_launch_args([archive]),
            ui_app.ExternalIntakeRequest((archive,), True, "keep", False),
        )
        self.assertEqual(
            ui_app.parse_launch_args(["--queue", archive]),
            ui_app.ExternalIntakeRequest((archive,), False, "keep", False),
        )
        self.assertEqual(
            ui_app.parse_launch_args(["--queue", "--start", archive]),
            ui_app.ExternalIntakeRequest((archive,), True, "keep", False),
        )
        self.assertEqual(
            ui_app.parse_launch_args(
                ["--extract-here", "--delete-source", archive]
            ),
            ui_app.ExternalIntakeRequest(
                (archive,), True, "permanent", True
            ),
        )
        self.assertEqual(
            ui_app.parse_launch_args(
                ["--delete-source", "--keep-source", archive]
            ),
            ui_app.ExternalIntakeRequest((archive,), True, "keep", False),
        )
        self.assertEqual(
            ui_app.parse_launch_args(["--queue", "--", "--start"]),
            ui_app.ExternalIntakeRequest(
                ("--start",), False, "keep", False
            ),
        )
        self.assertEqual(
            ui_app.parse_launch_args(["--context-menu", archive]),
            ui_app.ExternalIntakeRequest(
                (archive,), True, "keep", False, True
            ),
        )

    def test_run_app_forwards_paths_with_queue_intent(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "forwarded.zip"
            archive.write_bytes(b"payload")
            with mock.patch.object(
                ui_app,
                "forward_to_existing",
                return_value=ui_app.IPCForwardResult(
                    ui_app.IPC_FORWARD_ACCEPTED,
                    "accepted",
                    server_reached=True,
                ),
            ) as forward:
                with self.assertRaises(SystemExit) as raised:
                    ui_app.run_app(["--queue", str(archive)])

            self.assertEqual(raised.exception.code, 0)
            forward.assert_called_once_with(
                (str(archive),),
                auto_start=False,
                cleanup_policy="keep",
                extract_to_source=False,
                context_menu=False,
            )

    def test_run_app_without_paths_activates_existing_instance(self):
        with mock.patch.object(
            ui_app,
            "forward_to_existing",
            return_value=ui_app.IPCForwardResult(
                ui_app.IPC_FORWARD_ACCEPTED,
                "accepted",
                server_reached=True,
            ),
        ) as forward:
            with self.assertRaises(SystemExit) as raised:
                ui_app.run_app([])

        self.assertEqual(raised.exception.code, 0)
        forward.assert_called_once_with(
            (),
            auto_start=True,
            cleanup_policy="keep",
            extract_to_source=False,
            context_menu=False,
        )

    def test_run_app_does_not_start_second_instance_after_ipc_rejection(self):
        result = ui_app.IPCForwardResult(
            ui_app.IPC_FORWARD_REJECTED,
            "intake_full",
            server_reached=True,
        )
        with (
            mock.patch.object(ui_app, "forward_to_existing", return_value=result),
            mock.patch.object(
                ui_app,
                "create_root",
                side_effect=AssertionError("must not start a second instance"),
            ),
            mock.patch.object(ui_app.messagebox, "showerror") as showerror,
        ):
            with self.assertRaises(SystemExit) as raised:
                ui_app.run_app([])

        self.assertEqual(raised.exception.code, 1)
        showerror.assert_called_once()

    def test_server_stopping_is_retryable_only_for_shutdown_handoff(self):
        result = ui_app.IPCForwardResult(
            ui_app.IPC_FORWARD_REJECTED,
            "server_stopping",
            server_reached=True,
        )

        with mock.patch.object(ui_app.messagebox, "showerror") as showerror:
            self.assertEqual(ui_app._forward_exit_code(result), 1)
            self.assertIsNone(
                ui_app._forward_exit_code(
                    result,
                    allow_shutdown_handoff=True,
                )
            )

        showerror.assert_called_once()

    def test_run_app_takes_over_after_server_stopping_releases_mutex(self):
        stopping = ui_app.IPCForwardResult(
            ui_app.IPC_FORWARD_REJECTED,
            "server_stopping",
            server_reached=True,
        )
        mutex_handle = object()
        root = _FakeRoot()
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                with (
                    mock.patch.object(ui_app.sys, "platform", "win32"),
                    mock.patch.object(
                        ui_app,
                        "forward_to_existing",
                        return_value=stopping,
                    ) as forward,
                    mock.patch.object(
                        ui_app,
                        "create_mutex",
                        side_effect=[None, mutex_handle],
                    ) as mutex,
                    mock.patch.object(ui_app, "close_mutex", return_value=True) as close,
                    mock.patch.object(ui_app, "create_root", return_value=root),
                    mock.patch.object(
                        ui_app.BoundedIPCServer,
                        "start",
                        return_value=True,
                    ),
                ):
                    ui_app.run_app([])

        self.assertEqual(forward.call_count, 2)
        self.assertEqual(mutex.call_count, 2)
        close.assert_called_once_with(mutex_handle)
        self.assertTrue(root.destroyed)

    def test_run_app_retries_server_stopping_then_forwards_once(self):
        stopping = ui_app.IPCForwardResult(
            ui_app.IPC_FORWARD_REJECTED,
            "server_stopping",
            server_reached=True,
        )
        accepted = ui_app.IPCForwardResult(
            ui_app.IPC_FORWARD_ACCEPTED,
            "accepted",
            server_reached=True,
        )
        with (
            mock.patch.object(ui_app.sys, "platform", "win32"),
            mock.patch.object(
                ui_app,
                "forward_to_existing",
                side_effect=[stopping, accepted],
            ) as forward,
            mock.patch.object(ui_app, "create_mutex", return_value=None) as mutex,
            mock.patch.object(
                ui_app,
                "create_root",
                side_effect=AssertionError("accepted retry must not create Tk"),
            ),
        ):
            with self.assertRaises(SystemExit) as raised:
                ui_app.run_app([])

        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(forward.call_count, 2)
        mutex.assert_called_once_with()

    def test_run_app_waits_for_starting_instance_and_forwards_without_root(self):
        unavailable = ui_app.IPCForwardResult(
            ui_app.IPC_FORWARD_UNAVAILABLE,
            "state_unavailable",
        )
        accepted = ui_app.IPCForwardResult(
            ui_app.IPC_FORWARD_ACCEPTED,
            "accepted",
            server_reached=True,
        )
        with (
            mock.patch.object(ui_app.sys, "platform", "win32"),
            mock.patch.object(
                ui_app,
                "forward_to_existing",
                side_effect=[unavailable, accepted],
            ) as forward,
            mock.patch.object(ui_app, "create_mutex", return_value=None) as mutex,
            mock.patch.object(
                ui_app,
                "create_root",
                side_effect=AssertionError("waiting process must not create Tk"),
            ),
        ):
            with self.assertRaises(SystemExit) as raised:
                ui_app.run_app([])

        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(forward.call_count, 2)
        mutex.assert_called_once_with()

    def test_run_app_takes_over_when_starting_instance_exits(self):
        unavailable = ui_app.IPCForwardResult(
            ui_app.IPC_FORWARD_UNAVAILABLE,
            "state_unavailable",
        )
        mutex_handle = object()
        root = _FakeRoot()
        with tempfile.TemporaryDirectory() as temp:
            with _patched_ui(_test_config(temp)):
                with (
                    mock.patch.object(ui_app.sys, "platform", "win32"),
                    mock.patch.object(
                        ui_app,
                        "forward_to_existing",
                        return_value=unavailable,
                    ) as forward,
                    mock.patch.object(
                        ui_app,
                        "create_mutex",
                        side_effect=[None, mutex_handle],
                    ) as mutex,
                    mock.patch.object(ui_app, "close_mutex", return_value=True) as close,
                    mock.patch.object(ui_app, "create_root", return_value=root),
                    mock.patch.object(
                        ui_app.BoundedIPCServer,
                        "start",
                        return_value=True,
                    ),
                ):
                    ui_app.run_app([])

        self.assertEqual(forward.call_count, 2)
        self.assertEqual(mutex.call_count, 2)
        close.assert_called_once_with(mutex_handle)
        self.assertTrue(root.destroyed)

    def test_run_app_startup_wait_timeout_never_creates_scheduler(self):
        unavailable = ui_app.IPCForwardResult(
            ui_app.IPC_FORWARD_UNAVAILABLE,
            "state_unavailable",
        )
        with (
            mock.patch.object(ui_app.sys, "platform", "win32"),
            mock.patch.object(
                ui_app,
                "forward_to_existing",
                return_value=unavailable,
            ) as forward,
            mock.patch.object(ui_app, "create_mutex", return_value=None) as mutex,
            mock.patch.object(ui_app, "INSTANCE_STARTUP_WAIT_SECONDS", 0.0),
            mock.patch.object(
                ui_app,
                "create_root",
                side_effect=AssertionError("timeout must not create Tk or Scheduler"),
            ),
            mock.patch.object(ui_app.messagebox, "showerror") as showerror,
        ):
            with self.assertRaises(SystemExit) as raised:
                ui_app.run_app([])

        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(forward.call_count, 2)
        self.assertEqual(mutex.call_count, 2)
        showerror.assert_called_once()

    def test_run_app_releases_mutex_when_root_creation_fails(self):
        unavailable = ui_app.IPCForwardResult(
            ui_app.IPC_FORWARD_UNAVAILABLE,
            "state_unavailable",
        )
        mutex_handle = object()
        with (
            mock.patch.object(ui_app.sys, "platform", "win32"),
            mock.patch.object(ui_app, "forward_to_existing", return_value=unavailable),
            mock.patch.object(ui_app, "create_mutex", return_value=mutex_handle),
            mock.patch.object(ui_app, "close_mutex", return_value=True) as close,
            mock.patch.object(
                ui_app,
                "create_root",
                side_effect=RuntimeError("Tk startup failed"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "Tk startup failed"):
                ui_app.run_app([])

        close.assert_called_once_with(mutex_handle)

    def test_local_enqueue_waits_for_start_external_enqueue_autostarts(self):
        with tempfile.TemporaryDirectory() as temp:
            local = Path(temp) / "local.zip"
            external = Path(temp) / "external.zip"
            local.write_bytes(b"local")
            external.write_bytes(b"external")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                scheduler = _FakeScheduler.instances[-1]

                app._enqueue_path(str(local), auto_start=False)
                self.assertEqual(scheduler.enable_count, 0)
                app._enqueue_path(str(external), auto_start=True)
                self.assertEqual(scheduler.enable_count, 1)
                app._on_closing()

    def test_drop_enqueue_waits_for_start(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "dropped.zip"
            archive.write_bytes(b"dropped")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                scheduler = _FakeScheduler.instances[-1]
                app._on_drop(types.SimpleNamespace(data=str(archive)))

                self.assertEqual(scheduler.enable_count, 0)
                self.assertEqual(len(scheduler.jobs), 1)
                self.assertEqual(scheduler.jobs[0].path, str(archive))
                self.assertTrue(scheduler.jobs[0].explicit_input)
                app._on_closing()

    def test_direct_external_file_bypasses_automatic_classifier(self):
        with tempfile.TemporaryDirectory() as temp:
            document = Path(temp) / "direct.docx"
            with zipfile.ZipFile(document, "w") as output:
                output.writestr("[Content_Types].xml", "<Types/>")
                output.writestr("_rels/.rels", "<Relationships/>")
                output.writestr("word/document.xml", "<document/>")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                scheduler = _FakeScheduler.instances[-1]
                with mock.patch.object(
                    ui_app,
                    "classify_automatic_candidate",
                    side_effect=AssertionError("direct files must bypass filtering"),
                ):
                    app._process_external_paths(
                        [str(document)],
                        auto_start=True,
                        source="CLI",
                    )

                self.assertEqual(len(scheduler.jobs), 1)
                self.assertTrue(scheduler.jobs[0].explicit_input)
                self.assertEqual(scheduler.enable_count, 1)
                app._on_closing()

    def test_external_request_uses_committed_cleanup_config(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "external.zip"
            archive.write_bytes(b"external")
            config = _test_config(temp)
            config["cleanup_policy"] = "keep"
            with _patched_ui(config):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                scheduler = _FakeScheduler.instances[-1]
                app.var_cleanup_policy.set("permanent")

                self.assertTrue(
                    app._process_external_paths(
                        [str(archive)], auto_start=False, source="IPC"
                    )
                )

                self.assertEqual(len(scheduler.jobs), 1)
                self.assertEqual(scheduler.jobs[0].cleanup_policy_snapshot, "keep")
                self.assertFalse(hasattr(scheduler.jobs[0], "trusted_input"))
                app._on_closing()

    def test_external_request_never_inherits_permanent_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "external.zip"
            archive.write_bytes(b"external")
            config = _test_config(temp)
            config["cleanup_policy"] = "permanent"
            config["del_archive"] = True
            with _patched_ui(config):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                scheduler = _FakeScheduler.instances[-1]

                self.assertTrue(
                    app._process_external_paths(
                        [str(archive)], auto_start=True, source="IPC"
                    )
                )

                self.assertEqual(len(scheduler.jobs), 1)
                self.assertEqual(scheduler.jobs[0].cleanup_policy_snapshot, "keep")
                app._on_closing()

    def test_explicit_external_delete_policy_is_frozen_on_job(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "external-delete.zip"
            archive.write_bytes(b"external")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                scheduler = _FakeScheduler.instances[-1]

                self.assertTrue(
                    app._process_external_paths(
                        [str(archive)],
                        auto_start=True,
                        source="IPC",
                        cleanup_policy="permanent",
                        extract_to_source=True,
                    )
                )

                self.assertEqual(len(scheduler.jobs), 1)
                self.assertEqual(
                    scheduler.jobs[0].cleanup_policy_snapshot, "permanent"
                )
                self.assertTrue(scheduler.jobs[0].extract_to_source_override)
                app._on_closing()

    def test_external_directory_scan_preserves_delete_and_destination_modes(self):
        with tempfile.TemporaryDirectory() as temp:
            incoming = Path(temp) / "incoming"
            incoming.mkdir()
            archive = incoming / "external-delete.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("payload.txt", "payload")

            with _patched_ui(_test_config(temp)):
                root = _FakeRoot()
                app = ui_app.Smart7zAppModern(root)
                scheduler = _FakeScheduler.instances[-1]

                self.assertTrue(
                    app._process_external_paths(
                        [str(incoming)],
                        auto_start=True,
                        source="IPC",
                        cleanup_policy="permanent",
                        extract_to_source=True,
                    )
                )
                app._scan_thread.join(timeout=2)
                root.run_deferred("_drain_tk_queue")

                self.assertEqual(len(scheduler.jobs), 1)
                job = scheduler.jobs[0]
                self.assertEqual(job.path, str(archive))
                self.assertEqual(job.cleanup_policy_snapshot, "permanent")
                self.assertTrue(job.extract_to_source_override)
                self.assertFalse(job.explicit_input)
                self.assertEqual(scheduler.enable_count, 1)
                app._on_closing()

    def test_config_save_failure_restores_all_controls(self):
        with tempfile.TemporaryDirectory() as temp:
            config = _test_config(temp)
            config.update(
                {
                    "extract_to_source": True,
                    "wait_disk_space": True,
                    "extract_mode": "staging",
                    "deep_scan": False,
                    "nested_extraction": False,
                    "cleanup_policy": "keep",
                    "max_nested_depth": 2,
                }
            )
            with _patched_ui(config):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                scheduler = _FakeScheduler.instances[-1]
                active_config = dict(app.config)
                app.var_extract_to_source.set(False)
                app.var_wait_space.set(False)
                app.var_staging_mode.set(False)
                app._select_scan_mode(ui_app.SCAN_MODE_DEEP)
                app.var_nested.set(True)
                app.var_cleanup_policy.set("permanent")
                for entry, value in (
                    (app.entry_target, "changed-target"),
                    (app.entry_temp, "changed-temp"),
                    (app.entry_pwd, "changed-passwords"),
                    (app.spin_nested_depth, "9"),
                ):
                    entry.delete(0, ui_app.tk.END)
                    entry.insert(0, value)

                with mock.patch.object(
                    ui_app, "save_config", side_effect=OSError("read only")
                ):
                    self.assertFalse(app._sync_config())

                self.assertTrue(app.var_extract_to_source.get())
                self.assertTrue(app.var_wait_space.get())
                self.assertTrue(app.var_staging_mode.get())
                self.assertFalse(app.var_deep_scan.get())
                self.assertFalse(app.var_nested.get())
                self.assertEqual(app.var_cleanup_policy.get(), "keep")
                self.assertEqual(app.entry_target.get(), config["target_dir"])
                self.assertEqual(app.entry_temp.get(), config["temp_dir"])
                self.assertEqual(app.entry_pwd.get(), config["password_file"])
                self.assertEqual(app.spin_nested_depth.get(), "2")
                self.assertEqual(scheduler.refresh_count, 0)
                self.assertEqual(app.config, active_config)
                app._on_closing()

    def test_folder_scan_filters_semantic_containers_and_marks_jobs_automatic(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "archive.docx"
            document = Path(temp) / "document.zip"
            unknown = Path(temp) / "unknown.bin"
            hidden = Path(temp) / "hidden.bin"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("payload.txt", "payload")
            with zipfile.ZipFile(document, "w") as output:
                output.writestr("[Content_Types].xml", "<Types/>")
                output.writestr("_rels/.rels", "<Relationships/>")
                output.writestr("word/document.xml", "<document/>")
            unknown.write_bytes(b"not an archive")
            with hidden.open("wb") as stream:
                stream.truncate(3 * 1024 * 1024)
                stream.seek(1536 * 1024)
                stream.write(b"7z\xbc\xaf\x27\x1c\x00\x04payload")

            config = _test_config(temp)
            config["deep_scan"] = True
            with _patched_ui(config):
                root = _FakeRoot()
                app = ui_app.Smart7zAppModern(root)
                scheduler = _FakeScheduler.instances[-1]
                app._start_background_scan([temp], auto_start=False)
                app._scan_thread.join(timeout=2)
                root.run_deferred("_drain_tk_queue")

                self.assertTrue(
                    app._scan_thread is None or not app._scan_thread.is_alive()
                )
                self.assertEqual(
                    {Path(job.path).name for job in scheduler.jobs},
                    {"archive.docx", "hidden.bin"},
                )
                self.assertTrue(
                    all(not job.explicit_input for job in scheduler.jobs)
                )
                hidden_job = next(
                    job
                    for job in scheduler.jobs
                    if Path(job.path).name == "hidden.bin"
                )
                self.assertTrue(hidden_job.stego_candidates)
                self.assertFalse(app.scan_progress_frame.packed)
                app._on_closing()

    def test_compat_scan_reuses_candidate_without_full_file_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            media = Path(temp) / "hidden.mp4"
            media.write_bytes(b"media")
            candidate = ArchiveCandidate(
                host_format="bmff",
                embedded_format="zip",
                start_offset=1,
                end_offset=5,
                mode="steganographier_mp4_trailing",
                confidence=Confidence.HIGH,
                validation_flags=["steganographier_compatible"],
            )
            with _patched_ui(_test_config(temp)):
                root = _FakeRoot()
                app = ui_app.Smart7zAppModern(root)
                scheduler = _FakeScheduler.instances[-1]
                with (
                    mock.patch.object(
                        ui_app,
                        "classify_automatic_candidate",
                        return_value=AutoDiscoveryDecision(
                            False,
                            "semantic_container",
                            semantic_kind="iso_bmff_media",
                        ),
                    ) as classifier,
                    mock.patch.object(
                        ui_app,
                        "find_steganographier_candidates",
                        return_value=[candidate],
                    ) as compat_scan,
                    mock.patch.object(
                        ui_app,
                        "find_candidates",
                        side_effect=AssertionError(
                            "compat mode must not run the full scanner"
                        ),
                    ),
                ):
                    self.assertTrue(app._start_background_scan([temp]))
                    app._scan_thread.join(timeout=2)
                    root.run_deferred("_drain_tk_queue")

                self.assertEqual(len(scheduler.jobs), 1)
                self.assertEqual(scheduler.jobs[0].stego_candidates, [candidate])
                self.assertEqual(compat_scan.call_count, 1)
                self.assertFalse(
                    classifier.call_args.kwargs["allow_full_embedded_scan"]
                )
                app._on_closing()

    def test_scan_exception_releases_slot_and_allows_next_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            failed_dir = Path(temp) / "failed"
            next_dir = Path(temp) / "next"
            failed_dir.mkdir()
            next_dir.mkdir()
            failed_path = failed_dir / "failed.zip"
            next_path = next_dir / "next.zip"
            failed_path.write_bytes(b"failed")
            with zipfile.ZipFile(next_path, "w") as output:
                output.writestr("payload.txt", "payload")

            with _patched_ui(_test_config(temp)):
                root = _FakeRoot()
                app = ui_app.Smart7zAppModern(root)
                scheduler = _FakeScheduler.instances[-1]
                original_classifier = ui_app.classify_automatic_candidate

                def classify(path, *args, **kwargs):
                    if Path(path) == failed_path:
                        raise RuntimeError("classifier failure")
                    return original_classifier(path, *args, **kwargs)

                with mock.patch.object(
                    ui_app,
                    "classify_automatic_candidate",
                    side_effect=classify,
                ):
                    self.assertTrue(app._start_background_scan([str(failed_dir)]))
                    failed_thread = app._scan_thread
                    failed_thread.join(timeout=2)
                    self.assertFalse(failed_thread.is_alive())
                    root.run_deferred("_drain_tk_queue")

                    self.assertIsNone(app._scan_thread)
                    self.assertNotIn(failed_thread, app._scan_threads)
                    self.assertTrue(app._start_background_scan([str(next_dir)]))
                    next_thread = app._scan_thread
                    self.assertIsNot(next_thread, failed_thread)
                    next_thread.join(timeout=2)
                    self.assertFalse(next_thread.is_alive())
                    root.run_deferred("_drain_tk_queue")

                self.assertEqual(
                    [Path(job.path).name for job in scheduler.jobs],
                    ["next.zip"],
                )
                app._on_closing()

    def test_cancelled_scan_drops_late_results_and_allows_new_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            old_path = Path(temp) / "old.zip"
            new_path = Path(temp) / "new.zip"
            old_path.write_bytes(b"old")
            new_path.write_bytes(b"new")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                scheduler = _FakeScheduler.instances[-1]
                old_thread = threading.current_thread()

                app._scan_generation = 1
                app._scan_thread = old_thread
                app._scan_threads.add(old_thread)
                app._cancel_remaining()
                cancelled_generation = app._scan_generation - 1

                self.assertFalse(
                    app._enqueue_scanned_path(
                        cancelled_generation,
                        str(old_path),
                        False,
                        dict(app.config),
                    )
                )
                self.assertEqual(scheduler.jobs, [])

                new_generation = app._scan_generation
                new_thread = threading.Thread(target=lambda: None)
                app._scan_thread = new_thread
                app._scan_threads.add(new_thread)
                app._finish_background_scan(
                    cancelled_generation,
                    1,
                    old_thread,
                )

                self.assertIs(app._scan_thread, new_thread)
                self.assertIn(new_thread, app._scan_threads)
                self.assertEqual(app._scan_generation, new_generation)
                app._on_closing()

    def test_finished_scan_holds_external_file_until_main_thread_settles(self):
        with tempfile.TemporaryDirectory() as temp:
            external = Path(temp) / "external.zip"
            external.write_bytes(b"external")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                scheduler = _FakeScheduler.instances[-1]
                finished_scan = threading.Thread(target=lambda: None)
                finished_scan.start()
                finished_scan.join()
                app._scan_thread = finished_scan

                self.assertTrue(
                    app._enqueue_path(
                        str(external),
                        auto_start=True,
                        config_snapshot=dict(app.config),
                    )
                )
                self.assertEqual(scheduler.jobs, [])
                self.assertEqual(len(app._pending_intake), 1)

                app._start_next_pending_scan()

                self.assertEqual([job.path for job in scheduler.jobs], [str(external)])
                self.assertEqual(app._pending_intake, [])
                app._on_closing()

    def test_external_files_and_directories_share_one_fifo(self):
        with tempfile.TemporaryDirectory() as temp:
            first = Path(temp) / "first.zip"
            directory = Path(temp) / "folder"
            second = Path(temp) / "second.zip"
            first.write_bytes(b"first")
            directory.mkdir()
            second.write_bytes(b"second")
            with _patched_ui(_test_config(temp)):
                app = ui_app.Smart7zAppModern(_FakeRoot())
                scheduler = _FakeScheduler.instances[-1]
                finished_scan = threading.Thread(target=lambda: None)
                finished_scan.start()
                finished_scan.join()
                app._scan_thread = finished_scan

                self.assertTrue(
                    app._process_external_paths(
                        [str(first), str(directory), str(second)],
                        auto_start=False,
                        source="IPC",
                    )
                )
                self.assertEqual(
                    [item[0] for item in app._pending_intake],
                    ["file", "scan", "file"],
                )

                app._scan_thread = None
                with mock.patch.object(
                    app, "_launch_background_scan", return_value=True
                ) as launch:
                    app._release_pending_intake()
                    self.assertEqual([job.path for job in scheduler.jobs], [str(first)])
                    launch.assert_called_once()
                    self.assertEqual(
                        [item[1] for item in app._pending_intake], [str(second)]
                    )
                    app._start_next_pending_scan()

                self.assertEqual(
                    [job.path for job in scheduler.jobs], [str(first), str(second)]
                )
                app._on_closing()

    def test_external_batch_capacity_failure_has_no_partial_intake(self):
        with tempfile.TemporaryDirectory() as temp:
            first = Path(temp) / "first.zip"
            second = Path(temp) / "second.zip"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            with (
                _patched_ui(_test_config(temp)),
                mock.patch.object(ui_app, "PENDING_INTAKE_LIMIT", 1),
            ):
                app = ui_app.Smart7zAppModern(_FakeRoot())

                self.assertFalse(
                    app.process_ipc_args([str(first), str(second)], auto_start=True)
                )
                self.assertEqual(app._pending_intake, [])
                self.assertEqual(app._pending_intake_keys, set())
                self.assertEqual(_FakeScheduler.instances[-1].jobs, [])
                app._on_closing()

    def test_missing_sevenzip_blocks_startup_and_closes_cleanly(self):
        with tempfile.TemporaryDirectory() as temp:
            root = _FakeRoot()
            with _patched_ui(_test_config(temp), sevenzip_path=None):
                with mock.patch.object(ui_app, "create_root", return_value=root):
                    ui_app.run_app([])

                self.assertTrue(root.destroyed)
                self.assertEqual(_FakeScheduler.instances, [])
                ui_app.messagebox.showerror.assert_called_once()

    def test_ipc_bind_failure_stops_already_started_scheduler(self):
        with tempfile.TemporaryDirectory() as temp:
            root = _FakeRoot()
            with _patched_ui(_test_config(temp)):
                with (
                    mock.patch.object(ui_app, "create_root", return_value=root),
                    mock.patch.object(ui_app.BoundedIPCServer, "start", return_value=False),
                    mock.patch.object(
                        ui_app,
                        "forward_to_existing",
                        return_value=ui_app.IPCForwardResult(
                            ui_app.IPC_FORWARD_UNAVAILABLE,
                            "state_unavailable",
                        ),
                    ),
                ):
                    ui_app.run_app([])

                scheduler = _FakeScheduler.instances[-1]
                self.assertEqual(scheduler.stop_count, 1)
                self.assertTrue(root.destroyed)

    def test_mainloop_failure_runs_shutdown_finally(self):
        with tempfile.TemporaryDirectory() as temp:
            root = _FakeRoot(mainloop_error=RuntimeError("mainloop failed"))
            with _patched_ui(_test_config(temp)):
                with (
                    mock.patch.object(ui_app, "create_root", return_value=root),
                    mock.patch.object(ui_app.BoundedIPCServer, "start", return_value=True),
                ):
                    with self.assertRaisesRegex(RuntimeError, "mainloop failed"):
                        ui_app.run_app([])

                scheduler = _FakeScheduler.instances[-1]
                self.assertEqual(scheduler.stop_count, 1)
                self.assertTrue(root.destroyed)


class TestIpcLifecycle(unittest.TestCase):
    def test_round_trip_ack_and_listener_shutdown(self):
        received = []
        delivered = threading.Event()

        class Root:
            @staticmethod
            def after(_delay, callback, *args):
                callback(*args)

        class App:
            root = Root()

            @staticmethod
            def _post_to_tk(callback, *args):
                callback(*args)
                return True

            @staticmethod
            def process_ipc_args(
                paths,
                auto_start=True,
                cleanup_policy="keep",
                extract_to_source=False,
                context_menu=False,
            ):
                received.append(
                    (
                        list(paths),
                        auto_start,
                        cleanup_policy,
                        extract_to_source,
                        context_menu,
                    )
                )
                delivered.set()
                return True

            @staticmethod
            def activate_window():
                return True

        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "IPC 路径.zip"
            archive.write_bytes(b"payload")
            state_path = str(Path(temp) / "ipc-state.json")
            server = ui_app.BoundedIPCServer(
                App(), port=0, state_path=state_path
            )
            try:
                self.assertTrue(server.start())
                port = server.sock.getsockname()[1]
                self.assertTrue(
                    ui_app.try_forward_to_existing(
                        [str(archive)],
                        port=port,
                        auto_start=False,
                        cleanup_policy="permanent",
                        extract_to_source=True,
                        context_menu=True,
                        token=server.token,
                    )
                )
                self.assertTrue(delivered.wait(2.0))
                self.assertEqual(
                    received,
                    [
                        (
                            [os.path.normpath(str(archive))],
                            False,
                            "permanent",
                            True,
                            True,
                        )
                    ],
                )
            finally:
                server.close()

            self.assertIsNone(server.sock)
            self.assertIsNone(server._thread)

    def test_rejected_reply_is_distinct_from_unavailable_server(self):
        class Root:
            @staticmethod
            def after(_delay, callback, *args):
                callback(*args)

        class App:
            root = Root()

            @staticmethod
            def _post_to_tk(callback, *args):
                callback(*args)
                return True

            @staticmethod
            def process_ipc_args(
                _paths,
                _auto_start=True,
                _cleanup_policy="keep",
                _extract_to_source=False,
                _context_menu=False,
            ):
                return False

            @staticmethod
            def activate_window():
                return False

        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "rejected.zip"
            archive.write_bytes(b"payload")
            state_path = str(Path(temp) / "ipc-state.json")
            server = ui_app.BoundedIPCServer(
                App(), port=0, state_path=state_path
            )
            try:
                self.assertTrue(server.start())
                result = ui_app.forward_to_existing(
                    [str(archive)],
                    port=server.port,
                    token=server.token,
                )
            finally:
                server.close()

        self.assertEqual(result.status, ui_app.IPC_FORWARD_REJECTED)
        self.assertEqual(result.reason, "intake_full")
        self.assertTrue(result.reached_existing)

    def test_pending_dispatch_timeout_cancels_late_tk_callback(self):
        calls = []

        class App:
            @staticmethod
            def process_ipc_args(
                paths,
                auto_start=True,
                cleanup_policy="keep",
                extract_to_source=False,
                context_menu=False,
            ):
                calls.append(
                    (
                        paths,
                        auto_start,
                        cleanup_policy,
                        extract_to_source,
                        context_menu,
                    )
                )
                return True

        server = ui_app.BoundedIPCServer(App())
        ticket = ui_app._IPCDispatchTicket()

        self.assertEqual(ticket.result_after_timeout(), (False, "dispatch_timeout"))
        server._dispatch_request(
            server._generation,
            ui_app.ExternalIntakeRequest((r"C:\input.zip",)),
            ticket,
        )

        self.assertEqual(calls, [])
        self.assertEqual(ticket.result(), (False, "dispatch_timeout"))

    def test_running_dispatch_timeout_is_reported_as_indeterminate(self):
        ticket = ui_app._IPCDispatchTicket()

        self.assertTrue(ticket.begin())
        self.assertEqual(
            ticket.result_after_timeout(),
            (False, "dispatch_in_progress"),
        )
        ticket.finish(True, "accepted")

        self.assertEqual(ticket.result(), (True, "accepted"))

    def test_dispatch_exception_is_reported_without_killing_listener(self):
        disable_calls = []

        class App:
            @staticmethod
            def process_ipc_args(
                _paths,
                _auto_start=True,
                _cleanup_policy="keep",
                _extract_to_source=False,
                _context_menu=False,
            ):
                raise RuntimeError("dispatch failed")

            @staticmethod
            def _disable_context_auto_close(abnormal=False):
                disable_calls.append(abnormal)

        server = ui_app.BoundedIPCServer(App())
        ticket = ui_app._IPCDispatchTicket()

        with self.assertLogs(ui_app.logger, level="ERROR"):
            server._dispatch_request(
                server._generation,
                ui_app.ExternalIntakeRequest((r"C:\input.zip",)),
                ticket,
            )

        self.assertEqual(ticket.result(), (False, "dispatch_error"))
        self.assertEqual(disable_calls, [True])

    def test_client_rejects_empty_and_over_limit_inputs_without_connecting(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "one.zip"
            archive.write_bytes(b"payload")
            self.assertFalse(ui_app.try_forward_to_existing([""], port=1))
            self.assertFalse(
                ui_app.try_forward_to_existing(
                    [str(archive)],
                    port=1,
                    auto_start="yes",
                )
            )
            self.assertFalse(
                ui_app.try_forward_to_existing(
                    [str(archive)],
                    port=1,
                    cleanup_policy="recycle",
                )
            )
            self.assertFalse(
                ui_app.try_forward_to_existing(
                    [str(archive)],
                    port=1,
                    extract_to_source="yes",
                )
            )
            self.assertFalse(
                ui_app.try_forward_to_existing(
                    [str(archive)],
                    port=1,
                    context_menu="yes",
                )
            )
            self.assertFalse(
                ui_app.try_forward_to_existing([], port=1, context_menu=True)
            )
            self.assertFalse(
                ui_app.try_forward_to_existing(
                    [str(archive)] * (ui_app.IPC_MAX_PATHS + 1), port=1
                )
            )

    def test_server_path_probe_errors_are_rejected(self):
        server = ui_app.BoundedIPCServer(types.SimpleNamespace())
        payload = ui_app.json.dumps(
            {
                "version": ui_app.IPC_VERSION,
                "token": server.token,
                "action": "enqueue",
                "paths": [r"C:\broken"],
                "auto_start": True,
            }
        ).encode("utf-8")
        with mock.patch.object(ui_app.os.path, "exists", side_effect=OSError("bad path")):
            self.assertIsNone(server._parse_request(payload))

    def test_server_accepts_authenticated_request_and_rejects_invalid_mode(self):
        server = ui_app.BoundedIPCServer(types.SimpleNamespace())
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "legacy.zip"
            archive.write_bytes(b"payload")
            request = ui_app.json.dumps(
                {
                    "version": ui_app.IPC_VERSION,
                    "token": server.token,
                    "action": "enqueue",
                    "paths": [str(archive)],
                    "auto_start": True,
                    "cleanup_policy": "permanent",
                    "extract_to_source": True,
                    "context_menu": True,
                }
            ).encode("utf-8")
            parsed = server._parse_request(request)

            self.assertEqual(parsed.action, "enqueue")
            self.assertEqual(
                parsed.paths, (os.path.normpath(str(archive)),)
            )
            self.assertTrue(parsed.auto_start)
            self.assertEqual(parsed.cleanup_policy, "permanent")
            self.assertTrue(parsed.extract_to_source)
            self.assertTrue(parsed.context_menu)

            invalid = ui_app.json.dumps(
                {
                    "version": ui_app.IPC_VERSION,
                    "token": server.token,
                    "paths": [str(archive)],
                    "auto_start": "yes",
                }
            ).encode("utf-8")
            self.assertIsNone(server._parse_request(invalid))

            invalid_policy = ui_app.json.dumps(
                {
                    "version": ui_app.IPC_VERSION,
                    "token": server.token,
                    "paths": [str(archive)],
                    "auto_start": True,
                    "cleanup_policy": "recycle",
                }
            ).encode("utf-8")
            self.assertIsNone(server._parse_request(invalid_policy))

            invalid_context = ui_app.json.dumps(
                {
                    "version": ui_app.IPC_VERSION,
                    "token": server.token,
                    "paths": [str(archive)],
                    "auto_start": True,
                    "context_menu": "yes",
                }
            ).encode("utf-8")
            self.assertIsNone(server._parse_request(invalid_context))


class TestWindowsAdapterLifecycle(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows named-mutex behavior")
    def test_named_mutex_is_exclusive_until_handle_closes(self):
        name = f"Smart7z_Test_Instance_Mutex_{os.getpid()}_{id(self)}"
        first = windows_adapters.create_mutex(name)
        self.assertIsNotNone(first)
        try:
            self.assertIsNone(windows_adapters.create_mutex(name))
        finally:
            self.assertTrue(windows_adapters.close_mutex(first))

        replacement = windows_adapters.create_mutex(name)
        self.assertIsNotNone(replacement)
        self.assertTrue(windows_adapters.close_mutex(replacement))

    def test_close_mutex_closes_handle(self):
        handle = object()
        with (
            mock.patch.object(windows_adapters.sys, "platform", "win32"),
            mock.patch.object(
                windows_adapters,
                "_CloseHandle",
                return_value=1,
                create=True,
            ) as close,
        ):
            self.assertTrue(windows_adapters.close_mutex(handle))
        close.assert_called_once_with(handle)

    def test_context_menu_quotes_source_and_substituted_path(self):
        executable = r"C:\Program Files\Python\python.exe"
        script = r"C:\Smart App\smart7z.py"
        with (
            mock.patch.object(windows_adapters.sys, "executable", executable),
            mock.patch.object(windows_adapters.sys, "argv", [script]),
            mock.patch.object(windows_adapters.sys, "frozen", False, create=True),
        ):
            keep_command = windows_adapters.build_context_menu_command("keep")
            delete_command = windows_adapters.build_context_menu_command(
                "permanent"
            )
        self.assertEqual(
            keep_command,
            subprocess.list2cmdline(
                [
                    executable,
                    script,
                    "--context-menu",
                    "--start",
                    "--extract-here",
                    "--keep-source",
                ]
            )
            + ' "%1"',
        )
        self.assertEqual(
            delete_command,
            subprocess.list2cmdline(
                [
                    executable,
                    script,
                    "--context-menu",
                    "--start",
                    "--extract-here",
                    "--delete-source",
                ]
            )
            + ' "%1"',
        )

    def test_context_menu_quotes_frozen_target(self):
        executable = r"C:\Program Files\Smart7z\smart7z.exe"
        with (
            mock.patch.object(windows_adapters.sys, "executable", executable),
            mock.patch.object(windows_adapters.sys, "frozen", True, create=True),
        ):
            command = windows_adapters.build_context_menu_command("permanent")
        self.assertEqual(
            command,
            subprocess.list2cmdline(
                [
                    executable,
                    "--context-menu",
                    "--start",
                    "--extract-here",
                    "--delete-source",
                ]
            )
            + ' "%1"',
        )

    def test_context_menu_rejects_unsupported_cleanup_policy(self):
        with self.assertRaises(ValueError):
            windows_adapters.build_context_menu_command("recycle")

    def test_context_menu_registers_two_file_and_directory_actions(self):
        class RegistryKey:
            def __init__(self, registry, path):
                self.registry = registry
                self.path = path

            def __enter__(self):
                return self

            def __exit__(self, _exc_type, _exc, _traceback):
                return False

        class FakeWinreg:
            HKEY_CURRENT_USER = object()
            REG_SZ = 1

            def __init__(self):
                self.keys = set()
                self.values = {}

            def CreateKey(self, _root, path):
                self.keys.add(path)
                return RegistryKey(self, path)

            def SetValue(self, key, _name, _kind, value):
                self.values[(key.path, "default")] = value

            def SetValueEx(self, key, name, _reserved, _kind, value):
                self.values[(key.path, name)] = value

            def DeleteKey(self, _root, path):
                if path not in self.keys:
                    raise FileNotFoundError(path)
                self.keys.remove(path)
                self.values = {
                    key: value
                    for key, value in self.values.items()
                    if key[0] != path
                }

        registry = FakeWinreg()
        legacy_keys = set()
        for scope in windows_adapters._CONTEXT_MENU_SCOPES:
            legacy_key = f"{scope}\\Smart7z"
            legacy_command_key = f"{legacy_key}\\command"
            legacy_keys.update((legacy_key, legacy_command_key))
            registry.keys.update((legacy_key, legacy_command_key))
            registry.values[(legacy_key, "default")] = "使用 Smart7z 解压"
            registry.values[(legacy_command_key, "default")] = "legacy command"
        executable = r"C:\Program Files\Smart7z\smart7z.exe"
        with (
            mock.patch.object(windows_adapters.sys, "platform", "win32"),
            mock.patch.object(windows_adapters.sys, "executable", executable),
            mock.patch.object(windows_adapters.sys, "frozen", True, create=True),
            mock.patch.dict(sys.modules, {"winreg": registry}),
        ):
            self.assertTrue(windows_adapters.register_context_menu())

            self.assertTrue(legacy_keys.isdisjoint(registry.keys))
            self.assertTrue(
                all(path not in legacy_keys for path, _name in registry.values)
            )
            for scope in windows_adapters._CONTEXT_MENU_SCOPES:
                for verb, label, policy in windows_adapters._CONTEXT_MENU_ENTRIES:
                    key_path = f"{scope}\\{verb}"
                    self.assertEqual(
                        registry.values[(key_path, "default")], label
                    )
                    self.assertEqual(
                        registry.values[(f"{key_path}\\command", "default")],
                        windows_adapters.build_context_menu_command(policy),
                    )

            self.assertTrue(windows_adapters.unregister_context_menu())
            self.assertEqual(registry.keys, set())

    def test_stale_session_cleanup_rejects_reparse_points(self):
        with tempfile.TemporaryDirectory() as temp:
            session = Path(temp) / "Smart7z_Session_99999999"
            session.mkdir()
            with (
                mock.patch.object(windows_adapters, "_is_pid_running", return_value=False),
                mock.patch.object(windows_adapters, "is_reparse_point", return_value=True),
                mock.patch.object(windows_adapters, "safe_rmtree") as remove,
            ):
                windows_adapters.cleanup_stale_sessions(temp)
            remove.assert_not_called()
            self.assertTrue(session.is_dir())

    def test_confirmed_stale_plain_session_is_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, _token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)
            with (
                mock.patch.object(windows_adapters, "_is_pid_running", return_value=False),
                mock.patch.object(windows_adapters, "is_reparse_point", return_value=False),
            ):
                windows_adapters.cleanup_stale_sessions(temp)
            self.assertFalse(session.exists())

    def test_stale_session_with_empty_stego_scaffold_is_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, _token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)
            (session / "stego").mkdir()
            with (
                mock.patch.object(windows_adapters, "_is_pid_running", return_value=False),
                mock.patch.object(windows_adapters, "is_reparse_point", return_value=False),
            ):
                windows_adapters.cleanup_stale_sessions(temp)
            self.assertFalse(session.exists())

    def test_stale_session_with_nonempty_stego_scaffold_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, _token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)
            stego = session / "stego"
            stego.mkdir()
            (stego / "sentinel.txt").write_text("later", encoding="utf-8")
            with (
                mock.patch.object(windows_adapters, "_is_pid_running", return_value=False),
                mock.patch.object(windows_adapters, "is_reparse_point", return_value=False),
            ):
                windows_adapters.cleanup_stale_sessions(temp)
            self.assertTrue(session.exists())

    def test_stale_session_with_unregistered_content_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            session_path, _token = windows_adapters.create_owned_session(temp)
            session = Path(session_path)
            (session / "sentinel.txt").write_text("later", encoding="utf-8")
            with (
                mock.patch.object(windows_adapters, "_is_pid_running", return_value=False),
                mock.patch.object(windows_adapters, "is_reparse_point", return_value=False),
            ):
                windows_adapters.cleanup_stale_sessions(temp)
            self.assertTrue(session.exists())

    @unittest.skipUnless(os.name == "nt", "Windows process handle check")
    def test_current_process_is_detected(self):
        self.assertTrue(windows_adapters._is_pid_running(os.getpid()))


if __name__ == "__main__":
    unittest.main()
