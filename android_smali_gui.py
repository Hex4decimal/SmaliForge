#!/usr/bin/env python3
"""Android Smali GUI

Desktop GUI for listing packages on a connected, non-rooted Android device,
pulling installed APKs with ADB, and decoding them to smali with Apktool.

Only use this on applications/devices you own or are authorized to inspect.
"""

from __future__ import annotations

import json
import hashlib
import os
import queue
import re
import secrets
import shutil
import subprocess
import struct
import sys
import threading
import time
import urllib.request
import zlib
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, X, Y, BooleanVar, DoubleVar, StringVar, Tk, filedialog, messagebox
from tkinter import ttk

try:
    import keyring
    from keyring.errors import KeyringError
except ImportError:  # handled with a clear error only when signing is requested
    keyring = None
    KeyringError = Exception

APP_NAME = "Android Smali GUI"
CONFIG_DIR = Path.home() / ".android_smali_gui"
CONFIG_FILE = CONFIG_DIR / "config.json"
TOOLS_DIR = CONFIG_DIR / "tools"
APKTOOL_JAR = TOOLS_DIR / "apktool.jar"
KEYS_DIR = CONFIG_DIR / "keys"
DEFAULT_KEYSTORE = KEYS_DIR / "android-smali-gui.keystore"
DEFAULT_KEY_ALIAS = "android_smali_gui"
GITHUB_LATEST = "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest"

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

APKTOOL_BUILD_TIMEOUT = 3600  # hard safety ceiling; live output is streamed
APKTOOL_JOBS = min(8, max(1, os.cpu_count() or 4))
SMART_BUILD_STATE_VERSION = 2
KEYRING_SERVICE = "Android Smali GUI"


@dataclass
class Device:
    serial: str
    state: str
    description: str


@dataclass
class PackageItem:
    package: str
    kind: str  # user/system


class ToolError(RuntimeError):
    pass


class InstallSignatureConflict(ToolError):
    """Raised when Android refuses an in-place update because signatures differ."""



def run_process(args: list[str], *, timeout: int | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        cp = subprocess.run(
            args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except FileNotFoundError as exc:
        raise ToolError(f"Tool not found: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"Command timed out: {' '.join(args)}") from exc

    if check and cp.returncode != 0:
        msg = cp.stderr.strip() or cp.stdout.strip() or f"exit code {cp.returncode}"
        raise ToolError(msg)
    return cp


def sanitize_filename(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return value[:180] or "package"


def safe_rmtree(path: Path, allowed_parent: Path, *, ignore_errors: bool = False) -> None:
    """Remove a directory only when it is a strict descendant of allowed_parent."""
    target = path.expanduser().resolve(strict=False)
    parent = allowed_parent.expanduser().resolve(strict=False)
    if target == parent or parent not in target.parents:
        raise ToolError(f"Refusing unsafe directory removal: {target}")
    shutil.rmtree(target, ignore_errors=ignore_errors)


def find_adb(configured: str = "") -> str | None:
    candidates: list[str] = []
    if configured:
        candidates.append(configured)
    path_adb = shutil.which("adb")
    if path_adb:
        candidates.append(path_adb)

    home = Path.home()
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            candidates.append(str(Path(local) / "Android" / "Sdk" / "platform-tools" / "adb.exe"))
        candidates.extend([
            str(home / "AppData" / "Local" / "Android" / "Sdk" / "platform-tools" / "adb.exe"),
            r"C:\Android\platform-tools\adb.exe",
        ])
    else:
        sdk = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
        if sdk:
            candidates.append(str(Path(sdk) / "platform-tools" / "adb"))
        candidates.extend([
            str(home / "Android" / "Sdk" / "platform-tools" / "adb"),
            "/usr/local/bin/adb",
            "/opt/homebrew/bin/adb",
        ])

    seen = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        p = Path(candidate).expanduser()
        if p.is_file():
            return str(p)
    return None


def find_java() -> str | None:
    java = shutil.which("java")
    if java:
        return java
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        exe = "java.exe" if os.name == "nt" else "java"
        p = Path(java_home) / "bin" / exe
        if p.is_file():
            return str(p)
    return None


def find_keytool() -> str | None:
    keytool = shutil.which("keytool")
    if keytool:
        return keytool

    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        exe = "keytool.exe" if os.name == "nt" else "keytool"
        p = Path(java_home) / "bin" / exe
        if p.is_file():
            return str(p)

    java = find_java()
    if java:
        p = Path(java).with_name("keytool.exe" if os.name == "nt" else "keytool")
        if p.is_file():
            return str(p)

    return None


def _version_key(value: str) -> tuple:
    parts = re.split(r"([0-9]+)", value)
    return tuple(int(p) if p.isdigit() else p.lower() for p in parts)


def android_sdk_roots() -> list[Path]:
    candidates: list[Path] = []

    for env_name in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        value = os.environ.get(env_name)
        if value:
            candidates.append(Path(value))

    home = Path.home()
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            candidates.append(Path(local) / "Android" / "Sdk")
        candidates.append(home / "AppData" / "Local" / "Android" / "Sdk")
    else:
        candidates.extend([
            home / "Android" / "Sdk",
            home / "Library" / "Android" / "sdk",
            Path("/opt/android-sdk"),
            Path("/usr/local/android-sdk"),
        ])

    result: list[Path] = []
    seen: set[str] = set()

    for root in candidates:
        root = root.expanduser()
        key = str(root).lower()
        if key in seen:
            continue
        seen.add(key)
        if root.is_dir():
            result.append(root)

    return result


def find_android_build_tool(name: str) -> str | None:
    direct = shutil.which(name)
    if direct:
        return direct

    if os.name == "nt":
        filenames = {
            "apksigner": ["apksigner.bat", "apksigner.cmd", "apksigner.exe"],
            "zipalign": ["zipalign.exe", "zipalign"],
        }.get(name, [name + ".exe", name + ".bat", name + ".cmd", name])
    else:
        filenames = [name]

    for sdk_root in android_sdk_roots():
        build_tools = sdk_root / "build-tools"
        if not build_tools.is_dir():
            continue

        versions = sorted(
            (p for p in build_tools.iterdir() if p.is_dir()),
            key=lambda p: _version_key(p.name),
            reverse=True,
        )

        for version_dir in versions:
            for filename in filenames:
                candidate = version_dir / filename
                if candidate.is_file():
                    return str(candidate)

    return None


def executable_command(path: str) -> list[str]:
    suffix = Path(path).suffix.lower()
    if os.name == "nt" and suffix in {".bat", ".cmd"}:
        return ["cmd.exe", "/d", "/s", "/c", path]
    return [path]


def load_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(config: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(config, indent=2), encoding="utf-8")
    try:
        if os.name != "nt":
            os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(CONFIG_FILE)


class AndroidSmaliGui:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1050x700")
        self.root.minsize(850, 560)

        self.config = load_config()
        # Migrate legacy plaintext signing passwords into the OS credential store
        # the next time signing is used, then remove them from config.json.
        self._legacy_signing_password = str(self.config.pop("signing_password", "")).strip()
        if self._legacy_signing_password:
            save_config(self.config)
        self.adb_path = StringVar(value=find_adb(self.config.get("adb_path", "")) or "")
        self.device_serial = StringVar()
        self.search_var = StringVar()
        self.show_user = BooleanVar(value=True)
        self.show_system = BooleanVar(value=False)
        self.status_var = StringVar(value="Ready")
        self.heartbeat_var = StringVar(value="Idle")
        self.progress_var = DoubleVar(value=0.0)
        self.output_dir = StringVar(value=self.config.get("output_dir", str(Path.home() / "Desktop" / "decompiled_android_apps")))
        self.install_after_rebuild = BooleanVar(value=bool(self.config.get("install_after_rebuild", False)))
        self.remember_signing_key = BooleanVar(value=bool(self.config.get("remember_signing_key", True)))
        self.install_after_rebuild_enabled = bool(self.install_after_rebuild.get())
        self.remember_signing_key_enabled = bool(self.remember_signing_key.get())

        self.devices: list[Device] = []
        self.packages: list[PackageItem] = []
        self.package_rows: dict[str, str] = {}
        self.worker_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.busy = False
        self.operation_started_at: float | None = None
        self.last_activity_at: float | None = None
        self.pending_installs: list[tuple[str, list[str]]] = []
        self._session_signing_password: str | None = None
        self._session_signing_keystore: Path | None = None

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._poll_queue)
        self.root.after(1000, self._update_heartbeat)
        self.root.after(250, self.refresh_devices)

    def _on_close(self) -> None:
        if self._session_signing_keystore is not None:
            try:
                self._session_signing_keystore.unlink(missing_ok=True)
                parent = self._session_signing_keystore.parent
                if parent.is_dir() and not any(parent.iterdir()):
                    parent.rmdir()
            except OSError:
                pass
        self._session_signing_password = None
        self.root.destroy()

    def _build_ui(self) -> None:
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=X)

        ttk.Label(top, text="ADB:").pack(side=LEFT)
        self.adb_entry = ttk.Entry(top, textvariable=self.adb_path)
        self.adb_entry.pack(side=LEFT, fill=X, expand=True, padx=(6, 6))
        ttk.Button(top, text="Browse", command=self.choose_adb).pack(side=LEFT)
        ttk.Button(top, text="Refresh devices", command=self.refresh_devices).pack(side=LEFT, padx=(6, 0))

        device_frame = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        device_frame.pack(fill=X)
        ttk.Label(device_frame, text="Device:").pack(side=LEFT)
        self.device_combo = ttk.Combobox(device_frame, textvariable=self.device_serial, state="readonly", width=55)
        self.device_combo.pack(side=LEFT, padx=(6, 6))
        self.device_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh_packages())
        ttk.Button(device_frame, text="Load apps", command=self.refresh_packages).pack(side=LEFT)
        ttk.Button(device_frame, text="Install/Update Apktool", command=self.install_apktool).pack(side=RIGHT)

        filters = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        filters.pack(fill=X)
        ttk.Label(filters, text="Filter:").pack(side=LEFT)
        search_entry = ttk.Entry(filters, textvariable=self.search_var)
        search_entry.pack(side=LEFT, fill=X, expand=True, padx=(6, 10))
        search_entry.bind("<KeyRelease>", lambda _e: self.apply_filter())
        ttk.Checkbutton(filters, text="User apps", variable=self.show_user, command=self.refresh_packages).pack(side=LEFT)
        ttk.Checkbutton(filters, text="System apps", variable=self.show_system, command=self.refresh_packages).pack(side=LEFT, padx=(6, 0))

        options = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        options.pack(fill=X)
        ttk.Checkbutton(
            options,
            text="Install to device after rebuild",
            variable=self.install_after_rebuild,
            command=self._save_preferences,
        ).pack(side=LEFT)
        ttk.Checkbutton(
            options,
            text="Reuse persistent signing key",
            variable=self.remember_signing_key,
            command=self._save_preferences,
        ).pack(side=LEFT, padx=(12, 0))

        body = ttk.Panedwindow(self.root, orient="vertical")
        body.pack(fill=BOTH, expand=True, padx=10)

        list_frame = ttk.Frame(body)
        body.add(list_frame, weight=4)
        columns = ("package", "kind")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="extended")
        self.tree.heading("package", text="Package / App ID")
        self.tree.heading("kind", text="Type")
        self.tree.column("package", width=760, anchor="w")
        self.tree.column("kind", width=100, anchor="center")
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        scroll.pack(side=RIGHT, fill=Y)
        self.tree.bind("<Double-1>", lambda _e: self.decompile_selected())

        log_frame = ttk.Frame(body)
        body.add(log_frame, weight=2)
        self.log = __import__("tkinter").Text(log_frame, height=10, wrap="word")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=log_scroll.set)
        self.log.pack(side=LEFT, fill=BOTH, expand=True)
        log_scroll.pack(side=RIGHT, fill=Y)

        bottom = ttk.Frame(self.root, padding=10)
        bottom.pack(fill=X)
        ttk.Label(bottom, text="Output:").pack(side=LEFT)
        ttk.Entry(bottom, textvariable=self.output_dir).pack(side=LEFT, fill=X, expand=True, padx=(6, 6))
        ttk.Button(bottom, text="Browse", command=self.choose_output).pack(side=LEFT)
        ttk.Button(bottom, text="Open output", command=self.open_output).pack(side=LEFT, padx=(6, 0))
        self.decompile_btn = ttk.Button(bottom, text="Decompile selected", command=self.decompile_selected)
        self.decompile_btn.pack(side=RIGHT, padx=(10, 0))
        self.recompile_btn = ttk.Button(bottom, text="Recompile selected", command=self.recompile_selected)
        self.recompile_btn.pack(side=RIGHT, padx=(10, 0))
        self.recompile_folder_btn = ttk.Button(
            bottom,
            text="Recompile folder…",
            command=self.recompile_folder,
        )
        self.recompile_folder_btn.pack(side=RIGHT, padx=(10, 0))

        status = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        status.pack(fill=X)
        self.progress = ttk.Progressbar(status, mode="determinate", maximum=100, variable=self.progress_var, length=220)
        self.progress.pack(side=RIGHT)
        ttk.Label(status, textvariable=self.status_var).pack(side=LEFT)
        ttk.Label(status, textvariable=self.heartbeat_var).pack(side=RIGHT, padx=(0, 12))

    def write_log(self, text: str) -> None:
        self.log.insert(END, text.rstrip() + "\n")
        self.log.see(END)

    def _save_preferences(self) -> None:
        self.install_after_rebuild_enabled = bool(self.install_after_rebuild.get())
        self.remember_signing_key_enabled = bool(self.remember_signing_key.get())
        self.config["install_after_rebuild"] = self.install_after_rebuild_enabled
        self.config["remember_signing_key"] = self.remember_signing_key_enabled
        save_config(self.config)

    def _report_progress(self, current: int, total: int, status: str) -> None:
        percent = 0.0 if total <= 0 else max(0.0, min(100.0, current * 100.0 / total))
        self.worker_queue.put(("progress", (percent, status)))

    def _update_heartbeat(self) -> None:
        if self.busy and self.operation_started_at is not None:
            now = time.monotonic()
            elapsed = int(now - self.operation_started_at)
            since_activity = int(now - (self.last_activity_at or self.operation_started_at))
            mm, ss = divmod(elapsed, 60)
            heartbeat = f"{mm:02d}:{ss:02d} elapsed"
            if since_activity >= 5:
                heartbeat += f" · working ({since_activity}s since output)"
            self.heartbeat_var.set(heartbeat)
        else:
            self.heartbeat_var.set("Idle")
        self.root.after(1000, self._update_heartbeat)

    def set_busy(self, busy: bool, status: str = "") -> None:
        self.busy = busy
        if status:
            self.status_var.set(status)
        if busy:
            self.operation_started_at = time.monotonic()
            self.last_activity_at = self.operation_started_at
            self.progress_var.set(0.0)
            self.decompile_btn.configure(state="disabled")
            self.recompile_btn.configure(state="disabled")
            self.recompile_folder_btn.configure(state="disabled")
        else:
            self.progress_var.set(100.0 if self.progress_var.get() > 0 else 0.0)
            self.operation_started_at = None
            self.last_activity_at = None
            self.decompile_btn.configure(state="normal")
            self.recompile_btn.configure(state="normal")
            self.recompile_folder_btn.configure(state="normal")

    def choose_adb(self) -> None:
        filename = filedialog.askopenfilename(title="Select adb executable")
        if filename:
            self.adb_path.set(filename)
            self.config["adb_path"] = filename
            save_config(self.config)
            self.refresh_devices()

    def choose_output(self) -> None:
        folder = filedialog.askdirectory(title="Choose output folder")
        if folder:
            self.output_dir.set(folder)
            self.config["output_dir"] = folder
            save_config(self.config)

    def open_output(self) -> None:
        p = Path(self.output_dir.get()).expanduser()
        p.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(p)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(p)])
        else:
            subprocess.Popen(["xdg-open", str(p)])

    def _adb(self) -> str:
        adb = self.adb_path.get().strip()
        if not adb:
            adb = find_adb("") or ""
            if adb:
                self.adb_path.set(adb)
        if not adb or not Path(adb).is_file():
            raise ToolError("ADB was not found. Install Android Platform Tools or choose adb manually.")
        return adb

    def _selected_serial(self) -> str:
        raw = self.device_serial.get().strip()
        if not raw:
            raise ToolError("No Android device is selected.")

        # The combobox displays a descriptive row, but adb -s requires only
        # the actual serial. Prefer the selected Device object when possible.
        try:
            index = self.device_combo.current()
            if 0 <= index < len(self.devices):
                serial = self.devices[index].serial.strip()
                if serial:
                    return serial
        except Exception:
            pass

        # Fallback for a display value such as:
        # 57221FDCQS023A  [device]  Pixel_10_Pro_XL / mustang
        serial = raw.split()[0]
        if not serial:
            raise ToolError("No Android device is selected.")
        return serial

    def refresh_devices(self) -> None:
        if self.busy:
            return
        try:
            adb = self._adb()
        except ToolError as exc:
            self.status_var.set(str(exc))
            return

        self.set_busy(True, "Detecting devices…")

        def task() -> None:
            try:
                run_process([adb, "start-server"], timeout=15)
                cp = run_process([adb, "devices", "-l"], timeout=15)
                devices: list[Device] = []
                for line in cp.stdout.splitlines()[1:]:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    serial = parts[0]
                    state = parts[1] if len(parts) > 1 else "unknown"
                    fields = {}
                    for part in parts[2:]:
                        if ":" in part:
                            k, v = part.split(":", 1)
                            fields[k] = v
                    desc_parts = [fields.get("model", ""), fields.get("device", "")]
                    desc = " / ".join(x for x in desc_parts if x) or state
                    devices.append(Device(serial, state, desc))
                self.worker_queue.put(("devices", devices))
            except Exception as exc:
                self.worker_queue.put(("error", exc))

        threading.Thread(target=task, daemon=True).start()

    def refresh_packages(self) -> None:
        if self.busy:
            return
        try:
            adb = self._adb()
            serial = self._selected_serial()
        except ToolError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return

        args: list[tuple[str, str]] = []
        if self.show_user.get():
            args.append(("user", "-3"))
        if self.show_system.get():
            args.append(("system", "-s"))
        if not args:
            self.packages = []
            self.apply_filter()
            return

        self.set_busy(True, "Loading installed apps…")

        def task() -> None:
            try:
                items: dict[str, PackageItem] = {}
                for kind, flag in args:
                    cp = run_process([adb, "-s", serial, "shell", "pm", "list", "packages", flag], timeout=60)
                    for line in cp.stdout.splitlines():
                        if line.startswith("package:"):
                            pkg = line[len("package:"):].strip()
                            if pkg:
                                items[pkg] = PackageItem(pkg, kind)
                self.worker_queue.put(("packages", sorted(items.values(), key=lambda x: x.package.lower())))
            except Exception as exc:
                self.worker_queue.put(("error", exc))

        threading.Thread(target=task, daemon=True).start()

    def apply_filter(self) -> None:
        query = self.search_var.get().strip().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.package_rows.clear()
        for item in self.packages:
            if query and query not in item.package.lower():
                continue
            iid = self.tree.insert("", END, values=(item.package, item.kind))
            self.package_rows[iid] = item.package
        self.status_var.set(f"{len(self.tree.get_children())} apps shown")

    def install_apktool(self) -> None:
        if self.busy:
            return
        if not find_java():
            messagebox.showerror(APP_NAME, "Java was not found. Install a current Java runtime/JDK first, then try again.")
            return

        self.set_busy(True, "Downloading latest Apktool…")
        self.write_log("Checking the official Apktool GitHub release…")

        def task() -> None:
            try:
                req = urllib.request.Request(GITHUB_LATEST, headers={"User-Agent": "Android-Smali-GUI"})
                with urllib.request.urlopen(req, timeout=30) as response:
                    release = json.load(response)
                assets = release.get("assets", [])
                jar_asset = next((a for a in assets if re.fullmatch(r"apktool_.*\.jar", a.get("name", ""))), None)
                if not jar_asset:
                    raise ToolError("Could not find the Apktool jar in the latest release.")
                url = str(jar_asset["browser_download_url"])
                if not url.startswith("https://github.com/iBotPeaches/Apktool/releases/download/"):
                    raise ToolError(f"Refusing unexpected Apktool download URL: {url}")
                TOOLS_DIR.mkdir(parents=True, exist_ok=True)
                tmp = APKTOOL_JAR.with_suffix(".jar.part")
                urllib.request.urlretrieve(url, tmp)
                digest = hashlib.sha256(tmp.read_bytes()).hexdigest()
                self.worker_queue.put(("log", f"Downloaded Apktool SHA-256: {digest}"))
                tmp.replace(APKTOOL_JAR)
                self.worker_queue.put(("apktool_installed", (release.get("tag_name", "latest"), str(APKTOOL_JAR))))
            except Exception as exc:
                self.worker_queue.put(("error", exc))

        threading.Thread(target=task, daemon=True).start()

    def _apktool_command(self) -> list[str]:
        path_cmd = shutil.which("apktool")
        if path_cmd:
            return [path_cmd]
        if APKTOOL_JAR.is_file():
            java = find_java()
            if not java:
                raise ToolError("Apktool is installed, but Java was not found.")
            return [java, "-jar", str(APKTOOL_JAR)]
        raise ToolError("Apktool is not installed. Click ‘Install/Update Apktool’ first, or put apktool on PATH.")

    def decompile_selected(self) -> None:
        if self.busy:
            return
        selections = self.tree.selection()
        if not selections:
            messagebox.showinfo(APP_NAME, "Select one or more apps first.")
            return
        packages = [self.package_rows[iid] for iid in selections if iid in self.package_rows]
        if not packages:
            return

        try:
            adb = self._adb()
            serial = self._selected_serial()
            apktool = self._apktool_command()
        except ToolError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return

        output_root = Path(self.output_dir.get()).expanduser()
        output_root.mkdir(parents=True, exist_ok=True)
        self.config["adb_path"] = adb
        self.config["output_dir"] = str(output_root)
        save_config(self.config)

        self.set_busy(True, f"Decompiling {len(packages)} app(s)…")
        self.write_log(f"Device: {serial}")
        self.write_log(f"Selected: {', '.join(packages)}")

        def task() -> None:
            failures: list[tuple[str, str]] = []
            completed: list[str] = []
            for index, pkg in enumerate(packages, start=1):
                try:
                    self._report_progress(index - 1, len(packages), f"Decompiling {index}/{len(packages)}: {pkg}")
                    self.worker_queue.put(("log", f"\n=== {pkg} ==="))
                    result_dir = self._decompile_package(adb, serial, apktool, pkg, output_root)
                    completed.append(str(result_dir))
                except Exception as exc:
                    failures.append((pkg, str(exc)))
                    self.worker_queue.put(("log", f"FAILED: {pkg}: {exc}"))
            self._report_progress(len(packages), len(packages), "Decompile complete")
            self.worker_queue.put(("decompile_done", (completed, failures)))

        threading.Thread(target=task, daemon=True).start()

    def _decompile_package(self, adb: str, serial: str, apktool: list[str], package: str, output_root: Path) -> Path:
        cp = run_process([adb, "-s", serial, "shell", "pm", "path", package], timeout=30)
        remote_paths = []
        for line in cp.stdout.splitlines():
            if line.startswith("package:"):
                remote_paths.append(line[len("package:"):].strip())
        if not remote_paths:
            raise ToolError("Android did not return an APK path for this package.")

        package_dir = output_root / sanitize_filename(package)
        apk_dir = package_dir / "apks"
        decoded_root = package_dir / "decoded"
        apk_dir.mkdir(parents=True, exist_ok=True)
        decoded_root.mkdir(parents=True, exist_ok=True)

        manifest = {
            "package": package,
            "device_serial": serial,
            "remote_apks": remote_paths,
            "apk_entries": [],
            "note": "Split APKs are decoded into separate folders. base.apk normally contains the app's main classes/resources.",
        }

        for index, remote in enumerate(remote_paths):
            remote_name = Path(remote).name or f"split_{index}.apk"
            local_name = remote_name
            if (apk_dir / local_name).exists() and len(remote_paths) > 1:
                local_name = f"{index:02d}_{remote_name}"
            local_apk = apk_dir / local_name
            self.worker_queue.put(("log", f"Pulling {remote} -> {local_apk.name}"))
            pull = run_process([adb, "-s", serial, "pull", remote, str(local_apk)], timeout=180)
            if pull.stdout.strip():
                self.worker_queue.put(("log", pull.stdout.strip()))

            decoded_name = sanitize_filename(Path(local_name).stem)
            decoded_dir = decoded_root / decoded_name
            if decoded_dir.exists():
                safe_rmtree(decoded_dir, decoded_root)

            manifest["apk_entries"].append({
                "remote_path": remote,
                "local_apk": local_name,
                "decoded_dir": decoded_name,
            })

            cmd = apktool + ["d", "-f", "-o", str(decoded_dir), str(local_apk)]
            self.worker_queue.put(("log", f"Decoding {local_apk.name}…"))
            decoded = run_process(cmd, timeout=600)
            if decoded.stdout.strip():
                self.worker_queue.put(("log", decoded.stdout.strip()))
            if decoded.stderr.strip():
                self.worker_queue.put(("log", decoded.stderr.strip()))

        (package_dir / "pull_manifest.json").write_text(
            json.dumps(manifest, indent=2),
            encoding="utf-8",
        )
        return package_dir

    def recompile_folder(self) -> None:
        """Rebuild an arbitrary existing Apktool project or split-package folder."""
        if self.busy:
            return

        folder = filedialog.askdirectory(
            title="Choose decoded APK / package folder to recompile"
        )
        if not folder:
            return

        project_root = Path(folder)

        try:
            apktool = self._apktool_command()
            projects = self._discover_apktool_projects(project_root)
        except ToolError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return

        package_name = self._infer_package_name(project_root, projects)
        self.set_busy(True, f"Recompiling {len(projects)} APK split(s)…")
        self.write_log("\n=== Recompile folder ===")
        self.write_log(f"Project: {project_root}")
        self.write_log(
            "Detected project(s): "
            + ", ".join(decoded.name for decoded, _apk_name in projects)
        )
        self.write_log(
            f"Smart build enabled: {APKTOOL_JOBS} Apktool job(s); "
            "validated unchanged outputs are reused; trusted changed builds "
            "compile incrementally with automatic clean fallback."
        )

        def task() -> None:
            try:
                outputs = self._recompile_project_folder(
                    apktool,
                    project_root,
                    projects,
                )
                self.worker_queue.put(("recompile_folder_done", [str(p) for p in outputs]))
                if self.install_after_rebuild_enabled:
                    if package_name:
                        self.worker_queue.put(("install_ready", (package_name, [str(p) for p in outputs])))
                    else:
                        self.worker_queue.put(("log", "Auto-install skipped: package name could not be inferred from the decoded project."))
            except Exception as exc:
                self.worker_queue.put(("error", exc))

        threading.Thread(target=task, daemon=True).start()

    @staticmethod
    def _is_apktool_project(path: Path) -> bool:
        return (
            path.is_dir()
            and (path / "apktool.yml").is_file()
            and (path / "AndroidManifest.xml").exists()
        )

    def _discover_apktool_projects(
        self,
        selected_root: Path,
    ) -> list[tuple[Path, str]]:
        """Detect one decoded APK or every split under a package directory."""
        selected_root = selected_root.expanduser().resolve()

        if not selected_root.is_dir():
            raise ToolError(f"Folder does not exist: {selected_root}")

        # Directly selecting a decoded split/base project is supported.
        if self._is_apktool_project(selected_root):
            return [(selected_root, selected_root.name + ".apk")]

        # Use the GUI's manifest mapping when available, so names such as
        # split_config.arm64_v8a.apk are preserved exactly.
        manifest_entries: dict[str, str] = {}
        manifest_file = selected_root / "pull_manifest.json"
        if manifest_file.is_file():
            try:
                manifest = json.loads(
                    manifest_file.read_text(encoding="utf-8")
                )
                for item in manifest.get("apk_entries", []):
                    decoded_name = str(item.get("decoded_dir", "")).strip()
                    apk_name = str(item.get("local_apk", "")).strip()
                    if decoded_name and apk_name:
                        manifest_entries[decoded_name] = Path(apk_name).name
            except Exception as exc:
                self.write_log(
                    f"Warning: could not read pull_manifest.json: {exc}"
                )

        # Typical GUI layout:
        #   com.package/
        #       decoded/base/
        #       decoded/split_config.arm64_v8a/
        #
        # Also support:
        #   com.package/base/
        #   com.package/split_config.arm64_v8a/
        decoded_root = selected_root / "decoded"
        search_root = decoded_root if decoded_root.is_dir() else selected_root

        candidates = [
            p
            for p in sorted(search_root.iterdir(), key=lambda p: p.name.lower())
            if self._is_apktool_project(p)
        ]

        # Support one extra nesting level if a project was copied into a
        # wrapper directory.
        if not candidates:
            for child in sorted(
                (p for p in search_root.iterdir() if p.is_dir()),
                key=lambda p: p.name.lower(),
            ):
                candidates.extend(
                    p
                    for p in sorted(
                        child.iterdir(),
                        key=lambda p: p.name.lower(),
                    )
                    if self._is_apktool_project(p)
                )

        if not candidates:
            raise ToolError(
                "No decoded Apktool projects were found.\n\n"
                "Select either a decoded folder containing apktool.yml, "
                "or a package folder containing decoded/base and any "
                "decoded split folders."
            )

        projects: list[tuple[Path, str]] = []
        used_names: set[str] = set()

        for decoded_dir in candidates:
            output_name = manifest_entries.get(
                decoded_dir.name,
                decoded_dir.name + ".apk",
            )
            output_name = Path(output_name).name
            if not output_name.lower().endswith(".apk"):
                output_name += ".apk"

            # Protect against accidental filename collisions.
            candidate_name = output_name
            number = 2
            while candidate_name.lower() in used_names:
                stem = Path(output_name).stem
                candidate_name = f"{stem}_{number}.apk"
                number += 1

            used_names.add(candidate_name.lower())
            projects.append((decoded_dir, candidate_name))

        return projects

    @staticmethod
    def _looks_like_dex_reference_overflow(message: str) -> bool:
        lowered = message.lower()
        return (
            "unsigned short value out of range: 65536" in lowered
            or "too many field references" in lowered
            or "too many method references" in lowered
            or "too many type references" in lowered
        )

    @staticmethod
    def _validate_dex_bytes(data: bytes, name: str) -> None:
        """Validate the standard DEX header plus its embedded hashes."""
        if len(data) < 0x70:
            raise ToolError(
                f"{name} is truncated: {len(data)} bytes (minimum DEX header is 112)."
            )

        if not (
            data[:4] == b"dex\n"
            and data[4:7].isdigit()
            and data[7] == 0
        ):
            raise ToolError(
                f"{name} has invalid DEX magic: {data[:8]!r}"
            )

        file_size = struct.unpack_from("<I", data, 0x20)[0]
        header_size = struct.unpack_from("<I", data, 0x24)[0]
        endian_tag = struct.unpack_from("<I", data, 0x28)[0]

        if file_size != len(data):
            raise ToolError(
                f"{name} DEX header file_size={file_size}, "
                f"but ZIP entry contains {len(data)} bytes."
            )
        if header_size != 0x70:
            raise ToolError(
                f"{name} has unexpected DEX header_size 0x{header_size:x}."
            )
        if endian_tag not in (0x12345678, 0x78563412):
            raise ToolError(
                f"{name} has invalid DEX endian tag 0x{endian_tag:08x}."
            )

        expected_sha1 = data[12:32]
        actual_sha1 = hashlib.sha1(data[32:]).digest()
        if expected_sha1 != actual_sha1:
            raise ToolError(
                f"{name} has an invalid DEX SHA-1 signature."
            )

        expected_adler = struct.unpack_from("<I", data, 8)[0]
        actual_adler = zlib.adler32(data[12:]) & 0xFFFFFFFF
        if expected_adler != actual_adler:
            raise ToolError(
                f"{name} has an invalid DEX Adler-32 checksum."
            )

    def _validate_apk_dex(
        self,
        apk: Path,
        *,
        require_dex: bool,
    ) -> dict[str, str]:
        """Validate all classes*.dex entries and return their SHA-256 hashes."""
        if not apk.is_file():
            raise ToolError(f"APK does not exist: {apk}")

        try:
            with zipfile.ZipFile(apk, "r") as archive:
                dex_names = sorted(
                    (
                        name
                        for name in archive.namelist()
                        if re.fullmatch(r"classes\d*\.dex", name)
                    ),
                    key=lambda name: (
                        1 if name == "classes.dex" else int(name[7:-4]),
                        name,
                    ),
                )

                if require_dex and not dex_names:
                    raise ToolError(
                        f"{apk.name} contains no classes*.dex entries."
                    )

                hashes: dict[str, str] = {}
                for dex_name in dex_names:
                    data = archive.read(dex_name)
                    self._validate_dex_bytes(
                        data,
                        f"{apk.name}!{dex_name}",
                    )
                    hashes[dex_name] = hashlib.sha256(data).hexdigest()

                return hashes
        except zipfile.BadZipFile as exc:
            raise ToolError(f"Invalid APK/ZIP: {apk}") from exc

    @staticmethod
    def _compare_dex_hashes(
        before: dict[str, str],
        after: dict[str, str],
        label: str,
    ) -> None:
        if before != after:
            raise ToolError(
                f"DEX contents changed unexpectedly during {label}.\n"
                f"Before: {before}\nAfter: {after}"
            )

    def _run_logged_process(
        self,
        args: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run a long command while streaming its combined output into the GUI."""
        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                args,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                creationflags=CREATE_NO_WINDOW,
            )
        except FileNotFoundError as exc:
            raise ToolError(f"Tool not found: {args[0]}") from exc

        output_lines: list[str] = []
        line_queue: queue.Queue[object] = queue.Queue()
        sentinel = object()

        def reader() -> None:
            try:
                assert proc.stdout is not None
                for raw_line in proc.stdout:
                    line_queue.put(raw_line.rstrip("\r\n"))
            finally:
                line_queue.put(sentinel)

        threading.Thread(target=reader, daemon=True).start()
        reader_done = False
        try:
            while True:
                if timeout is not None and time.monotonic() - start > timeout:
                    proc.kill()
                    proc.wait(timeout=10)
                    raise ToolError(
                        f"Command timed out after {timeout}s: {' '.join(args)}"
                    )
                try:
                    item = line_queue.get(timeout=0.20)
                    if item is sentinel:
                        reader_done = True
                    else:
                        line = str(item)
                        output_lines.append(line)
                        if line:
                            self.worker_queue.put(("log", line))
                except queue.Empty:
                    pass
                if reader_done and proc.poll() is not None:
                    break
            return_code = proc.wait()
        finally:
            if proc.poll() is None:
                proc.kill()

        output = "\n".join(output_lines)
        if return_code != 0:
            raise ToolError(output.strip() or f"exit code {return_code}")
        elapsed = time.monotonic() - start
        self.worker_queue.put(("log", f"Command completed in {elapsed:.1f}s."))
        return subprocess.CompletedProcess(args, return_code, output, "")

    @staticmethod
    def _meaningful_source_roots(decoded_dir: Path) -> list[Path]:
        roots: list[Path] = []
        for child in decoded_dir.iterdir():
            if child.is_dir() and (
                child.name == "smali"
                or re.fullmatch(r"smali_classes\d+", child.name)
                or child.name in {"res", "assets", "lib", "unknown"}
            ):
                roots.append(child)
        for filename in ("AndroidManifest.xml", "apktool.yml"):
            candidate = decoded_dir / filename
            if candidate.is_file():
                roots.append(candidate)
        return sorted(roots, key=lambda p: p.name.lower())

    @staticmethod
    def _windows_extended_path(path: Path) -> str:
        """Return a Windows extended-length path when needed.

        Windows' traditional MAX_PATH boundary is 260 characters. Decompiled
        Android packages frequently exceed that because Java package/class
        names become deeply nested filesystem paths.
        """
        value = str(path.resolve())

        if os.name != "nt":
            return value

        if value.startswith("\\\\?\\"):
            return value

        if value.startswith("\\\\"):
            # UNC path: \\server\share\... -> \\?\UNC\server\share\...
            return "\\\\?\\UNC\\" + value[2:]

        return "\\\\?\\" + value

    def _source_fingerprint(self, decoded_dir: Path) -> str:
        """Fast metadata fingerprint for smart rebuild decisions.

        Uses extended-length Windows paths so deeply nested smali class names
        do not trip the legacy 260-character MAX_PATH boundary.
        """
        digest = hashlib.sha256()

        def add_file(path: Path) -> None:
            rel = path.relative_to(decoded_dir).as_posix()

            try:
                # Path.stat() can fail exactly at/above MAX_PATH on Windows
                # depending on the Python/OS long-path configuration.
                stat = os.stat(self._windows_extended_path(path))
            except FileNotFoundError:
                # A file can disappear between os.walk() enumeration and stat
                # if another process is editing the tree. Include a marker so
                # the fingerprint remains conservative rather than crashing.
                digest.update(rel.encode("utf-8", errors="surrogatepass"))
                digest.update(b"\0MISSING\n")
                return
            except OSError as exc:
                raise ToolError(
                    f"Could not fingerprint source file:\n{path}\n\n{exc}"
                ) from exc

            digest.update(rel.encode("utf-8", errors="surrogatepass"))
            digest.update(b"\0")
            digest.update(str(stat.st_size).encode("ascii"))
            digest.update(b"\0")
            digest.update(str(stat.st_mtime_ns).encode("ascii"))
            digest.update(b"\n")

        for root in self._meaningful_source_roots(decoded_dir):
            if root.is_file():
                add_file(root)
                continue

            # os.walk can enumerate directories whose child file path exceeds
            # MAX_PATH; add_file() handles the final long path using \\?\.
            for current, dirs, files in os.walk(root):
                dirs.sort()
                files.sort()
                current_path = Path(current)

                for filename in files:
                    add_file(current_path / filename)

        return digest.hexdigest()

    @staticmethod
    def _smart_state_path(decoded_dir: Path, output_apk: Path) -> Path:
        state_root = output_apk.parent.parent / "build_state"
        state_root.mkdir(parents=True, exist_ok=True)
        return state_root / f"{sanitize_filename(decoded_dir.name)}.json"

    @staticmethod
    def _load_smart_state(path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _save_smart_state(path: Path, state: dict) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        tmp.replace(path)

    def _validate_build_cache_dex(self, decoded_dir: Path) -> bool:
        build_apk = decoded_dir / "build" / "apk"
        if not build_apk.is_dir():
            return True
        for dex_file in sorted(build_apk.glob("classes*.dex")):
            try:
                self._validate_dex_bytes(dex_file.read_bytes(), str(dex_file))
            except Exception as exc:
                self.worker_queue.put(("log", f"Cached DEX is invalid and will not be reused: {dex_file.name}: {exc}"))
                return False
        return True

    @staticmethod
    def _clean_apktool_build_cache(decoded_dir: Path) -> None:
        build_dir = decoded_dir / "build"
        if build_dir.exists():
            safe_rmtree(build_dir, decoded_dir, ignore_errors=True)

    def _build_apktool_project_smart(
        self,
        apktool: list[str],
        decoded_dir: Path,
        output_apk: Path,
    ) -> subprocess.CompletedProcess[str]:
        """Build with validated reuse, incremental builds, and a clean fallback."""
        state_path = self._smart_state_path(decoded_dir, output_apk)
        fingerprint = self._source_fingerprint(decoded_dir)
        state = self._load_smart_state(state_path)

        if (
            state.get("version") == SMART_BUILD_STATE_VERSION
            and state.get("fingerprint") == fingerprint
            and output_apk.is_file()
        ):
            try:
                current_hashes = self._validate_apk_dex(output_apk, require_dex=True)
                if current_hashes == state.get("dex_hashes"):
                    self.worker_queue.put(("log", f"Reusing validated unchanged build: {output_apk.name}"))
                    return subprocess.CompletedProcess(["reuse", str(output_apk)], 0, "Reused validated build", "")
            except Exception as exc:
                self.worker_queue.put(("log", f"Previous output cannot be reused: {exc}"))

        cache_is_healthy = self._validate_build_cache_dex(decoded_dir)
        trusted_baseline = state.get("version") == SMART_BUILD_STATE_VERSION and bool(state.get("validated"))
        use_incremental = trusted_baseline and cache_is_healthy

        def command(force: bool) -> list[str]:
            cmd = apktool + ["b"]
            if force:
                cmd.append("-f")
            cmd += ["-j", str(APKTOOL_JOBS), str(decoded_dir), "-o", str(output_apk)]
            return cmd

        def run_attempt(*, force: bool, reason: str) -> subprocess.CompletedProcess[str]:
            if force:
                self.worker_queue.put(("log", f"Clean build: {reason}"))
                self._clean_apktool_build_cache(decoded_dir)
            else:
                self.worker_queue.put(("log", f"Incremental build: {reason}"))
            if output_apk.exists():
                output_apk.unlink()
            self.worker_queue.put(("log", f"Apktool jobs: {APKTOOL_JOBS}. Live build output follows."))
            return self._run_logged_process(command(force), timeout=APKTOOL_BUILD_TIMEOUT)

        first_force = not use_incremental
        first_reason = "no trusted validated build yet" if first_force else "trusted cache is valid and sources changed"
        try:
            built = run_attempt(force=first_force, reason=first_reason)
        except ToolError as exc:
            if self._looks_like_dex_reference_overflow(str(exc)):
                raise ToolError(
                    str(exc)
                    + "\n\nThe project exceeded a DEX reference limit. "
                    "Android Smali GUI will not move arbitrary classes between DEX files automatically; "
                    "rebalance the multidex layout explicitly and rebuild."
                ) from exc
            if not first_force:
                self.worker_queue.put(("log", "Incremental build failed. Retrying once from a clean cache…"))
                built = run_attempt(force=True, reason="incremental build failed")
            else:
                raise

        try:
            dex_hashes = self._validate_apk_dex(output_apk, require_dex=True)
        except Exception as exc:
            if not first_force:
                self.worker_queue.put(("log", f"Incremental output failed DEX validation: {exc}"))
                built = run_attempt(force=True, reason="incremental output failed DEX validation")
                dex_hashes = self._validate_apk_dex(output_apk, require_dex=True)
            else:
                raise

        fingerprint = self._source_fingerprint(decoded_dir)
        self._save_smart_state(state_path, {
            "version": SMART_BUILD_STATE_VERSION,
            "validated": True,
            "fingerprint": fingerprint,
            "dex_hashes": dex_hashes,
            "apk_name": output_apk.name,
            "apk_size": output_apk.stat().st_size,
            "timestamp": time.time(),
            "jobs": APKTOOL_JOBS,
        })
        self.worker_queue.put(("log", f"DEX validation passed for {output_apk.name}: " + ", ".join(dex_hashes.keys())))
        return built

    def _signing_identity(self) -> tuple[Path, str, str]:
        """Create/reuse a development signing identity without storing its password in config.json."""
        keytool = find_keytool()
        if not keytool:
            raise ToolError("Java keytool was not found. Install/use a JDK and set JAVA_HOME.")
        if keyring is None:
            raise ToolError(
                "Secure signing-key persistence requires the Python 'keyring' package. "
                "Install dependencies with: pip install -r requirements.txt"
            )

        persistent = self.remember_signing_key_enabled
        if persistent:
            keystore = Path(self.config.get("signing_keystore", str(DEFAULT_KEYSTORE))).expanduser()
            alias = str(self.config.get("signing_alias", DEFAULT_KEY_ALIAS)).strip() or DEFAULT_KEY_ALIAS
            credential_name = str(keystore.resolve()) + "::" + alias
            try:
                password = keyring.get_password(KEYRING_SERVICE, credential_name)
            except KeyringError as exc:
                raise ToolError(f"Could not read the signing password from the OS credential store: {exc}") from exc
            if not password and self._legacy_signing_password:
                password = self._legacy_signing_password
                self._legacy_signing_password = ""
            if keystore.is_file() and not password:
                raise ToolError(
                    "The persistent keystore exists but its password is missing from the OS credential store. "
                    "Choose a new keystore path or remove the old development keystore."
                )
            if not password:
                password = secrets.token_hex(24)
        else:
            session_dir = CONFIG_DIR / "session_keys"
            session_dir.mkdir(parents=True, exist_ok=True)
            if self._session_signing_keystore is None:
                self._session_signing_keystore = session_dir / f"session-{os.getpid()}.keystore"
            if self._session_signing_password is None:
                self._session_signing_password = secrets.token_hex(24)
            keystore = self._session_signing_keystore
            alias = DEFAULT_KEY_ALIAS
            credential_name = ""
            password = self._session_signing_password

        if not keystore.is_file():
            keystore.parent.mkdir(parents=True, exist_ok=True)
            self.worker_queue.put(("log", f"Creating {'persistent' if persistent else 'session'} local signing key: {keystore}"))
            run_process([
                keytool, "-genkeypair",
                "-keystore", str(keystore),
                "-storepass", password,
                "-keypass", password,
                "-alias", alias,
                "-keyalg", "RSA",
                "-keysize", "3072",
                "-validity", "10000",
                "-dname", "CN=Android Smali GUI, OU=Local Testing, O=Local, L=Local, ST=Local, C=US",
            ], timeout=120)

        if persistent:
            try:
                keyring.set_password(KEYRING_SERVICE, credential_name, password)
            except KeyringError as exc:
                raise ToolError(f"Could not save the signing password in the OS credential store: {exc}") from exc
            self.config["signing_keystore"] = str(keystore)
            self.config["signing_alias"] = alias
            self.config.pop("signing_password", None)
            save_config(self.config)

        return keystore, alias, password

    def _signing_tools(self) -> tuple[str, str]:
        zipalign = find_android_build_tool("zipalign")
        apksigner = find_android_build_tool("apksigner")

        if not zipalign or not apksigner:
            checked = "\n".join(f"• {p}" for p in android_sdk_roots()) or "• none"
            raise ToolError(
                "Android SDK Build Tools are required for signing.\n\n"
                f"zipalign: {zipalign or 'NOT FOUND'}\n"
                f"apksigner: {apksigner or 'NOT FOUND'}\n\n"
                "Install Android SDK Build Tools or set ANDROID_SDK_ROOT.\n"
                f"SDK roots checked:\n{checked}"
            )

        return zipalign, apksigner

    @staticmethod
    def _certificate_digest_from_apksigner(output: str) -> str | None:
        match = re.search(
            r"certificate SHA-256 digest:\s*([0-9A-Fa-f:]+)",
            output,
        )
        if not match:
            return None
        return match.group(1).replace(":", "").lower()

    def _align_and_sign_apk_set(
        self,
        unsigned_apks: list[Path],
        rebuilt_root: Path,
    ) -> list[Path]:
        if not unsigned_apks:
            return []

        zipalign, apksigner = self._signing_tools()
        keystore, alias, password = self._signing_identity()

        aligned_root = rebuilt_root / "aligned"
        signed_root = rebuilt_root / "signed"

        if aligned_root.exists():
            safe_rmtree(aligned_root, rebuilt_root)
        if signed_root.exists():
            safe_rmtree(signed_root, rebuilt_root)

        aligned_root.mkdir(parents=True, exist_ok=True)
        signed_root.mkdir(parents=True, exist_ok=True)

        signed_apks: list[Path] = []
        cert_digests: dict[str, str] = {}
        total = len(unsigned_apks)

        for index, unsigned_apk in enumerate(unsigned_apks, start=1):
            self._report_progress(index - 1, total, f"Signing {index}/{total}: {unsigned_apk.name}")
            aligned_apk = aligned_root / unsigned_apk.name
            signed_apk = signed_root / unsigned_apk.name

            require_dex = unsigned_apk.name.lower() == "base.apk"
            unsigned_dex = self._validate_apk_dex(
                unsigned_apk,
                require_dex=require_dex,
            )

            self.worker_queue.put((
                "log",
                f"[sign {index}/{total}] zipalign {unsigned_apk.name}"
            ))

            aligned = run_process(
                executable_command(zipalign) + [
                    "-p", "-f", "4",
                    str(unsigned_apk),
                    str(aligned_apk),
                ],
                timeout=300,
            )
            if aligned.stdout.strip():
                self.worker_queue.put(("log", aligned.stdout.strip()))
            if aligned.stderr.strip():
                self.worker_queue.put(("log", aligned.stderr.strip()))

            aligned_dex = self._validate_apk_dex(
                aligned_apk,
                require_dex=require_dex,
            )
            self._compare_dex_hashes(
                unsigned_dex,
                aligned_dex,
                f"zipalign of {unsigned_apk.name}",
            )

            self.worker_queue.put((
                "log",
                f"[sign {index}/{total}] apksigner {unsigned_apk.name}"
            ))

            signed = run_process(
                executable_command(apksigner) + [
                    "sign",
                    "--ks", str(keystore),
                    "--ks-key-alias", alias,
                    "--ks-pass", f"pass:{password}",
                    "--key-pass", f"pass:{password}",
                    "--out", str(signed_apk),
                    str(aligned_apk),
                ],
                timeout=300,
            )
            if signed.stdout.strip():
                self.worker_queue.put(("log", signed.stdout.strip()))
            if signed.stderr.strip():
                self.worker_queue.put(("log", signed.stderr.strip()))

            signed_dex = self._validate_apk_dex(
                signed_apk,
                require_dex=require_dex,
            )
            self._compare_dex_hashes(
                unsigned_dex,
                signed_dex,
                f"signing of {unsigned_apk.name}",
            )

            verified = run_process(
                executable_command(apksigner) + [
                    "verify",
                    "--verbose",
                    "--print-certs",
                    str(signed_apk),
                ],
                timeout=120,
            )

            verify_text = (verified.stdout or "") + "\n" + (verified.stderr or "")
            digest = self._certificate_digest_from_apksigner(verify_text)
            if not digest:
                raise ToolError(
                    f"Could not determine signing certificate for {signed_apk}"
                )

            cert_digests[signed_apk.name] = digest
            signed_apks.append(signed_apk)

        if len(set(cert_digests.values())) != 1:
            details = "\n".join(
                f"• {name}: {digest}"
                for name, digest in cert_digests.items()
            )
            raise ToolError(
                "The APK set was not signed with one certificate:\n" + details
            )

        digest = next(iter(cert_digests.values()))
        self.worker_queue.put((
            "log",
            "All APKs verified with the same signing certificate "
            f"(SHA-256 {digest})."
        ))

        self._report_progress(total, total, "Signing complete")
        safe_rmtree(aligned_root, rebuilt_root, ignore_errors=True)
        return signed_apks

    @staticmethod
    def _manifest_package(decoded_dir: Path) -> str | None:
        manifest = decoded_dir / "AndroidManifest.xml"
        if not manifest.is_file():
            return None
        try:
            root = ET.parse(manifest).getroot()
            package = (root.attrib.get("package") or "").strip()
            return package or None
        except (ET.ParseError, OSError):
            return None

    def _infer_package_name(self, selected_root: Path, projects: list[tuple[Path, str]]) -> str | None:
        for candidate in (selected_root / "pull_manifest.json", selected_root.parent / "pull_manifest.json"):
            if candidate.is_file():
                try:
                    package = str(json.loads(candidate.read_text(encoding="utf-8")).get("package", "")).strip()
                    if package:
                        return package
                except Exception:
                    pass
        for decoded_dir, _ in projects:
            package = self._manifest_package(decoded_dir)
            if package:
                return package
        return None

    @staticmethod
    def _device_has_package(adb: str, serial: str, package: str) -> bool:
        cp = run_process([adb, "-s", serial, "shell", "pm", "path", package], timeout=30, check=False)
        return cp.returncode == 0 and any(line.startswith("package:") for line in cp.stdout.splitlines())

    def _install_apk_set(self, adb: str, serial: str, package: str, apks: list[Path], *, replace: bool) -> None:
        if not apks:
            raise ToolError("No APKs were produced to install.")
        for apk in apks:
            if not apk.is_file():
                raise ToolError(f"APK no longer exists: {apk}")
        args = [adb, "-s", serial]
        if len(apks) == 1:
            args += ["install"]
            if replace:
                args.append("-r")
            args.append(str(apks[0]))
        else:
            args += ["install-multiple"]
            if replace:
                args.append("-r")
            args += [str(p) for p in apks]
        self.worker_queue.put(("log", f"Installing {len(apks)} APK(s) to {serial}…"))
        cp = run_process(args, timeout=600, check=False)
        output = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()
        if cp.returncode != 0:
            lowered = output.lower()
            if "install_failed_update_incompatible" in lowered or "signatures do not match" in lowered or "inconsistent certificates" in lowered:
                raise InstallSignatureConflict(output or "Android rejected the update because the signing certificate differs.")
            raise ToolError(output or f"ADB install failed with exit code {cp.returncode}")
        self.worker_queue.put(("install_done", (package, serial, output or "Success")))

    def _process_next_install(self) -> None:
        if self.busy or not self.pending_installs:
            return
        package, paths = self.pending_installs.pop(0)
        self._begin_install_prompt(package, paths)

    def _begin_install_prompt(self, package: str, apk_paths: list[str]) -> None:
        try:
            adb = self._adb()
            serial = self._selected_serial()
        except ToolError as exc:
            messagebox.showerror(APP_NAME, f"Rebuild succeeded, but install could not start:\n\n{exc}")
            return
        apks = [Path(p) for p in apk_paths]
        installed = self._device_has_package(adb, serial, package)
        if installed:
            proceed = messagebox.askyesno(
                APP_NAME,
                f"{package} is already installed on the selected device.\n\n"
                "Update/replace the installed package with this rebuilt APK set?\n\n"
                "This attempts an in-place update and preserves app data, but Android will reject it if the signing certificates differ.",
            )
            if not proceed:
                self.write_log(f"Install skipped for {package}: user declined update/replace.")
                self._process_next_install()
                return
        self.set_busy(True, f"Installing {package}…")
        def task() -> None:
            try:
                self._install_apk_set(adb, serial, package, apks, replace=installed)
            except InstallSignatureConflict as exc:
                self.worker_queue.put(("install_signature_conflict", (package, serial, [str(p) for p in apks], str(exc))))
            except Exception as exc:
                self.worker_queue.put(("error", exc))
        threading.Thread(target=task, daemon=True).start()

    def _fresh_install_after_uninstall(self, package: str, serial: str, apk_paths: list[str]) -> None:
        try:
            adb = self._adb()
        except ToolError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        self.set_busy(True, f"Replacing {package} with a fresh install…")
        def task() -> None:
            try:
                uninstall = run_process([adb, "-s", serial, "uninstall", package], timeout=180, check=False)
                if uninstall.returncode != 0:
                    raise ToolError((uninstall.stdout or uninstall.stderr or "ADB uninstall failed").strip())
                self.worker_queue.put(("log", f"Uninstalled {package}; app data was removed."))
                self._install_apk_set(adb, serial, package, [Path(p) for p in apk_paths], replace=False)
            except Exception as exc:
                self.worker_queue.put(("error", exc))
        threading.Thread(target=task, daemon=True).start()

    def _recompile_project_folder(
        self,
        apktool: list[str],
        selected_root: Path,
        projects: list[tuple[Path, str]],
    ) -> list[Path]:
        """Build every discovered base/split Apktool project."""
        # For a package root such as:
        # D:\\AndroidProjects\\com.example.app
        # outputs become:
        # D:\\AndroidProjects\\com.example.app\\rebuilt\\*.apk
        #
        # When one decoded split itself is selected, rebuilt/ is placed next
        # to that decoded directory.
        if self._is_apktool_project(selected_root):
            rebuilt_root = selected_root.parent / "rebuilt"
        else:
            rebuilt_root = selected_root / "rebuilt"

        unsigned_root = rebuilt_root / "unsigned"
        unsigned_root.mkdir(parents=True, exist_ok=True)

        outputs: list[Path] = []
        total = len(projects)

        original_apk_root = selected_root / "apks"

        for index, (decoded_dir, output_name) in enumerate(projects, start=1):
            self._report_progress(index - 1, max(1, total + len(projects)), f"Building {index}/{total}: {output_name}")
            output_apk = unsigned_root / output_name

            if output_apk.exists():
                output_apk.unlink()

            # Configuration splits generated by an Android App Bundle are
            # usually unchanged by smali edits in base.apk. Rebuilding them
            # individually through Apktool/aapt2 can fail because they are
            # linked as dependent split packages. Preserve the original split
            # bytes and re-sign them together with the rebuilt base later.
            is_config_split = output_name.lower().startswith("split_config.")
            original_split = original_apk_root / output_name

            if is_config_split:
                if not original_split.is_file():
                    raise ToolError(
                        f"Original configuration split not found:\n"
                        f"{original_split}\n\n"
                        "Keep the original apks/ folder beside decoded/."
                    )

                self.worker_queue.put((
                    "log",
                    f"[{index}/{total}] Copying unchanged config split "
                    f"{original_split} -> {output_apk}"
                ))
                shutil.copy2(original_split, output_apk)
                outputs.append(output_apk)
                continue

            self.worker_queue.put((
                "log",
                f"[{index}/{total}] Building "
                f"{decoded_dir} -> {output_apk}"
            ))

            built = self._build_apktool_project_smart(
                apktool,
                decoded_dir,
                output_apk,
            )

            if built.stdout.strip():
                self.worker_queue.put(("log", built.stdout.strip()))
            if built.stderr.strip():
                self.worker_queue.put(("log", built.stderr.strip()))

            if not output_apk.is_file():
                raise ToolError(
                    f"Apktool completed without producing: {output_apk}"
                )

            outputs.append(output_apk)

        return self._align_and_sign_apk_set(outputs, rebuilt_root)

    def recompile_selected(self) -> None:
        """Rebuild the decoded APK(s) for the selected package(s) with Apktool."""
        if self.busy:
            return

        selections = self.tree.selection()
        if not selections:
            messagebox.showinfo(APP_NAME, "Select one or more apps first.")
            return

        packages = [self.package_rows[iid] for iid in selections if iid in self.package_rows]
        if not packages:
            return

        try:
            apktool = self._apktool_command()
        except ToolError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return

        output_root = Path(self.output_dir.get()).expanduser()
        self.set_busy(True, f"Recompiling {len(packages)} app(s)…")
        self.write_log(f"Recompile selected: {', '.join(packages)}")

        def task() -> None:
            failures: list[tuple[str, str]] = []
            completed: list[str] = []
            install_requests: list[tuple[str, list[str]]] = []

            for index, pkg in enumerate(packages, start=1):
                try:
                    self._report_progress(index - 1, len(packages), f"Recompiling {index}/{len(packages)}: {pkg}")
                    self.worker_queue.put(("log", f"\n=== Recompile {pkg} ==="))
                    outputs = self._recompile_package(apktool, pkg, output_root)
                    completed.extend(str(p) for p in outputs)
                    if self.install_after_rebuild_enabled:
                        install_requests.append((pkg, [str(p) for p in outputs]))
                except Exception as exc:
                    failures.append((pkg, str(exc)))
                    self.worker_queue.put(("log", f"FAILED: {pkg}: {exc}"))

            self._report_progress(len(packages), len(packages), "Recompile complete")
            self.worker_queue.put(("recompile_done", (completed, failures)))
            for request in install_requests:
                self.worker_queue.put(("install_ready", request))

        threading.Thread(target=task, daemon=True).start()

    def _load_apk_entries(self, package_dir: Path) -> list[tuple[Path, str]]:
        """Return (decoded_dir, output_apk_name) pairs for a decompiled package.

        Newer projects use pull_manifest.json's apk_entries mapping. Older
        projects created by previous versions of this GUI are supported by
        matching decoded directory names against APK filenames.
        """
        decoded_root = package_dir / "decoded"
        apk_root = package_dir / "apks"
        manifest_file = package_dir / "pull_manifest.json"

        if not decoded_root.is_dir():
            raise ToolError(f"Decoded directory not found: {decoded_root}")

        entries: list[tuple[Path, str]] = []

        if manifest_file.is_file():
            try:
                manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                for item in manifest.get("apk_entries", []):
                    decoded_name = str(item.get("decoded_dir", "")).strip()
                    apk_name = str(item.get("local_apk", "")).strip()
                    decoded_dir = decoded_root / decoded_name
                    if decoded_name and apk_name and decoded_dir.is_dir():
                        entries.append((decoded_dir, apk_name))
            except Exception:
                entries = []

        if entries:
            return entries

        apk_names: dict[str, str] = {}
        if apk_root.is_dir():
            for apk in apk_root.glob("*.apk"):
                apk_names[sanitize_filename(apk.stem)] = apk.name

        for decoded_dir in sorted(p for p in decoded_root.iterdir() if p.is_dir()):
            output_name = apk_names.get(decoded_dir.name, decoded_dir.name + ".apk")
            entries.append((decoded_dir, output_name))

        if not entries:
            raise ToolError(f"No decoded APK folders were found in {decoded_root}")

        return entries

    def _recompile_package(self, apktool: list[str], package: str, output_root: Path) -> list[Path]:
        package_dir = output_root / sanitize_filename(package)
        if not package_dir.is_dir():
            raise ToolError(
                f"No decompiled project was found for {package}. "
                f"Expected: {package_dir}"
            )

        entries = self._load_apk_entries(package_dir)
        rebuilt_root = package_dir / "rebuilt"
        unsigned_root = rebuilt_root / "unsigned"
        unsigned_root.mkdir(parents=True, exist_ok=True)

        outputs: list[Path] = []
        original_apk_root = package_dir / "apks"

        for decoded_dir, original_apk_name in entries:
            output_apk = unsigned_root / original_apk_name

            if output_apk.exists():
                output_apk.unlink()

            is_config_split = original_apk_name.lower().startswith("split_config.")
            original_split = original_apk_root / original_apk_name

            if is_config_split:
                if not original_split.is_file():
                    raise ToolError(
                        f"Original configuration split not found: {original_split}"
                    )

                self.worker_queue.put((
                    "log",
                    f"Copying unchanged config split "
                    f"{original_split.name} -> {output_apk.name}"
                ))
                shutil.copy2(original_split, output_apk)
                outputs.append(output_apk)
                continue

            self.worker_queue.put((
                "log",
                f"Building {decoded_dir.name} -> {output_apk.name}"
            ))

            built = self._build_apktool_project_smart(
                apktool,
                decoded_dir,
                output_apk,
            )

            if built.stdout.strip():
                self.worker_queue.put(("log", built.stdout.strip()))
            if built.stderr.strip():
                self.worker_queue.put(("log", built.stderr.strip()))

            if not output_apk.is_file():
                raise ToolError(
                    f"Apktool reported success but did not create {output_apk}"
                )

            outputs.append(output_apk)

        return self._align_and_sign_apk_set(outputs, rebuilt_root)

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.worker_queue.get_nowait()
                if kind == "devices":
                    self.devices = payload  # type: ignore[assignment]
                    choices = []
                    ready_serials = []
                    for d in self.devices:
                        choices.append(f"{d.serial}  [{d.state}]  {d.description}")
                        if d.state == "device":
                            ready_serials.append(d.serial)
                    self.device_combo["values"] = choices
                    if choices:
                        ready_index = next((i for i, d in enumerate(self.devices) if d.state == "device"), 0)
                        self.device_combo.current(ready_index)
                        selected = self.devices[ready_index]
                        self.device_serial.set(selected.serial)
                        if selected.state == "unauthorized":
                            self.status_var.set("Device unauthorized — accept the USB debugging prompt on the phone")
                        elif selected.state != "device":
                            self.status_var.set(f"Device state: {selected.state}")
                        else:
                            self.status_var.set("Device connected")
                    else:
                        self.device_serial.set("")
                        self.status_var.set("No ADB devices found")
                    self.set_busy(False)
                    if ready_serials:
                        self.refresh_packages()
                elif kind == "packages":
                    self.packages = payload  # type: ignore[assignment]
                    self.apply_filter()
                    self.set_busy(False)
                elif kind == "apktool_installed":
                    version, path = payload  # type: ignore[misc]
                    self.write_log(f"Apktool {version} installed at {path}")
                    self.set_busy(False, f"Apktool {version} ready")
                elif kind == "log":
                    self.last_activity_at = time.monotonic()
                    self.write_log(str(payload))
                elif kind == "progress":
                    percent, status_text = payload  # type: ignore[misc]
                    self.last_activity_at = time.monotonic()
                    self.progress_var.set(float(percent))
                    self.status_var.set(str(status_text))
                elif kind == "install_ready":
                    package, paths = payload  # type: ignore[misc]
                    self.pending_installs.append((str(package), list(paths)))
                    if not self.busy:
                        self.status_var.set("Rebuild complete; install confirmation required")
                        self._process_next_install()
                elif kind == "install_signature_conflict":
                    package, serial, paths, details = payload  # type: ignore[misc]
                    self.set_busy(False, "Install blocked by signing-certificate conflict")
                    proceed = messagebox.askyesno(
                        APP_NAME,
                        f"Android refused to update {package} because the installed app and rebuilt APK are signed differently.\n\n"
                        "Do you want to UNINSTALL the existing app and then install the rebuilt version?\n\n"
                        "WARNING: uninstalling removes that app's local data unless the app has its own backup/sync. This cannot be undone by Android Smali GUI.\n\n"
                        f"ADB response:\n{details}",
                    )
                    if proceed:
                        self._fresh_install_after_uninstall(str(package), str(serial), list(paths))
                    else:
                        self.write_log(f"Fresh install skipped for {package}: user declined uninstall.")
                        self._process_next_install()
                elif kind == "install_done":
                    package, serial, details = payload  # type: ignore[misc]
                    self.set_busy(False, "Install complete")
                    self.write_log(f"Installed {package} on {serial}: {details}")
                    messagebox.showinfo(APP_NAME, f"Installed {package} successfully on {serial}.")
                    self._process_next_install()
                elif kind == "decompile_done":
                    completed, failures = payload  # type: ignore[misc]
                    self.set_busy(False, "Finished")
                    if failures:
                        details = "\n".join(f"• {pkg}: {err}" for pkg, err in failures)
                        messagebox.showwarning(APP_NAME, f"Finished with errors.\n\n{details}")
                    else:
                        messagebox.showinfo(APP_NAME, f"Finished decompiling {len(completed)} app(s).")
                elif kind == "recompile_done":
                    completed, failures = payload  # type: ignore[misc]
                    self.set_busy(False, "Recompile finished")
                    if failures:
                        details = "\n".join(f"• {pkg}: {err}" for pkg, err in failures)
                        messagebox.showwarning(APP_NAME, f"Recompile finished with errors.\n\n{details}")
                    else:
                        where = "\n".join(completed)
                        self.write_log(f"Rebuilt APK(s):\n{where}")
                        messagebox.showinfo(
                            APP_NAME,
                            f"Recompiled {len(completed)} APK(s).\n\n"
                            "Signed outputs are in each package's rebuilt/signed folder."
                        )
                elif kind == "recompile_folder_done":
                    completed = payload  # type: ignore[assignment]
                    self.set_busy(False, "Recompile finished")
                    where = "\n".join(str(p) for p in completed)
                    self.write_log(f"Rebuilt APK(s):\n{where}")

                    output_folder = (
                        str(Path(completed[0]).parent)
                        if completed
                        else ""
                    )
                    messagebox.showinfo(
                        APP_NAME,
                        f"Successfully rebuilt {len(completed)} "
                        f"APK(s)/split(s).\n\nOutput:\n{output_folder}"
                    )
                elif kind == "error":
                    self.set_busy(False, "Error")
                    self.write_log(f"ERROR: {payload}")
                    messagebox.showerror(APP_NAME, str(payload))
                    self._process_next_install()
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)


def main() -> None:
    root = Tk()
    try:
        ttk.Style().theme_use("vista" if os.name == "nt" else "clam")
    except Exception:
        pass
    AndroidSmaliGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()
