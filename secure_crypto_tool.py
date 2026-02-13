from __future__ import annotations

import base64
import binascii
import importlib.metadata
import os
from typing import Any

try:
    import tkinter as tk
    from tkinter import filedialog, ttk
    from tkinter.scrolledtext import ScrolledText
except ModuleNotFoundError:  # pragma: no cover - environment dependent
    tk = None  # type: ignore[assignment]
    filedialog = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    ScrolledText = Any  # type: ignore[assignment]

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 100000
SALT_SIZE = 16
IV_SIZE = 12
MIN_CRYPTOGRAPHY_VERSION = (46, 0, 5)


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_text(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)
    encrypted = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    return base64.b64encode(salt + iv + encrypted).decode("ascii")


def decrypt_text(ciphertext_base64: str, password: str) -> str:
    combined = base64.b64decode(ciphertext_base64)
    if len(combined) <= SALT_SIZE + IV_SIZE:
        raise ValueError("Invalid encrypted payload")

    salt = combined[:SALT_SIZE]
    iv = combined[SALT_SIZE : SALT_SIZE + IV_SIZE]
    encrypted = combined[SALT_SIZE + IV_SIZE :]

    key = derive_key(password, salt)
    return AESGCM(key).decrypt(iv, encrypted, None).decode("utf-8")


def check_cryptography_version() -> None:
    version_text = importlib.metadata.version("cryptography")
    current = tuple(int(part) for part in version_text.split(".")[:3])
    if current < MIN_CRYPTOGRAPHY_VERSION:
        min_version = ".".join(str(v) for v in MIN_CRYPTOGRAPHY_VERSION)
        raise RuntimeError(
            f"cryptography>={min_version} is required for security, current: {version_text}"
        )


class SecureCryptoApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("🔒 安全加密工具 Secure Crypto Tool")
        self.root.geometry("980x760")
        self.root.minsize(860, 660)

        self.notifier = tk.StringVar(value="")
        self.encrypt_strength = tk.StringVar(value="")
        self.encrypt_password_visible = tk.BooleanVar(value=False)
        self.decrypt_password_visible = tk.BooleanVar(value=False)

        self._build_style()
        self._build_ui()

    def _build_style(self) -> None:
        self.root.configure(bg="#f3f4fb")
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Card.TFrame", background="#ffffff")
        style.configure("Header.TFrame", background="#4f46e5")
        style.configure("Header.TLabel", background="#4f46e5", foreground="#ffffff", font=("Segoe UI", 19, "bold"))
        style.configure("SubHeader.TLabel", background="#4f46e5", foreground="#dbeafe", font=("Segoe UI", 11))
        style.configure("Section.TLabel", background="#ffffff", foreground="#111827", font=("Segoe UI", 10, "bold"))
        style.configure("Action.TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.configure("Secondary.TButton", font=("Segoe UI", 9), padding=6)
        style.map("Action.TButton", background=[("active", "#3730a3")], foreground=[("active", "white")])

    def _build_ui(self) -> None:
        container = ttk.Frame(self.root, style="Card.TFrame", padding=16)
        container.pack(fill="both", expand=True, padx=14, pady=14)

        header = ttk.Frame(container, style="Header.TFrame", padding=(18, 14))
        header.pack(fill="x")
        ttk.Label(header, text="🔒 安全加密工具", style="Header.TLabel").pack(anchor="center")
        ttk.Label(header, text="Secure Encryption & Decryption Tool (Python)", style="SubHeader.TLabel").pack(anchor="center", pady=(4, 0))

        notebook = ttk.Notebook(container)
        notebook.pack(fill="both", expand=True, pady=(12, 10))

        encrypt_tab = ttk.Frame(notebook, style="Card.TFrame", padding=14)
        decrypt_tab = ttk.Frame(notebook, style="Card.TFrame", padding=14)
        notebook.add(encrypt_tab, text="🔐 加密 Encrypt")
        notebook.add(decrypt_tab, text="🔓 解密 Decrypt")

        self._build_encrypt_tab(encrypt_tab)
        self._build_decrypt_tab(decrypt_tab)

        self.notice_label = tk.Label(
            container,
            textvariable=self.notifier,
            anchor="w",
            justify="left",
            bg="#eef2ff",
            fg="#1f2937",
            font=("Segoe UI", 10),
            padx=12,
            pady=8,
        )
        self.notice_label.pack(fill="x")

    def _build_encrypt_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="输入要加密的内容 (Enter content to encrypt):", style="Section.TLabel").pack(anchor="w")
        self.encrypt_input = ScrolledText(parent, height=12, wrap="word", font=("Consolas", 10))
        self.encrypt_input.pack(fill="both", expand=True, pady=(6, 12))

        ttk.Label(parent, text="加密密码 (Encryption password):", style="Section.TLabel").pack(anchor="w")
        pwd_frame = ttk.Frame(parent, style="Card.TFrame")
        pwd_frame.pack(fill="x", pady=(6, 2))

        self.encrypt_password = ttk.Entry(pwd_frame, show="*", font=("Segoe UI", 10))
        self.encrypt_password.pack(side="left", fill="x", expand=True)
        self.encrypt_password.bind("<KeyRelease>", self._update_password_strength)

        ttk.Checkbutton(
            pwd_frame,
            text="显示密码 Show",
            variable=self.encrypt_password_visible,
            command=lambda: self._toggle_password(self.encrypt_password, self.encrypt_password_visible),
        ).pack(side="left", padx=(8, 0))

        self.encrypt_strength_label = ttk.Label(parent, textvariable=self.encrypt_strength, background="#ffffff", foreground="#b45309", font=("Segoe UI", 9, "bold"))
        self.encrypt_strength_label.pack(anchor="w", pady=(0, 8))

        ttk.Button(parent, text="🔐 加密内容 Encrypt Content", style="Action.TButton", command=self.handle_encrypt).pack(fill="x", pady=(2, 10))

        ttk.Label(parent, text="加密结果 (Encrypted result):", style="Section.TLabel").pack(anchor="w")
        self.encrypt_output = ScrolledText(parent, height=8, wrap="word", font=("Consolas", 10))
        self.encrypt_output.pack(fill="both", expand=True, pady=(6, 8))

        buttons = ttk.Frame(parent, style="Card.TFrame")
        buttons.pack(fill="x")
        ttk.Button(buttons, text="📋 复制 Copy", style="Secondary.TButton", command=lambda: self._copy(self.encrypt_output)).pack(side="left", expand=True, fill="x", padx=(0, 6))
        ttk.Button(buttons, text="💾 下载 Download", style="Secondary.TButton", command=lambda: self._save(self.encrypt_output, "encrypted.txt")).pack(side="left", expand=True, fill="x", padx=6)
        ttk.Button(buttons, text="🗑️ 清除 Clear", style="Secondary.TButton", command=self.clear_encrypt).pack(side="left", expand=True, fill="x", padx=(6, 0))

    def _build_decrypt_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="输入要解密的内容 (Enter encrypted content):", style="Section.TLabel").pack(anchor="w")
        self.decrypt_input = ScrolledText(parent, height=12, wrap="word", font=("Consolas", 10))
        self.decrypt_input.pack(fill="both", expand=True, pady=(6, 12))

        ttk.Label(parent, text="解密密码 (Decryption password):", style="Section.TLabel").pack(anchor="w")
        pwd_frame = ttk.Frame(parent, style="Card.TFrame")
        pwd_frame.pack(fill="x", pady=(6, 8))

        self.decrypt_password = ttk.Entry(pwd_frame, show="*", font=("Segoe UI", 10))
        self.decrypt_password.pack(side="left", fill="x", expand=True)

        ttk.Checkbutton(
            pwd_frame,
            text="显示密码 Show",
            variable=self.decrypt_password_visible,
            command=lambda: self._toggle_password(self.decrypt_password, self.decrypt_password_visible),
        ).pack(side="left", padx=(8, 0))

        ttk.Button(parent, text="🔓 解密内容 Decrypt Content", style="Action.TButton", command=self.handle_decrypt).pack(fill="x", pady=(2, 10))

        ttk.Label(parent, text="解密结果 (Decrypted result):", style="Section.TLabel").pack(anchor="w")
        self.decrypt_output = ScrolledText(parent, height=8, wrap="word", font=("Consolas", 10))
        self.decrypt_output.pack(fill="both", expand=True, pady=(6, 8))

        buttons = ttk.Frame(parent, style="Card.TFrame")
        buttons.pack(fill="x")
        ttk.Button(buttons, text="📋 复制 Copy", style="Secondary.TButton", command=lambda: self._copy(self.decrypt_output)).pack(side="left", expand=True, fill="x", padx=(0, 6))
        ttk.Button(buttons, text="💾 下载 Download", style="Secondary.TButton", command=lambda: self._save(self.decrypt_output, "decrypted.txt")).pack(side="left", expand=True, fill="x", padx=6)
        ttk.Button(buttons, text="🗑️ 清除 Clear", style="Secondary.TButton", command=self.clear_decrypt).pack(side="left", expand=True, fill="x", padx=(6, 0))

    def _toggle_password(self, entry: ttk.Entry, visible_var: tk.BooleanVar) -> None:
        entry.configure(show="" if visible_var.get() else "*")

    def _update_password_strength(self, _event: tk.Event | None = None) -> None:
        password = self.encrypt_password.get()
        if not password:
            self.encrypt_strength.set("")
            self.encrypt_strength_label.configure(foreground="#b45309")
            return

        checks = [
            len(password) >= 8,
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
        score = sum(checks)

        if score <= 2:
            self.encrypt_strength.set("⚠️ 弱密码 Weak Password")
            self.encrypt_strength_label.configure(foreground="#dc2626")
        elif score <= 4:
            self.encrypt_strength.set("✓ 中等密码 Medium Password")
            self.encrypt_strength_label.configure(foreground="#b45309")
        else:
            self.encrypt_strength.set("✓ 强密码 Strong Password")
            self.encrypt_strength_label.configure(foreground="#15803d")

    def handle_encrypt(self) -> None:
        plaintext = self.encrypt_input.get("1.0", "end-1c")
        password = self.encrypt_password.get()

        if not plaintext:
            self._notify("请输入要加密的内容 Please enter content to encrypt", "error")
            return
        if not password:
            self._notify("请输入密码 Please enter a password", "error")
            return
        if len(password) < 8:
            self._notify("密码至少需要8位 Password must be at least 8 characters", "error")
            return

        try:
            encrypted = encrypt_text(plaintext, password)
            self.encrypt_output.delete("1.0", "end")
            self.encrypt_output.insert("1.0", encrypted)
            self._notify("✓ 加密成功 Encryption successful!", "success")
        except Exception as exc:  # pragma: no cover - UI feedback path
            self._notify(f"加密失败 Encryption failed: {exc}", "error")

    def handle_decrypt(self) -> None:
        ciphertext = self.decrypt_input.get("1.0", "end-1c").strip()
        password = self.decrypt_password.get()

        if not ciphertext:
            self._notify("请输入要解密的内容 Please enter encrypted content", "error")
            return
        if not password:
            self._notify("请输入密码 Please enter password", "error")
            return

        try:
            plaintext = decrypt_text(ciphertext, password)
            self.decrypt_output.delete("1.0", "end")
            self.decrypt_output.insert("1.0", plaintext)
            self._notify("✓ 解密成功 Decryption successful!", "success")
        except binascii.Error:
            self.decrypt_output.delete("1.0", "end")
            self._notify("解密失败 Decryption failed: 非法的加密文本格式 Invalid encrypted text format", "error")
        except (InvalidTag, ValueError):
            self.decrypt_output.delete("1.0", "end")
            self._notify("解密失败 Decryption failed: 密码错误或数据损坏 Invalid password or corrupted data", "error")

    def clear_encrypt(self) -> None:
        self.encrypt_input.delete("1.0", "end")
        self.encrypt_password.delete(0, "end")
        self.encrypt_output.delete("1.0", "end")
        self.encrypt_strength.set("")
        self._notify("✓ 已清除 Cleared", "info")

    def clear_decrypt(self) -> None:
        self.decrypt_input.delete("1.0", "end")
        self.decrypt_password.delete(0, "end")
        self.decrypt_output.delete("1.0", "end")
        self._notify("✓ 已清除 Cleared", "info")

    def _copy(self, widget: ScrolledText) -> None:
        value = widget.get("1.0", "end-1c")
        if not value:
            self._notify("没有内容可复制 No content to copy", "error")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self._notify("✓ 已复制到剪贴板 Copied to clipboard!", "success")

    def _save(self, widget: ScrolledText, default_name: str) -> None:
        value = widget.get("1.0", "end-1c")
        if not value:
            self._notify("没有内容可下载 No content to download", "error")
            return

        path = filedialog.asksaveasfilename(
            title="保存 Save",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text", "*.txt"), ("All Files", "*.*")],
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(value)
        self._notify("✓ 下载成功 Download successful!", "success")

    def _notify(self, message: str, level: str) -> None:
        palette = {
            "success": ("#ecfdf3", "#166534"),
            "error": ("#fef2f2", "#991b1b"),
            "info": ("#eef2ff", "#3730a3"),
        }
        bg, fg = palette.get(level, palette["info"])
        self.notifier.set(message)
        self.notice_label.configure(bg=bg, fg=fg)


def main() -> None:
    try:
        check_cryptography_version()
    except RuntimeError as exc:
        print(str(exc))
        raise SystemExit(1) from exc

    if tk is None:
        print("tkinter is required. On Debian/Ubuntu install: sudo apt-get install python3-tk")
        raise SystemExit(1)

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"无法启动图形界面 GUI unavailable: {exc}")
        raise SystemExit(1) from exc

    SecureCryptoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
