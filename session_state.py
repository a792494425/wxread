"""Encrypted session persistence for ephemeral GitHub Actions runners.

Only the encrypted state file is cached. Its encryption key is derived from the
original WXREAD_CURL_BASH secret; neither plaintext cookies nor the key are
written to the file or logs.
"""

import base64
import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path


class EncryptedCookieState:
    def __init__(self, source_curl=None, state_path=None):
        self.path = Path(state_path) if source_curl and state_path else None
        self.key = (
            base64.urlsafe_b64encode(
                hashlib.sha256(b"wxread/session-state/v1\0" + source_curl.encode("utf-8")).digest()
            )
            if self.path is not None
            else None
        )

    def restore(self, cookies):
        """Restore authenticated cookies, or keep the configured ones on a cache miss."""
        if self.path is None or not self.path.is_file():
            return False
        try:
            from cryptography.fernet import Fernet

            data = json.loads(Fernet(self.key).decrypt(self.path.read_bytes()))
            recovered = data.get("cookies") if data.get("version") == 1 else None
            if not isinstance(recovered, dict) or any(
                not isinstance(k, str)
                or not isinstance(v, str)
                or len(k) > 200
                or len(v) > 8192
                for k, v in recovered.items()
            ):
                raise ValueError("invalid session payload")
            # A re-login changes the original cURL secret, invalidating the old
            # encrypted cache automatically.
            cookies.update(recovered)
            logging.info("已恢复加密保存的微信读书会话。")
            return True
        except Exception:
            logging.warning("会话缓存无法解密或格式不兼容，使用当前配置的登录信息。")
            return False

    @staticmethod
    def absorb_response(cookies, response):
        """Apply all server-side Cookie rotations, not only wr_skey."""
        changed = False
        for item in response.cookies:
            if not item.name:
                continue
            if not item.value or item.is_expired():
                if item.name in cookies:
                    del cookies[item.name]
                    changed = True
            elif cookies.get(item.name) != item.value:
                cookies[item.name] = item.value
                changed = True
        return changed

    def save(self, cookies):
        """Write only encrypted data, atomically, so interrupted runs keep the old state."""
        if self.path is None:
            return False
        temp_name = None
        try:
            from cryptography.fernet import Fernet

            payload = json.dumps(
                {"version": 1, "cookies": cookies},
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            encrypted = Fernet(self.key).encrypt(payload)
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(prefix=".wxread-", dir=self.path.parent)
            with os.fdopen(fd, "wb") as stream:
                stream.write(encrypted)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
            return True
        except Exception as exc:
            logging.warning("无法安全保存加密会话状态：%s", type(exc).__name__)
            return False
        finally:
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)
