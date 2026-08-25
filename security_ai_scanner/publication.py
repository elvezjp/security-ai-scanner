"""Exclusive, atomic publication of scan artifacts."""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

from .exceptions import PublicationError


LOCK_NAME = ".sais.lock"
SUMMARY_NAME = "summary.json"


class OutputPublication:
    """Hold one output directory exclusively and atomically replace files."""

    def __init__(self, output_dir: Path, run_id: str):
        self.output_dir = output_dir
        self.run_id = run_id
        self.lock_path = output_dir / LOCK_NAME
        self._owns_lock = False

    def __enter__(self) -> OutputPublication:
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise PublicationError(
                f"Cannot create output directory {self.output_dir}: {exc}"
            ) from exc

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            descriptor = os.open(self.lock_path, flags, 0o666)
        except FileExistsError as exc:
            raise PublicationError(
                f"Output directory is already in use: {self.output_dir} "
                f"({LOCK_NAME} exists). If a previous run was interrupted, "
                "confirm that no writer is active before removing the lock."
            ) from exc
        except OSError as exc:
            raise PublicationError(
                f"Cannot lock output directory {self.output_dir}: {exc}"
            ) from exc

        try:
            payload = json.dumps(
                {"run_id": self.run_id, "pid": os.getpid()},
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            self._owns_lock = True
            self._invalidate_stale_summary()
        except Exception:
            self._remove_owned_lock(ignore_errors=True)
            raise
        return self

    def __exit__(self, exc_type, _exc, _traceback) -> bool:
        try:
            self._remove_owned_lock(ignore_errors=exc_type is not None)
        finally:
            self._owns_lock = False
        return False

    def _invalidate_stale_summary(self) -> None:
        summary_path = self.output_dir / SUMMARY_NAME
        try:
            summary_path.unlink(missing_ok=True)
        except OSError as exc:
            raise PublicationError(
                f"Cannot invalidate stale {summary_path}: {exc}"
            ) from exc

    def _remove_owned_lock(self, *, ignore_errors: bool) -> None:
        if not self._owns_lock and not self.lock_path.exists():
            return
        try:
            self.lock_path.unlink(missing_ok=True)
        except OSError as exc:
            if not ignore_errors:
                raise PublicationError(
                    f"Cannot remove output lock {self.lock_path}: {exc}"
                ) from exc

    def write_text(self, name: str, content: str) -> Path:
        """Atomically replace one UTF-8 artifact in the locked directory."""
        if not self._owns_lock:
            raise PublicationError("Output publication lock is not held")
        if Path(name).name != name:
            raise PublicationError(f"Artifact name must be a file name: {name!r}")

        final_path = self.output_dir / name
        temporary_path = self.output_dir / (
            f".{name}.{self.run_id}.{uuid4().hex}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        descriptor: int | None = None
        try:
            descriptor = os.open(temporary_path, flags, 0o666)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(content.encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, final_path)
        except OSError as exc:
            raise PublicationError(
                f"Cannot atomically publish {final_path}: {exc}"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                # Preserve the publication error. The unique temporary file is
                # never referenced by summary.json and is safe to remove later.
                pass
        return final_path
