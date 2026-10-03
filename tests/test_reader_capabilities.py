"""OS capability regressions for the existing explicit local-file contract."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ci_trust_boundary_review.input import read_local
import ci_trust_boundary_review.input as reader
from ci_trust_boundary_review.input import OpenInput
from ci_trust_boundary_review import Limits
from ci_trust_boundary_review.cli import main


class ReaderCapabilities(unittest.TestCase):
    def invoke(self, path):
        return read_local(str(path), Limits())

    def test_missing_none_zero_bool_and_noninteger_flags_fail_before_open(self):
        for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_CLOEXEC"):
            for value in (None, 0, True, False, -1, "flag"):
                with self.subTest(flag=flag, value=value):
                    with patch.object(reader.os, "open") as opened:
                        with patch.object(reader.os, "supports_dir_fd", {opened}):
                            with patch.object(reader.os, flag, value):
                                with self.assertRaises(OpenInput):
                                    self.invoke(Path("synthetic-1.0-py3-none-any.whl"))
                        opened.assert_not_called()
            with patch.object(reader.os, flag, create=True):
                delattr(reader.os, flag)
                with self.assertRaises(OpenInput):
                    self.invoke(Path("synthetic-1.0-py3-none-any.whl"))

    def test_directory_relative_capability_boundary(self):
        for value in (None, set(), [], True):
            with self.subTest(value=value), patch.object(reader.os, "open") as opened:
                with patch.object(reader.os, "supports_dir_fd", value):
                    with self.assertRaises(OpenInput):
                        self.invoke(Path("synthetic-1.0-py3-none-any.whl"))
                opened.assert_not_called()
        with patch.object(reader.os, "supports_dir_fd", create=True):
            delattr(reader.os, "supports_dir_fd")
            with self.assertRaises(OpenInput):
                self.invoke(Path("synthetic-1.0-py3-none-any.whl"))

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor contract")
    def test_valid_regular_symlink_and_fifo_nonblocking_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "synthetic-1.0-py3-none-any.whl"
            path.write_bytes(b"synthetic")
            self.assertEqual(self.invoke(path), b"synthetic")
            link = root / "leaf-1.0-py3-none-any.whl"
            link.symlink_to(path)
            pipe = root / "pipe-1.0-py3-none-any.whl"
            os.mkfifo(pipe)
            for target in (link, pipe):
                with self.assertRaises((OpenInput, OSError)):
                    self.invoke(target)
            directory_link = root / "parent"
            directory_link.symlink_to(root, target_is_directory=True)
            with self.assertRaises((OpenInput, OSError)):
                self.invoke(directory_link / path.name)

    def test_cli_missing_capability_preserves_open_json(self):
        path = Path("synthetic-1.0-py3-none-any.whl")
        output = io.StringIO()
        with patch.object(reader.os, "O_NOFOLLOW", 0), contextlib.redirect_stdout(output):
            status = main([str(path)])
        self.assertEqual(status, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "OPEN")
        self.assertFalse(result.get("complete", False))
