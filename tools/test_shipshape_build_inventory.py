"""Inert fixtures for the proposed helper; no Bazel or extension execution."""

import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import runpy
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import shipshape_build_inventory as helper


def inert_thin(target):
    raw = bytearray(128)
    if target.startswith("darwin"):
        cpu, subtype = (0x01000007, 3) if target.endswith("amd64") else (0x0100000C, 0)
        struct.pack_into("<IIII", raw, 0, 0xFEEDFACF, cpu, subtype, 2)
    elif target.startswith("linux"):
        raw[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", raw, 16, 2, 62 if target.endswith("amd64") else 183)
    else:
        raw[:2] = b"MZ"
        struct.pack_into("<I", raw, 60, 64)
        raw[64:68] = b"PE\0\0"
        struct.pack_into("<H", raw, 68, 0x8664)
        struct.pack_into("<H", raw, 88, 0x20B)
    return bytes(raw)


def fake_lipo(command, **options):
    # This trusted mock assembles inert bytes; no output file is executed.
    if command[:3] != ["/usr/bin/lipo", "-create", "-output"]:
        raise AssertionError("unexpected subprocess")
    raw = bytearray(4096)
    struct.pack_into(">II", raw, 0, 0xCAFEBABE, 2)
    for index, name in enumerate(command[4:]):
        body = Path(name).read_bytes()
        offset = (len(raw) + 4095) & ~4095
        raw.extend(bytes(offset - len(raw)))
        cpu, subtype = struct.unpack_from("<II", body, 4)
        struct.pack_into(">IIIII", raw, 8 + index * 20, cpu, subtype, offset, len(body), 12)
        raw.extend(body)
    Path(command[3]).write_bytes(raw)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        source = "a" * 40  # Explicit unit fixture locator, never live evidence.
        self.env = {"RUNNER_TEMP": str(self.root), "TRIAL_SOURCE_SHA": source,
                    "GITHUB_REPOSITORY_ID": helper.REPOSITORY_ID,
                    "GITHUB_REPOSITORY": "macadmins/osquery-extension",
                    "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                    "GITHUB_SHA": source, "GITHUB_WORKFLOW_SHA": source,
                    "GITHUB_WORKFLOW_REF": "macadmins/osquery-extension/.github/workflows/shipshape-build-inventory.yml@refs/heads/main",
                    "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
        self.environment = patch.dict(os.environ, self.env)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.invocation = helper.context(self.env)

    def fixture_args(self):
        workspace = self.root / "workspace"
        workspace.mkdir()
        (workspace / "VERSION").write_text("1.5.5\n")
        (workspace / ".bazelversion").write_text("7.4.1\n")
        output_root = self.root / "osquery-trial-bazel/output"
        output_root.mkdir(parents=True)
        paths = []
        for target, _ in helper.TARGETS:
            path = output_root / target
            path.write_bytes(inert_thin(target))
            paths.append(str(path))
        (self.root / "root.txt").write_text(str(output_root))
        (self.root / "paths.txt").write_text("\n".join(paths))
        (self.root / "tree.txt").write_text("b" * 40)
        (self.root / "tools.json").write_text(json.dumps({"bazel": "bazel 7.4.1", "host_go": "go version go1.27.3 darwin/arm64", "python": "Python 3.9.6"}))
        args = argparse.Namespace(workspace=str(workspace), output_root=str(self.root / "root.txt"), output_files=str(self.root / "paths.txt"), source_tree=str(self.root / "tree.txt"), tool_versions=str(self.root / "tools.json"), output=str(self.root / "transfer" / helper.TRANSFER_NAME))
        return args

    def fixture(self):
        args = self.fixture_args()
        helper.collect(args, self.invocation)
        return Path(args.output)

    def test_collect_package_inert_positive_and_unknown_provenance(self):
        transfer = self.fixture()
        args = argparse.Namespace(transfer=str(transfer), output=str(self.root / "inventory"))
        with patch.object(helper.subprocess, "run", side_effect=fake_lipo) as run:
            helper.package(args, self.invocation)
        self.assertEqual(run.call_count, 1)
        output = Path(args.output)
        metadata = json.loads((output / "inventory.json").read_bytes())
        self.assertEqual(metadata["dependency_inventory"], "unknown")
        self.assertEqual(metadata["embedded_platform_settings"], "not_collected")
        self.assertEqual(metadata["publication"], "not_attempted")
        self.assertEqual({record["target"] for record in metadata["darwin_slices"]}, {"darwin-amd64", "darwin-arm64"})
        for record in metadata["darwin_slices"]:
            self.assertEqual(record["sha256"], helper.digest(inert_thin(record["target"])))
            self.assertEqual(record["bytes"], 128)
            self.assertEqual(record["offset"] % 4096, 0)
        self.assertEqual(len(list((output / "thin").iterdir())), 5)
        with zipfile.ZipFile(output / "macadmins_extension.zip") as archive:
            self.assertEqual(len(archive.infolist()), 4)
            self.assertEqual(archive.read("macadmins_extension/linux/macadmins_extension.amd64.ext"), inert_thin("linux-amd64"))
        self.assertNotIn("complete", metadata)

    def test_context_and_output_escape_rejected(self):
        for key, value in (("TRIAL_SOURCE_SHA", "A" * 40), ("GITHUB_WORKFLOW_SHA", "b" * 40), ("GITHUB_REF", "refs/heads/other"), ("GITHUB_RUN_ATTEMPT", "0")):
            environment = dict(self.env, **{key: value})
            with self.assertRaises(helper.Invalid):
                helper.context(environment)
        with self.assertRaises(helper.Invalid):
            helper.scratch_output(self.root.parent / "escape")
        target = self.root / "real"
        target.write_bytes(b"inert")
        link = self.root / "link"
        link.symlink_to(target)
        with self.assertRaises(helper.Invalid):
            helper.read_file(link, helper.Budget())

    def test_changed_thin_hash_rejected_before_lipo(self):
        transfer = self.fixture()
        expected = {"thin/" + target for target, _ in helper.TARGETS} | {"build.json"}
        members = helper.transfer_members(transfer.read_bytes(), expected, helper.Budget())
        members["thin/linux-amd64"] += b"changed"
        transfer.write_bytes(helper.make_zip(members, helper.Budget()))
        with patch.object(helper.subprocess, "run") as run:
            with self.assertRaises(helper.Invalid):
                helper.package(argparse.Namespace(transfer=str(transfer), output=str(self.root / "bad")), self.invocation)
            run.assert_not_called()

    def test_directory_bounds_and_shared_budget(self):
        raw = bytearray(helper.make_zip({"expected": b"inert"}, helper.Budget()))
        struct.pack_into("<H", raw, len(raw) - 12, 65535)
        with patch.object(helper.zipfile, "ZipFile") as parser:
            with self.assertRaises(helper.Invalid):
                helper.transfer_members(bytes(raw), {"expected"}, helper.Budget())
            parser.assert_not_called()
        budget = helper.Budget(8)
        budget.charge(5)
        with self.assertRaises(helper.Invalid):
            budget.charge(4)
        with self.assertRaises(helper.Invalid):
            helper.pairs([("duplicate", 1), ("duplicate", 2)])

    def test_cli_collect_and_package_real_validation(self):
        args = self.fixture_args()
        arguments = [str(Path(helper.__file__)), "collect"]
        for name, value in vars(args).items():
            arguments.extend(("--" + name.replace("_", "-"), value))
        with patch.object(sys, "argv", arguments):
            self.assertEqual(helper.main(), 0)
        output = self.root / "cli-package"
        arguments = [str(Path(helper.__file__)), "package", "--transfer", args.output,
                     "--output", str(output)]
        with patch.object(sys, "argv", arguments), patch.object(helper.subprocess, "run", side_effect=fake_lipo):
            self.assertEqual(helper.main(), 0)
        self.assertEqual(json.loads((output / "inventory.json").read_bytes())["dependency_inventory"], "unknown")
        self.assertEqual(len(list((output / "thin").iterdir())), 5)

    def test_cli_failures_report_incomplete_and_wrapper_exits_nonzero(self):
        arguments = [str(Path(helper.__file__)), "package", "--transfer",
                     str(self.root / "missing.zip"), "--output", str(self.root / "not-created")]
        error = io.StringIO()
        with patch.object(sys, "argv", arguments), redirect_stderr(error):
            self.assertEqual(helper.main(), 1)
        self.assertIn("unsigned diagnostic incomplete:", error.getvalue())
        self.assertFalse((self.root / "not-created").exists())
        # Execute only this controller-authored Python entry point, never a built file.
        with patch.object(sys, "argv", arguments), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exited:
                runpy.run_path(str(Path(helper.__file__).resolve()), run_name="__main__")
        self.assertEqual(exited.exception.code, 1)
        with patch.object(sys, "argv", [arguments[0], "package"]), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as missing:
                helper.main()
        self.assertEqual(missing.exception.code, 2)
        with patch.object(sys, "argv", [arguments[0], "--help"]), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as helped:
                helper.main()
        self.assertEqual(helped.exception.code, 0)

    def test_regular_file_changes_before_and_during_read_rejected(self):
        target = self.root / "changing"
        target.write_bytes(b"inert")
        original_open = helper.os.open

        def change_before_open(path, flags):
            target.write_bytes(b"changed-size")
            return original_open(path, flags)

        with patch.object(helper.os, "open", side_effect=change_before_open):
            with self.assertRaisesRegex(helper.Invalid, "changed before read"):
                helper.read_file(target, helper.Budget())
        target.write_bytes(b"inert")
        original_fstat = helper.os.fstat

        def truncate_after_fstat(descriptor):
            metadata = original_fstat(descriptor)
            target.write_bytes(b"x")
            return metadata

        with patch.object(helper.os, "fstat", side_effect=truncate_after_fstat):
            with self.assertRaisesRegex(helper.Invalid, "changed during read"):
                helper.read_file(target, helper.Budget())

    def test_small_limits_and_invalid_executable_headers(self):
        with patch.object(helper, "JSON_LIMIT", 8):
            with self.assertRaisesRegex(helper.Invalid, "JSON exceeds limit"):
                helper.json_bytes({"diagnostic": "inert"})
        with patch.object(helper, "FILE_LIMIT", 4):
            with self.assertRaisesRegex(helper.Invalid, "ZIP size exceeds limit"):
                helper.BoundedBuffer().write(b"inert")
        with self.assertRaisesRegex(helper.Invalid, "member size exceeds limit"):
            helper.make_zip({"empty": b""}, helper.Budget())
        for raw in (b"short", bytes(128), inert_thin("windows-amd64")[:80]):
            with self.subTest(bytes=len(raw)), self.assertRaises(helper.Invalid):
                helper.thin_platform(raw)

    def test_zip_directory_and_unexpected_member_rejected(self):
        with self.assertRaisesRegex(helper.Invalid, "directory missing"):
            helper.transfer_members(b"inert-not-a-zip", {"expected"}, helper.Budget())
        original = helper.make_zip({"expected": b"inert"}, helper.Budget())
        directory = original.index(b"PK\x01\x02")
        corrupt = bytearray(original)
        corrupt[directory:directory + 4] = b"bad!"
        with self.assertRaisesRegex(helper.Invalid, "invalid ZIP directory entry"):
            helper.transfer_members(bytes(corrupt), {"expected"}, helper.Budget())
        corrupt = bytearray(original)
        struct.pack_into("<H", corrupt, directory + 32, 1)  # A comment beyond the fixed directory.
        with self.assertRaisesRegex(helper.Invalid, "directory count mismatch"):
            helper.transfer_members(bytes(corrupt), {"expected"}, helper.Budget())
        unexpected = helper.make_zip({"unexpected": b"inert"}, helper.Budget())
        with self.assertRaisesRegex(helper.Invalid, "unsafe transfer member"):
            helper.transfer_members(unexpected, {"expected"}, helper.Budget())

    def test_collect_rejects_changed_pins_paths_headers_and_tree(self):
        args = self.fixture_args()
        paths = Path(args.output_files).read_text().splitlines()
        cases = ((Path(args.output_root), str(self.root), "unexpected Bazel output root"),
                 (Path(args.output_files), "\n".join(paths[:4]), "exactly one output"),
                 (Path(args.workspace) / "VERSION", "1.5.6", "baseline version/tool pin changed"),
                 (Path(args.workspace) / ".bazelversion", "8.0.0", "baseline version/tool pin changed"),
                 (Path(args.source_tree), "not-a-source-tree", "malformed source-tree"),
                 (Path(args.output_files), "\n" + "\n".join(paths[1:]), "invalid Bazel output locator"),
                 (Path(args.output_files), "\n".join([str(Path(args.workspace) / "VERSION"), *paths[1:]]), "output escaped"),
                 (Path(paths[0]), inert_thin("darwin-arm64"), "header differs"))
        for path, changed, message in cases:
            original = path.read_bytes()
            with self.subTest(message=message):
                try:
                    path.write_bytes(changed if isinstance(changed, bytes) else changed.encode())
                    with self.assertRaisesRegex(helper.Invalid, message):
                        helper.collect(args, self.invocation)
                finally:
                    path.write_bytes(original)
        self.assertFalse(Path(args.output).exists())

    def test_package_rejects_diagnostic_identity_tree_and_inventory_changes(self):
        transfer = self.fixture()
        expected = {"thin/" + target for target, _ in helper.TARGETS} | {"build.json"}
        members = helper.transfer_members(transfer.read_bytes(), expected, helper.Budget())
        original = json.loads(members["build.json"])
        cases = (("diagnostic_only", False, "identity/profile mismatch"),
                 ("source_sha", "b" * 40, "identity/profile mismatch"),
                 ("dependency_inventory", "complete", "identity/profile mismatch"),
                 ("source_tree_sha", "bad-tree", "malformed source-tree"),
                 ("files", original["files"][:4], "wrong thin output inventory"))
        for key, value, message in cases:
            with self.subTest(field=key):
                changed = dict(original, **{key: value})
                members["build.json"] = helper.json_bytes(changed)
                transfer.write_bytes(helper.make_zip(members, helper.Budget()))
                with patch.object(helper.subprocess, "run") as run:
                    with self.assertRaisesRegex(helper.Invalid, message):
                        helper.package(argparse.Namespace(transfer=str(transfer), output=str(self.root / "rejected")), self.invocation)
                    run.assert_not_called()
        self.assertFalse((self.root / "rejected").exists())

    def test_tool_version_unknown_and_universal_slice_changes_rejected(self):
        versions = {"bazel": "bazel 7.4.1", "host_go": "go version go1.27.3 darwin/arm64", "python": "Python 3.9.6"}
        for changed in ({}, dict(versions, bazel="bazel 8.0.0"), dict(versions, python=3)):
            with self.subTest(versions=changed), self.assertRaisesRegex(helper.Invalid, "unexpected tool version"):
                helper.tool_versions(changed)
        transfer = self.fixture()

        def changed_lipo(command, corruption):
            fake_lipo(command)
            path = Path(command[3])
            raw = bytearray(path.read_bytes())
            if corruption == "profile":
                raw[0] = 0
            elif corruption == "bounds":
                struct.pack_into(">I", raw, 16, len(raw) + 1)
            else:
                offset = struct.unpack_from(">I", raw, 16)[0]
                raw[offset + 100] ^= 1
            path.write_bytes(raw)

        for corruption, message in (("profile", "unexpected universal"), ("bounds", "invalid universal slice"), ("bytes", "differs from thin bytes")):
            with self.subTest(corruption=corruption):
                output = self.root / ("bad-universal-" + corruption)
                with patch.object(helper.subprocess, "run", side_effect=lambda command, **options: changed_lipo(command, corruption)):
                    with self.assertRaisesRegex(helper.Invalid, message):
                        helper.package(argparse.Namespace(transfer=str(transfer), output=str(output)), self.invocation)
                self.assertFalse((output / "inventory.json").exists())

    def test_current_source_guard_rejects_main_advancing_between_jobs(self):
        workflow = Path(__file__).parent / "shipshape-build-inventory.yml"
        if not workflow.exists():
            workflow = Path(__file__).resolve().parents[1] / ".github/workflows/shipshape-build-inventory.yml"
        text = workflow.read_text()
        python = text.split("          python3 - <<'PY'\n", 1)[1].split("          PY\n", 1)[0]
        code = compile("\n".join(line[10:] for line in python.splitlines()), "<workflow-owned-source-guard>", "exec")
        self.assertEqual(text.count("run: *guard-current-source"), 3)
        event = self.root / "event.json"
        event.write_text(json.dumps({"inputs": {"source_sha": self.env["TRIAL_SOURCE_SHA"]}}))
        os.environ.update(GITHUB_EVENT_PATH=str(event), GITHUB_OUTPUT=str(self.root / "job-output"))

        class Response(io.BytesIO):
            pass

        class Opener:
            def __init__(self, advance):
                self.heads = 0
                self.advance = advance

            def open(inner, request, timeout):
                self.assertTrue(request.full_url.startswith("https://api.github.com/repos/macadmins/osquery-extension"))
                if request.full_url.endswith("/git/ref/heads/main"):
                    inner.heads += 1
                    value = {"object": {"sha": "b" * 40 if inner.advance and inner.heads == 2 else self.env["TRIAL_SOURCE_SHA"]}}
                else:
                    value = {"id": 273057431, "full_name": "macadmins/osquery-extension", "default_branch": "main", "fork": False}
                return Response(json.dumps(value).encode())
        with patch("urllib.request.build_opener", return_value=Opener(False)):
            exec(code, {})
        with patch("urllib.request.build_opener", return_value=Opener(True)):
            with self.assertRaises(SystemExit):
                exec(code, {})


if __name__ == "__main__":
    unittest.main()
