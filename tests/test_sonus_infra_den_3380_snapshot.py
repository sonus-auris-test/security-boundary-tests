from __future__ import annotations

import hashlib
import json
import pathlib
import re
import stat
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "sonus-infra-den-3380"
MANIFEST_PATH = FIXTURE / "source-manifest.json"
EXPECTED_COMMIT = "1e08ff61066e3b19b83fb41661b12db069e2de85"
EXPECTED_TREE = "616acb176fb6dc1fba5b3a4ab6965994770d3712"


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


class SonusInfraDen3380SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_source_provenance_is_immutable(self) -> None:
        self.assertEqual(
            self.manifest["source_repository"],
            "sonus-auris/sonus-auris.infra",
        )
        self.assertEqual(self.manifest["source_visibility"], "private")
        self.assertEqual(self.manifest["source_pull_request"], 5)
        self.assertEqual(self.manifest["linear_issue"], "DEN-3380")
        self.assertEqual(self.manifest["source_commit"], EXPECTED_COMMIT)
        self.assertEqual(self.manifest["source_tree"], EXPECTED_TREE)

    def test_every_snapshot_file_matches_its_source_git_blob_and_mode(self) -> None:
        for relative, evidence in self.manifest["files"].items():
            with self.subTest(path=relative):
                path = FIXTURE / relative
                self.assertTrue(path.is_file(), f"missing snapshot file: {relative}")
                self.assertEqual(git_blob_sha(path.read_bytes()), evidence["blob"])
                executable = bool(path.stat().st_mode & stat.S_IXUSR)
                self.assertEqual(executable, evidence["mode"] == "100755")

    def test_shell_sources_parse(self) -> None:
        subprocess.run(
            [
                "bash",
                "-n",
                str(FIXTURE / "scripts" / "_env-lib"),
                str(FIXTURE / "scripts" / "cf-tunnel"),
            ],
            check=True,
        )

    def test_dotenv_loader_preserves_spaces_and_never_executes_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = pathlib.Path(directory)
            env_file = directory_path / "test.env"
            marker = directory_path / "must-not-exist"
            env_file.write_text(
                "TUNNEL_INGRESS=api-dev=http://localhost:8088 "
                "web-dev=http://localhost:8099\n"
                f"UNTRUSTED=$(touch {marker})\n"
                "QUOTED='value with spaces'\n"
                "DOUBLE_QUOTED=\"another value with spaces\"\n",
                encoding="utf-8",
            )
            command = (
                'source "$1"; load_env_file "$2"; '
                "printf '%s\\n%s\\n%s\\n%s\\n' \"$TUNNEL_INGRESS\" "
                '"$UNTRUSTED" "$QUOTED" "$DOUBLE_QUOTED"'
            )
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    command,
                    "bash",
                    str(FIXTURE / "scripts" / "_env-lib"),
                    str(env_file),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                result.stdout.splitlines(),
                [
                    "api-dev=http://localhost:8088 web-dev=http://localhost:8099",
                    f"$(touch {marker})",
                    "value with spaces",
                    "another value with spaces",
                ],
            )
            self.assertFalse(marker.exists())

    def test_dotenv_loader_rejects_non_assignment_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = pathlib.Path(directory) / "invalid.env"
            env_file.write_text("VALID=value\nprintf pwned\n", encoding="utf-8")
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; load_env_file "$2"',
                    "bash",
                    str(FIXTURE / "scripts" / "_env-lib"),
                    str(env_file),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid dotenv assignment", result.stderr)
            self.assertNotIn("pwned", result.stdout)

    def test_agent_compatibility_files_are_pointers_only(self) -> None:
        root_pointer = (
            "# Canonical agent instructions\n\n"
            "Read and apply [`agents.md`](agents.md). This compatibility file "
            "must not duplicate repository instructions.\n"
        )
        nested_pointer = (
            "# Canonical agent instructions\n\n"
            "Read and apply [`../agents.md`](../agents.md). Do not duplicate "
            "repository instructions here.\n"
        )
        self.assertEqual(
            (FIXTURE / "AGENTS.md").read_text(encoding="utf-8"), root_pointer
        )
        for relative in (
            ".claude/CLAUDE.md",
            ".gemini/GEMINI.md",
            ".openai/AGENTS.md",
        ):
            self.assertEqual(
                (FIXTURE / relative).read_text(encoding="utf-8"), nested_pointer
            )
        canonical = (FIXTURE / "agents.md").read_text(encoding="utf-8")
        self.assertIn("Resolve conflicts semantically", canonical)
        self.assertIn("git fetch --all --prune", canonical)
        self.assertGreater(len(canonical), len(root_pointer) * 10)

    def test_tunnel_process_ownership_is_checkout_scoped(self) -> None:
        script = (FIXTURE / "scripts" / "cf-tunnel").read_text(encoding="utf-8")
        managed = re.search(
            r"(?ms)^managed_tunnel_pid\(\) \{\n(?P<body>.*?)^\}", script
        )
        self.assertIsNotNone(managed)
        body = managed.group("body")
        self.assertIn('pid_file="$state_dir/cloudflared.pid"', script)
        self.assertIn('[[ "$pid" =~ ^[0-9]+$ ]]', body)
        self.assertIn('kill -0 "$pid"', body)
        self.assertIn('ps -ww -p "$pid" -o command=', body)
        self.assertIn('"--token-file $state_dir/token"', body)
        self.assertNotIn("pgrep", script)
        self.assertNotIn("pkill -f", script)

        down = re.search(r"(?ms)^cmd_down\(\) \{\n(?P<body>.*?)^\}", script)
        self.assertIsNotNone(down)
        down_body = down.group("body")
        self.assertIn('pid="$(managed_tunnel_pid)"', down_body)
        self.assertIn('kill -TERM "$pid"', down_body)
        self.assertNotIn("pgrep", down_body)
        self.assertNotIn("pkill", down_body)

    def test_tunnel_credential_never_appears_in_cloudflared_argv(self) -> None:
        script = (FIXTURE / "scripts" / "cf-tunnel").read_text(encoding="utf-8")
        self.assertIn('install -m 600 /dev/null "$state_dir/token"', script)
        self.assertIn(
            'cloudflared tunnel run --token-file "$state_dir/token"', script
        )
        self.assertNotRegex(script, r"cloudflared\s+tunnel\s+run\s+--token(?:\s|=)")

    def test_public_origin_preflight_remains_fail_closed(self) -> None:
        script = (FIXTURE / "scripts" / "cf-tunnel").read_text(encoding="utf-8")
        self.assertIn("preflight_origins", script)
        self.assertIn("SOUND_RECORDER_ALLOW_PUBLIC_DEVICE_REGISTRATION=false", script)
        self.assertIn("TUNNEL_ALLOW_OPEN_ORIGIN=1", script)
        self.assertIn('die "preflight failed; tunnel not started"', script)

    def test_snapshot_contains_no_credential_literal(self) -> None:
        credential = re.compile(
            r"(?:ghp_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}|"
            r"cfat_[A-Za-z0-9_-]{20,})"
        )
        for relative in self.manifest["files"]:
            path = FIXTURE / relative
            self.assertIsNone(credential.search(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
