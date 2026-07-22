from __future__ import annotations

import subprocess
import sys
import unittest

from backend.remote_gateway import (
    BoundedProcessResult,
    INSPECTION_REMOTE_COMMAND,
    MAX_INSPECTION_STDOUT,
    NasEnvironmentInspector,
    NasCompatibilityEvaluator,
    NasCompatibilityPolicy,
    NasInspectionRequest,
    parse_inspection_output,
    render_inspection_script,
    run_bounded_process,
    ssh_inspection_command,
)


def _valid_output(**overrides: str) -> bytes:
    values = {
        "protocol": "guardian-nas-inspection-v1",
        "architecture": "x86_64",
        "kernel_name": "Linux",
        "kernel_release": "6.1.0",
        "os_id": "fixtureos",
        "os_version": "1.0",
        "python_command": "python3",
        "python_version": "Python 3.12.1",
        "glibc_version": "glibc 2.36",
        "openssl_version": "OpenSSL 3.0.11",
        "supervisor": "systemd_user",
        "current_user": "fixture-user",
        "home": "/home/fixture-user",
        "data_port_state": "not_listening",
        "control_port_state": "not_listening",
        "disk_total_kib": "1048576",
        "disk_available_kib": "524288",
        "memory_total_kib": "2097152",
        "memory_available_kib": "1048576",
        "stdin_mode": "script_ok",
    }
    values.update(overrides)
    lines = ["GUARDIAN_NAS_INSPECTION_BEGIN"]
    lines.extend(f"{key}={value}" for key, value in values.items())
    lines.append("GUARDIAN_NAS_INSPECTION_END")
    return ("\n".join(lines) + "\n").encode("utf-8")


class RecordingRunner:
    def __init__(self, result: BoundedProcessResult) -> None:
        self.result = result
        self.calls: list[tuple[list[str], bytes, float, int, int]] = []

    def __call__(
        self,
        command: object,
        input_payload: bytes,
        timeout: float,
        max_stdout: int,
        max_stderr: int,
    ) -> BoundedProcessResult:
        self.calls.append((list(command), input_payload, timeout, max_stdout, max_stderr))
        return self.result


class RemoteGatewayInspectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.host = {
            "target": "fixture-nas",
            "port": 2222,
            "display_name": "Fixture NAS",
            "host_id": "fixture-host",
        }
        self.request = NasInspectionRequest(data_port=43117, control_port=43118)

    def test_fixed_command_and_approved_stdin_have_no_sensitive_paths(self) -> None:
        runner = RecordingRunner(
            BoundedProcessResult(returncode=0, stdout=_valid_output(), stderr=b"")
        )
        result = NasEnvironmentInspector(runner=runner).inspect(self.host, self.request)
        self.assertTrue(result["ok"])
        self.assertEqual(len(runner.calls), 1)
        command, script, _timeout, max_stdout, max_stderr = runner.calls[0]
        self.assertEqual(command[-1], INSPECTION_REMOTE_COMMAND)
        self.assertEqual(command, ssh_inspection_command(self.host))
        self.assertIn(b"port_state 43117", script)
        self.assertIn(b"port_state 43118", script)
        self.assertIn(b'guardian-nas-inspection-v1" ] || exit 64', script)
        joined = b"\0".join(part.encode() for part in command) + b"\0" + script
        lowered = joined.lower()
        for forbidden in (
            b"authorization",
            b"bearer ",
            b"api-key",
            b".codex",
            b"sessions",
            b"archived_sessions",
            b"state_5.sqlite",
            b"session_index",
        ):
            self.assertNotIn(forbidden, lowered)
        self.assertLessEqual(max_stdout, MAX_INSPECTION_STDOUT)
        self.assertLessEqual(max_stderr, 8 * 1024)

    def test_script_contains_no_remote_write_or_service_mutation_commands(self) -> None:
        script = render_inspection_script(self.request).decode("utf-8")
        lowered = script.lower()
        for forbidden in (
            "systemctl start",
            "systemctl stop",
            "systemctl restart",
            "systemctl enable",
            "systemctl disable",
            "mkdir ",
            "chmod ",
            "chown ",
            "rm ",
            "mv ",
            "cp ",
            "> /",
            ">~/",
        ):
            self.assertNotIn(forbidden, lowered)

    def test_parser_accepts_only_allowlisted_projection(self) -> None:
        parsed = parse_inspection_output(_valid_output())
        self.assertEqual(parsed["architecture"], "x86_64")
        self.assertEqual(parsed["disk_available_kib"], 524288)
        self.assertEqual(parsed["supervisor"], "systemd_user")
        self.assertNotIn("stderr", parsed)
        self.assertNotIn("command", parsed)

    def test_malformed_host_output_and_command_injection_fail_closed(self) -> None:
        runner = RecordingRunner(
            BoundedProcessResult(returncode=0, stdout=b"hostile\n", stderr=b"")
        )
        malformed = NasEnvironmentInspector(runner=runner).inspect(self.host, self.request)
        self.assertEqual(malformed["error_code"], "nas_inspection_output_invalid")

        hostile_host = dict(self.host, target="fixture; touch /tmp/owned")
        rejected = NasEnvironmentInspector(runner=runner).inspect(hostile_host, self.request)
        self.assertEqual(rejected["error_code"], "nas_inspection_host_invalid")
        self.assertEqual(len(runner.calls), 1)

        option_host = dict(self.host, target="-oProxyCommand=hostile")
        rejected = NasEnvironmentInspector(runner=runner).inspect(option_host, self.request)
        self.assertEqual(rejected["error_code"], "nas_inspection_host_invalid")
        self.assertEqual(len(runner.calls), 1)

        hostile_label = dict(self.host, display_name="NAS\r\nforged", host_id="id\x00tail")
        sanitized = NasEnvironmentInspector(
            runner=RecordingRunner(
                BoundedProcessResult(returncode=0, stdout=_valid_output(), stderr=b"")
            )
        ).inspect(hostile_label, self.request)
        self.assertEqual(sanitized["display_name"], "NAS forged")
        self.assertEqual(sanitized["host_id"], "id tail")

    def test_hostile_values_unknown_keys_and_oversize_are_rejected(self) -> None:
        hostile = _valid_output(home="/home/user$(touch bad)")
        result = NasEnvironmentInspector(
            runner=RecordingRunner(
                BoundedProcessResult(returncode=0, stdout=hostile, stderr=b"")
            )
        ).inspect(self.host, self.request)
        self.assertEqual(result["error_code"], "nas_inspection_output_invalid")

        unknown = _valid_output().replace(
            b"GUARDIAN_NAS_INSPECTION_END",
            b"secret=value\nGUARDIAN_NAS_INSPECTION_END",
        )
        result = NasEnvironmentInspector(
            runner=RecordingRunner(
                BoundedProcessResult(returncode=0, stdout=unknown, stderr=b"")
            )
        ).inspect(self.host, self.request)
        self.assertEqual(result["error_code"], "nas_inspection_output_invalid")

        result = NasEnvironmentInspector(
            runner=RecordingRunner(
                BoundedProcessResult(
                    returncode=0,
                    stdout=b"x" * MAX_INSPECTION_STDOUT,
                    stderr=b"",
                    stdout_truncated=True,
                )
            )
        ).inspect(self.host, self.request)
        self.assertEqual(result["error_code"], "nas_inspection_output_too_large")

    def test_timeout_nonzero_and_hostile_stderr_return_stable_codes(self) -> None:
        timeout = NasEnvironmentInspector(
            runner=RecordingRunner(
                BoundedProcessResult(
                    returncode=-9,
                    stdout=b"",
                    stderr=b"secret-bearing remote text",
                    timed_out=True,
                )
            )
        ).inspect(self.host, self.request)
        self.assertEqual(timeout["error_code"], "nas_inspection_timeout")
        self.assertNotIn("stderr", timeout)

        failed = NasEnvironmentInspector(
            runner=RecordingRunner(
                BoundedProcessResult(
                    returncode=255,
                    stdout=b"",
                    stderr=b"Authorization: Bearer fixture-secret",
                )
            )
        ).inspect(self.host, self.request)
        self.assertEqual(failed["error_code"], "nas_inspection_ssh_failed")
        self.assertNotIn("fixture-secret", str(failed))

    def test_invalid_ports_never_reach_runner(self) -> None:
        with self.assertRaisesRegex(ValueError, "nas_inspection_port_invalid"):
            NasInspectionRequest(data_port=22, control_port=43118)
        with self.assertRaisesRegex(ValueError, "nas_inspection_ports_must_differ"):
            NasInspectionRequest(data_port=43117, control_port=43117)

    def test_compatibility_requires_every_deployment_precondition(self) -> None:
        environment = parse_inspection_output(
            _valid_output(
                current_user="guardian",
                home="/home/guardian",
            )
        )
        decision = NasCompatibilityEvaluator().evaluate(environment)
        self.assertTrue(decision.compatible)
        self.assertEqual(decision.package_mode, "locked_venv")
        self.assertEqual(decision.supervisor, "systemd_user")
        self.assertEqual(decision.blockers, ())
        self.assertEqual(
            set(decision.as_public_document()),
            {"compatible", "package_mode", "supervisor", "blockers"},
        )

        cron_environment = parse_inspection_output(
            _valid_output(
                current_user="guardian",
                home="/home/guardian",
                supervisor="cron_user",
            )
        )
        cron_decision = NasCompatibilityEvaluator().evaluate(cron_environment)
        self.assertTrue(cron_decision.compatible)
        self.assertEqual(cron_decision.supervisor, "cron_user")

    def test_compatibility_unknown_or_unsafe_values_fail_closed(self) -> None:
        environment = parse_inspection_output(
            _valid_output(
                architecture="armv7l",
                python_version="Python 3.10.14",
                glibc_version="unknown",
                openssl_version="unknown",
                supervisor="unknown",
                current_user="root",
                home="/root",
                data_port_state="unknown",
                control_port_state="listening",
                disk_available_kib="1024",
                memory_available_kib="1024",
            )
        )
        decision = NasCompatibilityEvaluator().evaluate(environment)
        self.assertFalse(decision.compatible)
        self.assertIsNone(decision.package_mode)
        self.assertIsNone(decision.supervisor)
        self.assertEqual(
            decision.blockers,
            (
                "nas_architecture_unsupported",
                "nas_python_unsupported",
                "nas_glibc_unverified",
                "nas_openssl_unverified",
                "nas_supervisor_unsupported",
                "nas_data_port_unavailable",
                "nas_control_port_unavailable",
                "nas_service_user_unsupported",
                "nas_disk_insufficient",
                "nas_memory_insufficient",
            ),
        )

    def test_compatibility_policy_is_explicit_and_bounded(self) -> None:
        with self.assertRaisesRegex(ValueError, "nas_compatibility_python_policy_invalid"):
            NasCompatibilityPolicy(minimum_python=(2, 7))
        with self.assertRaisesRegex(ValueError, "nas_compatibility_resource_policy_invalid"):
            NasCompatibilityPolicy(minimum_disk_available_kib=0)

    def test_bounded_runner_limits_output_and_timeout(self) -> None:
        output = run_bounded_process(
            [sys.executable, "-c", "import sys; sys.stdin.buffer.read(); sys.stdout.write('x' * 64)"],
            b"approved-stdin",
            5,
            16,
            16,
        )
        self.assertEqual(output.returncode, 0)
        self.assertEqual(len(output.stdout), 16)
        self.assertTrue(output.stdout_truncated)

        timed_out = run_bounded_process(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            b"",
            0.05,
            16,
            16,
        )
        self.assertTrue(timed_out.timed_out)
        self.assertNotEqual(timed_out.returncode, 0)


if __name__ == "__main__":
    unittest.main()
