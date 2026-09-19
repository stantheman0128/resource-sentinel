import importlib.util
import unittest
from pathlib import Path

from sentinel.command_classification import classify_command, is_single_static_command


ROOT = Path(__file__).resolve().parents[1]


class CommandClassificationTests(unittest.TestCase):
    def assert_commands(self, expected, commands, **kwargs):
        for command in commands:
            with self.subTest(command=command, **kwargs):
                self.assertEqual(classify_command(command, **kwargs), expected)

    def test_data_arguments_are_light_even_with_legacy_gradle_pattern(self):
        commands = [
            'git show branch:app/build.gradle.kts',
            'git add app/build.gradle.kts',
            'git -C "C:/Projects/gradle repo" show branch:app/build.gradle.kts',
            'git --no-pager diff -- app/build.gradle.kts',
            'ls ~/.gradle/jdks',
            'cat app/build.gradle.kts',
            'grep -n gradle README.md',
            'rg "npm run build|gradle|pytest" docs',
            'echo "gradle && npm run build"',
            "printf '%s' 'cargo build --release'",
            'git log --grep="gradle"', 'git grep gradle -- app/build.gradle.kts',
        ]
        self.assert_commands('LIGHT', commands)
        self.assert_commands('LIGHT', commands, heavy_patterns=[r'gradle', r'pytest', r'npm\s+run\s+build'])

    def test_actual_gradle_executables_are_heavy(self):
        self.assert_commands('HEAVY', [
            'gradle assembleDebug', 'gradlew test', './gradlew.bat assemble',
            r'.\gradlew.bat test', r'C:\Tools\gradle\bin\gradle.bat build',
            r'"C:\Program Files\Gradle\gradle.exe" build',
            r'& "C:\Program Files\Gradle\gradle.exe" build',
        ])

    def test_shell_wrappers_preserve_real_execution(self):
        self.assert_commands('HEAVY', [
            'cmd /c gradlew.bat build', 'cmd /d /s /c "gradle build"',
            "bash -c 'gradle build'", "bash -lc './gradlew test'",
            "bash --noprofile --norc -c 'cd app && ./gradlew.bat test'",
            'pwsh -NoProfile -Command "gradle build"',
            "env JAVA_HOME=/jdk gradle build", "command gradle build",
            "nohup gradle build", "exec gradle build",
        ])
        self.assert_commands('LIGHT', [
            'cmd /c git show branch:app/build.gradle.kts',
            "bash -lc 'git show branch:app/build.gradle.kts'",
            'pwsh -NoProfile -Command "cat app/build.gradle.kts"',
        ], heavy_patterns=['gradle'])

    def test_each_chain_branch_is_classified(self):
        self.assert_commands('HEAVY', [
            'git status && gradle build', 'git status||gradle test',
            'ls ~/.gradle;./gradlew.bat build', 'echo x | gradle build',
            'git status\ngradle build', 'git status & gradle build',
            "bash -c 'git status && gradle build'",
        ])
        self.assert_commands('LIGHT', [
            'git status && cat app/build.gradle.kts',
            'git show branch:build.gradle.kts | grep gradle',
            "echo 'gradle && npm run build' # gradle build",
        ], heavy_patterns=['gradle'])

    def test_existing_resource_tiers(self):
        self.assert_commands('EXTREME', [
            'docker compose up --build', 'cargo build --release',
            'playwright test --project chromium',
            'npx --yes playwright test --workers=2',
            'pnpm exec playwright test --project=chromium',
            'git status && cargo build --release',
            'cargo build --release --target-dir "$BUILD_DIR"',
            'docker compose up --build "$SERVICE"',
            'playwright test --workers="$WORKERS"',
            'cargo +stable build --release',
            'docker --context desktop-linux compose up --build',
            'docker compose --project-name app up --build',
        ])
        self.assert_commands('HEAVY', [
            'npm install', 'pnpm install', 'yarn install', 'bun install',
            'npm run build', 'npm run test', 'cargo build', 'go test ./...',
            'dotnet restore', 'pytest tests/', 'python -m pytest tests/',
            'py -I -m pytest tests/', 'jest', 'vitest', 'vite build', 'tsc',
            'docker build .', 'mvn package', 'cmake --build build',
        ])
        self.assert_commands('MEDIUM', [
            'pytest tests/a.py::test_x', 'pytest -k selected tests/',
            'python -m pytest tests/a.py::test_x', 'py -m pytest -k=one tests/',
            'npm run lint', 'pnpm run typecheck',
        ])

    def test_custom_patterns_apply_to_execution_semantics(self):
        self.assertEqual(classify_command('git status', [r'^git\s+status$']), 'HEAVY')
        self.assertEqual(classify_command('git show status', [r'^git\s+status$']), 'LIGHT')
        self.assertEqual(classify_command('cat pytest', [r'pytest']), 'LIGHT')
        self.assertEqual(classify_command('pytest one::test', [r'pytest']), 'HEAVY')
        self.assertEqual(classify_command('bash -c "git status"', [r'^bash$']), 'HEAVY')

    def test_bad_patterns_fail_closed_without_exceptions(self):
        for patterns in ('gradle', ['['], [None], ['x' * 257], ['x'] * 65, [r'(a+)+$']):
            with self.subTest(patterns=patterns):
                self.assertEqual(classify_command('git status', patterns), 'HEAVY')
                self.assertEqual(classify_command('docker compose up --build', patterns), 'EXTREME')

    def test_unknown_or_dynamic_shell_syntax_is_not_light(self):
        self.assert_commands('HEAVY', [
            'bash -c', "bash -c 'unclosed", 'bash script.sh',
            'cmd /v:on /c !COMMAND!', 'cmd /c', 'cmd /c echo %COMMAND%',
            'python -c "import subprocess"', 'python arbitrary.py',
            'powershell -EncodedCommand abc', 'pwsh -File other.ps1',
            'eval "gradle build"', 'xargs gradle', 'find . -exec gradle {} ;',
            'echo $(gradle build)', 'echo "$(gradle build)"',
            'echo `gradle build`', 'git -c alias.foo=!gradle foo',
            'git diff --ext-diff', r'gra^dle build', 'unknown-wrapper gradle',
            'echo x > result.txt', 'a' * 16_385,
            'cmd /c "echo # & gradle build"', 'echo # & gradle build',
            '''cmd /c "echo '& gradle build & echo '"''',
            'rg --pre gradle .', 'sort --compress-program=gradle file',
        ])
        self.assertEqual(classify_command(None), 'HEAVY')

    def test_wrapper_depth_is_bounded(self):
        self.assertEqual(classify_command('env ' * 100 + 'git status'), 'HEAVY')


    def test_trusted_wrapper_boundary_requires_one_static_command(self):
        wrapper = ROOT / 'scripts' / 'invoke-sentinel.ps1'
        command = f'powershell -NoProfile -File "{wrapper}" -Command "git status && gradle build"'
        self.assertTrue(is_single_static_command(command))
        self.assertTrue(is_single_static_command('& ' + command))
        for suffix in ('&&gradlew build', ';gradlew build', '|gradlew build', '\ngradlew build'):
            with self.subTest(suffix=suffix):
                self.assertFalse(is_single_static_command(command + suffix))
        self.assertFalse(is_single_static_command('echo $(gradle build)'))

    def test_cmd_dialect_does_not_treat_single_quotes_as_protection(self):
        command = "echo '& gradle build & echo '"
        self.assertEqual(classify_command(command), 'LIGHT')
        self.assertEqual(classify_command(command, shell='cmd'), 'HEAVY')
        self.assertEqual(classify_command("echo '& cargo build --release & echo '", shell='cmd'), 'EXTREME')
        self.assert_commands('HEAVY', [
            'echo # & gradle build', 'echo %COMMAND%',
            'cmd /c "echo %COMMAND%"',
        ], shell='cmd')
        self.assert_commands('LIGHT', [
            'git show branch:app/build.gradle.kts', 'git add app/build.gradle.kts',
            'git grep gradle -- app/build.gradle.kts', r'dir C:\gradle\jdks',
        ], shell='cmd', heavy_patterns=['gradle'])
        self.assertEqual(classify_command('git status', shell='unknown'), 'HEAVY')

    def test_explicit_cmd_payload_is_reparsed_before_quotes_are_lost(self):
        self.assert_commands('HEAVY', [
            "cmd /c \"echo '& gradle build & echo '\"",
            "cmd /c echo '& gradle build & echo '",
        ])
        self.assert_commands('LIGHT', [
            "cmd /c 'git show branch:app/build.gradle.kts'",
            "bash -lc 'cat app/build.gradle.kts'",
            "bash -lc 'ls ~/.gradle/jdks'",
        ])
        self.assertEqual(classify_command('cmd /c "echo # & cargo build --release"'), 'EXTREME')

    def test_git_grep_pager_options_require_admission(self):
        self.assert_commands('HEAVY', [
            'git grep -O gradle', 'git grep -Onpm gradle',
            'git grep --open-files-in-pager gradle',
            'git grep --open-files-in-pager=gradle pattern',
        ])
        self.assert_commands('LIGHT', [
            'git grep -o gradle', 'git grep -- -Ogradle',
            'git grep gradle -- app/build.gradle.kts',
        ])

    def test_atomic_wrapper_cannot_be_a_fake_file_argument(self):
        spec = importlib.util.spec_from_file_location(
            'sentinel_gate_command_classification_test', ROOT / 'hooks' / 'sentinel-gate.py')
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        self.assertEqual(gate.PROJECT, ROOT)
        wrapper = gate.ATOMIC_WRAPPER
        legitimate = f'powershell -NoProfile -ExecutionPolicy Bypass -File "{wrapper}" -Command "git status"'
        self.assertTrue(gate.is_atomic_wrapper(legitimate))
        self.assertTrue(gate.is_atomic_wrapper(legitimate.replace(
            'powershell ', 'pwsh -WindowStyle Hidden ')))
        for command in [
            f'powershell -Command gradle -File "{wrapper}"',
            f'powershell -c gradle -File "{wrapper}"',
            f'powershell -EncodedCommand ZwByAGEAZABsAGUA -File "{wrapper}"',
            f'pwsh -enc ZwByAGEAZABsAGUA -File "{wrapper}"',
            f'powershell other.ps1 -File "{wrapper}"',
            f'powershell -ExecutionPolicy -File "{wrapper}"',
            legitimate + '&&gradlew build', legitimate + ';gradlew build',
        ]:
            with self.subTest(command=command):
                self.assertFalse(gate.is_atomic_wrapper(command))

    def test_queue_escape_hatches_require_exact_repo_script(self):
        cli = ROOT / 'scripts' / 'sentinelctl.py'
        waiter = ROOT / 'scripts' / 'wait-slot.ps1'
        cancel = f'py "{cli}" cancel --request-key {"a" * 64} --owner-pid 42'
        wait = f'py "{cli}" wait-existing --request-key {"a" * 64}'
        ps_wait = f'powershell -NoProfile -ExecutionPolicy Bypass -File "{waiter}" -RequestId {"a" * 64}'
        self.assert_commands('LIGHT', [cancel, wait, ps_wait])
        self.assert_commands('HEAVY', [
            cancel + ' && gradle build', ps_wait + ' ; npm run build',
            'py C:/other/scripts/sentinelctl.py cancel --owner-pid 42',
            'py sentinelctl.py cancel --owner-pid 42',
            f'py "{cli}" run --command "gradle build"',
            'powershell -File C:/other/wait-slot.ps1',
        ])


if __name__ == '__main__':
    unittest.main()
