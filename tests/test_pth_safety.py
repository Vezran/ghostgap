"""
Prove that .pth files execute BEFORE any Python user code.

This is the fundamental limitation of any pip-installed Python tool:
CPython's site.py processes .pth files during interpreter startup,
before main() or any entry point runs.

ghostgap-safe.sh solves this by never starting Python until .pth files
are quarantined. The pip-installed `ghostgap` command cannot.
"""

import os
import subprocess
import sys

import pytest


def _venv_paths(venv_dir):
    """Return (site_packages, python_exe) for a venv."""
    if os.name == "nt":
        py_exe = os.path.join(venv_dir, "Scripts", "python.exe")
        site_pkgs = os.path.join(venv_dir, "Lib", "site-packages")
    else:
        py_ver = "python{}.{}".format(sys.version_info[0], sys.version_info[1])
        py_exe = os.path.join(venv_dir, "bin", "python")
        site_pkgs = os.path.join(venv_dir, "lib", py_ver, "site-packages")
    return site_pkgs, py_exe


@pytest.fixture
def venv_with_pth(tmp_path):
    """Create a venv with a .pth file that writes a marker when executed."""
    venv_dir = str(tmp_path / "venv")
    subprocess.run(
        [sys.executable, "-m", "venv", venv_dir],
        check=True,
        capture_output=True,
    )

    site_pkgs, py_exe = _venv_paths(venv_dir)
    marker = str(tmp_path / "pth_proof")

    # Plant a .pth file that creates a marker file on execution
    pth_path = os.path.join(site_pkgs, "test_evil.pth")
    with open(pth_path, "w") as f:
        f.write('import os; open(r"{}","w").write("pwned")\n'.format(marker))

    return py_exe, marker, pth_path


class TestPthExecutesDuringStartup:
    """Prove that .pth import lines run during Python startup."""

    def test_pth_fires_before_user_code(self, venv_with_pth):
        """A .pth import line executes before any user code runs."""
        py_exe, marker, _ = venv_with_pth

        subprocess.run(
            [py_exe, "-c", "pass"],
            capture_output=True,
            timeout=30,
        )

        assert os.path.exists(marker), (
            ".pth file did not execute. CPython's site.py should have "
            "run the import line during startup, before 'pass' executed."
        )
        with open(marker) as f:
            assert f.read() == "pwned"

    def test_S_flag_prevents_pth_execution(self, venv_with_pth):
        """python -S skips site.py entirely, so .pth files never execute.

        This is why ghostgap-safe.sh works: it launches Python with -S
        after quarantining .pth files with bash.
        """
        py_exe, marker, _ = venv_with_pth

        subprocess.run(
            [py_exe, "-S", "-c", "pass"],
            capture_output=True,
            timeout=30,
        )

        assert not os.path.exists(marker), (
            ".pth file executed despite -S flag. This should never happen."
        )


class TestGhostgapEntryPoint:
    """Prove the pip-installed ghostgap command cannot prevent .pth execution."""

    def test_entry_point_triggers_pth(self, venv_with_pth):
        """THE PROOF: running ghostgap triggers .pth before main() starts.

        The old launcher.py claimed:
            'RESULT: .pth executable lines NEVER run. Zero data stolen.'

        This test proves that claim was false for the pip-installed command.
        """
        py_exe, marker, _ = venv_with_pth

        # Install ghostgap into the venv
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        subprocess.run(
            [py_exe, "-m", "pip", "install", "-q", repo_root],
            capture_output=True,
            timeout=120,
        )

        # Run ghostgap — .pth fires during Python startup, before main()
        subprocess.run(
            [py_exe, "-m", "ghostgap.launcher"],
            capture_output=True,
            timeout=30,
        )

        assert os.path.exists(marker), (
            "Expected .pth to execute before ghostgap's main(). "
            "If this fails, either CPython changed .pth behavior, or "
            "the test venv is misconfigured."
        )
        with open(marker) as f:
            assert f.read() == "pwned"

    def test_safe_sh_approach_blocks_pth(self, venv_with_pth):
        """ghostgap-safe.sh's approach (bash quarantine + python -S) works.

        This validates the safe path: quarantine .pth with system tools,
        then launch Python with -S so no .pth code ever runs.
        """
        py_exe, marker, pth_path = venv_with_pth

        # Simulate what ghostgap-safe.sh does: remove .pth, then python -S
        os.unlink(pth_path)

        subprocess.run(
            [py_exe, "-S", "-c", "pass"],
            capture_output=True,
            timeout=30,
        )

        assert not os.path.exists(marker), (
            "Marker exists after quarantine + -S. The safe approach failed."
        )
