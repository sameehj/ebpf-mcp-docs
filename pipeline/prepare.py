from pathlib import Path
import subprocess
import sys
from collectors.collect_kernel_samples import KernelSamplesCollector

LINUX_REPO_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
DEFAULT_VERSION = "v6.1"
KERNEL_DIR = Path("sources/linux")
EXAMPLES_DIR = Path("data/examples")


def fetch_kernel(version=DEFAULT_VERSION):
    if KERNEL_DIR.exists():
        print(f"✅ Kernel source already exists at {KERNEL_DIR}")
    else:
        print(f"📥 Cloning Linux kernel {version}…")
        KERNEL_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            "git", "clone", "--depth=1", "--branch", version,
            LINUX_REPO_URL,
            str(KERNEL_DIR)
        ], check=True)
        print(f"🎉 Kernel {version} cloned into {KERNEL_DIR}")
        return

    # Check the current version
    res = subprocess.run(["git", "-C", str(KERNEL_DIR), "describe", "--tags"], capture_output=True, text=True)
    current = res.stdout.strip()
    if current != version:
        print(f"🔄 Checking out kernel version {version}…")
        subprocess.run(["git", "-C", str(KERNEL_DIR), "fetch", "--tags"], check=True)
        subprocess.run(["git", "-C", str(KERNEL_DIR), "checkout", version], check=True)
    else:
        print(f"✅ Kernel is already at desired version: {version}")


def main():
    version = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_VERSION

    fetch_kernel(version)

    print(f"🔍 Collecting kernel samples from {version}…")
    collector = KernelSamplesCollector(
        kernel_path=KERNEL_DIR,
        output_path=EXAMPLES_DIR
    )
    collector.collect()
    print(f"🎯 Done. Examples collected in {EXAMPLES_DIR}")


if __name__ == "__main__":
    main()
