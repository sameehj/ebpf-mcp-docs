from collectors.collect_kernel_samples import KernelSamplesCollector
from pathlib import Path

if __name__ == "__main__":
    collector = KernelSamplesCollector(
        kernel_path=Path("sources/linux"),
        output_path=Path("data/examples")
    )
    collector.collect()
