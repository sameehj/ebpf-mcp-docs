from pathlib import Path
from collectors.multi_kernel_collector import MultiKernelCollector


def main():
    base_path = Path(".")
    mkc = MultiKernelCollector(base_path)

    print("🚀 Starting Multi-Kernel Collection…")
    mkc.collect_all_versions()

    print("\n📊 Generating compatibility matrix…")
    matrix = mkc.generate_compatibility_matrix()

    print(f"\n✅ Multi-kernel collection complete.")
    print(f"📈 Success rates:")
    for version, stats in matrix.items():
        rate = stats.get("success_rate", 0) * 100
        print(f"  Kernel {version}: {rate:.1f}% success ({stats['compatible']}/{stats['total']})")


if __name__ == "__main__":
    main()
