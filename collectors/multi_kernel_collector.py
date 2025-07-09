from pathlib import Path
import json
import subprocess
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import tempfile
import os
import re
from datetime import datetime
from common.utils import (
    extract_helpers,
    extract_includes,
    extract_program_type,
    uses_btf,
    uses_co_re,
)


@dataclass
class KernelVersion:
    version: str
    tag: str
    features: Dict[str, bool]
    btf_support: Dict[str, bool]
    stable: bool


class MultiKernelCollector:
    """Collect and validate eBPF programs across multiple kernel versions"""
    
    SUPPORTED_KERNELS = [
        KernelVersion("4.18", "v4.18", {"xdp": True, "kprobe": True, "btf": False}, 
                     {"kernel_btf": False, "co_re": False, "vmlinux_btf": False}, True),
        KernelVersion("5.4", "v5.4", {"xdp": True, "kprobe": True, "btf": True}, 
                     {"kernel_btf": True, "co_re": True, "vmlinux_btf": True}, True),
        KernelVersion("5.15", "v5.15", {"xdp": True, "kprobe": True, "btf": True}, 
                     {"kernel_btf": True, "co_re": True, "vmlinux_btf": True}, True),
        KernelVersion("6.1", "v6.1", {"xdp": True, "kprobe": True, "btf": True}, 
                     {"kernel_btf": True, "co_re": True, "vmlinux_btf": True}, True),
        KernelVersion("6.8", "v6.8", {"xdp": True, "kprobe": True, "btf": True}, 
                     {"kernel_btf": True, "co_re": True, "vmlinux_btf": True}, False),
    ]
    
    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.sources_path = base_path / "sources"
        self.data_path = base_path / "data"
        self.cache_path = base_path / "cache"
        
        # Create directories
        for path in [self.sources_path, self.data_path, self.cache_path]:
            path.mkdir(parents=True, exist_ok=True)
    
    def collect_all_versions(self):
        """Collect data from all supported kernel versions"""
        print("🔄 Starting multi-kernel collection...")
        
        for kernel in self.SUPPORTED_KERNELS:
            print(f"\n📦 Processing kernel {kernel.version}...")
            
            try:
                # Setup kernel source
                kernel_path = self.setup_kernel_source(kernel)
                
                # Collect version-specific data
                version_data = self.collect_version_data(kernel, kernel_path)
                
                # Save results
                self.save_version_data(kernel, version_data)
                
                print(f"✅ Completed kernel {kernel.version}")
                
            except Exception as e:
                print(f"❌ Failed to process kernel {kernel.version}: {e}")
                continue
    
    def setup_kernel_source(self, kernel: KernelVersion) -> Path:
        """Setup kernel source for specific version"""
        kernel_path = self.sources_path / f"linux-{kernel.version}"
        
        if not kernel_path.exists():
            print(f"📥 Cloning kernel {kernel.version}...")
            subprocess.run([
                "git", "clone", "--depth=1", "--branch", kernel.tag,
                "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
                str(kernel_path)
            ], check=True)
        else:
            print(f"✅ Kernel {kernel.version} already available")
        
        return kernel_path
    
    def collect_version_data(self, kernel: KernelVersion, kernel_path: Path) -> Dict:
        """Collect comprehensive data for a kernel version"""
        
        # Import the enhanced collector
        from collections import defaultdict
        
        samples_path = kernel_path / "samples" / "bpf"
        programs_data = []
        
        if samples_path.exists():
            c_files = list(samples_path.glob("*.c"))
            print(f"📁 Found {len(c_files)} programs in {kernel.version}")
            
            for c_file in c_files:
                try:
                    program_data = self.analyze_program_for_version(c_file, kernel)
                    programs_data.append(program_data)
                except Exception as e:
                    print(f"⚠️  Error analyzing {c_file.name}: {e}")
        
        # Collect helper information
        helpers_data = self.collect_helper_info(kernel_path, kernel)
        
        # Collect verifier error patterns
        error_patterns = self.collect_error_patterns(kernel)
        
        return {
            "kernel": kernel.version,
            "tag": kernel.tag,
            "features": kernel.features,
            "btf_support": kernel.btf_support,
            "programs": programs_data,
            "helpers": helpers_data,
            "error_patterns": error_patterns,
            "collection_metadata": {
                "timestamp": self.get_timestamp(),
                "total_programs": len(programs_data),
                "successful_programs": len([p for p in programs_data if p.get("valid", False)])
            }
        }
    
    def analyze_program_for_version(self, file_path: Path, kernel: KernelVersion) -> Dict:
        """Analyze a program in context of specific kernel version"""
        
        text = file_path.read_text(encoding='utf-8', errors='ignore')
        
        # Basic analysis
        basic_data = {
            "file_name": file_path.name,
            "program_type": extract_program_type(text),
            "helpers_used": extract_helpers(text),
            "includes": extract_includes(text),
            "uses_btf": uses_btf(text),
            "uses_co_re": uses_co_re(text)
        }
        
        # Version compatibility analysis
        compatibility = self.analyze_compatibility(basic_data, kernel)
        
        return {
            **basic_data,
            "kernel_version": kernel.version,
            "compatibility": compatibility,
            "valid": compatibility["compatible"],
            "issues": compatibility.get("issues", []),
            "alternatives": compatibility.get("alternatives", [])
        }


    def analyze_compatibility(self, program_data: Dict, kernel: KernelVersion) -> Dict:
        """Analyze program compatibility with kernel version"""
        
        issues = []
        alternatives = []
        compatible = True
        
        # Check BTF requirements
        if program_data["uses_btf"] and not kernel.btf_support["kernel_btf"]:
            compatible = False
            issues.append({
                "type": "btf_not_available",
                "message": f"Program uses BTF but kernel {kernel.version} doesn't support it",
                "severity": "high"
            })
            alternatives.append({
                "type": "remove_btf",
                "description": "Rewrite without BTF/CO-RE, use explicit struct definitions"
            })
        
        # Check CO-RE requirements
        if program_data["uses_co_re"] and not kernel.btf_support["co_re"]:
            compatible = False
            issues.append({
                "type": "co_re_not_available", 
                "message": f"Program uses CO-RE but kernel {kernel.version} doesn't support it",
                "severity": "high"
            })
            alternatives.append({
                "type": "remove_co_re",
                "description": "Replace BPF_CORE_READ with bpf_probe_read"
            })
        
        # Check helper availability (simplified)
        unavailable_helpers = []
        for helper in program_data["helpers_used"]:
            if not self.is_helper_available(helper, kernel):
                unavailable_helpers.append(helper)
        
        if unavailable_helpers:
            compatible = False
            issues.append({
                "type": "helper_not_available",
                "message": f"Helpers not available: {', '.join(unavailable_helpers)}",
                "severity": "medium"
            })
        
        return {
            "compatible": compatible,
            "issues": issues,
            "alternatives": alternatives,
            "confidence": 0.8 if compatible else 0.6
        }
    
    def collect_helper_info(self, kernel_path: Path, kernel: KernelVersion) -> Dict:
        """Collect helper function information for kernel version"""
        
        helpers = {}
        
        # Look for helper definitions in kernel source
        helper_files = [
            kernel_path / "kernel" / "bpf" / "helpers.c",
            kernel_path / "net" / "core" / "filter.c",
            kernel_path / "kernel" / "trace" / "bpf_trace.c"
        ]
        
        for helper_file in helper_files:
            if helper_file.exists():
                try:
                    helpers.update(self.parse_helper_definitions(helper_file))
                except Exception as e:
                    print(f"⚠️  Error parsing {helper_file}: {e}")
        
        return helpers
    
    def parse_helper_definitions(self, helper_file: Path) -> Dict:
        """Parse helper function definitions from kernel source"""
        
        helpers = {}
        text = helper_file.read_text(encoding='utf-8', errors='ignore')
        
        # Look for BPF_CALL_* patterns
        call_patterns = re.findall(r'BPF_CALL_\d+\((bpf_[^,]+)', text)
        
        for helper_name in call_patterns:
            # Try to find the function signature
            signature_match = re.search(
                rf'static.*?{re.escape(helper_name)}\s*\([^)]*\)',
                text, re.DOTALL
            )
            
            if signature_match:
                helpers[helper_name] = {
                    "name": helper_name,
                    "signature": signature_match.group(0).strip(),
                    "source_file": helper_file.name
                }
        
        return helpers
    
    def collect_error_patterns(self, kernel: KernelVersion) -> List[Dict]:
        """Collect verifier error patterns for kernel version"""
        
        # This is a simplified version - in practice you'd want to
        # run test programs and collect actual verifier errors
        
        error_patterns = []
        
        # Common error patterns by version
        if kernel.version < "5.4":
            error_patterns.extend([
                {
                    "pattern": "invalid mem access",
                    "kernel_version": kernel.version,
                    "common_cause": "Missing bounds check",
                    "example_fix": "Add bounds check before pointer access"
                },
                {
                    "pattern": "invalid argument",
                    "kernel_version": kernel.version,
                    "common_cause": "Helper function argument type mismatch",
                    "example_fix": "Check helper function signature"
                }
            ])
        
        if kernel.version >= "5.4":
            error_patterns.extend([
                {
                    "pattern": "R1 invalid mem access 'scalar'",
                    "kernel_version": kernel.version,
                    "common_cause": "Using scalar as pointer",
                    "example_fix": "Ensure proper pointer type"
                }
            ])
        
        return error_patterns
    
    def save_version_data(self, kernel: KernelVersion, data: Dict):
        """Save collected data for kernel version"""
        
        version_dir = self.data_path / f"kernel-{kernel.version}"
        version_dir.mkdir(exist_ok=True)
        
        # Save main data
        main_file = version_dir / "data.json"
        with main_file.open("w") as f:
            json.dump(data, f, indent=2)
        
        # Save programs separately
        programs_dir = version_dir / "programs"
        programs_dir.mkdir(exist_ok=True)
        
        for program in data["programs"]:
            program_file = programs_dir / f"{program['file_name']}.json"
            with program_file.open("w") as f:
                json.dump(program, f, indent=2)
        
        # Save helpers
        if data["helpers"]:
            helpers_file = version_dir / "helpers.json"
            with helpers_file.open("w") as f:
                json.dump(data["helpers"], f, indent=2)
        
        print(f"💾 Saved data for kernel {kernel.version}")
    
    def generate_compatibility_matrix(self):
        """Generate compatibility matrix across all collected versions"""
        
        matrix = {}
        
        for kernel in self.SUPPORTED_KERNELS:
            version_dir = self.data_path / f"kernel-{kernel.version}"
            if not version_dir.exists():
                continue
                
            programs_dir = version_dir / "programs"
            if not programs_dir.exists():
                continue
            
            version_stats = {"total": 0, "compatible": 0, "issues": []}
            
            for program_file in programs_dir.glob("*.json"):
                with program_file.open() as f:
                    program_data = json.load(f)
                
                version_stats["total"] += 1
                if program_data.get("valid", False):
                    version_stats["compatible"] += 1
                else:
                    version_stats["issues"].extend(program_data.get("issues", []))
            
            if version_stats["total"] > 0:
                version_stats["success_rate"] = version_stats["compatible"] / version_stats["total"]
            
            matrix[kernel.version] = version_stats
        
        # Save matrix
        matrix_file = self.data_path / "compatibility_matrix.json"
        with matrix_file.open("w") as f:
            json.dump(matrix, f, indent=2)
        
        print(f"📊 Compatibility matrix saved to {matrix_file}")
        return matrix

    def is_helper_available(self, helper_name: str, kernel: KernelVersion) -> bool:
        """
        Naïve implementation: assume all helpers listed in kernel.helpers are available.
        If helpers were collected during `collect_helper_info`, use them.
        Otherwise, fallback to kernel.features.
        """
        # Optional: look up in helpers collected for that kernel
        # In future we can load `helpers.json` if already written
        if helper_name.startswith("bpf_"):
            # As a fallback, assume common helpers are present in >= 5.4
            if kernel.version >= "5.4":
                return True
            # In 4.18 fewer helpers
            if kernel.version == "4.18" and helper_name in {
                "bpf_map_lookup_elem", "bpf_map_update_elem", "bpf_trace_printk",
                "bpf_get_current_pid_tgid", "bpf_get_current_uid_gid",
            }:
                return True
        # Unknown helper — assume not available
        return False

    
    # Utility methods
    def extract_program_type(self, text: str) -> str:
        match = re.search(r'SEC\("([^"]+)"\)', text)
        return match.group(1) if match else "unknown"

    def get_timestamp(self) -> str:
        return datetime.utcnow().isoformat()