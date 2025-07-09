#!/usr/bin/env python3
"""
Enhanced eBPF Compatibility Analyzer with Verifier Logging and Detailed Analysis
"""

import re
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
import tempfile
import logging

@dataclass
class VerifierError:
    """Represents a verifier error with location and context."""
    line_number: Optional[int] = None
    instruction: Optional[str] = None
    error_message: str = ""
    error_category: str = "unknown"
    severity: str = "error"
    source_context: Optional[str] = None

@dataclass
class ProgramAnalysis:
    """Complete analysis of an eBPF program."""
    file_name: str
    program_type: str = ""
    helpers_used: List[str] = field(default_factory=list)
    includes: List[str] = field(default_factory=list)
    success: bool = False
    verifier_errors: List[VerifierError] = field(default_factory=list)
    verifier_log: str = ""
    compile_command: str = ""
    kernel_source_link: str = ""

@dataclass
class KernelCompatibility:
    """Enhanced kernel compatibility data with detailed analysis."""
    kernel: str
    tag: str
    features: Dict[str, bool] = field(default_factory=dict)
    btf_support: Dict[str, bool] = field(default_factory=dict)
    programs: List[ProgramAnalysis] = field(default_factory=list)
    success_rate: float = 0.0
    common_failures: Dict[str, int] = field(default_factory=dict)
    source_links: Dict[str, str] = field(default_factory=dict)

class EnhancedeBPFAnalyzer:
    """Enhanced eBPF analyzer with verifier logging and detailed error analysis."""
    
    def __init__(self, kernel_source_dir: Path):
        self.kernel_source_dir = kernel_source_dir
        self.error_categories = self._load_error_categories()
        
    def _load_error_categories(self) -> Dict[str, str]:
        """Map error patterns to categories for better analysis."""
        return {
            r"stack limit exceeded": "stack_overflow",
            r"invalid mem access": "memory_violation", 
            r"type mismatch": "type_error",
            r"unbounded loop": "loop_detection",
            r"unknown func": "helper_unavailable",
            r"program type not supported": "prog_type_unsupported",
            r"invalid map": "map_error",
            r"btf_id not found": "btf_missing",
            r"invalid instruction": "instruction_error",
            r"unreachable code": "dead_code",
            r"value out of range": "bounds_violation",
            r"misaligned access": "alignment_error",
            r"invalid access to packet": "packet_bounds",
            r"invalid access to context": "context_violation",
            r"back-edge": "loop_detection",
            r"helper call is not allowed": "helper_restricted",
            r"R\d+ invalid mem access": "register_bounds",
            r"off=\d+ size=\d+": "offset_bounds"
        }
    
    def categorize_error(self, error_msg: str) -> str:
        """Categorize verifier error based on message pattern."""
        for pattern, category in self.error_categories.items():
            if re.search(pattern, error_msg, re.IGNORECASE):
                return category
        return "unknown"
    
    def parse_verifier_log(self, log: str) -> List[VerifierError]:
        """Parse verifier log to extract structured error information."""
        errors = []
        lines = log.split('\n')
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('processed') or line.startswith('from'):
                continue
                
            # Look for line number references
            line_match = re.search(r'line (\d+)', line)
            line_number = int(line_match.group(1)) if line_match else None
            
            # Extract instruction number and content
            inst_match = re.match(r'(\d+):\s*(.+)', line)
            instruction = inst_match.group(2) if inst_match else None
            
            # Check if this line contains an error
            error_indicators = [
                'invalid', 'unknown', 'misaligned', 'out of bounds',
                'type mismatch', 'stack limit', 'unbounded', 'not allowed'
            ]
            
            if any(indicator in line.lower() for indicator in error_indicators):
                error = VerifierError(
                    line_number=line_number,
                    instruction=instruction,
                    error_message=line,
                    error_category=self.categorize_error(line),
                    severity="error" if any(x in line.lower() for x in ['invalid', 'unknown']) else "warning"
                )
                
                # Add source context from surrounding lines
                context_start = max(0, i-2)
                context_end = min(len(lines), i+3)
                error.source_context = '\n'.join(lines[context_start:context_end])
                
                errors.append(error)
        
        return errors
    
    def generate_kernel_source_links(self, kernel_version: str) -> Dict[str, str]:
        """Generate links to kernel source for the specific version."""
        base_url = f"https://github.com/torvalds/linux/tree/v{kernel_version}"
        
        return {
            "kernel_root": base_url,
            "samples_bpf": f"{base_url}/samples/bpf",
            "selftests_bpf": f"{base_url}/tools/testing/selftests/bpf",
            "bpf_headers": f"{base_url}/include/uapi/linux/bpf.h",
            "verifier_source": f"{base_url}/kernel/bpf/verifier.c",
            "helper_definitions": f"{base_url}/kernel/bpf/helpers.c"
        }
    
    def compile_with_debug_info(self, source_file: Path, output_dir: Path) -> Tuple[bool, str, str]:
        """Compile eBPF program with debug information for better error reporting."""
        output_file = output_dir / f"{source_file.stem}.o"
        
        # Enhanced compile command with debug info
        compile_cmd = [
            "clang",
            "-O2",
            "-g",  # Debug information for line numbers
            "-Wall",
            "-Werror",
            "-target", "bpf",
            "-c", str(source_file),
            "-o", str(output_file),
            "-I", str(self.kernel_source_dir / "include"),
            "-I", str(self.kernel_source_dir / "samples/bpf"),
            "-I", str(self.kernel_source_dir / "tools/lib")
        ]
        
        try:
            result = subprocess.run(
                compile_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0, str(output_file), ' '.join(compile_cmd)
            
        except subprocess.TimeoutExpired:
            return False, "", ' '.join(compile_cmd)
        except Exception as e:
            return False, "", f"Compilation failed: {e}"
    
    def load_and_capture_verifier_log(self, object_file: str) -> Tuple[bool, str]:
        """Load eBPF program and capture detailed verifier log."""
        try:
            # Use bpftool to load program and capture verifier output
            cmd = [
                "bpftool", "prog", "load", 
                object_file, "/sys/fs/bpf/test_prog",
                "--verifier-log-level", "2"  # Verbose verifier logging
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Clean up the loaded program
            subprocess.run(["rm", "-f", "/sys/fs/bpf/test_prog"], 
                         capture_output=True)
            
            # Return success status and full output (including verifier log)
            full_log = result.stdout + result.stderr
            return result.returncode == 0, full_log
            
        except subprocess.TimeoutExpired:
            return False, "Verifier timeout"
        except Exception as e:
            return False, f"Load failed: {e}"

    def analyze_program_from_json(self, json_file: Path, kernel_version: str) -> ProgramAnalysis:
        """Load program analysis from JSON file and optionally recompile"""
        with open(json_file) as f:
            data = json.load(f)

        analysis = ProgramAnalysis(
            file_name=data.get("file_name", json_file.stem),
            program_type=data.get("program_type", ""),
            helpers_used=data.get("helpers_used", []),
            includes=data.get("includes", []),
            success=data.get("valid", False),
            kernel_source_link=self.generate_kernel_source_links(kernel_version)["samples_bpf"]
        )

        # optionally: re-run compilation against this kernel headers
        source_file_guess = Path(f"./sources/linux-{kernel_version}/samples/bpf/{analysis.file_name}")
        if source_file_guess.exists():
            compile_success, _, compile_cmd = self.compile_with_debug_info(
                source_file_guess, Path(tempfile.gettempdir())
            )
            analysis.compile_command = compile_cmd
            analysis.success = compile_success or analysis.success

        return analysis

    def analyze_kernel_compatibility(self, kernel_version: str, programs_dir: Path) -> KernelCompatibility:
        """Analyze compatibility for a specific kernel version."""

        # new: look for kernel source
        kernel_source_dir = Path(f"./sources/linux-{kernel_version}")
        if kernel_source_dir.exists():
            self.kernel_source_dir = kernel_source_dir
        else:
            print(f"⚠️  Kernel source for {kernel_version} not found, using fallback.")
            self.kernel_source_dir = Path("./kernels")

        compatibility = KernelCompatibility(
            kernel=kernel_version,
            tag=f"v{kernel_version}",
            source_links=self.generate_kernel_source_links(kernel_version)
        )

        # programs_dir stays as is
        program_files = list(programs_dir.glob("*.json"))
        successful_programs = 0
        failure_categories = {}

        for program_file in program_files:
            analysis = self.analyze_program_from_json(program_file, kernel_version)
            compatibility.programs.append(analysis)

            if analysis.success:
                successful_programs += 1
            else:
                for error in analysis.verifier_errors:
                    category = error.error_category
                    failure_categories[category] = failure_categories.get(category, 0) + 1

        compatibility.success_rate = (successful_programs / len(program_files)) * 100 if program_files else 0
        compatibility.common_failures = failure_categories

        return compatibility

    def generate_compatibility_report(self, results: List[KernelCompatibility]) -> Dict:
        """Generate comprehensive compatibility report."""
        
        report = {
            "summary": {
                "kernels_analyzed": len(results),
                "total_programs": sum(len(r.programs) for r in results),
                "overall_trends": {}
            },
            "kernel_details": {},
            "failure_analysis": {},
            "recommendations": []
        }
        
        # Per-kernel analysis
        for result in results:
            report["kernel_details"][result.kernel] = {
                "success_rate": result.success_rate,
                "programs_tested": len(result.programs),
                "common_failures": result.common_failures,
                "source_links": result.source_links,
                "top_errors": sorted(result.common_failures.items(), 
                                   key=lambda x: x[1], reverse=True)[:5]
            }
        
        # Cross-kernel failure analysis
        all_failures = {}
        for result in results:
            for category, count in result.common_failures.items():
                all_failures[category] = all_failures.get(category, 0) + count
        
        report["failure_analysis"] = {
            "most_common_failures": sorted(all_failures.items(), 
                                         key=lambda x: x[1], reverse=True)[:10],
            "kernel_specific_issues": self._identify_kernel_specific_issues(results)
        }
        
        # Generate recommendations
        report["recommendations"] = self._generate_recommendations(results)
        
        return report
    
    def _identify_kernel_specific_issues(self, results: List[KernelCompatibility]) -> Dict:
        """Identify issues specific to certain kernel versions."""
        issues = {}
        
        for result in results:
            kernel_issues = []
            
            if result.success_rate < 50:
                kernel_issues.append(f"Low success rate ({result.success_rate:.1f}%)")
            
            if "helper_unavailable" in result.common_failures:
                kernel_issues.append("Missing helper functions")
            
            if "btf_missing" in result.common_failures:
                kernel_issues.append("BTF support issues")
            
            if kernel_issues:
                issues[result.kernel] = kernel_issues
        
        return issues
    
    def _generate_recommendations(self, results: List[KernelCompatibility]) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        # Find kernels with good compatibility
        good_kernels = [r for r in results if r.success_rate > 90]
        if good_kernels:
            kernel_names = ", ".join(r.kernel for r in good_kernels)
            recommendations.append(f"Use kernels {kernel_names} for best compatibility")
        
        # Check for common failure patterns
        all_failures = {}
        for result in results:
            for category, count in result.common_failures.items():
                all_failures[category] = all_failures.get(category, 0) + count
        
        if "helper_unavailable" in all_failures:
            recommendations.append("Consider feature detection for helper availability")
        
        if "btf_missing" in all_failures:
            recommendations.append("Ensure BTF support is enabled in kernel config")
        
        return recommendations

def main():
    """Example usage of enhanced analyzer."""
    
    analyzer = EnhancedeBPFAnalyzer(Path("./kernels"))
    
    # Analyze multiple kernels
    kernel_versions = ["4.18", "5.4", "5.15", "6.1", "6.8"]
    results = []
    
    for version in kernel_versions:
        print(f"🔍 Analyzing kernel {version}...")
        programs_dir = Path(f"data/kernel-{version}/programs")
        
        if programs_dir.exists():
            result = analyzer.analyze_kernel_compatibility(version, programs_dir)
            results.append(result)
            
            print(f"✅ Kernel {version}: {result.success_rate:.1f}% success rate")
            if result.common_failures:
                top_failure = max(result.common_failures.items(), key=lambda x: x[1])
                print(f"   Most common failure: {top_failure[0]} ({top_failure[1]} programs)")
    
    # Generate comprehensive report
    print("\n📊 Generating compatibility report...")
    report = analyzer.generate_compatibility_report(results)
    
    # Save detailed report
    with open("data/detailed_compatibility_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)
    
    print("✅ Detailed compatibility report saved to data/detailed_compatibility_report.json")
    
    # Print summary
    print(f"\n📈 Summary:")
    print(f"   Kernels analyzed: {report['summary']['kernels_analyzed']}")
    print(f"   Total programs: {report['summary']['total_programs']}")
    
    if report['recommendations']:
        print(f"\n💡 Recommendations:")
        for rec in report['recommendations']:
            print(f"   • {rec}")

if __name__ == "__main__":
    main()