from pathlib import Path
import re
import json
import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import hashlib


@dataclass
class ProgramMetadata:
    file_name: str
    file_path: str
    program_type: str
    helpers_used: List[str]
    map_types: List[str]
    includes: List[str]
    description: str
    kernel_version_added: Optional[str]
    complexity_score: int
    concept_mapping: str
    key_features: List[str]
    file_hash: str


class KernelSamplesCollector:
    def __init__(self, kernel_path: Path, output_path: Path):
        self.samples_path = kernel_path / "samples" / "bpf"
        self.tools_path = kernel_path / "tools" / "testing" / "selftests" / "bpf"
        self.output_path = output_path
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories for organized output
        (self.output_path / "raw").mkdir(exist_ok=True)
        (self.output_path / "processed").mkdir(exist_ok=True)
        
    def collect(self):
        """Main collection method"""
        print(f"🔍 Scanning {self.samples_path}...")
        
        # Collect from samples/bpf
        c_files = list(self.samples_path.glob("*.c"))
        print(f"📁 Found {len(c_files)} C files in samples/bpf")
        
        # Also collect from selftests if available
        if self.tools_path.exists():
            test_files = list(self.tools_path.glob("progs/*.c"))
            print(f"📁 Found {len(test_files)} test files in selftests")
            c_files.extend(test_files)
        
        collected_count = 0
        for c_file in c_files:
            try:
                metadata = self.extract_enhanced_metadata(c_file)
                
                # Save raw metadata
                raw_file = self.output_path / "raw" / (c_file.stem + ".json")
                with raw_file.open("w") as f:
                    json.dump(asdict(metadata), f, indent=2)
                
                # Process and save enhanced data
                processed_data = self.process_metadata(metadata)
                processed_file = self.output_path / "processed" / (c_file.stem + ".json")
                with processed_file.open("w") as f:
                    json.dump(processed_data, f, indent=2)
                
                collected_count += 1
                print(f"✅ Collected: {c_file.name}")
                
            except Exception as e:
                print(f"❌ Error processing {c_file.name}: {e}")
        
        print(f"🎯 Collection complete: {collected_count} files processed")
        
        # Generate summary
        self.generate_collection_summary(collected_count)
    
    def extract_enhanced_metadata(self, file_path: Path) -> ProgramMetadata:
        """Extract comprehensive metadata from eBPF program"""
        text = file_path.read_text(encoding='utf-8', errors='ignore')
        
        return ProgramMetadata(
            file_name=file_path.name,
            file_path=str(file_path),
            program_type=self.extract_sec(text),
            helpers_used=self.extract_helpers(text),
            map_types=self.extract_enhanced_maps(text),
            includes=self.extract_includes(text),
            description=self.extract_description(text),
            kernel_version_added=self.get_kernel_version(file_path),
            complexity_score=self.calculate_complexity(text),
            concept_mapping=self.map_to_concept(text),
            key_features=self.identify_key_features(text),
            file_hash=self.calculate_file_hash(text)
        )
    
    def extract_sec(self, text: str) -> str:
        """Extract SEC annotation - improved version"""
        matches = re.findall(r'SEC\("([^"]+)"\)', text)
        return matches[0] if matches else ""
    
    def extract_helpers(self, text: str) -> List[str]:
        """Extract BPF helper functions"""
        helpers = set()
        
        # Standard bpf_ helpers
        helpers.update(re.findall(r'\b(bpf_[a-z0-9_]+)\s*\(', text))
        
        # Also look for helper calls in comments/documentation
        doc_helpers = re.findall(r'(?:call|use|invoke)\s+(bpf_[a-z0-9_]+)', text, re.IGNORECASE)
        helpers.update(doc_helpers)
        
        return sorted(list(helpers))
    
    def extract_enhanced_maps(self, text: str) -> List[str]:
        """Extract map definitions with better parsing"""
        maps = []
        
        # New-style map definitions
        map_types = re.findall(r'__uint\(type,\s*([^)]+)\)', text)
        maps.extend(map_types)
        
        # Old-style map definitions
        old_style = re.findall(r'\.type\s*=\s*([^,\n]+)', text)
        maps.extend(old_style)
        
        # BPF_MAP_DEF style
        for line in text.splitlines():
            if "BPF_MAP_DEF" in line or "struct bpf_map_def" in line:
                maps.append(line.strip())
        
        return maps
    
    def extract_includes(self, text: str) -> List[str]:
        """Extract #include statements"""
        includes = re.findall(r'#include\s*[<"]([^>"]+)[>"]', text)
        return sorted(list(set(includes)))
    
    def extract_description(self, text: str) -> str:
        """Enhanced description extraction"""
        # Try /** */ style comments first
        doc_comment = re.search(r'/\*\*(.*?)\*/', text, re.DOTALL)
        if doc_comment:
            lines = doc_comment.group(1).splitlines()
            desc_lines = []
            for line in lines:
                clean_line = line.strip(' *').strip()
                if clean_line and not clean_line.startswith('@'):
                    desc_lines.append(clean_line)
            if desc_lines:
                return ' '.join(desc_lines)
        
        # Try single-line comments at the top
        lines = text.splitlines()
        desc_lines = []
        for line in lines[:10]:  # Check first 10 lines
            line = line.strip()
            if line.startswith('//') or line.startswith('/*'):
                clean_line = line.lstrip('/*').rstrip('*/').strip()
                if clean_line and len(clean_line) > 10:
                    desc_lines.append(clean_line)
        
        return ' '.join(desc_lines) if desc_lines else ""
    
    def get_kernel_version(self, file_path: Path) -> Optional[str]:
        """Get kernel version when file was added (simplified)"""
        try:
            # This is a simplified version - in production you'd want proper git log parsing
            result = subprocess.run([
                "git", "-C", str(file_path.parent.parent.parent),
                "log", "--follow", "--format=%H %s", "--reverse",
                str(file_path.relative_to(file_path.parent.parent.parent))
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout:
                first_commit = result.stdout.splitlines()[0]
                # Extract version info from commit message if possible
                version_match = re.search(r'v?(\d+\.\d+)', first_commit)
                if version_match:
                    return version_match.group(1)
            
        except (subprocess.TimeoutExpired, Exception):
            pass
        
        return None
    
    def calculate_complexity(self, text: str) -> int:
        """Calculate program complexity score"""
        score = 0
        
        # Basic metrics
        lines = len([line for line in text.splitlines() if line.strip()])
        score += min(lines // 10, 20)  # Max 20 points for length
        
        # Control structures
        score += len(re.findall(r'\b(if|while|for|switch)\b', text)) * 2
        
        # Function definitions
        score += len(re.findall(r'\w+\s*\([^)]*\)\s*\{', text)) * 3
        
        # Complex operations
        score += len(re.findall(r'(bpf_probe_read|bpf_map_lookup|bpf_map_update)', text)) * 2
        
        # Pointer operations
        score += len(re.findall(r'[-]>|\*\w+', text))
        
        return min(score, 100)  # Cap at 100
    
    def map_to_concept(self, text: str) -> str:
        """Map program to concept hierarchy"""
        program_type = self.extract_sec(text)
        
        if not program_type:
            return "/unknown"
        
        # XDP programs
        if program_type.startswith("xdp"):
            if "drop" in text.lower():
                return "/networking/xdp/packet_drop"
            elif "redirect" in text.lower():
                return "/networking/xdp/redirect"
            else:
                return "/networking/xdp/packet_processing"
        
        # Tracing programs
        if program_type.startswith("kprobe"):
            return "/tracing/kprobe/function_trace"
        elif program_type.startswith("tracepoint"):
            return "/tracing/tracepoint/event_trace"
        elif program_type.startswith("uprobe"):
            return "/tracing/uprobe/user_trace"
        
        # TC programs
        if program_type.startswith("tc") or program_type.startswith("classifier"):
            return "/networking/tc/traffic_control"
        
        # Socket programs
        if "socket" in program_type:
            return "/networking/socket/socket_filter"
        
        # Cgroup programs
        if program_type.startswith("cgroup"):
            return "/security/cgroup/resource_control"
        
        return f"/programs/{program_type}"
    
    def identify_key_features(self, text: str) -> List[str]:
        """Identify key features of the program"""
        features = []
        
        # Check for specific patterns
        if re.search(r'bpf_probe_read|BPF_CORE_READ', text):
            features.append("memory_access")
        
        if re.search(r'bpf_map_lookup|bpf_map_update', text):
            features.append("map_operations")
        
        if re.search(r'bpf_trace_printk|bpf_printk', text):
            features.append("debugging")
        
        if re.search(r'struct.*\*.*=.*ctx', text):
            features.append("context_access")
        
        if re.search(r'return.*XDP_', text):
            features.append("xdp_actions")
        
        if re.search(r'#include.*vmlinux\.h', text):
            features.append("btf_enabled")
        
        if re.search(r'BPF_CORE_READ|__builtin_preserve', text):
            features.append("co_re")
        
        if re.search(r'bpf_get_current_pid_tgid|bpf_get_current_uid_gid', text):
            features.append("process_context")
        
        return features
    
    def calculate_file_hash(self, text: str) -> str:
        """Calculate SHA256 hash of file content"""
        return hashlib.sha256(text.encode()).hexdigest()[:16]
    
    def process_metadata(self, metadata: ProgramMetadata) -> Dict:
        """Process metadata into enhanced format"""
        return {
            "metadata": asdict(metadata),
            "template_potential": self.assess_template_potential(metadata),
            "learning_value": self.assess_learning_value(metadata),
            "dependencies": self.extract_dependencies(metadata),
            "tags": self.generate_tags(metadata)
        }
    
    def assess_template_potential(self, metadata: ProgramMetadata) -> Dict:
        """Assess if program is good template material"""
        score = 0
        reasons = []
        
        # Good complexity range
        if 20 <= metadata.complexity_score <= 60:
            score += 30
            reasons.append("good_complexity")
        
        # Clear structure
        if metadata.description:
            score += 20
            reasons.append("documented")
        
        # Common use case
        common_concepts = ["/networking/xdp/", "/tracing/kprobe/"]
        if any(concept in metadata.concept_mapping for concept in common_concepts):
            score += 25
            reasons.append("common_use_case")
        
        # Not too many advanced features
        if len(metadata.key_features) <= 4:
            score += 15
            reasons.append("manageable_features")
        
        # Good helper usage
        if 2 <= len(metadata.helpers_used) <= 6:
            score += 10
            reasons.append("good_helper_usage")
        
        return {
            "score": score,
            "suitable": score >= 60,
            "reasons": reasons
        }
    
    def assess_learning_value(self, metadata: ProgramMetadata) -> Dict:
        """Assess educational value"""
        score = 0
        
        # Diverse features
        score += len(metadata.key_features) * 5
        
        # Good documentation
        if metadata.description:
            score += 20
        
        # Representative of concept
        if not metadata.concept_mapping.startswith("/unknown"):
            score += 15
        
        # Reasonable complexity
        if metadata.complexity_score > 10:
            score += 10
        
        return {
            "score": score,
            "high_value": score >= 40
        }
    
    def extract_dependencies(self, metadata: ProgramMetadata) -> Dict:
        """Extract program dependencies"""
        return {
            "headers": metadata.includes,
            "helpers": metadata.helpers_used,
            "maps": metadata.map_types,
            "btf_required": "btf_enabled" in metadata.key_features,
            "co_re_required": "co_re" in metadata.key_features
        }
    
    def generate_tags(self, metadata: ProgramMetadata) -> List[str]:
        """Generate searchable tags"""
        tags = []
        
        # Add program type
        if metadata.program_type:
            tags.append(f"type:{metadata.program_type}")
        
        # Add concept category
        concept_parts = metadata.concept_mapping.split("/")
        if len(concept_parts) > 1:
            tags.append(f"category:{concept_parts[1]}")
        
        # Add complexity level
        if metadata.complexity_score < 20:
            tags.append("complexity:beginner")
        elif metadata.complexity_score < 50:
            tags.append("complexity:intermediate")
        else:
            tags.append("complexity:advanced")
        
        # Add feature tags
        tags.extend(f"feature:{feature}" for feature in metadata.key_features)
        
        return tags
    
    def generate_collection_summary(self, collected_count: int):
        """Generate summary of collection results"""
        summary = {
            "collection_date": str(Path.cwd()),
            "total_files": collected_count,
            "output_path": str(self.output_path),
            "status": "complete"
        }
        
        summary_file = self.output_path / "collection_summary.json"
        with summary_file.open("w") as f:
            json.dump(summary, f, indent=2)
        
        print(f"📊 Collection summary saved to {summary_file}")