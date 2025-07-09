import re
from typing import List

def extract_helpers(text: str) -> List[str]:
    helpers = set()
    helpers.update(re.findall(r'\b(bpf_[a-z0-9_]+)\s*\(', text))
    doc_helpers = re.findall(r'(?:call|use|invoke)\s+(bpf_[a-z0-9_]+)', text, re.IGNORECASE)
    helpers.update(doc_helpers)
    return sorted(list(helpers))


def extract_includes(text: str) -> List[str]:
    includes = re.findall(r'#include\s*[<"]([^>"]+)[>"]', text)
    return sorted(list(set(includes)))


def extract_program_type(text: str) -> str:
    match = re.search(r'SEC\("([^"]+)"\)', text)
    return match.group(1) if match else ""


def uses_btf(text: str) -> bool:
    return bool(re.search(r'#include.*vmlinux\.h', text))


def uses_co_re(text: str) -> bool:
    return bool(re.search(r'BPF_CORE_READ|__builtin_preserve', text))
