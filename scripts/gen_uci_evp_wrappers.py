#!/usr/bin/env python3
"""Generate UCI wrappers for all EVP functions declared in OpenSSL's evp.h."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DEFAULT_HEADERS = [
    Path("/usr/include/openssl/evp.h"),
    PROJECT_ROOT.parent / "cangku" / "openssl" / "include" / "openssl" / "evp.h",
]
custom_header = os.environ.get("UCI_OPENSSL_EVP")
if custom_header:
    EVP_HEADER = Path(custom_header)
else:
    for candidate in DEFAULT_HEADERS:
        if candidate.exists():
            EVP_HEADER = candidate
            break
    else:
        EVP_HEADER = DEFAULT_HEADERS[-1]
OUT_HEADER = PROJECT_ROOT / "include" / "uci" / "uci_evp_autogen.h"
OUT_SOURCE = PROJECT_ROOT / "src" / "uci_evp_autogen.c"

VARARGS_SKIP = {"EVP_PKEY_Q_keygen"}
PROTOTYPE_RE = re.compile(
    r"(?P<ret>[^;{}]+?)\b(?P<name>EVP_[A-Za-z0-9_]+)\s*\((?P<params>[^;]*?)\)\s*;",
    re.S,
)


@dataclass
class FunctionDecl:
    name: str
    return_type: str
    decl_params: List[str]
    param_names: List[str]


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return text


def remove_preprocessor(text: str) -> str:
    lines = []
    skip_macro_body = False
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith('#'):
            skip_macro_body = line.rstrip().endswith('\\')
            continue
        if skip_macro_body:
            if line.rstrip().endswith('\\'):
                continue
            skip_macro_body = False
            continue
        lines.append(line)
    return "\n".join(lines)


def build_param_list(params: str) -> tuple[List[str], List[str]]:
    params = params.strip()
    if not params or params == 'void':
        return ['void'], []
    decls: List[str] = []
    names: List[str] = []
    buf: List[str] = []
    depth = 0
    for ch in params:
        if ch == ',' and depth == 0:
            token = ''.join(buf).strip()
            if token:
                decl, name = ensure_param_name(token, len(decls))
                decls.append(decl)
                if name:
                    names.append(name)
            buf = []
            continue
        buf.append(ch)
        if ch in '([':
            depth += 1
        elif ch in ')]':
            if depth > 0:
                depth -= 1
    if buf:
        token = ''.join(buf).strip()
        if token:
            decl, name = ensure_param_name(token, len(decls))
            decls.append(decl)
            if name:
                names.append(name)
    return decls, names


def ensure_param_name(token: str, idx: int) -> tuple[str, str | None]:
    token = token.strip()
    if token == 'void' or not token:
        return 'void', None
    if token == '...':
        raise ValueError('Varargs parameters are not supported')
    fn_ptr_match = re.search(r'\(\s*\*+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', token)
    if fn_ptr_match:
        return token, fn_ptr_match.group(1)
    array_match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*(\[[^\]]*\])?$', token)
    if array_match:
        return token, array_match.group(1)
    name = f'param{idx}'
    decl = f"{token} {name}"
    return decl, name


def collect_functions() -> List[FunctionDecl]:
    if not EVP_HEADER.exists():
        raise SystemExit(f"Unable to locate evp.h at {EVP_HEADER}")
    include_dir = EVP_HEADER.parent.parent
    cmd = [
        "gcc",
        "-E",
        "-P",
        f"-I{include_dir}",
        "-D__attribute__(x)=",
        "-D__attribute__((x))=",
        "-D__declspec(x)=",
        str(EVP_HEADER),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    text = strip_comments(result.stdout)
    functions: List[FunctionDecl] = []
    seen = set()
    for match in PROTOTYPE_RE.finditer(text):
        return_type = match.group('ret').strip()
        if not return_type or 'typedef' in return_type.split():
            continue
        name = match.group('name')
        params_part = match.group('params').strip()
        param_tokens = [tok.strip() for tok in params_part.split(',') if tok.strip()]
        if name in VARARGS_SKIP or '...' in param_tokens:
            continue
        if name in seen:
            continue
        seen.add(name)
        decl_params, param_names = build_param_list(params_part)
        functions.append(FunctionDecl(name=name,
                                      return_type=return_type,
                                      decl_params=decl_params,
                                      param_names=param_names))
    return functions


def format_params(params: List[str]) -> str:
    if len(params) == 1 and params[0] == 'void':
        return 'void'
    return ', '.join(params)


def build_call_arguments(names: List[str]) -> str:
    if not names:
        return ''
    return ', '.join(names)


def is_void_return(ret_type: str) -> bool:
    cleaned = ret_type.replace('__owur', '').strip()
    cleaned = re.sub(r'OSSL_[A-Za-z0-9_]+', '', cleaned).strip()
    return cleaned == 'void'


def generate_header(functions: List[FunctionDecl]) -> str:
    lines = []
    lines.append("/* Auto-generated by gen_uci_evp_wrappers.py. Do not edit directly. */")
    lines.append("#ifndef UCI_EVP_AUTOGEN_H")
    lines.append("#define UCI_EVP_AUTOGEN_H")
    lines.append("")
    lines.append("#include <openssl/evp.h>")
    lines.append("")
    lines.append("#ifdef __cplusplus")
    lines.append('extern "C" {')
    lines.append("#endif")
    lines.append("")
    for func in functions:
        params = format_params(func.decl_params)
        uci_name = 'UCI_' + func.name[4:]
        separator = '' if func.return_type.rstrip().endswith('*') else ' '
        lines.append(f"{func.return_type}{separator}{uci_name}({params});")
    lines.append("")
    lines.append("#ifdef __cplusplus")
    lines.append("}")
    lines.append("#endif")
    lines.append("")
    lines.append("#endif /* UCI_EVP_AUTOGEN_H */")
    lines.append("")
    return "\n".join(lines)


def generate_source(functions: List[FunctionDecl]) -> str:
    lines = []
    lines.append("/* Auto-generated by gen_uci_evp_wrappers.py. Do not edit directly. */")
    lines.append("#include \"uci/uci_evp_autogen.h\"")
    lines.append("")
    for func in functions:
        params = format_params(func.decl_params)
        call_args = build_call_arguments(func.param_names)
        uci_name = 'UCI_' + func.name[4:]
        separator = '' if func.return_type.rstrip().endswith('*') else ' '
        lines.append(f"{func.return_type}{separator}{uci_name}({params}) {{")
        call = f"{func.name}({call_args})" if call_args else f"{func.name}()"
        if is_void_return(func.return_type):
            lines.append(f"    {call};")
        else:
            lines.append(f"    return {call};")
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    functions = collect_functions()
    if not functions:
        raise SystemExit("No functions were parsed from evp.h")
    OUT_HEADER.write_text(generate_header(functions))
    OUT_SOURCE.write_text(generate_source(functions))
    print(f"Generated {len(functions)} wrappers.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pragma: no cover
        sys.stderr.write(f"Error: {exc}\n")
        sys.exit(1)
