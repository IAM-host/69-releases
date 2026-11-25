#!/usr/bin/env python3
"""Rebuild the bundled C-only helper with Android NDK 28.2.13676358.
Normal Android Studio builds use the supplied jniLibs and do not need this step.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ndk', default=os.environ.get('ANDROID_NDK_HOME') or os.environ.get('ANDROID_NDK_ROOT'))
parser.add_argument('--report', type=Path)
args = parser.parse_args()
if not args.ndk:
    parser.error('Pass --ndk with your installed Android NDK folder.')
ndk = Path(args.ndk).expanduser().resolve()
host = {'Linux':'linux-x86_64','Darwin':'darwin-x86_64','Windows':'windows-x86_64'}.get(platform.system())
if not host:
    parser.error('Unsupported build host.')
compiler = ndk / 'toolchains/llvm/prebuilt' / host / 'bin' / ('clang.exe' if os.name == 'nt' else 'clang')
if not compiler.is_file():
    parser.error('The NDK clang compiler was not found.')
project = Path(__file__).resolve().parents[1]
source = project / 'app/src/main/cpp/eunora_logi_native.c'
if not source.is_file():
    parser.error('The native source file was not found.')
targets = {'arm64-v8a':'aarch64-linux-android32','armeabi-v7a':'armv7a-linux-androideabi32','x86':'i686-linux-android32','x86_64':'x86_64-linux-android32'}
records = []
for abi, target in targets.items():
    destination = project / 'app/src/main/jniLibs' / abi / 'libeunora_logi_native.so'
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = [str(compiler), '--target='+target, '-std=c11', '-O2', '-fPIC', '-shared', '-fvisibility=hidden', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2', '-Wall', '-Wextra', '-Wno-unused-function', '-Wl,-z,relro,-z,now,-z,noexecstack,-z,max-page-size=16384', '-Wl,--build-id=sha1', '-Wl,-soname,libeunora_logi_native.so', str(source), '-llog', '-ldl', '-o', str(destination)]
    subprocess.run(command, check=True)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    records.append({'abi':abi,'target':target,'file':str(destination.relative_to(project)),'bytes':destination.stat().st_size,'sha256':digest})
    print(abi, digest)
report = {'NDK':(ndk/'source.properties').read_text(encoding='utf-8'),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'C_only':True,'Android_API':32,'max_page_size':16384,'libraries':records}
if args.report:
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
