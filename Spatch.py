#!/usr/bin/python3
import re, sys, os, subprocess, itertools, shutil
from pathlib import Path

# -------------- 配置单例 --------------
class C:
    BIN   = Path(__file__).resolve()          # 真实脚本路径（跟随软链）
    HERE  = BIN.parent
    LIBS  = HERE / 'libs'
    TPL   = HERE / 'snippet.py'
    LD_TXT_RE = re.compile(r'ld-linux-.+\.so\.2')
    log = None                               # 下方初始化

# -------------- 彩色日志 --------------
class Log:
    COLOR = {'r': '\033[31m', 'g': '\033[32m', 'b': '\033[94m', 'reset': '\033[0m'}
    def _br(self, lvl, col): return f'{self.COLOR[col]}[{lvl}]{self.COLOR["reset"]}'
    def info(self, msg, end='\n'): print(self._br('I', 'b'), msg, file=sys.stderr, end=end)
    def succ(self, msg): print(self._br('+', 'g'), msg, file=sys.stderr)
    def err(self, msg): print(self._br('-', 'r'), msg, file=sys.stderr)
C.log = Log()

# -------------- 通用工具 --------------
def fatal(msg): C.log.err(msg); sys.exit(1)
def run(cmd, **kw): return subprocess.check_output(cmd, shell=True, text=True, **kw).strip()
def arch_of(so: Path): return '64' if {'x86-64','64-bit'} & set(run(f'file {so}').split()) else '32'
def list_dirs():
    if not C.LIBS.is_dir(): fatal(f'{C.LIBS} 不存在')
    return sorted(d.name for d in C.LIBS.iterdir() if d.is_dir())

# -------------- 交互 --------------
def ask_choice(opts, prompt='请选择'):
    for i,(a,b) in enumerate(itertools.zip_longest(opts[::2], opts[1::2], fillvalue=''),1):
        print(f'[{i*2-1:>2}] {a:<38} [{i*2:>2}] {b}')
    while True:
        try:
            print(C.log._br('?', 'b'), f'{prompt} (1-{len(opts)}): ', end='', file=sys.stderr)
            sel = int(input().strip())
            if 1 <= sel <= len(opts):
                C.log.succ(f'已选择版本: {opts[sel-1]}')
                return opts[sel-1]
        except ValueError: pass
        print('输入无效，重试')

def ask_yes_no(q):
    print(C.log._br('?', 'b'), f'{q} [y/N] ', end='', file=sys.stderr)
    return input().strip().lower() == 'y'

# -------------- 核心业务 --------------
def patch_elf(elf: Path, ver_dir: str):
    bak = elf.with_name(elf.stem + '_patched')
    if bak.exists() and not ask_yes_no(f'{bak} 已存在，是否重新替换？'):
        return
    shutil.copy2(elf, bak)
    base = C.LIBS / ver_dir
    ld  = next(base.rglob('ld-linux-*.so.2'), None)
    libc = next(base.rglob('libc.so.6'), None)
    if not (ld and libc): fatal(f'{base} 下缺少 ld/libc')
    for cmd in (f'patchelf --set-interpreter {ld.resolve()} {bak}',
                f'patchelf --replace-needed libc.so.6 {libc.resolve()} {bak}'):
        C.log.info(f'执行: {cmd}'); run(cmd)
    bak.chmod(0o755); C.log.succ(f'patchelf 完成 => {bak}')
    if ask_yes_no('是否生成 exp.py？'): gen_exp(bak)

def gen_exp(binary: Path):
    exp = binary.with_name('exp.py')
    if exp.exists() and not ask_yes_no(f'{exp} 已存在，是否替换？'): return
    if not C.TPL.exists(): fatal(f'模板文件不存在: {C.TPL}')
    content = C.TPL.read_text().replace("file = ''", f"file = './{binary.name}'")
    exp.write_text(content); exp.chmod(0o755)
    C.log.succ(f'已生成 exploit 脚本 => {exp}')

# -------------- 主路由 --------------
def main():
    args = sys.argv[1:]
    if '-h' in args or '--help' in args or not args:
        print('''用法:
  Spatch                  列出版本目录（一行两列）
  Spatch ELF              用 libs/ 下版本 patch ELF（生成 ELF_patched、exp.py）
  Spatch ELF LIBC         按 LIBC 版本自动过滤后 patch
  Spatch - LIBC           仅显示与 LIBC 匹配的版本目录，不 patch
  Spatch -h/--help        显示本帮助'''); return

    no_patch, elf_path, libc_path = args[0] == '-', None, None
    if not no_patch:
        elf_path = Path(args[0])
        if not elf_path.is_file(): fatal(f'ELF 文件不存在: {elf_path}')
    if len(args) >= 2: 
        libc_path = Path(args[1])
        if not libc_path.is_file(): fatal(f'libc 文件不存在: {libc_path}')

    if not libc_path:                       # 仅列目录 或 单 ELF 让用户选
        opts = list_dirs()
        if elf_path: patch_elf(elf_path, ask_choice(opts))
        else: print_two_cols(opts)
        return

    # 带 libc 过滤
    ver = extract_ver(libc_path)
    if not ver: fatal('无法从该 libc 提取主版本号')
    arch = 'amd64' if arch_of(libc_path) == '64' else 'i386'
    C.log.info(f'检测到题目 libc 版本: {ver}  架构: {arch}')
    matched = [d for d in list_dirs() if ver in d and arch in d]
    if not matched: fatal('未找到完全匹配的目录')
    if no_patch: print_two_cols(matched)
    else: patch_elf(elf_path, ask_choice(matched))

# -------------- 工具补漏 --------------
def print_two_cols(lst):
    for i,(a,b) in enumerate(itertools.zip_longest(lst[::2], lst[1::2], fillvalue=''),1):
        print(f'[{i*2-1:>2}] {a:<38} [{i*2:>2}] {b}')

def extract_ver(libc_so: Path):
    txt = run(f'strings {libc_so} | grep -E "GNU libc|release version" || true')
    m = re.search(r'(\d+\.\d+)', txt)
    return m.group(1) if m else None

if __name__ == '__main__':
    main()