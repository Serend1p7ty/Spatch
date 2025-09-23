#!/usr/bin/python3
import re, sys, subprocess, itertools, shutil
from pathlib import Path

LIBS = Path(__file__).resolve().parent / 'libs'
PATCHELF = 'patchelf'

# ---------------- 彩色 log 模块（仅括号有色） ----------------
class log:
    COLOR = {
        'red':    '\033[31m',
        'green':  '\033[32m',
        'lblue':  '\033[94m',   # 浅蓝
        'reset':  '\033[0m'
    }

    @staticmethod
    def _colored_bracket(level, color):
        return f'{log.COLOR[color]}[{level}]{log.COLOR["reset"]}'

    @staticmethod
    def info(msg):
        print(f'{log._colored_bracket("I", "lblue")} {msg}', file=sys.stderr)

    @staticmethod
    def success(msg):
        print(f'{log._colored_bracket("+", "green")} {msg}', file=sys.stderr)

    @staticmethod
    def error(msg):
        print(f'{log._colored_bracket("-", "red")} {msg}', file=sys.stderr)

# ---------------- 工具 ----------------
def fatal(msg):
    log.error(msg)
    sys.exit(1)

def run(cmd, **kw):
    return subprocess.check_output(cmd, shell=True, text=True, **kw).strip()

def list_dirs():
    if not LIBS.is_dir():
        fatal(f'{LIBS} 不存在')
    return sorted([d.name for d in LIBS.iterdir() if d.is_dir()])

def print_two_cols(lst):
    for i, (a, b) in enumerate(itertools.zip_longest(lst[::2], lst[1::2], fillvalue=''), 1):
        print(f'[{i*2-1:>2}] {a:<38} [{i*2:>2}] {b}')

def arch_of(so: Path):
    txt = run(f'file {so}')
    return '64' if 'x86-64' in txt or '64-bit' in txt else '32'

def extract_ver(libc_so: Path):
    txt = run(f'strings {libc_so} | grep -E "GNU libc|release version" || true')
    m = re.search(r'(\d+\.\d+)', txt)
    return m.group(1) if m else None

def ask_choice(options, prompt='请选择'):
    print_two_cols(options)
    while True:
        try:
            sel = int(input(f'{log._colored_bracket("?", "lblue")} {prompt} (1-{len(options)}): ').strip())
            if 1 <= sel <= len(options):
                log.success(f'已选择版本: {options[sel-1]}')
                return options[sel - 1]
        except ValueError:
            pass
        print('输入无效，重试')

def do_patch(elf: Path, ver_dir: str):
    backup = elf.with_name(elf.stem + '_patched')
    if backup.exists():
        log.info(f'备份文件 {backup} 已存在')
        ans = input(log._colored_bracket('?', 'lblue') + ' 是否替换? [y/N] ').strip().lower()
        if ans != 'y':
            log.error('用户取消操作')
            return
        backup.unlink()
    shutil.copy2(elf, backup)
    log.success(f'已重新备份 => {backup}')

    # 以下保持不变
    base = LIBS / ver_dir
    ld   = next(base.rglob('ld-linux-*.so.2'), None)
    libc = next(base.rglob('libc.so.6'), None)
    if not ld or not libc:
        fatal(f'{base} 下缺少 ld-linux-*.so.2 或 libc.so.6')

    cmds = [
        f'{PATCHELF} --set-interpreter {ld.resolve()} {backup}',
        f'{PATCHELF} --replace-needed libc.so.6 {libc.resolve()} {backup}'
    ]
    for cmd in cmds:
        log.info(f'执行: {cmd}')
        run(cmd)
    log.success(f'patchelf 完成 => {backup}')
    
# ---------------- help ----------------
def print_help():
    log.success('用法:')
    print('''  Spatch                    列出版本目录（一行两列）
  Spatch ELF                用 libs/ 下版本 patch ELF（生成 ELF_patched）
  Spatch ELF LIBC           按 LIBC 版本自动过滤后 patch ELF
  Spatch - LIBC             仅显示与 LIBC 匹配的版本目录，不 patch
  Spatch -h, --help         显示本帮助
''')

# ---------------- main ----------------
def main():
# ---------- help ----------
    if len(sys.argv) == 2 and sys.argv[1] in ('-h', '--help'):
        print_help()
        return
    args = sys.argv[1:]
    if not args:
        print_two_cols(list_dirs())
        return

    elf_path, libc_path = None, None
    no_patch = args[0] == '-'
    if not no_patch:
        elf_path = Path(args[0])
        if not elf_path.is_file():
            fatal(f'ELF 文件不存在: {elf_path}')
    if len(args) >= 2:
        libc_path = Path(args[1])
        if not libc_path.is_file():
            fatal(f'libc 文件不存在: {libc_path}')

    # 仅列出版本目录（不比对）
    if elf_path and not libc_path:
        chosen = ask_choice(list_dirs(), '挑选要用的版本')
        do_patch(elf_path, chosen)
        return

    # 一对一过滤
    if libc_path:
        ver = extract_ver(libc_path)
        if not ver:
            fatal('无法从该 libc 提取主版本号')
        arch_key = 'amd64' if arch_of(libc_path) == '64' else 'i386'
        log.info(f'检测到题目 libc 版本: {ver}  架构: {arch_key}')
        dirs = list_dirs()
        matched = [d for d in dirs if ver in d and arch_key in d]
        if not matched:
            fatal('未找到完全匹配的目录')
        if no_patch:
            print_two_cols(matched)
        else:
            chosen = ask_choice(matched, '选择要用的版本')
            do_patch(elf_path, chosen)
        return

if __name__ == '__main__':
    main()
