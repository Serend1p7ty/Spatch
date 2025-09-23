#!/usr/bin/sh
set -e

BIN_NAME="Spatch"
INSTALL_DIR="/usr/local/bin"
SCRIPT="$(cd "$(dirname "$0")" && pwd)/Spatch.py"

# 确保脚本存在
[ -f "$SCRIPT" ] || { echo "[-] $SCRIPT 不存在" >&2; exit 1; }
# 添加可执行权限
chmod +x "$SCRIPT"  
# 自动提权
if [ -w "$INSTALL_DIR" ]; then
    SUDO=""
else
    echo "[I] 需要 sudo 权限安装到 $INSTALL_DIR" >&2
    SUDO="sudo"
fi

# 创建软链
$SUDO ln -sf "$SCRIPT" "$INSTALL_DIR/$BIN_NAME"
echo "[+] 已创建软链: $INSTALL_DIR/$BIN_NAME → $SCRIPT"
echo "[+] 安装完成！现在可直接运行 \`$BIN_NAME\` 在任何地方使用。"