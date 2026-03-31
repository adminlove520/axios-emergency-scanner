#!/bin/bash
# axios Supply Chain Poisoning Emergency Scanner
# 支持 Linux/macOS
# 检测 axios 恶意版本 (1.14.1, 0.30.4) 和 plain-crypto-js 投毒模块

MALICIOUS_VERSIONS="1.14.1 0.30.4"
MALICIOUS_PACKAGE="plain-crypto-js"
BACKUP_DIR="$HOME/.axios-scanner-backup"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ========== 函数 ==========
print_header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN} $1${NC}"
    echo -e "${CYAN}========================================${NC}"
}

print_section() {
    echo ""
    echo -e "[ $1 ]"
    echo "----------------------------------------"
}

check_npm_package() {
    local name=$1
    local version=$2
    local location=$3
    
    local clean_version=$(echo "$version" | sed 's/^[^^~]//')
    for mv in $MALICIOUS_VERSIONS; do
        if [[ "$clean_version" == "$mv" ]]; then
            echo -e "  ${RED}❌ MALICIOUS${NC}  $name@$version"
            echo -e "         Location: $location"
            return 1
        fi
    done
    echo -e "  ${GREEN}✅ Safe${NC}      $name@$version"
    echo -e "         Location: $location"
    return 0
}

check_project() {
    local pjson=$1
    local pdir=$(dirname "$pjson")
    
    echo -e "\n  🔍 检查: $pdir"
    
    # Check dependencies in package.json
    axios_ver=$(grep -E '"axios":' "$pjson" | sed -E 's/.*"axios": *"([^"]*)".*/\1/')
    if [[ -n "$axios_ver" ]]; then
        check_npm_package "axios" "$axios_ver" "$pjson"
    fi
    
    mal_pkg=$(grep -E "\"$MALICIOUS_PACKAGE\":" "$pjson")
    if [[ -n "$mal_pkg" ]]; then
        echo -e "  ${RED}❌ MALICIOUS${NC}: $MALICIOUS_PACKAGE 发现于 $pjson"
    fi

    # Check node_modules
    if [[ -d "$pdir/node_modules/$MALICIOUS_PACKAGE" ]]; then
        echo -e "  ${RED}❌ MALICIOUS${NC}: $MALICIOUS_PACKAGE 发现于 $pdir/node_modules"
    fi
}

check_rat() {
    print_section "RAT Artifact 检查"
    local artifacts=(
        "/tmp/ld.py"
        "/Library/Caches/com.apple.act.mond"
        "$HOME/.local/bin/kworker"
    )
    
    local found=0
    for art in "${artifacts[@]}"; do
        if [[ -f "$art" ]]; then
            echo -e "  ${RED}❌ COMPROMISED${NC}: 发现恶意文件 $art"
            found=1
        fi
    done
    
    if [[ $found -eq 0 ]]; then
        echo -e "  ${GREEN}✅ 未发现已知 RAT artifacts${NC}"
    fi
}

# ========== 主程序 ==========
clear
print_header "axios 供应链投毒应急扫描器"
echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# 1. 全局检查
print_section "NPM 全局安装包检查"
if command -v npm &> /dev/null; then
    global_axios=$(npm list -g axios --depth=0 2>/dev/null | grep axios@)
    if [[ -n "$global_axios" ]]; then
        ver=$(echo "$global_axios" | cut -d'@' -f2)
        check_npm_package "axios" "$ver" "npm global"
    else
        echo -e "  ${GREEN}✅ 未在全局发现 axios${NC}"
    fi
else
    echo "  ⚠️ npm 未安装"
fi

# 2. RAT 检查
check_rat

# 3. 项目检查
SCAN_PATH="${1:-.}"
print_section "项目检查 (递归): $SCAN_PATH"

find "$SCAN_PATH" -name "package.json" -not -path "*/node_modules/*" | while read -r pjson; do
    check_project "$pjson"
done

print_header "扫描结束"
echo -e "💡 建议: 如果发现问题，请立即隔离系统并更新 axios 到 ${YELLOW}1.14.0${NC} 或 ${YELLOW}0.30.3${NC}。"
echo -e "💡 提示: 也可以使用 ${CYAN}npm run scan${NC} 使用 Node.js 版扫描器。"
