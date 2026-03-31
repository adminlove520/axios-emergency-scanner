#!/bin/bash
# axios & OpenClaw Supply Chain Poisoning Emergency Scanner (v1.3.0)
# 支持 Linux/macOS
# 增加 OpenClaw 专项检测

MALICIOUS_VERSIONS="1.14.1 0.30.4"
MALICIOUS_PACKAGES=("plain-crypto-js" "openclaw" "open-claw" "axios-checker-utils")
MALICIOUS_DOMAINS=("axios-updates.com" "npm-security.org" "registry-npmjs.com" "plain-crypto.io" "open-claw.com" "open-claw.org" "claw-sync.net")

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ========== 函数 ==========
print_header() {
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${CYAN} 🛡️  $1${NC}"
    echo -e "${CYAN}============================================================${NC}"
}

print_section() {
    echo -e "\n[ $1 ]"
    echo "------------------------------------------------------------"
}

check_npm_package() {
    local name=$1
    local version=$2
    local location=$3
    
    local clean_version=$(echo "$version" | sed 's/^[^^~]//')
    for mv in $MALICIOUS_VERSIONS; do
        if [[ "$clean_version" == "$mv" ]]; then
            echo -e "  ${RED}❌ 发现投毒版本${NC}: $name@$version"
            echo -e "         位置: $location"
            return 1
        fi
    done
    
    for mp in "${MALICIOUS_PACKAGES[@]}"; do
        if [[ "$name" == "$mp" ]]; then
            echo -e "  ${RED}❌ 恶意包感染${NC}: $name@$version"
            echo -e "         位置: $location"
            return 1
        fi
    done

    echo -e "  ${GREEN}✅ 安全${NC}: $name@$version"
    return 0
}

check_project() {
    local pjson=$1
    local pdir=$(dirname "$pjson")
    
    echo -e "\n  🔍 检查项目: $pdir"
    
    # Check dependencies in package.json
    axios_ver=$(grep -E '"axios":' "$pjson" | sed -E 's/.*"axios": *"([^"]*)".*/\1/')
    if [[ -n "$axios_ver" ]]; then
        check_npm_package "axios" "$axios_ver" "$pjson"
    fi
    
    for mp in "${MALICIOUS_PACKAGES[@]}"; do
        if grep -q "\"$mp\":" "$pjson"; then
             echo -e "  ${RED}❌ 严重风险${NC}: $mp 发现于 $pjson"
        fi
    done

    # Check scripts for malicious domains
    for domain in "${MALICIOUS_DOMAINS[@]}"; do
        if grep -q "$domain" "$pjson"; then
             echo -e "  ${RED}❌ 恶意指令${NC}: 在 $pjson 中发现恶意域名 $domain"
        fi
    done

    # Check node_modules
    for mp in "${MALICIOUS_PACKAGES[@]}"; do
        if [[ -d "$pdir/node_modules/$mp" ]]; then
            echo -e "  ${RED}❌ 实体感染${NC}: $mp 发现于 $pdir/node_modules"
        fi
    done
}

check_rat() {
    print_section "RAT & OpenClaw Artifact 检查"
    local artifacts=(
        "/tmp/ld.py"
        "/Library/Caches/com.apple.act.mond"
        "$HOME/.local/bin/kworker"
        "/tmp/com.apple.sysmond.sh"
        "/etc/cron.d/axios-sync"
        "$HOME/.openclaw"
        "/tmp/.openclaw.lock"
    )
    
    local found=0
    for art in "${artifacts[@]}"; do
        if [[ -f "$art" || -d "$art" ]]; then
            echo -e "  ${RED}❌ 发现后门/恶意文件${NC}: $art"
            found=1
        fi
    done
    
    if [[ $found -eq 0 ]]; then
        echo -e "  ${GREEN}✅ 未发现已知 RAT/OpenClaw 留痕${NC}"
    fi
}

check_hosts() {
    print_section "网络配置审计 (Hosts)"
    local found=0
    for domain in "${MALICIOUS_DOMAINS[@]}"; do
        if grep -q "$domain" /etc/hosts 2>/dev/null; then
            echo -e "  ${RED}❌ Hosts 劫持${NC}: 发现恶意域名 $domain"
            found=1
        fi
    done
    if [[ $found -eq 0 ]]; then
        echo -e "  ${GREEN}✅ Hosts 文件安全${NC}"
    fi
}

# ========== 主程序 ==========
clear
print_header "axios & OpenClaw 供应链投毒应急审计工具"
echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# 1. 全局检查
print_section "NPM 全局包安全审计"
if command -v npm &> /dev/null; then
    global_list=$(npm list -g --depth=0 2>/dev/null)
    for mp in "${MALICIOUS_PACKAGES[@]}"; do
        if echo "$global_list" | grep -q "$mp@"; then
            echo -e "  ${RED}❌ 严重风险${NC}: 在全局发现恶意包 $mp"
        fi
    done
    
    global_axios=$(echo "$global_list" | grep axios@)
    if [[ -n "$global_axios" ]]; then
        ver=$(echo "$global_axios" | cut -d'@' -f2)
        check_npm_package "axios" "$ver" "npm global"
    else
        echo -e "  ${GREEN}✅ 未在全局发现 axios${NC}"
    fi
else
    echo "  ⚠️  npm 未安装"
fi

# 2. RAT 检查
check_rat

# 3. Hosts 检查
check_hosts

# 4. 项目检查
SCAN_PATH="${1:-.}"
print_section "本地项目递归审计: $SCAN_PATH"

find "$SCAN_PATH" -name "package.json" -not -path "*/node_modules/*" | while read -r pjson; do
    check_project "$pjson"
done

print_header "审计汇总"
echo -e "💡 建议: 如果发现问题，请参考 README_CN.md 中的处置建议。"
echo -e "💡 提示: 推荐使用 ${CYAN}npm run scan${NC} 以获得全功能 OpenClaw 扫描。"
