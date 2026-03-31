#!/bin/bash
# axios Supply Chain Poisoning Emergency Scanner
# 支持 Linux/macOS
# 检测 axios 恶意版本 (1.14.1, 0.30.4) 和 plain-crypto-js 投毒模块

MALICIOUS_VERSIONS="1.14.1 0.30.4"
MALICIOUS_PACKAGE="plain-crypto-js"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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
    
    for mv in $MALICIOUS_VERSIONS; do
        if [[ "$version" == "$mv" ]]; then
            echo -e "  ❌ MALICIOUS  $name@$version"
            echo -e "         Location: $location"
            return 1
        fi
    done
    echo -e "  ✅ Safe      $name@$version"
    echo -e "         Location: $location"
    return 0
}

check_axios_in_npm_list() {
    local output=$(npm list -g --json 2>/dev/null)
    if [[ -z "$output" ]]; then
        echo "  ⚠️ 无法获取全局包列表"
        return 0
    fi
    
    echo "$output" | grep -o '"axios@[^"]*"' 2>/dev/null | while read -r item; do
        version=$(echo "$item" | grep -o '@[^"]*$' | sed 's/@//')
        check_npm_package "axios" "$version" "npm global"
    done
}

check_project_axios() {
    local project_path=$1
    
    print_section "检查项目: $project_path"
    
    if [[ ! -f "$project_path/package.json" ]]; then
        echo "  ⚠️ 未找到 package.json"
        return 0
    fi
    
    # 检查 package.json
    if command -v jq &> /dev/null; then
        axios_version=$(jq -r '.dependencies.axios // .devDependencies.axios // empty' "$project_path/package.json" 2>/dev/null)
        if [[ -n "$axios_version" ]]; then
            clean_version=$(echo "$axios_version" | sed 's/^[\^~]//')
            check_npm_package "axios" "$clean_version" "$project_path/package.json"
        fi
        
        # 检查 devDependencies
        axios_dev_version=$(jq -r '.devDependencies.axios // empty' "$project_path/package.json" 2>/dev/null)
        if [[ -n "$axios_dev_version" && "$axios_dev_version" != "$axios_version" ]]; then
            clean_version=$(echo "$axios_dev_version" | sed 's/^[\^~]//')
            check_npm_package "axios (dev)" "$clean_version" "$project_path/package.json (devDependencies)"
        fi
    else
        # 备用方案：无 jq
        axios_line=$(grep -E '"axios":' "$project_path/package.json" 2>/dev/null)
        if [[ -n "$axios_line" ]]; then
            version=$(echo "$axios_line" | sed 's/.*"axios": *"\([^"]*\)".*/\1/')
            check_npm_package "axios" "$version" "$project_path/package.json"
        fi
    fi
    
    # 检查 package-lock.json
    if [[ -f "$project_path/package-lock.json" ]]; then
        echo ""
        echo "  [ package-lock.json 检查 ]"
        if command -v jq &> /dev/null; then
            jq -r '.packages | to_entries[] | select(.key | test("node_modules/axios$")) | "\(.key): \(.value.version)"' "$project_path/package-lock.json" 2>/dev/null | while IFS=: read -r path version; do
                check_npm_package "axios" "$version" "$path"
            done
        else
            grep -A1 '"axios"' "$project_path/package-lock.json" 2>/dev/null | grep '"version"' | sed 's/.*"version": *"\([^"]*\)".*/\1/' | while read -r version; do
                check_npm_package "axios" "$version" "$project_path/package-lock.json"
            done
        fi
    fi
    
    # 检查 plain-crypto-js
    echo ""
    echo "  [ plain-crypto-js 投毒检查 ]"
    if [[ -d "$project_path/node_modules/plain-crypto-js" ]]; then
        echo -e "  ❌ MALICIOUS: plain-crypto-js 发现于 $project_path/node_modules/plain-crypto-js"
        echo -e "         这表明投毒攻击已执行！"
    else
        echo -e "  ✅ 未发现 plain-crypto-js"
    fi
}

check_rat_artifacts() {
    print_section "RAT Artifact 检查"
    
    found_rat=0
    
    # Linux 检查
    if [[ -f "/tmp/ld.py" ]]; then
        echo -e "  ❌ COMPROMISED: Linux RAT (ld.py)"
        echo "         Path: /tmp/ld.py"
        found_rat=1
    fi
    
    # macOS 检查
    if [[ -f "/Library/Caches/com.apple.act.mond" ]]; then
        echo -e "  ❌ COMPROMISED: macOS RAT (act.mond)"
        echo "         Path: /Library/Caches/com.apple.act.mond"
        found_rat=1
    fi
    
    if [[ $found_rat -eq 0 ]]; then
        echo -e "  ✅ 未发现 RAT artifacts"
    fi
    
    return $found_rat
}

check_npm_cache() {
    print_section "NPM 缓存检查"
    
    found_malicious=0
    cache_locations=(
        "$HOME/.npm"
        "$HOME/.npm-cache"
        "/tmp/npm-*"
    )
    
    for cache in "${cache_locations[@]}"; do
        if ls $cache/plain-crypto-js 2>/dev/null; then
            echo -e "  ❌ MALICIOUS: plain-crypto-js 发现于缓存"
            echo "         Path: $cache"
            found_malicious=1
        fi
    done
    
    if [[ $found_malicious -eq 0 ]]; then
        echo -e "  ✅ NPM 缓存安全"
    fi
}

print_summary() {
    local global_safe=$1
    local project_safe=$2
    local rat_safe=$3
    local cache_safe=$4
    
    print_header "扫描结果汇总"
    
    all_safe=$((global_safe && project_safe && rat_safe && cache_safe))
    
    if [[ $all_safe -eq 0 ]]; then
        echo -e "⚠️ 发现问题！立即采取行动："
        echo -e "  ${RED}1. 隔离受感染系统${NC}"
        echo -e "  ${RED}2. 轮换所有凭证 (npm tokens, AWS keys, SSH keys)${NC}"
        echo -e "  ${RED}3. 从已知良好状态重建系统${NC}"
        echo -e "  ${RED}4. 审计 CI/CD 工作流${NC}"
    else
        echo -e "${GREEN}🎉 未发现 axios 投毒迹象！${NC}"
        echo ""
        echo "您的系统是安全的，但建议："
        echo -e "  ${YELLOW}1. 尽快将 axios 锁定到安全版本 (1.14.0 或 0.30.3)${NC}"
        echo -e "  ${YELLOW}2. 在 package.json 中添加 overrides 防止降级${NC}"
        echo -e "  ${YELLOW}3. CI/CD 中使用 npm ci --ignore-scripts${NC}"
    fi
}

# ========== 主程序 ==========
clear
print_header "axios 供应链投毒应急扫描器"
echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "系统: $(uname -s) ($(hostname))"
echo ""

global_safe=1
project_safe=1
rat_safe=1
cache_safe=1

# 1. 全局 npm 检查
print_section "NPM 全局安装包检查"
if command -v npm &> /dev/null; then
    check_axios_in_npm_list
else
    echo "  ⚠️ npm 未安装"
fi

# 2. RAT 检查
check_rat_artifacts
rat_safe=$?

# 3. 缓存检查
check_npm_cache
cache_safe=$?

# 4. 项目检查
if [[ -n "$1" ]]; then
    if [[ -d "$1" ]]; then
        check_project_axios "$1"
    else
        echo -e "  ❌ 项目路径不存在: $1"
    fi
else
    print_section "项目检查"
    echo "  请提供项目路径作为参数，或手动检查以下位置："
    echo "    - node_modules/axios"
    echo "    - package.json 中的 axios 版本"
    echo "    - package-lock.json 中的 axios 版本"
fi

# 汇总
print_summary $global_safe $project_safe $rat_safe $cache_safe
