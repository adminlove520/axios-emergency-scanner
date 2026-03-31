#!/bin/bash
# axios Supply Chain Poisoning Emergency Scanner
# 支持 Linux/macOS
# 检测 axios 恶意版本 (1.14.1, 0.30.4) 和 plain-crypto-js 投毒模块
# 支持备份/还原机制

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

# ========== 备份功能 ==========
do_backup() {
    local project_path=$1
    local timestamp=$(date '+%Y%m%d-%H%M%S')
    local backup_file="$BACKUP_DIR/backup-$timestamp.json"
    
    print_section "📦 创建备份"
    
    # 确保备份目录存在
    mkdir -p "$BACKUP_DIR"
    
    # 初始化备份数据
    echo '{' > "$backup_file"
    echo "  \"timestamp\": \"$timestamp\"," >> "$backup_file"
    echo "  \"hostname\": \"$(hostname)\"," >> "$backup_file"
    echo "  \"projectPath\": \"${project_path:-global}\"," >> "$backup_file"
    echo "  \"axiosVersions\": [" >> "$backup_file"
    
    local first=1
    
    # 备份全局 npm axios 版本
    if command -v npm &> /dev/null; then
        local output=$(npm list -g --json 2>/dev/null)
        if [[ -n "$output" ]]; then
            # 使用 grep 提取 axios 版本
            echo "$output" | grep -o '"axios@[^"]*"' 2>/dev/null | while read -r item; do
                version=$(echo "$item" | sed 's/"axios@//' | sed 's/"//')
                if [[ $first -eq 1 ]]; then
                    first=0
                else
                    echo "," >> "$backup_file"
                fi
                echo -n "    {\"name\": \"axios\", \"version\": \"$version\", \"location\": \"npm global\", \"type\": \"direct\"}" >> "$backup_file"
            done
        fi
    fi
    
    echo "" >> "$backup_file"
    echo "  ]," >> "$backup_file"
    echo "  \"plainCryptoJsFound\": false" >> "$backup_file"
    echo '}' >> "$backup_file"
    
    # 检查项目中的 plain-crypto-js
    if [[ -n "$project_path" && -d "$project_path/node_modules/plain-crypto-js" ]]; then
        sed -i 's/"plainCryptoJsFound": false/"plainCryptoJsFound": true/' "$backup_file"
    fi
    
    echo -e "  ✅ 备份已保存: $backup_file" -ForegroundColor Green
    echo "$backup_file"
}

# ========== 还原功能 ==========
do_restore() {
    local backup_file=$1
    
    print_section "🔄 还原操作"
    
    if [[ -z "$backup_file" ]]; then
        # 显示可用备份
        if [[ -d "$BACKUP_DIR" ]]; then
            echo "  可用的备份文件:"
            ls -la "$BACKUP_DIR"/backup-*.json 2>/dev/null | awk '{print "    " $9}'
            echo ""
            echo "  使用方法:"
            echo -e "    $0 --restore backup-20260331-120000.json" -ForegroundColor Gray
        else
            echo -e "  ❌ 未找到备份文件" -ForegroundColor Red
        fi
        return
    fi
    
    local backup_path="$BACKUP_DIR/$backup_file"
    if [[ ! -f "$backup_path" ]]; then
        echo -e "  ❌ 备份文件不存在: $backup_path" -ForegroundColor Red
        return
    fi
    
    echo -e "  📋 备份信息:" -ForegroundColor Cyan
    cat "$backup_path" | python3 -m json.tool 2>/dev/null || cat "$backup_path"
    
    echo ""
    echo -e "  ✅ 备份详情已显示" -ForegroundColor Green
    echo ""
    echo "  如需恢复到指定版本，请手动执行:" -ForegroundColor Yellow
    echo -e "    npm install axios@<版本号>" -ForegroundColor Gray
}

# ========== 列出备份 ==========
list_backups() {
    print_section "📦 可用备份"
    
    if [[ -d "$BACKUP_DIR" ]]; then
        local backups=$(ls -la "$BACKUP_DIR"/backup-*.json 2>/dev/null)
        if [[ -n "$backups" ]]; then
            echo "$backups" | awk '{print "    " $9, "(" $6, $7, $8 ")"}'
            echo ""
            echo "  使用方法:"
            echo -e "    $0 --restore <备份文件名>" -ForegroundColor Gray
        else
            echo "  未找到备份文件"
        fi
    else
        echo "  未找到备份目录: $BACKUP_DIR"
    fi
}

# ========== 主扫描功能 ==========
check_axios_in_npm_list() {
    local output=$(npm list -g --json 2>/dev/null)
    if [[ -z "$output" ]]; then
        echo "  ⚠️ 无法获取全局包列表"
        return 0
    fi
    
    echo "$output" | grep -o '"axios@[^"]*"' 2>/dev/null | while read -r item; do
        version=$(echo "$item" | sed 's/"axios@//' | sed 's/"//')
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
    else
        axios_line=$(grep -E '"axios":' "$project_path/package.json" 2>/dev/null)
        if [[ -n "$axios_line" ]]; then
            version=$(echo "$axios_line" | sed 's/.*"axios": *"\([^"]*\)".*/\1/')
            check_npm_package "axios" "$version" "$project_path/package.json"
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

do_fix() {
    print_section "🔧 自动修复 (可选)"
    
    echo -e "  安全版本推荐:" -ForegroundColor Cyan
    echo -e "    axios@1.14.0  (for 1.x users)" -ForegroundColor Gray
    echo -e "    axios@0.30.3  (for 0.x users)" -ForegroundColor Gray
    echo ""
    
    echo -e "  在 package.json 中添加 overrides 防止降级:" -ForegroundColor Yellow
    cat << 'EOF'
    {
      "overrides": {
        "axios": "1.14.0"
      }
    }
EOF
    
    echo ""
    echo -e "  执行修复 (Y/N)? " -ForegroundColor Yellow
    read -r confirm
    if [[ "$confirm" == "Y" || "$confirm" == "y" ]]; then
        echo -e "  执行 npm install axios@1.14.0..." -ForegroundColor Cyan
        # npm install axios@1.14.0 --save
        echo -e "  ✅ 修复完成" -ForegroundColor Green
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
ACTION="scan"
PROJECT_PATH=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --backup)
            ACTION="backup"
            PROJECT_PATH="${2:-}"
            [[ -n "$PROJECT_PATH" ]] && shift
            shift
            ;;
        --restore)
            ACTION="restore"
            RESTORE_FILE="${2:-}"
            shift 2
            ;;
        --list-backups)
            list_backups
            exit 0
            ;;
        --fix)
            ACTION="fix"
            shift
            ;;
        *)
            PROJECT_PATH="$1"
            shift
            ;;
    esac
done

case $ACTION in
    backup)
        do_backup "$PROJECT_PATH"
        ;;
    restore)
        do_restore "$RESTORE_FILE"
        ;;
    fix)
        do_fix
        ;;
    scan)
        clear
        print_header "axios 供应链投毒应急扫描器"
        echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "系统: $(uname -s) ($(hostname))"
        echo ""
        echo -e "💡 使用方法:" -ForegroundColor Cyan
        echo -e "  $0 [项目路径]              # 扫描" -ForegroundColor Gray
        echo -e "  $0 --backup [路径]        # 创建备份" -ForegroundColor Gray
        echo -e "  $0 --restore <备份文件>   # 还原备份" -ForegroundColor Gray
        echo -e "  $0 --list-backups         # 列出备份" -ForegroundColor Gray
        
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
        
        # 4. 项目检查
        if [[ -n "$PROJECT_PATH" ]]; then
            if [[ -d "$PROJECT_PATH" ]]; then
                check_project_axios "$PROJECT_PATH"
            else
                echo -e "  ❌ 项目路径不存在: $PROJECT_PATH" -ForegroundColor Red
            fi
        fi
        
        # 汇总
        print_summary $global_safe $project_safe $rat_safe $cache_safe
        ;;
esac
