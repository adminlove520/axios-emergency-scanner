#!/bin/bash
#========================================
# OpenClaw 迁移脚本 - Linux/macOS 用
# 将小溪的核心能力迁移到新环境
#========================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN} $1${NC}"
    echo -e "${CYAN}========================================${NC}"
}

print_step() {
    echo ""
    echo -e "${YELLOW}[ $1 ]${NC}"
}

# 检查是否为 OpenClaw 安装目录
check_openclaw_install() {
    if [[ ! -d "$HOME/.openclaw" ]]; then
        echo -e "${RED}❌ 未找到 ~/.openclaw 目录${NC}"
        echo "请确认 OpenClaw 已正确安装"
        exit 1
    fi
    echo -e "${GREEN}✅ 找到 OpenClaw 安装目录${NC}"
}

# 迁移 Skills
migrate_skills() {
    print_step "1. 迁移 Skills"
    
    # Bundled skills
    if [[ -d "$HOME/.openclaw/skills" ]]; then
        echo "  迁移 bundled skills..."
        # skills 目录通常在 OpenClaw 安装目录，不需要手动迁移
        # OpenClaw 会自动加载
    fi
    
    # Workspace skills
    if [[ -d "$HOME/.openclaw/workspace/skills" ]]; then
        echo "  迁移 workspace skills..."
        # workspace/skills 包含自定义技能
        echo -e "    ${GREEN}✅ workspace/skills 已存在${NC}"
    else
        echo -e "    ${YELLOW}⚠️ 未找到 workspace/skills${NC}"
    fi
}

# 迁移记忆文件
migrate_memory() {
    print_step "2. 迁移记忆文件"
    
    local memory_files=(
        "$HOME/.openclaw/workspace/SOUL.md"
        "$HOME/.openclaw/workspace/MEMORY.md"
        "$HOME/.openclaw/workspace/USER.md"
        "$HOME/.openclaw/workspace/AGENTS.md"
        "$HOME/.openclaw/workspace/TOOLS.md"
        "$HOME/.openclaw/workspace/NOW.md"
    )
    
    for file in "${memory_files[@]}"; do
        if [[ -f "$file" ]]; then
            echo -e "  ${GREEN}✅${NC} $(basename $file)"
        else
            echo -e "  ${YELLOW}⚠️${NC} $(basename $file) (不存在)"
        fi
    done
    
    # memory 目录
    if [[ -d "$HOME/.openclaw/workspace/memory" ]]; then
        echo "  发现 memory/ 目录 ($(ls $HOME/.openclaw/workspace/memory/ 2>/dev/null | wc -l) 个文件)"
    fi
}

# 迁移 Workspace 配置
migrate_workspace() {
    print_step "3. 迁移 Workspace 配置"
    
    # 迁移 skills 配置
    if [[ -f "$HOME/.openclaw/workspace/skills-config.json" ]]; then
        echo -e "  ${GREEN}✅${NC} skills-config.json"
    fi
    
    # 迁移 HEARTBEAT 配置
    if [[ -f "$HOME/.openclaw/workspace/HEARTBEAT.md" ]]; then
        echo -e "  ${GREEN}✅${NC} HEARTBEAT.md"
    fi
}

# 验证 Skills 可用性
verify_skills() {
    print_step "4. 验证核心 Skills"
    
    local core_skills=(
        "netease-music-assistant"
        "netease-music-cli"
        "weather"
        "github"
        "discord"
    )
    
    for skill in "${core_skills[@]}"; do
        if [[ -f "$HOME/.openclaw/skills/$skill/SKILL.md" ]] || \
           [[ -f "$HOME/.openclaw/workspace/skills/$skill/SKILL.md" ]]; then
            echo -e "  ${GREEN}✅${NC} $skill"
        else
            echo -e "  ${YELLOW}⚠️${NC} $skill (未找到)"
        fi
    done
}

# 列出需要额外安装的 Skills
list_external_skills() {
    print_step "5. 需要额外安装的 Skills"
    
    echo "  以下 skills 可能需要额外配置："
    echo ""
    
    # mcporter
    if ! command -v mcporter &> /dev/null; then
        echo -e "  ${YELLOW}⚠️ mcporter${NC} - 全局搜索工具"
        echo "    安装: npm install -g @meta-mcp/mcporter"
    fi
    
    # ncm-cli
    if ! command -v ncm-cli &> /dev/null; then
        echo -e "  ${YELLOW}⚠️ ncm-cli${NC} - 网易云音乐 CLI"
        echo "    参考: ~/.openclaw/skills/ncm-cli-setup/SKILL.md"
    fi
    
    # gh CLI
    if ! command -v gh &> /dev/null; then
        echo -e "  ${YELLOW}⚠️ gh${NC} - GitHub CLI"
        echo "    安装: https://cli.github.com/"
    fi
}

# 生成迁移报告
generate_report() {
    print_header "迁移就绪报告"
    
    echo "OpenClaw 迁移检查完成！"
    echo ""
    echo "📁 核心文件状态："
    echo "   - SOUL.md: $([[ -f "$HOME/.openclaw/workspace/SOUL.md" ]] && echo '✅' || echo '❌')"
    echo "   - MEMORY.md: $([[ -f "$HOME/.openclaw/workspace/MEMORY.md" ]] && echo '✅' || echo '❌')"
    echo "   - memory/: $([[ -d "$HOME/.openclaw/workspace/memory" ]] && echo '✅' || echo '❌')"
    echo "   - workspace/skills/: $([[ -d "$HOME/.openclaw/workspace/skills" ]] && echo '✅' || echo '❌')"
    echo ""
    echo "🚀 下一步："
    echo "   1. 运行 openclaw 配置向导"
    echo "   2. 配置 Telegram bot token"
    echo "   3. 启动服务: openclaw gateway start"
    echo ""
}

#========================================
# 主程序
#========================================

print_header "OpenClaw 迁移脚本 (Linux/macOS)"

echo "OpenClaw 根目录: $HOME/.openclaw"
echo "当前用户: $(whoami)"
echo "系统: $(uname -s)"
echo ""

check_openclaw_install
migrate_skills
migrate_memory
migrate_workspace
verify_skills
list_external_skills
generate_report
