#!/usr/bin/env python3
"""
ClawFeed 日报抓取脚本
自动抓取 ClawFeed AI 日报并写入 Obsidian

用法: python fetch_clawfeed.py
"""

import requests
import os
from datetime import datetime

CLAWFEED_API = "https://clawfeed.kevinhe.io/api/digests"
OBSIDIAN_PATH = r"C:\Users\whoami\OneDrive\文档\Obsidian Vault\AI新闻"

def fetch_latest_digest():
    """获取最新日报"""
    url = f"{CLAWFEED_API}?type=daily&limit=1&offset=0"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    data = response.json()
    return data[0] if data else None

def get_date_from_content(content):
    """从日报内容中提取日期"""
    import re
    match = re.search(r"(\d{4}-\d{2}-\d{2})", content)
    if match:
        return match.group(1)
    return datetime.now().strftime("%Y-%m-%d")

def format_for_obsidian(digest):
    """格式化为 Obsidian markdown"""
    content = digest.get("content", "")
    date = get_date_from_content(content)
    
    frontmatter = f"""---
date: {date}
source: ClawFeed
tags: [AI日报]
---

"""
    return frontmatter + content, date

def save_to_obsidian(content, date):
    """保存到 Obsidian"""
    os.makedirs(OBSIDIAN_PATH, exist_ok=True)
    filepath = os.path.join(OBSIDIAN_PATH, f"{date}.md")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    
    print(f"✅ 已保存: {filepath}")
    return filepath

def main():
    print("📥 正在抓取 ClawFeed 日报...")
    
    try:
        digest = fetch_latest_digest()
        if not digest:
            print("❌ 未获取到日报")
            return
        
        content, date = format_for_obsidian(digest)
        save_to_obsidian(content, date)
        print(f"✅ 完成！日期: {date}")
        
    except Exception as e:
        print(f"❌ 错误: {e}")
        raise

if __name__ == "__main__":
    main()
