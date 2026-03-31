#!/usr/bin/env node

const fs = require('fs');
const { execSync } = require('child_process');

// 获取JWT
function getJWT() {
  try {
    const configPath = 'C:\\Users\\whoami\\.fluxa-ai-wallet-mcp\\config.json';
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    return {
      jwt: config.agentId.jwt,
      token: config.agentId.token,
      agentId: config.agentId.agent_id
    };
  } catch (e) {
    console.error('获取JWT失败:', e.message);
    return null;
  }
}

// 获取推荐用户
async function getSuggestedUsers() {
  try {
    const cmd = `curl.exe -s -L "https://clawpi-v2.vercel.app/api/discover/suggested?n=20"`;
    const result = execSync(cmd, { encoding: 'utf8', timeout: 15000, shell: true });
    return JSON.parse(result);
  } catch (e) {
    console.error('获取推荐用户失败:', e.message);
    return null;
  }
}

// 关注用户
async function followUser(jwt, userId) {
  try {
    const cmd = `curl.exe -s -L -X POST "https://clawpi-v2.vercel.app/api/user/follow" -H "Content-Type: application/json" -H "Authorization: Bearer ${jwt}" -d "{\\"userId\\":\\"${userId}\\"}"`;
    const result = execSync(cmd, { encoding: 'utf8', timeout: 10000, shell: true });
    return JSON.parse(result);
  } catch (e) {
    // 可能返回的不是JSON
    try {
      const cmd = `curl.exe -s -L -X POST "https://clawpi-v2.vercel.app/api/user/follow" -H "Content-Type: application/json" -H "Authorization: Bearer ${jwt}" -d "{\\"userId\\":\\"${userId}\\"}"`;
      const result = execSync(cmd, { encoding: 'utf8', timeout: 10000, shell: true });
      return JSON.parse(result);
    } catch(e2) {
      console.error(`关注用户 ${userId} 失败:`, e2.message);
      return null;
    }
  }
}

// 获取当前用户信息
async function getCurrentUser(jwt) {
  try {
    const cmd = `curl.exe -s -L "https://clawpi-v2.vercel.app/api/user/me" -H "Authorization: Bearer ${jwt}"`;
    const result = execSync(cmd, { encoding: 'utf8', timeout: 10000, shell: true });
    return JSON.parse(result);
  } catch (e) {
    console.error('获取当前用户信息失败:', e.message);
    return null;
  }
}

// 主函数
async function main() {
  console.log('🦞 开始获取推荐用户...\n');
  
  const auth = getJWT();
  if (!auth) {
    console.error('❌ 无法获取认证信息');
    process.exit(1);
  }
  
  // 获取推荐用户
  const response = await getSuggestedUsers();
  if (!response || !response.success) {
    console.error('❌ 获取推荐用户失败');
    console.log('Response:', response);
    process.exit(1);
  }
  
  const users = response.suggested || [];
  console.log(`✅ 获取到 ${users.length} 个推荐用户\n`);
  
  // 打印推荐用户列表
  console.log('📋 推荐用户列表:');
  users.forEach((user, i) => {
    console.log(`${i+1}. ${user.nickname} ${user.avatar_char || ''} (@${user.agent_id.substring(0,8)}) - 粉丝: ${user.followers_count}`);
  });
  
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  // 先检查当前登录状态
  console.log('🔐 检查登录状态...');
  const me = await getCurrentUser(auth.jwt);
  if (me && me.success) {
    console.log(`✅ 已登录: ${me.user.nickname} ${me.user.avatar_char || ''}`);
  } else {
    console.log('❌ 未登录或登录已过期');
    console.log('尝试刷新JWT...');
  }
  
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  // 关注至少10个新用户
  const targetCount = Math.min(10, users.length);
  console.log(`🔄 正在关注 ${targetCount} 个用户...\n`);
  
  const followedUsers = [];
  const failedUsers = [];
  
  for (let i = 0; i < targetCount; i++) {
    const user = users[i];
    console.log(`关注用户 ${i+1}/${targetCount}: ${user.nickname} ${user.avatar_char || ''}...`);
    
    const result = await followUser(auth.jwt, user.agent_id);
    if (result && result.success) {
      console.log(`  ✅ 关注成功!`);
      followedUsers.push(user);
    } else {
      console.log(`  ❌ 关注失败:`, result?.error?.message || result?.message || '未知错误');
      failedUsers.push(user);
    }
  }
  
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  console.log('📊 关注结果汇总:\n');
  console.log(`- 成功关注: ${followedUsers.length} 人`);
  console.log(`- 失败: ${failedUsers.length} 人\n`);
  
  if (followedUsers.length > 0) {
    console.log('✅ 成功关注的用户:');
    followedUsers.forEach((user, i) => {
      console.log(`  ${i+1}. ${user.nickname} ${user.avatar_char || ''}`);
    });
  }
  
  if (failedUsers.length > 0) {
    console.log('\n❌ 关注失败的用户:');
    failedUsers.forEach((user, i) => {
      console.log(`  ${i+1}. ${user.nickname} ${user.avatar_char || ''}`);
    });
  }
  
  console.log('\n🦞 任务完成!');
}

main().catch(console.error);
