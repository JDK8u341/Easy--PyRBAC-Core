
### 一个简单RBAC python实现,仅建议您学习使用，本README由AI生成

# RBAC 权限管理系统

## 概述

这是一个基于角色的访问控制（RBAC）系统，提供细粒度的权限管理和操作审计功能。系统包含用户、角色、权限和命令等核心组件，支持权限分配、命令执行控制、安全审计等功能。

## 核心功能

### 1. 权限管理
- 创建权限对象并分配权限名称
- 将权限关联到角色或用户
- 权限变更审计日志记录

### 2. 角色管理
- 创建角色并分配权限
- 角色继承机制（支持从父角色继承权限）
- 角色与用户的多对多关系

### 3. 用户管理
- 用户创建与身份验证（SHA-256加盐加密）
- 支持直接权限分配和角色继承权限
- 用户会话管理（30分钟超时）

### 4. 命令执行
- 命令注册与权限关联
- 终端会话绑定用户上下文
- 权限检查与命令执行控制

### 5. 审计与监控
- 详细操作审计日志（JSON格式）
- Prometheus监控指标
  - 命令执行统计
  - 权限变更统计

### 6. 持久化存储
- Redis数据存储
- 对象关系重建机制
- 首次运行初始化支持

## 系统组件

### 核心类

| 类名 | 描述 |
|------|------|
| `User` | 系统用户，包含身份验证和权限信息 |
| `Role` | 角色实体，包含一组权限 |
| `Permission` | 权限实体，可关联到命令 |
| `Command` | 可执行命令，需特定权限才能运行 |
| `Terminal` | 终端会话，绑定用户并执行命令 |
| `Manager` | 系统管理器，协调所有组件 |
| `Logger` | 审计日志记录器 |
| `RedisManager` | Redis持久化管理器 |

### 辅助类
| 类名 | 功能 |
|------|------|
| `PermissionChecker` | 权限检查接口 |
| `DefaultChecker` | 默认权限检查实现 |
| `UserPool` | 用户对象池（对象复用） |
| `RelationRebuilder` | Redis数据关系重建器 |

## 快速开始

### 依赖安装
```bash
pip install redis prometheus-client
```

### 配置文件
1. **Redis配置**（在文档2中修改）：
```python
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
```

2. **日志配置**：
```python
LOGGER_SAVE_FILE = './security.json.log'
```

### 初始化系统
```python
# 创建管理器
manager = Manager()

# 创建Redis管理器
RM = RedisManager(REDIS_HOST, REDIS_PORT, manager)

# 初始化系统
initialize_system(manager, RM)
```

### 示例用法
```python
# 创建权限
can_fuck = Permission("can_fuck")
manager.config_permission(can_fuck)

# 创建命令
fuck_cmd = Command("fuck", "fuck")
manager.add_command_to_permission(fuck_cmd, can_fuck)

# 创建角色
fucker_role = Role("fucker", manager)
manager.config_role(fucker_role)

# 创建用户
user = UserPool.create_user("CAO", "12345678")

# 设置终端
terminal = Terminal(manager, DefaultChecker())
terminal.set_user(user)

# 授权并执行
manager.issue(user, can_fuck)
manager.add_user_to_role(user, "fucker")
user.login("12345678")
terminal.run(fuck_cmd)
```

### 命令配置
在`func_config.py`中添加命令实现：
```python
# func_config.py
def fuck():
    print("fuck you")

COMMAND_REGISTRY = {
    "fuck": fuck
}
```

## 监控指标
系统通过Prometheus暴露以下指标：
- `cmd_execute`: 命令执行统计
  - 标签: `cmd_name`, `status`(success/denied)
- `perm_changes`: 权限变更统计
  - 标签: `action`(grant/revoke)

启动监控服务：
```python
start_http_server(8000)  # 添加在文档2中
```

## 审计日志
系统记录所有关键操作的审计日志，格式为JSON对象：
```json
{
  "timestamp": "2023-01-01T12:00:00.000000",
  "event_type": "command_executed",
  "user": "CAO",
  "command": "fuck",
  "status": "success",
  "execution_time": "0.002s",
  "permissions": ["can_fuck"]
}
```

## 设计特点
1. **线程安全**：使用RLock确保多线程安全
2. **内存优化**：
   - 弱引用(`weakref`)管理对象关系
   - LRU缓存权限计算结果
   - 对象池重用资源
3. **安全机制**：
   - SHA-256加盐密码哈希
   - 权限UUID校验
   - 会话超时控制
4. **可扩展性**：
   - 插件式权限检查器
   - 动态命令注册
   - 关系重建机制

## 维护说明
1. Redis数据存储结构：
   - 用户: `user:<uuid>`
   - 角色: `role:<name>`
   - 权限: `permission:<name>`
   - 命令: `command:<name>`

2. 重建机制：
   - 系统启动时自动从Redis重建对象关系
   - 使用`RelationRebuilder`处理复杂对象依赖

3. 首次运行：
   - 当Redis为空时自动初始化
   - 可创建默认管理员账户

> 注意：系统需要Redis服务正常运行，首次使用前请确保Redis已安装并配置正确