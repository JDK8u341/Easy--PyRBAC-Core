
### 一个由初中生编写的简单RBAC python实现,仅建议您学习使用，本README由AI生成

# RBAC 权限管理系统

## 概述

这是一个基于角色的权限管理系统 (RBAC)，提供细粒度的访问控制和操作审计功能。系统支持权限管理、命令执行控制、用户角色分配和安全审计等功能，适用于需要严格权限控制的场景。

## 核心组件

### 1. 权限管理
- **Permission 类**：表示系统权限
  - 每个权限有唯一名称和 UUID 确保安全性
  - 支持绑定到具体命令
  - 自动记录创建时间和操作日志

### 2. 角色管理
- **Role 类**：用户角色容器
  - 包含一组权限集合
  - 支持动态添加/移除权限
  - 使用弱引用管理用户关系

### 3. 用户管理
- **User 类**：系统用户
  - 支持登录/登出状态管理
  - 可分配角色或直接授予权限
  - 密码哈希存储增强安全性

### 4. 命令管理
- **Command 类**：可执行命令
  - 绑定具体函数实现
  - 定义所需权限集
  - 自动记录执行时间和状态

### 5. 终端控制
- **Terminal 类**：命令执行环境
  - 绑定用户会话
  - 执行权限检查
  - 线程安全设计(使用RLock)

### 6. 系统管理
- **Manager 类**：核心管理器
  - 统一管理权限、角色和命令
  - 提供授权/解除授权接口
  - 维护对象间关联关系

## 审计与监控

### 日志系统
- 记录所有关键操作：
  - 用户登录/登出
  - 权限变更
  - 命令执行
  - 系统事件
- JSON格式日志，包含时间戳和详细上下文

### Prometheus 监控
- 内置指标：
  - `cmd_executed`：命令执行统计（按状态分类）
  - `perm_changes`：权限变更统计（按操作类型）
- 通过端口 8000 提供指标端点

## 安全特性

1. **权限验证**：
   - 默认检查器验证用户权限
   - 支持自定义检查器实现
   
2. **安全存储**：
   - 密码哈希存储
   - 权限UUID验证
   
3. **弱引用管理**：
   - 防止内存泄漏
   - 优化资源使用

4. **线程安全**：
   - 终端操作使用可重入锁
   - 日志系统线程安全

## 快速开始

```python
# 初始化系统组件
checker = DefaultChecker()
manager = Manager()

# 创建权限
view_perm = Permission('view_content')
manager.config_permission(view_perm)

# 创建角色
viewer_role = Role('viewer')
manager.config_role(viewer_role)
manager.issue(viewer_role, view_perm)

# 创建用户
user = User('john', 'password123')
manager.add_user_to_role(user, 'viewer')

# 创建命令
def view():
    print("Viewing content...")
    
view_cmd = Command('view', view)
manager.add_command(view_cmd, view_perm)

# 使用终端执行
terminal = Terminal(manager, checker)
terminal.set_user(user)
user.login('password123')
terminal.run(view_cmd)
```

## 监控指标

访问 Prometheus 指标：
```
http://localhost:8000/metrics
```

主要监控指标：
- `cmd_executed{cmd_name="<command>", status="success|denied|error"}`
- `perm_changes{action="grant|revoke"}`

## 审计日志

日志文件：`security.json.log`

日志格式示例：
```json
{
  "timestamp": "2025-08-07T12:30:45.123456",
  "event_type": "command_executed",
  "user": "john",
  "command": "view",
  "status": "success",
  "execution_time": "0.0023s",
  "permissions": ["view_content"]
}
```

## 注意事项

1. 用户必须登录后才能执行命令
2. 权限变更会实时影响相关用户
3. 使用弱引用需注意对象生命周期
4. 系统已内置线程安全机制

## 测试示例

包含简单测试，执行permission.py可直接运行测试：
```bash
python permission.py
```

测试内容包含：
- 权限验证测试
- 角色分配测试
- 登录状态验证
- 异常处理测试