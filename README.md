
### 一个简单RBAC python实现,仅建议您学习使用，本README由AI生成

# 权限管理与审计系统

## 项目概述
这是一个基于RBAC（基于角色的访问控制）的权限管理系统，集成了细粒度的权限控制、用户管理、命令执行审计和安全日志功能。系统通过预生成对象池优化性能，使用弱引用减少内存占用，并提供Prometheus监控指标支持。

## 核心特性

### 1. 权限控制模型
- **四层权限控制**：
  - 用户直接权限
  - 角色继承权限
  - 命令执行权限要求
  - 终端运行时权限检查
- **动态权限更新**：权限变更时自动刷新用户权限缓存

### 2. 安全审计
- 关键操作审计日志（用户登录、权限变更、命令执行）
- JSON格式结构化日志记录
- 详细的错误追踪和权限验证失败记录

### 3. 性能优化
- 用户对象池预生成和复用
- 弱引用管理减少内存占用
- LRU缓存加速权限查询
- 线程安全设计（可重入锁）

### 4. 监控指标
- 命令执行统计（成功/失败/拒绝次数）
- 权限变更跟踪（授权/撤销）
- Prometheus指标端点（端口8000）

## 核心组件说明

### 1. 权限管理类
| 类名              | 功能描述                                                                 |
|-------------------|--------------------------------------------------------------------------|
| `Permission`      | 权限实体，包含UUID、创建时间和关联命令                                   |
| `Role`            | 角色容器，支持权限继承和用户管理                                        |
| `User`            | 用户实体，支持登录验证、权限缓存和角色绑定                              |
| `Command`         | 可执行命令，记录最后执行时间和所需权限                                  |

### 2. 系统管理类
| 类名              | 功能描述                                                                 |
|-------------------|--------------------------------------------------------------------------|
| `Manager`         | 中央管理器，负责权限/角色/命令的注册和关系维护                          |
| `Terminal`        | 命令执行终端，绑定用户上下文并执行权限检查                              |
| `PermissionChecker`| 权限检查接口，支持自定义验证逻辑                                        |

### 3. 基础设施
| 类/机制           | 功能描述                                                                 |
|-------------------|--------------------------------------------------------------------------|
| `UserPool`        | 用户对象池管理，支持对象复用                                            |
| `Logger`          | 审计日志系统，记录结构化JSON日志                                        |
| 弱引用机制        | 使用`weakref`管理对象关系，避免循环引用                                 |
| LRU缓存           | 用户权限查询缓存（`@lru_cache`）                                        |

## 使用示例

### 1. 系统初始化
```python
# 创建管理器
manager = Manager()

# 创建权限
read_permission = Permission("can_read")
manager.config_permission(read_permission)

# 创建角色
admin_role = Role("admin", read_permission)
manager.config_role(admin_role)
```

### 2. 用户管理
```python
# 创建用户（使用对象池）
user = UserPool.create_user("john", "securePwd123")

# 分配角色
manager.add_user_to_role(user, "admin")

# 直接授权
manager.issue(user, read_permission)
```

### 3. 命令执行
```python
# 定义命令函数
def read_data():
    print("Reading sensitive data...")

# 注册命令
read_cmd = Command("read", read_data)
manager.add_command_to_permission(read_cmd, read_permission)

# 终端操作
terminal = Terminal(manager, DefaultChecker())
terminal.set_user(user)
terminal.run(read_cmd)  # 执行权限检查
```

### 4. 权限变更
```python
# 撤销权限
manager.relieve(user, read_permission)

# 尝试执行命令（将触发PermissionError）
terminal.run(read_cmd)
```

## 监控指标
系统默认在8000端口提供Prometheus指标：
- `cmd_execute_total`：命令执行计数器
  - 标签：`cmd_name`, `status`(success/denied/error)
- `perm_changes_total`：权限变更计数器
  - 标签：`action`(grant/revoke)

## 审计日志示例
```json
{
  "timestamp": "2023-08-08T15:22:45.123456",
  "event_type": "permission_denied",
  "user": "john",
  "command": "read",
  "missing_permissions": ["can_read"],
  "required_permissions": ["can_read"],
  "user_permissions": ["can_write"]
}
```

## 性能优化措施
1. **对象池预生成**：
   ```python
   # 预初始化100个用户对象
   UserPool._pool.extend(User("", "") for _ in range(100))
   ```

2. **内存优化**：
   - 使用`__slots__`减少对象内存占用
   - 弱引用管理对象关系(`WeakSet`, `WeakValueDictionary`)
   - LRU缓存权限查询结果

3. **并发控制**：
   - 线程安全锁(`RLock`)保护共享资源
   - 原子操作保证数据一致性

## 运行要求
- Python 3.7+
- 依赖包：
  ```bash
  pip install prometheus_client
  ```

## 启动方式
直接运行主文件：
```bash
python main.py
```

监控端点：`http://localhost:8000/metrics`

## 测试说明
代码包含完整测试用例，验证：
1. 基础权限验证流程
2. 角色权限继承
3. 登录状态检查
4. 权限撤销场景
5. 错误处理机制

执行测试：
```python
if __name__ == '__main__':
    # 包含完整的测试流程
    ...
```

## 注意事项
1. 用户登录状态30分钟过期
2. 权限变更后需要调用`user.update()`刷新缓存
3. 避免直接删除User对象，应使用`delete()`方法
4. 命令执行需通过Terminal进行权限验证

## 扩展建议
1. 实现自定义`PermissionChecker`
2. 扩展Logger支持远程日志服务
3. 添加用户会话管理模块
4. 集成加密模块增强密码安全

系统设计文档详见代码注释，核心接口保持稳定，内部实现可根据需求调整。