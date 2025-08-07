
### 一个简单RBAC python实现,仅建议您学习使用，本README由AI生成

### 权限管理系统 README

#### 项目概述
这是一个基于角色的访问控制（RBAC）系统，实现了细粒度的权限管理和审计功能。核心功能包括：
- 用户/角色/权限三级权限模型
- 命令执行时的动态权限检查
- 审计日志记录（文件+控制台双输出）
- Prometheus 性能监控
- 对象池优化资源管理
- 线程安全设计

---

#### 核心组件说明

1. **Logger (logger.py)**
   - 审计日志记录器
   - 输出格式：JSON（文件） + 可读格式（控制台）
   - 线程安全设计（使用RLock）

2. **权限体系**
   ```python
   # 权限实体（带唯一UUID）
   Permission(name="can_fuck")

   # 角色（包含权限集合）
   Role(name="admin", permission1, permission2)

   # 用户（可关联角色+附加权限）
   User(name="Alice", role=admin)
   ```

3. **命令系统**
   ```python
   # 创建命令
   cmd = Command(name="delete_file", func=delete_func)
   
   # 绑定所需权限
   cmd.need_permission.add(file_delete_perm)
   ```

4. **终端执行**
   ```python
   terminal = Terminal(manager, permission_checker)
   terminal.set_user(current_user)
   terminal.run(cmd)  # 自动检查权限
   ```

5. **管理器**
   ```python
   manager = Manager()
   manager.config_permission(perm)
   manager.add_command_to_permission(cmd, perm)
   manager.issue(role, perm)  # 授权
   ```

6. **性能优化**
   - 对象池 (`UserPool`)
   - 权限缓存（5秒有效期）
   - 弱引用 (`weakref`) 防内存泄漏

---

#### 快速开始

1. **安装依赖**
   ```bash
   pip install prometheus_client
   ```

2. **启动服务**
   ```bash
   python main.py  # 自动启动Prometheus(8000端口)
   ```

3. **基础流程示例**
   ```python
   # 初始化组件
   manager = Manager()
   checker = DefaultChecker()
   
   # 创建权限和角色
   perm = Permission("can_edit")
   role = Role("editor", perm)
   
   # 注册到系统
   manager.config_permission(perm)
   manager.config_role(role)
   
   # 创建用户
   user = UserPool.create_user("Bob", "pwd123")
   manager.add_user_to_role(user, "editor")
   
   # 创建命令
   edit_cmd = Command("edit", edit_function)
   manager.add_command_to_permission(edit_cmd, perm)
   
   # 执行命令
   terminal = Terminal(manager, checker)
   terminal.set_user(user)
   user.login("pwd123")
   terminal.run(edit_cmd)  # 权限验证通过
   ```

---

#### 监控指标
Prometheus 提供实时监控：
- `cmd_executed{cmd_name, status}`：命令执行统计
- `perm_changes{action}`：权限变更次数
访问 `http://localhost:8000` 查看指标

---

#### 审计日志示例
```json
{
  "timestamp": "2023-01-01T12:00:00.000",
  "event_type": "command_executed",
  "user": "Bob",
  "command": "edit",
  "status": "success",
  "execution_time": "0.045s"
}
```

---

#### 设计优势
1. **安全特性**
   - 权限UUID防伪造
   - 敏感信息SHA256加密
   - 操作全程审计跟踪

2. **性能优化**
   - 对象复用（用户池）
   - 并行锁粒度控制
   - 弱引用避免内存泄漏

3. **扩展性**
   - `PermissionChecker` 可扩展接口
   - Prometheus 自定义指标
   - 弱耦合组件设计

> 注意：生产环境需调整 `USER_POOL_INIT_USERS` 和 `CACHE_TIME` 参数以获得最佳性能