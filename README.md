
## 一个由初中生编写的简单RBAC python实现,仅建议您学习使用

---

#### **模块概述**
该模块实现了一个细粒度的权限管理系统，包含用户/角色管理、权限分配、命令执行审计等功能。核心特性包括：
- 基于角色的权限控制（RBAC）
- 命令执行审计与安全日志
- Prometheus 监控指标集成
- 线程安全设计
- 弱引用优化内存管理

---

### **核心类说明**

#### **1. `PermissionChecker` 权限检查接口**
```python   ”“python   ```python
"python"   “巨蟒”
```
class PermissionChecker:   经济舱PermissionChecker:   经济舱PermissionChecker:
    def check(self, user, command) -> bool:def 检查(self， 用户， 命令) -> booldef 检查(self， 用户， 命令) -> bool
```
- **功能**：验证用户是否有权限执行命令
- **参数**：
  - `user   用户`：用户对象
  - `command   命令`：命令对象
- **返回值**：`True   真正的` 有权限，`False   假` 无权限
- **实现类**：`DefaultChecker`（默认检查器）

#### **2. `Role   角色` 角色管理类**
```python   ”“python   ```python
"python"
```
class Role:   类角色:   类角色:
    def __init__(self, name, *init_permissions):
    def add_permission(self, permission):def self.add_permission(权限def self.add_permission(权限
    def remove_permission(self, permission):def 移除权限(self， 权限def 移除权限(self， 权限
```
- **属性**：
  - `name`：角色名称
  - `permissions`：角色权限列表
  - `users`：关联用户（弱引用集合）
- **方法**：
  - `add_user(user)`/`remove_user(user)`：关联/解绑用户
  - 权限操作自动更新关联用户

#### **3. `User` 用户管理类**
```python
class User:
    def __init__(self, name: str, password:str, role=None):
    def login(self, password):
    def leave(self):
    def update(self):
```
- **属性**：
  - `password`：哈希存储的密码
  - `is_login`：登录状态标识
  - `permissions`：权限集合（继承角色+单独授权）
- **安全特性**：
  - `login()` 验证密码并记录审计日志
  - `update()` 自动同步角色权限变更

#### **4. `Command` 命令执行类**
```python
class Command:
    def __init__(self, name, func):
    def run(self, *args):
```
- **属性**：
  - `need_permission`：所需权限列表
  - `last_executed`：最后执行时间
- **方法**：
  - `run()`：执行命令并记录：
    - 执行耗时
    - 执行状态（success/error）
    - 权限使用情况

#### **5. `Terminal` 终端控制类**
```python
class Terminal:
    def set_user(self, user):
    def run(self, command, *args):
```
- **核心流程**：
  1. 通过 `set_user()` 绑定用户
  2. `run()` 执行命令前检查：
     - 用户登录状态
     - 命令执行权限
     - 自动记录 Prometheus 指标
- **安全机制**：
  - 线程锁保证操作原子性
  - 未授权访问触发安全警报日志

#### **6. `Permission` 权限实体类**
```python
class Permission:
    def __init__(self, name):
    def add_command(self, command):
    def remove_command(self, command):
```
- **安全特性**：
  - 内置 UUID 防伪造
  - 弱引用关联命令对象
- **审计**：
  - 权限创建/分配/回收均记录审计日志

#### **7. `Manager` 系统管理中枢**
```python
class Manager:
    def config_permission(self, permission):
    def add_command(self, command, permission):
    def issue(self, user_or_role, permission):
    def relieve(self, user_or_role, permission):
```
- **核心功能**：
  - `issue()`/`relieve()`：权限授予/回收
  - 支持用户或角色级授权
  - 权限变更自动同步用户状态
- **对象管理**：
  - 全局管理权限/角色/命令对象
  - 弱引用字典存储优化内存

---

### **监控与审计**
#### **Prometheus 指标**
```python
CMD_EXECUTED = Counter('cmd_executed', '执行的命令数量', ['cmd_name', 'status'])
PERM_CHANGES = Counter('perm_changes', '权限变更次数', ['action'])
```
- 指标类型：
  1. 命令执行统计（按状态分类）
  2. 权限变更次数（grant/revoke）

#### **审计日志类型**
| 事件类型 | 触发场景 | 关键字段 |
|----------|----------|----------|
| `command_executed` | 命令执行 | 用户、状态、耗时、权限 |
| `permission_denied` | 权限拒绝 | 缺失权限、用户现有权限 |
| `permission_granted_*` | 权限授予 | 目标（用户/角色）、权限名 |
| `user_session` | 用户登录 | 用户、权限列表 |
| `security_alert` | 安全事件 | 未授权访问告警 |

---

### **使用示例**
#### 1. 初始化系统
```python   ”“python
checker = DefaultChecker()
manager = Manager()
terminal = Terminal(manager, checker)
```

#### 2. 创建权限与角色
```python
read_perm = Permission("read_data")
write_perm = Permission("write_data")
manager.config_permission(read_perm)
manager.config_permission(write_perm)

admin_role = Role("admin", read_perm, write_perm)
manager.config_role(admin_role)
```

#### 3. 注册命令
```python   ”“python
def data_export():
    print("Exporting data...")

export_cmd = Command("export", data_export)
manager.add_command(export_cmd, read_perm)  # 关联读取权限
```

#### 4. 用户与权限管理
```python   ”“python
user = User("Alice", "secure_pwd")
manager.add_user_to_role(user, "admin")  # 赋予管理员角色
terminal.set_user(user)   终端设置用户为 user 。
user.login("secure_pwd")  # 登录认证
```

#### 5. 执行命令
```python   ”“python
try:
    terminal.run(export_cmd)  # 成功执行
except PermissionError as e:
    print(f"执行失败: {e}")
```

---

### **注意事项**
1. **线程安全**：
   - 关键操作使用 `threading.RLock   线程。RLock` 锁
   - 日志记录器内置线程锁

2. **内存优化**：
   - 广泛使用 `weakref` 避免循环引用
   - `__slots__` 减少内存占用

3. **安全特性**：
   - 密码哈希存储
   - 权限 UUID 防伪造
   - 未登录用户禁止操作

4. **监控接入**：
   - Prometheus 服务端口：8000
   - 日志路径：`./security.json.log`

> 通过 `if __name__ == '__main__':` 的测试代码可快速验证全流程功能
