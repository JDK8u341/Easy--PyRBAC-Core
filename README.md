# Easy--PyRBAC-Core   #轻松——PyRBAC-Core   简单——PyRBAC-Core
A simple RBAC core written by a junior high school student一个由初中生编写的简单的基于角色的访问控制核心


---

### Permission Management System Documentation (English)

---

#### 1. Overview  
A role-based permission management framework with fine-grained access control and security auditing. Core components include Users, Roles, Permissions, Commands, and Terminals. Optimized with weak references, integrated with Prometheus monitoring and JSON logging.

---

#### 2. Core Components

##### 2.1 Permission  
- **Purpose**: Encapsulates rights required for command execution  
- **Attributes**:
  - `name`: Permission name (string)
  - `uuid`: Auto-generated unique identifier
  - `command_refs`: Weak-referenced set of bound commands  
- **Key Methods**:
  - `add_command(command)`: Bind to a command
  - `remove_command(command)`: Unbind from a command
  - `__eq__`: Validation using both name and UUID

##### 2.2 Role  
- **Purpose**: Container for permission sets  
- **Attributes**:
  - `name`: Role identifier
  - `permissions`: List of permissions
  - `users`: Weak-referenced set of assigned users  
- **Methods**:
  - `add_permission()` / `remove_permission()`: Manage permissions
  - `add_user()` / `remove_user()`: Manage users

##### 2.3 User  
- **Purpose**: Entity performing operations  
- **Attributes**:
  - `name`: User identifier
  - `role`: Assigned role
  - `permissions`: Personal permissions (weak set)  
- **Key Methods**:
  - `update()`: Sync role permissions to user
  - `add_permission()` / `remove_permission()`: Manage personal permissions

##### 2.4 Command  
- **Purpose**: Encapsulates executable actions  
- **Attributes**:   * * - * *属性:
  - `name`: Command identifier
  - `func`: Associated function
  - `need_permission`: Required permissions list  
- **Methods**:   - * * * *方法:
  - `run(*args)`: Execute command + log performance- `run(*args)`：执行命令  记录性能
  - Auto-tracks last execution time and user自动跟踪上次执行时间和用户

##### 2.5 Terminal     ##### 2.5终端
- **Purpose**: Entry point for command execution  - **目的**：命令执行的入口点
- **Attributes**:   * * - * *属性:
  - `user`: Logged-in user   已登录用户
  - `checker`: Permission validator- `checker`：权限验证器
  - `__lock`: Thread lock (ensures atomicity)  - `__lock`：线程锁（确保原子性）
- **Key Methods**:   关键方法**：
  - `set_user(user)`: Authenticate user- `set_user(user)`：验证用户
  - `run(command, *args)`: Validate permissions + execute- `run(command, *args)`：验证权限 执行

##### 2.6 Manager     ##### 2.6管理器
- **Purpose**: Central coordinator  - **目的**：中央协调员
- **Functions**:   * * - * *功能:
  - Global registry: Manages permissions/roles/commands (weakref-based)全局注册表：管理权限/角色/命令（基于弱引用）
  - Permission control: `issue()` grant / `relieve()` revoke权限控制：`issue()` 授予 / `relieve()` 撤销
  - Role management: `add_user_to_role()` / `remove_user_to_role()`- 角色管理：`add_user_to_role()` / `remove_user_to_role()`
  - Live updates: Auto-syncs user permissions on role changes实时更新：在角色变更时自动同步用户权限

---

#### 3. Auxiliary Systems   #### 3. 辅助系统

##### 3.1 Permission Checker  
- **Interface**: `check(user, command) -> bool`  
- **Default**: `DefaultChecker`  - **Default**: ‘ DefaultChecker ’
  - Verifies user permissions cover command requirements

##### 3.2 Audit Logging     3.2 审计日志记录
- **Format**: JSON Lines (one event per line)  - **格式**：JSON 行（每行一个事件）
- **Tracked Events**:   - **跟踪事件**：
  - Permission creation/binding/revocation权限创建/绑定/撤销
  - User login/permission changes用户登录/权限变更
  - Command execution (success/failure)命令执行（成功/失败）
  - Permission denial details  权限拒绝详情
- **Output**: File (`security.json.log`) + console输出：文件（`security.json.log`） 控制台

##### 3.3 Prometheus Monitoring  3.3 普罗米修斯监控
- **Metrics**:   - * * * *指标:
  - `cmd_executed`: Command executions (by status)- `cmd_executed`：按状态划分的命令执行情况
  - `perm_changes`: Permission modifications (grant/revoke)- `perm_changes`：权限修改（授予/撤销）
- **Port**: `8000` (via `start_http_server`)- **端口**：`8000`（通过 `start_http_server` 启动）

---

#### 4. Key Technologies     #### 4. 关键技术
- **Weak References**     - 弱引用
  - Used in `users`/`command_refs` collections  
  - Prevents memory leaks from circular references  
- **Thread Safety**  
  - `threading.RLock` in Terminal ensures atomic command execution  
- **UUID Validation**     - **UUID 验证**
  - Permission comparison uses name+UUID to prevent spoofing  权限比较使用名称 UUID 以防止欺骗。

---

#### 5. Workflow     # # # # 5。工作流
1. **Initialization**     1. 初始化
   - Create permissions/roles/commands → register with Manager  创建权限/角色/命令 → 在管理器处注册
   - Bind permissions to commands: `manager.add_command(cmd, perm)`  将权限绑定到命令：`manager.add_command(cmd, perm)`
2. **User Operation**     2. 用户操作
   - Authenticate user: `terminal.set_user(user)`  - 验证用户：`terminal.set_user(user)   终端设置用户为 user 。`
   - Execute command: `terminal.run(command)`  执行命令：`terminal.run(command)`
3. **Permission Check**     3. 权限检查
   - Validator checks permissions → Execute command or log denial  验证器检查权限 → 执行命令或记录拒绝情况
4. **Live Updates**     4. * * * *活更新
   - Role permission changes → Auto-update affected users  角色权限变更 → 自动更新受影响用户

---

#### 6. Example Scenario   6. 示例场景
```python   ”“python
# Initialize components   # 初始化组件
manager = Manager()   经理（）
perm_write = Permission('write_data')perm_write = 权限('写入数据
cmd_save = Command('save', save_function)cmd_save = Command('保存', save_function
terminal = Terminal(manager, DefaultChecker())终端 = 终端管理器(管理器， 默认检查器

# Configure permissions   # 配置权限
manager.config_permission(perm_write)管理员配置写入权限。
manager.add_command(cmd_save, perm_write)管理器添加命令（cmd_save），并设置权限为写入（perm_write）。

# Create role and grant permissions# 创建角色并授予权限
role_editor = Role('Editor')角色编辑 = 角色（'编辑'）
manager.config_role(role_editor)管理员配置编辑角色
manager.issue(role_editor, perm_write)经理授予（或分配）编辑角色写入权限。

# User execution flow   # 用户执行流程
user = User("Bob")   user = user （"Bob"）
terminal.set_user(user)   终端设置用户为 user 。
manager.add_user_to_role(user, 'Editor')经理将用户添加到“编辑”角色中。
terminal.run(cmd_save)  # Success!终端运行（cmd_save）  # 成功！
```
