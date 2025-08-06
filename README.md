# Easy--PyRBAC-Core   
A simple RBAC core written by a junior high school student一个由初中生编写的简单的基于角色的访问控制核心

# Note: This document was translated from Chinese and may contain some language errors

## Please note that this project is only recommended for study


```markdown   ”“减价
# Permission Management Audit System Documentation权限管理审计系统文档权限管理审计系统文档

## Overview   # #概述   # #概述
This Python module implements a thread-safe permission management audit system, including user/role permission management, command execution auditing, logging, and Prometheus monitoring functionality.此 Python 模块实现了一个线程安全的权限管理审计系统，包括用户/角色权限管理、命令执行审计、日志记录以及 Prometheus 监控功能。此 Python 模块实现了一个线程安全的权限管理审计系统，包括用户/角色权限管理、命令执行审计、日志记录以及 Prometheus 监控功能。

## Core Components   ##核心组件   ##核心组件

### 1. Logging and Monitoring System### 1. 日志记录与监控系统### 1. 日志记录与监控系统
```python   ”“python   ”“python
# Log configuration   #日志配置   #日志配置
logger = logging.getLogger('security_audit')日志记录器 = 日志记录模块.getLogger('安全审计日志记录器 = 日志记录模块.getLogger('安全审计
logger.setLevel(logging.INFO)日志记录器设置为信息级别。日志记录器设置为信息级别。

# Prometheus metrics   # 普罗米修斯指标   # 普罗米修斯指标
CMD_EXECUTED = Counter('cmd_executed', 'Number of commands executed', ['cmd_name', 'status'])CMD_EXECUTED = 计数器('cmd_executed', '已执行命令的数量', ['cmd_name', 'status'])CMD_EXECUTED = 计数器('cmd_executed', '已执行命令的数量', ['cmd_name', 'status'])CMD_EXECUTED = 计数器('cmd_executed', '已执行命令的数量', ['cmd_name', 'status'])CMD_EXECUTED = 计数器('cmd_executed', '已执行命令的数量', ['cmd_name', 'status'])
PERM_CHANGES = Counter('perm_changes', 'Number of permission changes', ['action'])PERM_CHANGES = Counter('perm_changes', '权限变更数量', ['action
```

### 2. Audit Log Class   ### 2.审计日志功能
```python   ”“python
class Logger:
    __slots__ = ['_lock'] 
    def __init__(self) -> None:
        self._lock = threading.RLock()
    def audit_log(self,event_type, details,level=None):
        with self._lock:    
            log_entry = {
                "timestamp": datetime.now().isoformat() ,
                "event_type": event_type,
                **details
            }
            if level is None:
                logger.info(json.dumps(log_entry))
            else:
                logger.error(json.dumps(log_entry))

Loggers = Logger() 
    }
```

### 3. Permission Check Interface
```python   ”“python
class PermissionChecker:
    def check(self, user, command) -> bool:
        """Abstract method for permission checking"""

class DefaultChecker(PermissionChecker):经济舱DefaultChecker (PermissionChecker):
    def check(self, user, command):
        """Default implementation: Check if user permissions include required command permissions"""
        return required_perms.issubset(user_perms)
```

### 4. Core Data Models
#### Role Model (Role)
```python   ”“python
class Role:   类角色:
    __slots__ = ["name", "permissions", "users", "__weakref__"]
    
    def add_permission(self, permission):
    def remove_permission(self, permission):
    def add_user(self, user):
    def remove_user(self, user):
```

#### User Model (User)
```python
class User:
    __slots__ = ["name", "role", "permissions", "__weakref__"]
    
    def update(self):
    def add_permission(self, permission):
    def remove_permission(self, permission):
    def set_role(self, role):
```

#### Command Model (Command)
```python
class Command:
    __slots__ = ["name", "func", "need_permission", "last_executed", "_last_user", "__weakref__"]
    
    def run(self, *args):
        """Execute command and record audit log"""
```

#### Permission Model (Permission)
```python
class Permission:
    __slots__ = ["name", "__uuid", "command_refs", "created_at", "__weakref__"]
    
    def add_command(self, command):
    def remove_command(self, command):
    def __eq__(self, other):
        """Dual validation based on name and UUID"""
```

### 5. Terminal System (Terminal)
```python
class Terminal:
    __slots__ = ["user", "manager", "__lock", "checker", "login_time"]
    
    def set_user(self, user):
    def run(self, command, *args):
        """Execute command with permission check"""
```

### 6. Central Manager (Manager)
```python
class Manager:
    __slots__ = ["permissions", "roles", "commands", "__weakref__"]
    
    # Permission management
    def config_permission(self, permission):
    def add_command(self, command, permission):
    def remove_command(self, command, permission):
    
    # Role management
    def config_role(self, role):
    def add_user_to_role(self, user, role_name):
    def remove_user_to_role(self, user, role_name):
    
    # Permission operations
    def issue(self, user_or_role, permission):  # Grant permission
    def relieve(self, user_or_role, permission): # Revoke permission
```

## System Features

1. **Thread-Safe Design**
   - Uses `threading.RLock` to ensure thread safety during command execution
   - Weak references (`weakref`) prevent memory leaks

2. **Audit Trail**
   - Structured JSON logs for all key operations
   - Command execution details (user, status, duration)
   - Permission change history (grant/revoke)

3. **Permission Verification**
   - Dual validation using UUID + name
   - Dynamic role permission updates
   - Detailed permission deficiency reporting

4. **Monitoring Integration**
   - Prometheus metrics:
     - `cmd_executed`: Command execution statistics
     - `perm_changes`: Permission change statistics
   - HTTP service port: 8000

5. **Memory Optimization**
   - `__slots__` reduce memory footprint
   - Weak reference sets prevent circular references
   - On-demand loading design

## Usage Example

```python
# Initialize system
C = DefaultChecker()
PM = Manager()
terminal = Terminal(PM, C)

# Create permission
P = Permission('file_delete')

# Create command
def delete_file():
    print("Deleting file...")
del_cmd = Command('delete', delete_file)

# Configure permission
PM.config_permission(P)
PM.add_command(del_cmd, P)

# Create user and role
admin_role = Role('Admin', P)
user = User('Alice')
terminal.set_user(user)

# Permission testing
terminal.run(del_cmd)  # Fails (no permission)
PM.issue(user, P)      # Grant permission
terminal.run(del_cmd)  # Succeeds
```

## Audit Log Example
```json
{
  "timestamp": "2023-10-05T12:34:56.789Z",
  "event_type": "command_executed",
  "user": "Alice",
  "command": "delete",
  "status": "success",
  "execution_time": "0.0023s",
  "permissions": ["file_delete"]
}
```

## Monitoring Metrics
- `cmd_executed{cmd_name="delete", status="success"} 1`
- `perm_changes{action="grant"} 1`

## Important Notes
1. Call `user.update()` after permission changes to synchronize state
2. Command execution must go through `Terminal.run()` for audit compliance
3. Manage lifecycle carefully for weak-referenced objects
4. Log files auto-generated at `security.json.log`
```
