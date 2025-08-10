from collections import deque
import uuid
import threading
from datetime import datetime
from prometheus_client import Counter, start_http_server
import weakref
import time
from hashlib import sha256
from functools import lru_cache
import os
import  json
import  redis
from  logger import Logger

USER_POOL_INIT_USERS = 100  # 预生成对象数量
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
LOGGER_SAVE_FILE = './security.json.log'
IS_FIRST_RUN = True

Loggers = Logger('security_audit',LOGGER_SAVE_FILE)  # 不想改了就直接初始化了。。。


# 指标定义一哈
CMD_EXECUTED = Counter('cmd_execute', '执行的命令数量', ['cmd_name', 'status'])
PERM_CHANGES = Counter('perm_changes', '权限变更次数', ['action'])


class PermissionChecker:
    def check(self, user, command) -> bool:
        """权限检查接口"""
        raise NotImplementedError


class DefaultChecker(PermissionChecker):
    def check(self, user, command):
        # 获取最新权限状态
        user_perms = user.get_perms()

        required_perms = {p.name for p in command.need_permission}
        return required_perms.issubset(user_perms)


# 角色类
class Role:
    __slots__ = ["name", "permissions", "users","_permission_names","_user_names","manager"]  # 省内存

    def __init__(self, name,manager,*init_permissions,parent=None):
        self.manager = manager
        self.permissions = set(init_permissions) #直接转set
        self.users = weakref.WeakSet()  # 用户s
        self.name = name  # 设置名字，没啥好说的，但还是忍不住逼逼两句，写注释写爽了（？）
        self._permission_names = set(p.name for p in init_permissions)
        self._user_names = set()        #这俩存关系用的（Redis持久化）
        if parent:
            self.permissions |= parent.permissions # 递归获取
            self._permission_names |= parent._permission_names  #名字也要获取
        RM.write_role_info(self)

    def add_permission(self, permission):
        self.permissions.add(permission)  # add方法封装，方便外部调用
        self._permission_names.add(permission.name)
        RM.write_role_permissions(self)

    def remove_permission(self, permission):  # remove方法封装，方便外部调用
        self.permissions.remove(permission)
        self._permission_names.remove(permission.name)
        RM.write_role_permissions(self)

    def add_user(self, user):  # 添加用户方法封装
        self.users.add(user)
        self._user_names.add(user.name)
        RM.write_role_user_names(self)

    def remove_user(self, user):  # 删除用户方法封装
        self.users.discard(user)
        self._user_names.discard(user.name)
        RM.write_role_user_names(self)

    def rebuild_relations(self, manager):
        # 1. 重建权限关系
        self.permissions = set()
        for perm_name in self._permission_names:
            perm = manager.get_permission_object(perm_name) #通过name获取obj
            if perm:    #如果有
                self.permissions.add(perm)

        # 2. 重建用户关系
        self.users = weakref.WeakSet()
        for username in self._user_names:
            user = manager.get_user_object(username)    #循环获取user的obj(*^▽^*)┛
            if user:
                self.users.add(user)    #如果有就添加
                user.role = self  # 双向关系啊啊啊(づ￣ 3￣)づ


class UserPool:
    _pool = deque(maxlen=10000)
    _lock = threading.RLock()

    @classmethod
    def create_user(cls, name, password, role=None):
        with cls._lock:
            if cls._pool:
                user = cls._pool.popleft()
                user.__init__(name, password, role)  # 调用原有初始化方法
                return user
            return User(name, password, role)

    @classmethod
    def recycle_user(cls, user):
        with cls._lock:
            user.name = None
            user.role = None
            user._password = None
            user._salt = None
            user._uuid = None
            user.permissions = weakref.WeakSet()
            user._is_login = False
            user._perm_cache = None # 清空减少占用
            user._login_time = None
            cls._pool.append(user)  # FIFO保证不区别对待，没得阶级固化（doge）




class User:
    __slots__ = ["name", "role", "permissions", "_password", "_perm_cache","__weakref__",
                 "_is_login","_login_time","_salt","_uuid","role_name",
                 "permission_names","_role_name","_permission_names"]
    def __init__(self, name: str, password: str, role=None):
        hash_object = sha256()
        self._salt = os.urandom(24)
        hash_object.update(password.encode('utf-8')+self._salt)  # 保密hash存储
        self._password = hash_object.hexdigest()
        self.name = name  # 设置用户名
        self.role = role  # 设置角色，默认没有（None）
        if self.role is not None:
            self.role_name = self.role.name
        else:
            self.role_name = ''
        self.permissions = weakref.WeakSet()  # 存权限的
        self.permission_names = [i.name for i in self.permissions]
        self._is_login = False
        self._perm_cache = None  # 权限缓存
        self._login_time = time.time()  # 登陆时间戳
        self._uuid = uuid.uuid4()
        # 存储关系名称
        self._role_name = role.name if role else None
        self._permission_names = set()
        if not role is None:  # 是None还加毛线
            role.users.add(self)  # 主动添加到角色
        RM.write_user_info(self)

    def login(self, password):
        hash_obj = sha256()
        # 使用字节串格式的 salt
        hash_obj.update(password.encode('utf-8') + self._salt)
        if hash_obj.hexdigest() == self._password:
            self._is_login = True
            self._login_time = time.time()
            Loggers.audit_log("user_login", {
                "user": self.name,
                "status": "success"
            })
            return True
        else:
            Loggers.audit_log("user_login", {
                "user": self.name,
                "status": "failed"
            })
            return False

    def leave(self):
        self._is_login = False  # 离开自动状态处理

    def update(self):
        self.get_perms.cache_clear()  #更新缓存
    def add_permission(self, permission):  # add方法封装，方便外部调用
        self.permissions.add(permission)
        permission.related_users.add(self)  # 增加反向绑定
        RM.write_user_permission(self)

    def remove_permission(self, permission):  # remove方法封装，方便外部调用
        self.permissions.remove(permission)
        permission.related_users.remove(self)  # 增加反向绑定
        RM.write_user_permission(self)

    def set_role(self, role):  # 设置role方法封装
        self.role = role
        RM.write_user_role_name(self)

    def delete(self):
        if self.role:
            self.role.remove_user(self)
            # 2. 解除权限关联
        for perm in dict(self.permissions).values():
            if self in perm.related_users:
                perm.remove(self)
        UserPool.recycle_user(self)

    @lru_cache(maxsize=1)
    def get_perms(self) -> set:
        perms = {p.name for p in self.permissions}
        if self.role:
            perms |= {p.name for p in self.role.permissions}

        self._perm_cache = perms
        return perms

    @property
    def is_login(self):
        return self._is_login and (time.time() - self._login_time) <= 1800


    def __del__(self):  # 如果你非得删了的话
        """不建议直接删了,建议您用delete方法复用对象以提高性能"""
        if self.role:
            self.role.remove_user(self)  # 清理

    def rebuild_relations(self, manager):
        # 1. 重建角色关系
        if self.role_name:  #如果角色存在
            role_obj = manager.get_role_object(self.role_name)  #调用manager获取角色对象
            if role_obj:    #如果他有
                self.role = role_obj    #设置我们的角色
                role_obj.users.add(self)  # 重建弱引用

        # 2. 重建权限关系
        for perm_name in self.permission_names: #获取每一个名字
            perm_obj = manager.get_permission_object(perm_name) #获取这个对象
            if perm_obj:    #如果有
                self.permissions.add(perm_obj)  #重建weakref
                perm_obj.related_users.add(self)  # 双向弱引用


class Command:
    __slots__ = ["name", "func_name", "need_permission", "last_executed", "_last_user", "__weakref__","_permission_names"]

    def __init__(self, name, func_name):
        self.name = name  # 设置命令名字
        self.func_name = func_name  # 设置调用的函数
        self.need_permission = set()  # 本命令要的权限
        self.last_executed = None  # 这俩记录
        self._last_user = None  # 用的

        # 存储权限名称
        self._permission_names = set()

    def run(self, *args):
        # 从函数配置中心获取实际函数
        func = self._get_function()
        if not func:
            raise RuntimeError(f"Command function '{self.func_name}' not found")
        start_time = time.perf_counter()  # 记录个时间
        try:
            func(*args)
            status = "success"  # 没报错返回SUCCESS！
        except Exception as e:
            status = "error"  # 报错就发个error
            raise
        finally:  # 必须TMD执行
            exec_time = time.perf_counter() - start_time  # 运行时间
            self.last_executed = datetime.now()  # 最后调用时间
            # 记录命令执行详情
            Loggers.audit_log("command_executed", {
                "user": getattr(self, '_last_user', 'system'),
                "command": self.name,
                "status": status,
                "execution_time": f"{exec_time:.4f}s",
                "permissions": [p.name for p in self.need_permission]  # 发一下log
            })

    def rebuild_relations(self, manager):
        self.need_permission = set()    #重建关系用的
        for perm_name in self._permission_names:
            perm = manager.get_permission_object(perm_name) #Get一下obj
            if perm:
                self.need_permission.add(perm)
                perm.command_refs.add(self)

    def _get_function(self):
        try:
            # 动态导入函数配置中心
            from func_config import COMMAND_REGISTRY
            return COMMAND_REGISTRY.get(self.func_name)
        except ImportError:
            Loggers.audit_log("system_error", {
                "event": "func_config_missing",
                "message": "func_config.py not found"
            }, level="ERROR")
            return None


class Terminal:  # 终端类
    __slots__ = ["user", "manager", "__lock", "checker", "bind_time"]

    def __init__(self, manager, checker: PermissionChecker):  # 初始化
        self.user = None  # 默认没得用户
        self.manager = weakref.ref(manager)  # 就是绑定一下manager类φ(*￣0￣)
        self.__lock = threading.RLock()  # 可重入锁，不然要是外部有锁了再进来就尴尬了😅
        self.checker = checker  # 检查器，用的Java同款接口，你就说有没有逼格就完了！
        self.bind_time = None  # 登寡郎，啊不对，用户绑定本终端的时间§(*￣▽￣*)§

    def set_user(self, user):  # 设置用户
        self.user = user  # 平平无奇的设置(*/ω＼*)
        self.bind_time = datetime.now()  # 登寡郎，啊不对，登录时间设置q(≧▽≦q)
        Loggers.audit_log("user_session", {
            "event": "login",
            "user": user.name,
            "permissions": [p.name for p in user.permissions]
        })  # 报log啊啊啊啊

    def run(self, command, *args):  # RUN！！！（兴奋）
        with self.__lock:  # 进锁，线程安全，with上下文
            if not self.user:
                Loggers.audit_log("security_alert", {
                    "event": "unauthorized_access",
                    "message": "Command execution attempt without user context"
                })  # 没设置user写log然后报错╰（‵□′）╯（—---谁让你不设置的！）
                raise ValueError("No user set for terminal!")

            # 临时记录一下(●'◡'●)
            command._last_user = self.user.name

            if not self.user.is_login:  # 没登录也报错
                Loggers.audit_log("user_no_login_but_run_command", {
                    "user": self.user.name,
                    "run_command": command.name,
                    "message": "The User is not login,but want run command"
                })  # log
                raise OSError(f"User {self.user.name} is not Login")

            # 超级有逼格的Java同款的检查器接口╰(￣ω￣ｏ)
            if self.checker.check(self.user, command):  # 通过了
                command.run(*args)  # 就TM运行！
                CMD_EXECUTED.labels(command.name, 'success').inc()  # 顺便记录
            else:
                # 否则，嘿嘿嘿┗|｀O′|┛（--老子直接TM给你拦下来）
                missing_perms = set(p.name for p in command.need_permission) - self.user.get_perms() # 还提示你少了哪些权限，这贴心度不给个五星好评对不起我ヾ(≧▽≦*)o
                Loggers.audit_log("permission_denied", {
                    "user": self.user.name,
                    "command": command.name,
                    "missing_permissions": list(missing_perms),
                    "required_permissions": [p.name for p in command.need_permission],
                    "user_permissions": list(self.user.get_perms())
                })  # log报一下
                CMD_EXECUTED.labels(command.name, 'denied').inc()  # 再记录
                raise PermissionError(f"Missing required permissions: {', '.join(missing_perms)}")  # 报错


class Permission:  # 权限类，你问我为啥不用str，因为清晰好用还多送你uuid安全大礼包！
    __slots__ = ["name", "__uuid", "command_refs", "created_at", "related_users", "__weakref__","_command_names","_user_names"]

    def __init__(self, name):
        self.name = str(name)  # 我告诉你，有些别有用心之人啊，就喜欢搞偷袭
        self.__uuid = uuid.uuid4()  # UUID安全BIG礼包！让你吃到爽
        # ref省内存我说了多少遍了，算了忘了o(〃＾▽＾〃)o
        self.command_refs = weakref.WeakSet()  # command弱引用
        self.created_at = datetime.now()  # 创建时间啊啊啊
        self.related_users = weakref.WeakSet()  # 绑定的用户
        # 存储关系名称
        self._command_names = set()
        self._user_names = set()
        Loggers.audit_log("permission_created", {
            "permission": self.name,
            "uuid": str(self.__uuid)
        })  # 继续报log

    def add_command(self, command):  # 添加绑定的命令啊
        # 只存ref省内存
        self.command_refs.add(command)  # 加他
        Loggers.audit_log("permission_assigned", {
            "permission": self.name,
            "command": command.name
        })  # 报log

    def remove_command(self, command):  # 移除啊！
        if command in self.command_refs:  # 先判断在不在里面，不然报错就尴尬了O(∩_∩)O
            self.command_refs.remove(command)
            Loggers.audit_log("permission_revoked", {
                "permission": self.name,
                "command": command.name
            })  # 继续让无情机器写log

    def __eq__(self, other):
        # 验证时同时检查名称和UUID，安全BIG礼包
        return self.name == other.name and self.__uuid == other.__uuid

    # 获取实际命令对象的方法，打下手的
    def get_commands(self):
        return list(self.command_refs)

    def add_user(self, user):  # 添加绑定的用户的方法
        self.related_users.add(user)

    def remove_user(self, user):  # 移除绑定的用户的方法
        self.related_users.discard(user)

    # 报错的时候找教程改的，我也不知道为什么QwQ
    def __hash__(self):
        return hash((self.name, self.__uuid))

    def rebuild_relations(self, manager):
        # 重建命令关系
        #逻辑一样的，不用讲了吧QwQ
        self.command_refs = weakref.WeakSet()
        for cmd_name in self._command_names:
            cmd = manager.get_command_object(cmd_name)
            if cmd:
                self.command_refs.add(cmd)
                cmd.need_permission.add(self)

        # 重建用户关系
        self.related_users = weakref.WeakSet()
        for username in self._user_names:
            user = manager.get_user_object(username)
            if user:
                self.related_users.add(user)
                user.permissions.add(self)


class Manager:  # 主管理器！
    __slots__ = ["permissions", "roles", "commands", "__weakref__","users"]

    def __init__(self):  # 初始化一下
        self.permissions = {}  # 改为普通dict
        self.roles = {}  # 存角色的
        self.users = {}
        self.commands = weakref.WeakValueDictionary()  # 存命令的
        Loggers.audit_log("system_event", {"event": "permission_manager_initialized"})  # 又TM写log

    def config_permission(self, permission):  # 配置一个权限
        self.permissions[permission.name] = permission  # 加字典里，名字：实际对象
        Loggers.audit_log("permission_registered", {
            "permission": permission.name,
            "system": "global"
        })  # 还是写log

    def add_command_to_permission(self, command, perm_obj):
        if perm_obj:  # 有才处理嘛╰(￣ω￣ｏ)
            perm_obj.add_command(command)  # 绑定一哈
            command.need_permission.add(perm_obj)  # 双向奔赴（doge）
        self.commands[command.name] = command  # 记录命令

    def remove_command_to_permission(self, command, perm_obj):  # 移除绑定
        if perm_obj:  # 没有处理毛线
            perm_obj.remove_command(command)  # 移除
            if perm_obj in command.need_permission:  # 双层校验包你平安
                command.need_permission.remove(perm_obj)
        if command in self.commands.keys():  # 自己存的也删了
            self.commands.pop(command.name)

    def config_role(self, role):  # 配置一下角色
        self.roles[role.name] = role  # 设置，角色名：角色对象
        Loggers.audit_log("role_registered", {
            "role": role.name,
            "system": "global"
        })  # 继续TMD写log

    def add_user_to_role(self, user, role_name):  # 设置一个用户为某个角色
        role = self.roles.get(role_name)  # 获取一哈
        role.add_user(user)  # 添加一哈
        user.set_role(role)  # 双向奔赴
        user.update()  # 更新
        Loggers.audit_log("set_user_role", {
            "user": user.name,
            "role": role.name,
            "permissions": list(i.name for i in user.permissions),
            "granted_by": "system"
        })  # 提log

    def remove_user_to_role(self, user, role_name):
        role = self.roles.get(role_name)  # 获取一哈
        if user in role.users:  # 有才移除
            role.remove_user(user)
        user.set_role(None)  # 设成None
        user.update()  # 更新哈状态
        Loggers.audit_log("reset_user_role", {
            "user": user.name,
            "role": role.name,
            "granted_by": "system"
        })  # 提log

    def issue(self, user_or_role, permission):  # 授权
        # try包裹防报错
        try:
            perm_obj = self.permissions.get(permission.name)  # Get一哈
            if not perm_obj:  # 如果没有就报错
                raise ValueError(f"Permission {permission.name} not found")
            if isinstance(user_or_role, User):  # User执行User操作
                user_or_role.add_permission(perm_obj)  # add
                permission.add_user(user_or_role)
                user_or_role.update()
                Loggers.audit_log("permission_granted_user", {
                    "user": user_or_role.name,
                    "permission": permission.name,
                    "user_permissions": list(user_or_role.get_perms()),
                    "granted_by": "system"
                })  # 提log
            elif isinstance(user_or_role, Role):  # Role执行role操作
                user_or_role.add_permission(perm_obj)  # add
                # 动态更新User状态
                for user in user_or_role.users:
                    user.update()  # 每个都更新一遍
                    permission.add_user(user)
                Loggers.audit_log("permission_granted_role", {
                    "role": user_or_role.name,
                    "permission": permission.name,
                    "role_permissions": list(i.name for i in user_or_role.permissions),
                    "granted_by": "system"
                })  # 提log
            PERM_CHANGES.labels('grant').inc()  # 提交一哈
        except Exception as e:
            Loggers.audit_log("permission_error", {
                "event": "grant_failed",
                "user": user_or_role.name,
                "permission": permission.name,
                "error": str(e)
            }, level="ERROR")  # 报错就写日志

    def relieve(self, user_or_role, permission):  # 解除你地授权！
        # 流程是一样的
        try:
            perm_obj = self.permissions.get(permission.name)
            if perm_obj and perm_obj in user_or_role.permissions:
                if isinstance(user_or_role, User):
                    user_or_role.remove_permission(perm_obj)  # 只有这里
                    permission.remove_user(user_or_role)
                    user_or_role.update()
                    Loggers.audit_log("permission_revoked_user", {
                        "user": user_or_role.name,
                        "permission": permission.name,
                        "user_permissions":list(user_or_role.get_perms()),
                        "revoked_by": "system"
                    })
                    PERM_CHANGES.labels('revoke').inc()
                elif isinstance(user_or_role, Role):
                    user_or_role.permissions.remove(perm_obj)  # 和这里
                    # 动态更新User状态s
                    for user in user_or_role.users:
                        user.update()
                        permission.remove_user(user)
                    Loggers.audit_log("permission_revoked_role", {
                        "role": user_or_role.name,
                        "permissions":permission.name,
                        "role_permissions":list(i.name for i in user_or_role.permissions),
                        "revoked_by": "system"
                    })  # 还有log不同
                PERM_CHANGES.labels('revoke').inc()
        except Exception as e:
            Loggers.audit_log("permission_error", {
                "event": "revoke_failed",
                "user": user_or_role.name,
                "permission": permission.name,
                "error": str(e)
            }, level="ERROR")

    def get_command_object(self, command_name):  # 辅助函数，获取对象用
        try:
            return self.commands.get(command_name)
        except IndexError:
            return None

    def get_role_object(self, role_name):  # 一样的
        try:
            return self.roles.get(role_name)
        except IndexError:
            return None

    def get_permission_object(self, permission_name):   # 还是一样的
        try:
            return self.permissions.get(permission_name)
        except IndexError:
            return None

class RedisManager:
    __slots__ = ["_pool","manager"]

    _lock = threading.RLock()

    def __init__(self,host,port,manager):
        self._pool = redis.ConnectionPool(
            host=host,
            port=port,
            decode_responses=True,  # 自动解码字符串
            max_connections=10
        )
        self.manager = manager


    def get_user_info(self,user_id=None,user=None):
        with redis.Redis(connection_pool=self._pool) as conn:
            if user is not None:
                user_info = conn.hgetall(f"user:{user._uuid}")
            elif user_id is not None:
                user_info =  conn.hgetall(f"user:{user_id}")
            else:
                raise ValueError("Not input User or User id")
            return user_info

    def get_user_password(self,user):
        with redis.Redis(connection_pool=self._pool) as conn:
            user_password = conn.hget(f"user:{user._uuid}","password_hash")
            user_salt = conn.hget(f"user:{user._uuid}","salt")
            return user_password,user_salt

    def get_user_permission(self,user):
        with redis.Redis(connection_pool=self._pool) as conn:
            user_permissions = conn.hget(f"user:{user._uuid}","permissions")
            return json.loads(user_permissions)

    def write_user_permission(self,user):
        with self._lock:
            with redis.Redis(connection_pool=self._pool) as conn:
                conn.hsetnx(f"user:{user._uuid}","permissions",json.dumps(list(user._permission_names)))


    def write_role_info(self, role):
        """存储角色信息到Redis"""
        role_info = {
            "name": role.name or "",
            "permission_names": json.dumps(list(role._permission_names)) if role._permission_names else "[]",
            "user_names": json.dumps(list(role._user_names)) if role._user_names else "[]"
        }
        with self._lock:
            with redis.Redis(connection_pool=self._pool) as conn:
                conn.hset(f"role:{role.name}", mapping=role_info)

    def write_permission_info(self, permission):
        """存储权限信息到Redis"""
        perm_info = {
            "name": permission.name or "",
            "command_names": json.dumps(list(permission._command_names)) if permission._command_names else "[]",
            "user_names": json.dumps(list(permission._user_names)) if permission._user_names else "[]"
        }
        with self._lock:
            with redis.Redis(connection_pool=self._pool) as conn:
                conn.hset(f"permission:{permission.name}", mapping=perm_info)



    def load_role(self, role_name):
        """加载并重建角色"""
        with redis.Redis(connection_pool=self._pool) as conn:
            role_info = conn.hgetall(f"role:{role_name}")

        if not role_info:
            return None

        role = Role(role_info["name"],self.manager)
        role._permission_names = set(json.loads(role_info.get("permission_names", "[]")))
        role._user_names = set(json.loads(role_info.get("user_names", "[]")))
        role.rebuild_relations(self.manager)
        return role

    def load_permission(self, perm_name, manager):
        """加载并重建权限"""
        with redis.Redis(connection_pool=self._pool) as conn:
            perm_info = conn.hgetall(f"permission:{perm_name}")

        if not perm_info:
            return None

        perm = Permission(perm_info["name"])
        perm._command_names = set(json.loads(perm_info.get("command_names", "[]")))
        perm._user_names = set(json.loads(perm_info.get("user_names", "[]")))

        perm.rebuild_relations(manager)
        return perm

    def write_command_info(self, command):
        """存储命令信息到Redis"""
        cmd_info = {
            "name": command.name or "",
            "func_name": command.func_name or "",
            "permission_names": json.dumps(list(command._permission_names)) if command._permission_names else "[]"
        }
        with self._lock:
            with redis.Redis(connection_pool=self._pool) as conn:
                conn.hset(f"command:{command.name}", mapping=cmd_info)

    def load_command(self, name):
        """从Redis加载命令信息"""
        with redis.Redis(connection_pool=self._pool) as conn:
            cmd_info = conn.hgetall(f"command:{name}")

        if not cmd_info:
            return None

        # 创建命令对象（不立即重建关系）
        return Command(
            name=cmd_info["name"],
            func_name=cmd_info["func_name"]
        )
    def write_role_permissions(self,role):
        with self._lock:
            with redis.Redis(connection_pool=self._pool) as conn:
                conn.hsetnx(f"role:{role.name}","permissions_names",json.dumps(list(role._permission_names)))

    def write_role_user_names(self,role):
        with self._lock:
            with redis.Redis(connection_pool=self._pool) as conn:
                conn.hsetnx(f"role:{role.name}","user_names",json.dumps(list(role._user_names)))

    def write_user_role_name(self,user):
        with self._lock:
            with redis.Redis(connection_pool=self._pool) as conn:
                conn.hsetnx(f"user:{user.name}","role",json.dumps(list(user.role_name)))

    def get_all_command_names(self):
        """获取所有命令名称"""
        with redis.Redis(connection_pool=self._pool) as conn:
            try:
                # 使用模式匹配查找所有命令键
                cmd_keys = conn.keys("command:*")
                # 从键名中提取命令名称
                return [key.split(":")[1] for key in cmd_keys] if cmd_keys else []
            except Exception as e:
                Loggers.audit_log("redis_error", {
                    "event": "get_all_command_names_failed",
                    "error": str(e)
                }, level="ERROR")
                return []  # 确保返回空列表而不是None


    def get_all_role_names(self):
        """获取所有角色名称"""
        with redis.Redis(connection_pool=self._pool) as conn:
            try:
                role_keys = conn.keys("role:*")
                return [key.split(":")[1] for key in role_keys] if role_keys else []
            except Exception as e:
                Loggers.audit_log("redis_error", {
                    "event": "get_all_role_names_failed",
                    "error": str(e)
                }, level="ERROR")
                return []

    def get_all_permission_names(self):
        """获取所有权限名称"""
        with redis.Redis(connection_pool=self._pool) as conn:
            try:
                perm_keys = conn.keys("permission:*")
                return [key.split(":")[1] for key in perm_keys] if perm_keys else []
            except Exception as e:
                Loggers.audit_log("redis_error", {
                    "event": "get_all_permission_names_failed",
                    "error": str(e)
                }, level="ERROR")
                return []

    def is_redis_empty(self):
        """检查Redis是否为空（首次运行）"""
        with redis.Redis(connection_pool=self._pool) as conn:
            # 检查是否有任何键存在
            if conn.dbsize() == 0 or IS_FIRST_RUN:
                return True
            else:
                return False

    def write_user_info(self, user):
        """存储用户信息到Redis"""
        user_info = {
            "name": user.name or "unknown",
            "password_hash": user._password or "",
            "salt": user._salt.hex() if user._salt else "",
            "role": user._role_name or "",
            "permission_names": json.dumps(list(user._permission_names)) if user._permission_names else "[]",
            "uuid": str(user._uuid)  # 确保 uuid 被存储
        }
        with self._lock:
            with redis.Redis(connection_pool=self._pool) as conn:
                conn.hset(f"user:{user._uuid}", mapping=user_info)

    def load_user(self, user_id):
        """从Redis加载用户信息"""
        try:
            with redis.Redis(connection_pool=self._pool) as conn:
                user_info = conn.hgetall(f"user:{user_id}")

            if not user_info:
                return None

            # 创建用户对象，使用 get 方法并提供默认值
            user = User(
                name=user_info.get("name", "unknown"),
                password="",
                role=None
            )
            user._uuid = uuid.UUID(user_id)
            user._password = user_info.get("password_hash", "")
            # permission.py
            user._permission_names = set(json.loads(user_info.get("permission_names", "[]")))

            # 处理 salt
            salt_hex = user_info.get("salt", "")
            user._salt = bytes.fromhex(salt_hex) if salt_hex else b""

            user._role_name = user_info.get("role", "")
            user._permission_names = set(json.loads(user_info.get("permission_names", "[]")))
            return user
        except Exception as e:
            Loggers.audit_log("redis_error", {
                "event": "load_user_failed",
                "user_id": user_id,
                "error": str(e)
            }, level="ERROR")
            return None

    def get_all_user_ids(self):
        """获取所有用户ID"""
        with redis.Redis(connection_pool=self._pool) as conn:
            user_keys = conn.keys("user:*")
            # 确保只返回有效的 UUID
            return [key.split(":")[1] for key in user_keys
                    if len(key.split(":")) > 1 and
                    self.is_valid_uuid(key.split(":")[1])] if user_keys else []

    def is_valid_uuid(self, val):
        """检查是否为有效的UUID"""
        try:
            uuid.UUID(str(val))
            return True
        except ValueError:
            return False


class RelationRebuilder:
    def __init__(self, manager):
        self.manager = manager
        self.users = []
        self.roles = []
        self.permissions = []
        self.commands = []

    def register_user(self, user):
        self.users.append(user)

    def register_role(self, role):
        self.roles.append(role)

    def register_permission(self, permission):
        self.permissions.append(permission)

    def register_command(self, command):
        self.commands.append(command)

    def rebuild_all(self):
        """重建所有关系（核心逻辑）"""
        # 1. 先重建角色（独立实体）
        for role in self.roles:
            self._rebuild_role(role)

        # 2. 重建权限（独立实体）
        for perm in self.permissions:
            self._rebuild_permission(perm)

        # 3. 重建命令（依赖权限）
        for cmd in self.commands:
            self._rebuild_command(cmd)

        # 4. 最后重建用户（依赖角色和权限）
        for user in self.users:
            self._rebuild_user(user)

    def _rebuild_role(self, role):
        """重建角色关系"""
        # 重建角色-权限关系
        role.permissions = set()
        for perm_name in role._permission_names:
            perm = self.manager.get_permission_object(perm_name)
            if perm:
                role.permissions.add(perm)

        # 重建角色-用户关系
        role.users = weakref.WeakSet()
        for username in role._user_names:
            user = self.manager.get_user_object(username)
            if user:
                role.users.add(user)

    def _rebuild_permission(self, perm):
        """重建权限关系"""
        # 重建权限-命令关系
        perm.command_refs = weakref.WeakSet()
        for cmd_name in perm._command_names:
            cmd = self.manager.get_command_object(cmd_name)
            if cmd:
                perm.command_refs.add(cmd)

        # 重建权限-用户关系
        perm.related_users = weakref.WeakSet()
        for username in perm._user_names:
            user = self.manager.get_user_object(username)
            if user:
                perm.related_users.add(user)

    def _rebuild_command(self, cmd):
        """重建命令关系"""
        cmd.need_permission = set()
        for perm_name in cmd._permission_names:
            perm = self.manager.get_permission_object(perm_name)
            if perm:
                cmd.need_permission.add(perm)

    def _rebuild_user(self, user):
        """重建用户关系"""
        # 重建用户-角色关系
        if user._role_name:
            role = self.manager.get_role_object(user._role_name)
            if role:
                user.role = role
                role.users.add(user)  # 双向关系

        # 重建用户-权限关系
        user.permissions = weakref.WeakSet()
        for perm_name in user._permission_names:
            perm = self.manager.get_permission_object(perm_name)
            if perm:
                user.permissions.add(perm)
                perm.related_users.add(user)  # 双向关系


def load_all_objects(rebuilder,RM):
    """从Redis加载所有对象并注册到重建器"""
    # 加载用户
    user_ids = RM.get_all_user_ids()
    for user_id in user_ids:
        user = RM.load_user(user_id)
        if user:
            rebuilder.register_user(user)
            manager.users[user.name] = user

    # 加载角色
    role_names = RM.get_all_role_names()
    for name in role_names:
        role = RM.load_role(name)
        if role:
            rebuilder.register_role(role)
            manager.roles[name] = role

    # 加载权限
    perm_names = RM.get_all_permission_names()
    for name in perm_names:
        perm = RM.load_permission(name)
        if perm:
            rebuilder.register_permission(perm)
            manager.permissions[name] = perm

    # 加载命令
    cmd_names = RM.get_all_command_names()
    for name in cmd_names:
        cmd = RM.load_command(name)
        if cmd:
            rebuilder.register_command(cmd)
            manager.commands[name] = cmd


def initialize_system(manager, RM):
    """初始化系统，处理首次运行情况"""
    # 1. 检查 Redis 是否为空
    is_first_run = RM.is_redis_empty()

    # 2. 如果是首次运行，创建默认管理员账户
    #if is_first_run:

    # 3. 加载所有对象
    rebuilder = RelationRebuilder(manager)

    # 获取所有用户ID
    user_ids = RM.get_all_user_ids() or []
    for user_id in user_ids:
        user = RM.load_user(user_id)
        if user:
            rebuilder.register_user(user)
            manager.users[user.name] = user

    # 获取所有角色名称
    role_names = RM.get_all_role_names() or []
    for name in role_names:
        role = RM.load_role(name)
        if role:
            rebuilder.register_role(role)
            manager.roles[name] = role

    # 获取所有权限名称
    perm_names = RM.get_all_permission_names() or []
    for name in perm_names:
        perm = RM.load_permission(name,manager)
        if perm:
            rebuilder.register_permission(perm)
            manager.permissions[name] = perm

    # 获取所有命令名称
    cmd_names = RM.get_all_command_names() or []
    for name in cmd_names:
        cmd = RM.load_command(name)
        if cmd:
            rebuilder.register_command(cmd)
            manager.commands[name] = cmd

    # 4. 重建所有关系
    rebuilder.rebuild_all()

    # 5. 如果是首次运行，创建其他默认对象



if __name__ == '__main__':
    # 1. 创建管理器
    manager = Manager()

    # 2. 创建Redis管理器
    RM = RedisManager(REDIS_HOST, REDIS_PORT, manager)

    # 3. 初始化系统
    initialize_system(manager, RM)

    # 4. 创建测试对象
    # 创建权限
    can_fuck = Permission("can_fuck")
    manager.config_permission(can_fuck)



    # 需要先定义函数配置
    from func_config import COMMAND_REGISTRY


    fuck_cmd = Command("fuck", "fuck")
    manager.add_command_to_permission(fuck_cmd, can_fuck)

    # 创建角色
    fucker_role = Role("fucker",manager)
    manager.config_role(fucker_role)

    # 创建用户
    user = UserPool.create_user("CAO", "12345678")

    # 5. 测试
    terminal = Terminal(manager, DefaultChecker())
    terminal.set_user(user)

    # 授权
    manager.issue(user, can_fuck)  # 给用户授权
    manager.add_user_to_role(user, "fucker")  # 添加用户到角色

    # 登录
    user.login("12345678")

    # 执行命令
    terminal.run(fuck_cmd)

