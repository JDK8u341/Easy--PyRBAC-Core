import uuid
import threading
import logging
from datetime import datetime
from prometheus_client import Counter, start_http_server
import weakref
import json
import time

# 指标定义一哈
CMD_EXECUTED = Counter('cmd_executed', '执行的命令数量', ['cmd_name', 'status'])
PERM_CHANGES = Counter('perm_changes', '权限变更次数', ['action'])

# 配置log
logger = logging.getLogger('security_audit')
logger.setLevel(logging.INFO)

# 创建日志处理器
file_handler = logging.FileHandler('security.json.log')
file_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(file_handler)

# 添加控制台日志
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))
logger.addHandler(console_handler)

#辅助函数，写log的无情机器
def audit_log(event_type, details,level=None):
    log_entry = {
        "timestamp": datetime.now().isoformat() + "Z",
        "event_type": event_type,
        **details
    }
    if level is None:
        logger.info(json.dumps(log_entry))
    else:
        logger.error(json.dumps(log_entry))

class PermissionChecker:
    def check(self, user, command) -> bool:
        """权限检查接口"""
        raise NotImplementedError

class DefaultChecker(PermissionChecker):
    def check(self, user, command):
        user_perms = {perm for perm in user.permissions}
        required_perms = {perm for perm in command.need_permission}
        return required_perms.issubset(user_perms)


#角色类
class Role:
    __slots__ = ["name","permissions","users","__weakref__"]  #省内存

    def __init__(self,name,*init_permissions):
        if init_permissions is None:
            init_permissions = []       #如果不传初始化为空列表
        self.permissions = list(init_permissions)   #重要！不list新建对象的话拿到的是init_permissions的指针（内存地址）,会成元组，亲身体验过QwQ
        self.users = weakref.WeakSet()      #weakref省内存+保存安全
        self.name = name    #设置名字，没啥好说的，但还是忍不住逼逼两句，写注释写爽了（？）

    def add_permission(self,permission):
        self.permissions.append(permission)     #add方法封装，方便外部调用

    def remove_permission(self,permission):     #remove方法封装，方便外部调用
        self.permissions.remove(permission)

    def add_user(self,user):        #添加用户方法封装
        self.users.add(user)

    def remove_user(self,user):     #删除用户方法封装
        self.users.remove(user)

class User:
    __slots__ = ["name","role","permissions","__weakref__"]

    def __init__(self, name:str,role=None):
        self.name = name    #设置用户名
        self.role = role    #设置角色，默认没有（None）
        self.permissions = weakref.WeakSet()    #weakref省内存+防泄漏
        if not role is None:    #是None还加毛线
            for j in role.permissions:
                self.permissions.add(j)     #添加该角色有的权限
    def update(self):
        self.permissions = weakref.WeakSet() #重置权限列表
        if not self.role is None:   #虽然前面说了，但我还是忍不住再说一遍：是None还加毛线
            for j in self.role.permissions:
                self.permissions.add(j)     #添加该角色有的权限，懂得都懂（doge）

    def add_permission(self,permission):    #add方法封装，方便外部调用
        self.permissions.add(permission)

    def remove_permission(self,permission):     #remove方法封装，方便外部调用
        self.permissions.remove(permission)

    def set_role(self,role):        #设置role方法封装
        self.role = role


class Command:
    __slots__ = ["name","func","need_permission","last_executed","_last_user","__weakref__"]

    def __init__(self,name,func):
        self.name = name    #设置命令名字
        self.func = func    #设置调用的函数
        self.need_permission = []   #本命令要的权限
        self.last_executed = None   #这俩记录
        self._last_user = None      #用的

    def run(self,*args):
        start_time = time.perf_counter()    #记录个时间
        try:
            self.func(*args)
            status = "success"  #没报错返回SUCCESS！
        except Exception as e:
            status = "error"    #报错就发个error
            raise
        finally:    #必须TMD执行
            exec_time = time.perf_counter() - start_time    #运行时间
            self.last_executed = datetime.now() #最后调用时间
            # 记录命令执行详情
            audit_log("command_executed", {
                "user": getattr(self, '_last_user', 'system'),
                "command": self.name,
                "status": status,
                "execution_time": f"{exec_time:.4f}s",
                "permissions": [p.name for p in self.need_permission]   #发一下log
            })


class Terminal: #终端类
    __slots__ = ["user","manager","__lock","checker","login_time"]

    def __init__(self,manager,checker: PermissionChecker):   #初始化
        self.user = None    #默认没得用户
        self.manager = weakref.ref(manager)    #就是绑定一下manager类φ(*￣0￣)
        self.__lock = threading.RLock()  # 可重入锁，不然要是外部有锁了再进来就尴尬了😅
        self.checker = checker      #检查器，用的Java同款接口，你就说有没有逼格就完了！
        self.login_time = None      #登寡郎，啊不对，登录时间§(*￣▽￣*)§

    def set_user(self,user):    #设置用户
        self.user = user    #平平无奇的设置(*/ω＼*)
        self.login_time = datetime.now()    #登寡郎，啊不对，登录时间设置q(≧▽≦q)
        audit_log("user_session", {
            "event": "login",
            "user": user.name,
            "permissions": [p.name for p in user.permissions]
        })  #报log啊啊啊啊

    def run(self, command,*args):   #RUN！！！（兴奋）
        with self.__lock:  # 进锁，线程安全，with上下文
            if not self.user:
                audit_log("security_alert", {
                    "event": "unauthorized_access",
                    "message": "Command execution attempt without user context"
                })  #没设置user写log然后报错╰（‵□′）╯（—---谁让你不设置的！）
                raise ValueError("No user set for terminal!")

            # 临时记录一下(●'◡'●)
            command._last_user = self.user.name

            #超级有逼格的Java同款的检查器接口╰(￣ω￣ｏ)
            if self.checker.check(self.user, command):  #通过了
                command.run(*args)  #就TM运行！
                CMD_EXECUTED.labels(command.name, 'success').inc()  #顺便记录
            else:
                #否则，嘿嘿嘿┗|｀O′|┛（--老子直接TM给你拦下来）
                missing_perms = set(p.name for p in command.need_permission) - set(p.name for p in self.user.permissions)   #还提示你少了哪些权限，这贴心度不给个五星好评对不起我ヾ(≧▽≦*)o
                audit_log("permission_denied", {
                    "user": self.user.name,
                    "command": command.name,
                    "missing_permissions": list(missing_perms),
                    "required_permissions": [p.name for p in command.need_permission],
                    "user_permissions": [p.name for p in self.user.permissions]
                })#log报一下
                CMD_EXECUTED.labels(command.name, 'denied').inc()   #再记录
                raise OSError(f"Missing required permissions: {', '.join(missing_perms)}")      #选OSError因为逼格拉满

class Permission:   #权限类，你问我为啥不用str，因为清晰好用还多送你uuid安全大礼包！
    __slots__ = ["name","__uuid","command_refs","created_at","__weakref__"]

    def __init__(self, name):
        self.name = str(name)   #我告诉你，有些别有用心之人啊，就喜欢搞偷袭
        self.__uuid = uuid.uuid4()      #UUID安全BIG礼包！让你吃到爽
        # ref省内存我说了多少遍了，算了忘了o(〃＾▽＾〃)o
        self.command_refs = weakref.WeakSet()   #绑定的命令的ref
        self.created_at = datetime.now()    #创建时间啊啊啊
        audit_log("permission_created", {
            "permission": self.name,
            "uuid": str(self.__uuid)
        })  #继续报log

    def add_command(self, command):     #添加绑定的命令啊
        # 只存ref省内存
        self.command_refs.add(command)  #加他
        audit_log("permission_assigned", {
            "permission": self.name,
            "command": command.name
        })#报log

    def remove_command(self, command):  #移除啊！
        if command in self.command_refs:    #先判断在不在里面，不然报错就尴尬了O(∩_∩)O
            self.command_refs.remove(command)
            audit_log("permission_revoked", {
                "permission": self.name,
                "command": command.name
            })#继续让无情机器写log

    def __eq__(self, other):
        # 验证时同时检查名称和UUID，安全BIG礼包
        return self.name == other.name and self.__uuid == other.__uuid

    # 获取实际命令对象的方法，打下手的
    def get_commands(self):
        return list(self.command_refs)

    #报错的时候找教程改的，我也不知道为什么QwQ
    def __hash__(self):
        return hash(self.name)

class Manager:  #主管理器！
    __slots__ = ["permissions","roles","commands","__weakref__"]

    def __init__(self): #初始化一下
        self.permissions = weakref.WeakValueDictionary()    #又是ref，字典款ref，用来存需要管理的权限，你值得拥有(　o=^•ェ•)o　┏━┓
        self.roles = weakref.WeakValueDictionary()  #存角色的
        self.commands = weakref.WeakValueDictionary()   #存命令的
        audit_log("system_event", {"event": "permission_manager_initialized"})#又TM写log

    def config_permission(self, permission):    #配置一个权限
        self.permissions[permission.name] = permission  #加字典里，名字：实际对象
        audit_log("permission_registered", {
            "permission": permission.name,
            "system": "global"
        })#还是写log

    def add_command(self, command, permission):
        # 通过权限名获取实际对象
        perm_obj = self.permissions.get(permission.name)
        if perm_obj:    #有才处理嘛╰(￣ω￣ｏ)
            perm_obj.add_command(command)   #绑定一哈
            command.need_permission.append(perm_obj)    #双向奔赴（doge）
        self.commands[command.name] = command #记录命令

    def remove_command(self, command, permission):  #移除绑定
        # 通过权限名获取实际对象
        perm_obj = self.permissions.get(permission.name)
        if perm_obj:        #没有处理毛线
            perm_obj.remove_command(command)    #移除
            if perm_obj in command.need_permission:     #双层校验包你平安
                command.need_permission.remove(perm_obj)
        if command in self.commands.keys(): #自己存的也删了
            self.commands.pop(command.name)

    def config_role(self,role): #配置一下角色
        self.roles[role.name] = role    #设置，角色名：角色对象
        audit_log("role_registered", {
            "role": role.name,
            "system": "global"
        })#继续TMD写log

    def add_user_to_role(self,user,role_name):  #设置一个用户为某个角色
        role = self.roles.get(role_name)    #获取一哈
        role.add_user(user) #添加一哈
        user.set_role(role) #双向奔赴
        user.update()   #更新

    def remove_user_to_role(self,user,role_name):
        role =  self.roles.get(role_name)   #获取一哈
        if user in role.users:  #有才移除
            role.remove_user(user)
        user.set_role(None) #设成None
        user.update()   #更新哈状态

    def issue(self, user_or_role, permission):  #授权
        #try包裹防报错
        try:
            perm_obj = self.permissions.get(permission.name)    #Get一哈
            if not perm_obj:    #如果没有就报错
                raise ValueError(f"Permission {permission.name} not found")
            if isinstance(user_or_role,User):   #User执行User操作
                user_or_role.add_permission(perm_obj)   #add
                audit_log("permission_granted_user", {
                    "user": user_or_role.name,
                    "permission": permission.name,
                    "granted_by": "system"
                })#提log
            elif isinstance(user_or_role,Role):     #Role执行role操作
                user_or_role.add_permission(perm_obj)   #add
                audit_log("permission_granted_role", {
                    "role": user_or_role.name,
                    "permission": permission.name,
                    "granted_by": "system"
                })  #提log
                # 动态更新User状态
                for user in user_or_role.users:
                    user.update()   #每个都更新一遍
            PERM_CHANGES.labels('grant').inc()  #提交一哈
        except Exception as e:
            audit_log("permission_error", {
                "event": "grant_failed",
                "user": user_or_role.name,
                "permission": permission.name,
                "error": str(e)
            }, level="ERROR")   #报错就写日志

    def relieve(self, user_or_role, permission): #解除你地授权！
        #流程是一样的
        try:
            perm_obj = self.permissions.get(permission.name)
            if perm_obj and perm_obj in user_or_role.permissions:
                if isinstance(user_or_role, User):
                    user_or_role.remove_permission(perm_obj)#只有这里
                    audit_log("permission_revoked_user", {
                        "user": user_or_role.name,
                        "permission": permission.name,
                        "revoked_by": "system"
                    })
                    PERM_CHANGES.labels('revoke').inc()
                elif isinstance(user_or_role, Role):
                    user_or_role.permissions.remove(perm_obj)#和这里
                    audit_log("permission_revoked_role", {
                        "user": user_or_role.name,
                        "role": permission.name,
                        "revoked_by": "system"
                    })#还有log不同
                    #动态更新User状态
                    for user in user_or_role.users:
                        user.update()
                PERM_CHANGES.labels('revoke').inc()
        except Exception as e:
            audit_log("permission_error", {
                "event": "revoke_failed",
                "user": user_or_role.name,
                "permission": permission.name,
                "error": str(e)
            }, level="ERROR")

    def get_command_object(self,command_name):  #辅助函数，获取对象用
        return self.commands.get(command_name)

    def get_role_object(self,role_name):    #一样的
        return self.roles.get(role_name)

    def get_permission_object(self,permission_name):    #还是一样的
        return self.permissions.get(permission_name)

start_http_server(8000) #server，启动



if __name__ == '__main__':
    #测试小程序
    def fuck():
        print("fuck teacher and homeworks!!!")

    C = DefaultChecker()    #check接口
    PM = Manager()  #主管理器
    P = Permission('fuck')  #权限名
    R = Role('R')   #定义一个角色
    terminal = Terminal(PM,C)   #定义一个终端，绑定Check和管理器
    user1 = User('草')   #定义用户
    terminal.set_user(user1)    #设置该终端的用户
    c = Command('fuck',fuck)    #定义命令
    PM.config_permission(P)     #添加权限P（fuck）
    PM.add_command(c,P)     #绑定命令c到P
    PM.config_role(R)   #添加角色R
    PM.issue(R,P)   #授权角色R有P权限（相当于用户组）
    i = 0
    for_test= False#是否重复循环测试
    try:
        while True:
            i = i+1
            Cmd = PM.get_command_object('fuck') #没错我就是故意的
            try:
                terminal.run(Cmd)
            except OSError as e:
                print('TEST OK:   '+str(e))

            PM.issue(user1,P)   #授权（对用户）
            terminal.run(Cmd)
            PM.relieve(user1,P) #取消授权（对用户）
            try:
                terminal.run(Cmd) #报错
            except OSError as e:
                print('TEST OK:   '+str(e))

            PM.add_user_to_role(user1,'R')  #添加角色到用户
            terminal.run(Cmd)
            PM.remove_user_to_role(user1,'R')   #解除
            try:
                terminal.run(Cmd)
            except OSError as e:
                print('TEST Role OK:   ' + str(e))  #绝对报错
            if not for_test:
                break

    except KeyboardInterrupt:
        print("RUN :"+ str(i))
