# VNC，端口 5900
### 安装
Centos 6 以上：
```
yum install tigervnc-server
yum groupinstall "X Window System"
```

### 复制模板配置文件
```
cp /lib/systemd/system/vncserver@.service /lib/systemd/system/vncserver@:1.service
```
其中 1 代表一个用户序号，分配的端口为 5091，依次类推。修改配置文件中的 USER 为对应的系统用户名

```
remove /etc/systemd/system/default.target
ln -s /lib/systemd/system/graphical.target /etc/systemd/system/default.target
```
设置系统默认使用图形化界面

### 设置独立密码
```
su foobar
vncpasswd
```
用户登录 VNC 密码，不同于系统用户密码，家目录下生成 .vnc 目录，密码存在于 ~/.vnc/passwd

启用服务：
```
systemctl reload-daemon
systemctl enable vncserver@:1.service
systemctl start vncserver@:1.service
```

### 安全
爆破可以使用 Metasploit 的 vnc_login 模块，tigervnc 有防爆破措施，必须设置单线程：
```
set BRUTEFORCE_SPEED 1
```

# vsftpd
### 安装
```
yum install vsftpd
```

### 配置
配置文件位于 /etc/vsftpd/vsftpd.conf，通过该文件可关闭匿名，限制读写。限制用户切换到其他目录：
```
local_chroot=YES
allow_writeable_chroot=YES # 这个是必须的，否则无法限制用户在个人目录
```

使用本地用户进行验证。

# pure-ftpd

### 安装
```
yum install pure-ftpd
```

验证方式有多种：本地用户、虚拟用户 和 MySQL 数据库用户

### 配置
配置文件位于 /etc/pure-ftpd/pure-ftpd.conf，可以在其中禁用匿名访问。开启本地用户登录（默认是允许的）：
```
PAMAuthentication yes
```

使用 pure-ftpd 携带的 pure-pw 可以添加虚拟用户，首先新建 ftpuser 和 ftpgroup 组：
```
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /sbin/nologin ftpuser
```

之后使用 pure-pw 添加用户，设置密码，并建立本地数据库：
```
pure-pw useradd foo -d /home/foo -u ftpuser
pure-pw mkdb
```

虚拟用户会存储在 /etc/pure-ftpd/pure-ftpd.passwd 中（可设置 PURE_PASSWDFILE 来指定。

使用 pure-pw 来修改虚拟用户密码：
```
pure-pw passwd foo
```

pure-ftpd 还支持使用 MySQL 数据存储用户凭据，具体在其配置文件有描述，可通过登陆 MySQL 来修改用户信息，密码加密方式同样在配置文件中指出，如 MD5，SHA1。

# Proftpd

### 配置
```
DefaultRoot ~       # 禁止所有用户切换到非个人目录
MaxLoginAttempts 2  # 最大登陆错误次数
```

可以在配置文件中定义 Anonymous 标签允许匿名登录，最新版 Proftpd 已经定义，但是需要在 /etc/sysconfig/proftpd 文件中启用：
```
PROFTPD_OPTIONS="-DANONYMOUS_FTP"
```

Proftpd 同样支持多种验证方式，常见：本地用户，虚拟用户，数据库用户。

#### 配置数据库用户：
```
<IfModule mod_sql.c>
<..SNIPPED..>
</IfModule>
```
> 加密方式由 SQLAuthTypes 指定，参考 [http://www.proftpd.org/docs/directives/linked/config_ref_SQLAuthTypes.html](http://www.proftpd.org/docs/directives/linked/config_ref_SQLAuthTypes.html)

#### 配置虚拟用户：

安装 proftpd-utils：
```
yum install proftpd-utils
```
设置配置文件：
```
RequireValidShell off # 无 Shell 也能登陆
AuthOrder mod_auth_file.c # 必须制定只允许虚拟用户登录
AuthUserFile /etc/proftpd/ftpd.passwd
```
使用 ftpasswd 建立用户：
```
ftpasswd --passwd --name=foo --home=/home/foo --shell=/bin/false --uid=1000
```
目录下会生成 ftpd.passwd 文件，包含用户信息，修改密码：
```
ftpasswd --passwd --name=foo --change-password
```

# NFS，端口 2049

### 配置
NFS 用于文件共享，其配置非常简单，**NFS 不支持密码验证**，但是可以限制 IP 访问，配置文件位于 /etc/exports：
```
/var/secret 192.168.2.1(rw,sync)
```
该配置共享 /var/secret 文件，同时限制只能由 192.168.2.1 用户访问，允许读写。也可以制定一个网段 192.168.2.0/24，指定本地 IP 可以限制外部访问（也有可能被改 IP 绕过。

### 挂载共享
显示远程主机共享目录：
```
showmount -e 192.168.56.3
```
可以看到如下：
```
Export list for 192.168.56.3:
/var/secret 192.168.56.0/24
```

尝试挂载：
```
mkdir /tmp/secret
mount -t nfs 192.168.56.3:/var/secret /tmp/secret
```

# rsync，端口 873

### 配置
配置文件位于 /etc/rsync.conf，主要安全参数：
```
use chroot = yes
read only = yes
hosts allow =192.168.56.0/255.255.255.0 172.10.1.0/255.255.255.0
hosts deny =*
```
设置可同步文件源（同样加入到配置文件：
```
[datasource]
path = /var/datasource
list = yes
auth users = root, foobar
secrets file = /etc/rsyncd.secrets
exclude = secret/
```
list 设置是否在列出数据源，仅知道数据源名称可以访问，默认开启。auth users 和 secrets file 用于用户验证，/etc/rsyncd.secrets 的格式如下：
```
root:p@ssw0rd
foo:gu3ssm3
```

### 同步
列出目标主机目录列表（无需密码也可以访问：
```
rsync --list-only 192.168.56.3::
```
**::** 代表为远程主机，之后可以进行同步：
```
rsync -avzP 192.168.56.3::datasource datasrc
```
>具体命令参考[http://www.cnblogs.com/itech/archive/2009/08/10/1542945.html](http://www.cnblogs.com/itech/archive/2009/08/10/1542945.html)

# Samba，端口 139
```
yum install samba
```

### 配置
位于 /etc/samba/smb.conf：
```
[datasource]
path = /var/datasource
browseable = yes
read only = yes
```

将用户添加至 Samba 数据库，并设置密码：
```
smbpasswd -a foo
```

### 访问
使用 smbclient 列出共享目录：
```
smbclient -L 192.168.56.3 -U foo
```
smbclient 支持类 FTP 的方式访问共享目录，首先进入交互式界面：
```
smbclient //192.168.56.3/datasource -U foo
```
获取文件：
```
smb: \> get secret.txt
```

# redis，端口 6379
```
yum install redis
```

### 配置
配置文件位于 /etc/redis.conf：
```
bind 127.0.0.1 # 限制本地访问
requirepass bullshit # 密码访问
```

### 访问
使用 redis-cli 访问：
```
redis-cli -h 192.168.56.3
```
或者 nc 直接访问：
```
nc 192.168.56.3 6379
```

如果设置 requirepass，需要使用 auth 命令验证：
```
auth bullshit
```

查看基本信息：
```
info
```
切换 key-value 空间（namespace：
```
$ info keyspace
db0:keys=1,expires=0,avg_ttl=0
$ select 0
```
显示所有键：
```
$ keys *
```
键值对存储与读取：
```
set name John
get name
```

# Memcached，端口 11211
```
yum install memcached php-memcached
```

PHP 访问 memcached：
```
$mem = new Memcache; // 注意不是 Memcached
$mem->connect('192.168.56.3', 11211);
$mem->set('name', 'John');
$mem->sey('password', 'secret');
```

使用 nc 访问 memcached 服务：
```
nc 192.168.56.3 11211
```

显示键值对数目：
```
stats items
```

显示 slabs 信息，并通过 slabs id 获取其中的键：
```
stats slabs
stats cachedump <id> <size>
```

查看键值对内容：
```
get name
get password
```

Memcached 无验证机制，通过回环监听来限制访问，配置文件位于 /etc/sysconfig/memcached：
```
OPTIONS="-l 127.0.0.1"
```

# mongodb（```未完善```）

# iptables

### 防爆破
```
iptables -A INPUT -p tcp --dport 21 -m recent --name ftp --set
iptables -A INPUT -p tcp --dport 21 -m recent --update --name ftp --seconds 60 --hitcount 10 -j DROP
```

- 规则一：指定 recent 模块，将访问 21 端口的 IP 存放在 ftp 仓库中，这是 --set 命令的作用
- 规则二：从 ftp 仓库取出 IP，如果 60 秒内登陆次数达到 9 次，则抛弃后续连接，否则计数器累加

### DNAT 和 SNAT（```未完善```）
首先开启路由转发：
```
echo 1 > /proc/sys/net/ipv4/ip_forward
```
如果为静态 IP：
```
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.56.1:80
iptables -t nat -A POSTROUTING -s 192.168.56.0/24 -j SNAT --to-source 192.168.56.3
```

### 禁止 ICMP
使用系统网络配置：
```
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
```
或者使用 iptables：
```
iptables -A INPUT -p icmp --icmp-type 8 -j DROP
```
