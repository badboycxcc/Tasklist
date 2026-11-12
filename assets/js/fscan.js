/*!
 * Fscan Report Inspector - fscan 结果解析引擎
 * ---------------------------------------------------------------
 * 解决"fscan 结果很乱"的问题: 把纯文本结果归一化成结构化数据。
 *
 * 输入(支持混排, 自动识别):
 *   - 端口开放行:      192.168.1.1:445 open  /  [+] 192.168.1.1:445 open
 *   - [+] 结果行:      [+] 192.168.1.1:445	smb	Windows Server 2008 R2 7601
 *                      [+] 192.168.1.1:22	ssh	root:123456
 *                      [+] 192.168.1.1:6379	redis	Redis unauthorized access
 *   - 漏洞命中:        [+] MS17-010 192.168.1.5 445
 *                      [+] PocScan http://192.168.1.6/ poc-yaml-tomcat-cve-2017-12615
 *   - Web 标题:        [+] http://192.168.1.7:8080  Apache Tomcat/7.0.47
 *                      [+] WebTitle http://192.168.1.7  IIS Windows Server
 *   - 兼容 nmap:       Nmap scan report for 1.2.3.4 + 445/tcp open microsoft-ds
 *
 * 输出:
 *   hosts[]    每个 IP: 端口/服务/Web 标题/弱口令/漏洞/操作系统/风险分
 *   findings[] 弱点清单: 系统过旧(EOL)/弱口令/未授权/已知漏洞/高危端口/组件过旧/后台暴露
 *   osGroups[] 按操作系统分组
 *   portMatrix 端口矩阵(端口 → 命中主机)
 *   unknown[]  没能识别的原始行(便于排查解析器)
 *
 * 纯字符串处理, 无外部依赖, 可在 Node 下 require 做自测。
 */
(function (root) {
  "use strict";

  /* ============================================================
   * 1. 端口 → 服务 / 风险
   * ============================================================ */
  var PORT_MAP = {
    21: { s: "ftp", n: "FTP", lv: "medium", note: "FTP 明文传输, 常见匿名访问与弱口令", noteEn: "FTP sends cleartext — anonymous access and weak credentials are common" },
    22: { s: "ssh", n: "SSH", lv: "low" },
    23: { s: "telnet", n: "Telnet", lv: "high", note: "Telnet 明文登录, 口令可被嗅探", noteEn: "Telnet cleartext login — credentials can be sniffed" },
    25: { s: "smtp", n: "SMTP", lv: "low" },
    53: { s: "dns", n: "DNS", lv: "low" },
    69: { s: "tftp", n: "TFTP", lv: "medium", note: "TFTP 无认证, 可读写设备配置", noteEn: "TFTP has no authentication — device configs can be read or overwritten" },
    80: { s: "http", n: "HTTP", lv: "low" },
    81: { s: "http", n: "HTTP", lv: "low" },
    88: { s: "kerberos", n: "Kerberos", lv: "low" },
    110: { s: "pop3", n: "POP3", lv: "low" },
    111: { s: "rpcbind", n: "rpcbind", lv: "medium", note: "rpcbind 暴露, 可枚举 NFS 挂载", noteEn: "rpcbind exposed — NFS exports can be enumerated" },
    135: { s: "msrpc", n: "MSRPC", lv: "high", note: "Windows RPC, 常用于横向移动与信息枚举", noteEn: "Windows RPC — abused for lateral movement and enumeration" },
    137: { s: "netbios-ns", n: "NetBIOS-NS", lv: "medium" },
    139: { s: "netbios", n: "NetBIOS", lv: "high", note: "NetBIOS 共享, 可枚举主机名/共享/用户", noteEn: "NetBIOS — enumerate hostnames, shares and users" },
    143: { s: "imap", n: "IMAP", lv: "low" },
    161: { s: "snmp", n: "SNMP", lv: "medium", note: "SNMP 常见 public 团体字, 泄露系统与网络信息", noteEn: "SNMP often keeps the public community string — leaks system and network info" },
    389: { s: "ldap", n: "LDAP", lv: "medium", note: "LDAP 可能允许匿名枚举域信息", noteEn: "LDAP may allow anonymous domain enumeration" },
    443: { s: "https", n: "HTTPS", lv: "low" },
    445: { s: "smb", n: "SMB", lv: "high", note: "SMB 共享, MS17-010(永恒之蓝)/SMBGhost 的主要入口", noteEn: "SMB — primary entry for MS17-010 (EternalBlue) / SMBGhost" },
    512: { s: "exec", n: "rexec", lv: "medium" },
    513: { s: "login", n: "rlogin", lv: "medium" },
    514: { s: "shell", n: "rsh", lv: "high", note: "rsh 免密命令执行", noteEn: "rsh remote shell often trusts hosts without a password" },
    873: { s: "rsync", n: "rsync", lv: "medium", note: "rsync 未授权可同步全站文件", noteEn: "rsync may allow unauthenticated full-file sync" },
    993: { s: "imaps", n: "IMAPS", lv: "low" },
    995: { s: "pop3s", n: "POP3S", lv: "low" },
    1080: { s: "socks", n: "SOCKS", lv: "medium", note: "代理端口暴露, 可作为内网跳板", noteEn: "Proxy exposed — usable as a pivot into the intranet" },
    1099: { s: "rmi", n: "Java RMI", lv: "high", note: "Java RMI 反序列化高危面", noteEn: "Java RMI — deserialization attack surface" },
    1433: { s: "mssql", n: "MSSQL", lv: "high", note: "SQL Server 直连, 弱口令即可拿库", noteEn: "SQL Server exposed — weak credentials lead straight to the database" },
    1434: { s: "mssql-browser", n: "MSSQL Browser", lv: "medium" },
    1521: { s: "oracle", n: "Oracle", lv: "high", note: "Oracle 监听暴露", noteEn: "Oracle listener exposed" },
    2049: { s: "nfs", n: "NFS", lv: "high", note: "NFS 未授权挂载可读写文件", noteEn: "NFS may allow unauthenticated read/write mounts" },
    2181: { s: "zookeeper", n: "ZooKeeper", lv: "medium", note: "ZooKeeper 未授权可读写配置", noteEn: "ZooKeeper unauthenticated reads/writes config" },
    2222: { s: "ssh", n: "SSH", lv: "low" },
    2375: { s: "docker", n: "Docker API", lv: "high", note: "Docker API 未授权 = 宿主 root", noteEn: "Unauthenticated Docker API equals host root" },
    2376: { s: "docker", n: "Docker API(TLS)", lv: "high", note: "Docker API 暴露 = 容器逃逸/宿主控制", noteEn: "Docker API exposed — container escape / host takeover" },
    2379: { s: "etcd", n: "etcd", lv: "high", note: "etcd 未授权可读密钥与证书", noteEn: "etcd without auth leaks secrets and certificates" },
    3000: { s: "http", n: "HTTP", lv: "low" },
    3306: { s: "mysql", n: "MySQL", lv: "high", note: "MySQL 直连, 弱口令即可拿库", noteEn: "MySQL exposed — weak credentials lead straight to the database" },
    3389: { s: "rdp", n: "RDP", lv: "high", note: "RDP 暴露: 弱口令爆破 / BlueKeep(CVE-2019-0708)", noteEn: "RDP exposed — credential brute force / BlueKeep (CVE-2019-0708)" },
    4444: { s: "other", n: "unknown", lv: "medium" },
    4848: { s: "glassfish", n: "GlassFish", lv: "medium" },
    5000: { s: "http", n: "HTTP", lv: "low" },
    5432: { s: "postgres", n: "PostgreSQL", lv: "high", note: "PostgreSQL 直连, 弱口令即可拿库", noteEn: "PostgreSQL exposed — weak credentials lead straight to the database" },
    5555: { s: "adb", n: "ADB", lv: "high", note: "Android 调试桥未授权 = 设备被控", noteEn: "ADB without auth means full device control" },
    5601: { s: "kibana", n: "Kibana", lv: "medium" },
    5672: { s: "rabbitmq", n: "RabbitMQ", lv: "medium" },
    5900: { s: "vnc", n: "VNC", lv: "high", note: "VNC 常见空口令/弱口令", noteEn: "VNC often has empty or weak passwords" },
    5985: { s: "winrm", n: "WinRM", lv: "high", note: "WinRM 弱口令可直接执行命令", noteEn: "WinRM weak credentials give direct command execution" },
    5986: { s: "winrm", n: "WinRM(TLS)", lv: "high", note: "WinRM 弱口令可直接执行命令", noteEn: "WinRM weak credentials give direct command execution" },
    6066: { s: "kafka", n: "Kafka", lv: "medium" },
    6379: { s: "redis", n: "Redis", lv: "high", note: "Redis 未授权 = 写 SSH 公钥/crontab 拿权限", noteEn: "Unauthenticated Redis — write SSH keys or cron jobs to gain a shell" },
    6443: { s: "k8s-api", n: "K8s API", lv: "high", note: "K8s API 未授权 = 集群控制", noteEn: "Unauthenticated Kubernetes API means cluster control" },
    7001: { s: "weblogic", n: "WebLogic", lv: "high", note: "WebLogic 历史反序列化 RCE 重灾区", noteEn: "WebLogic — historic deserialization RCEs" },
    7002: { s: "weblogic", n: "WebLogic(TLS)", lv: "high" },
    8000: { s: "http", n: "HTTP", lv: "low" },
    8009: { s: "ajp", n: "AJP", lv: "high", note: "AJP Ghostcat(CVE-2020-1938) 可读文件/RCE", noteEn: "AJP Ghostcat (CVE-2020-1938) — file read / RCE" },
    8080: { s: "http", n: "HTTP", lv: "low" },
    8081: { s: "http", n: "HTTP", lv: "low" },
    8089: { s: "splunk", n: "Splunk", lv: "medium" },
    8161: { s: "activemq", n: "ActiveMQ", lv: "high", note: "ActiveMQ 默认 admin/admin, CVE-2016-3088 可写马", noteEn: "ActiveMQ default admin/admin; CVE-2016-3088 allows webshell upload" },
    8443: { s: "https", n: "HTTPS", lv: "low" },
    8500: { s: "consul", n: "Consul", lv: "medium" },
    8888: { s: "http", n: "HTTP", lv: "low" },
    9000: { s: "http", n: "HTTP", lv: "medium", note: "常为 PHP-FPM/FastCGI, 配置不当可 RCE", noteEn: "Often PHP-FPM / FastCGI — misconfiguration leads to RCE" },
    9042: { s: "cassandra", n: "Cassandra", lv: "medium" },
    9090: { s: "http", n: "HTTP", lv: "low" },
    9200: { s: "elasticsearch", n: "Elasticsearch", lv: "high", note: "ES 未授权, 数据可读写", noteEn: "Elasticsearch without auth — data can be read and written" },
    9300: { s: "elasticsearch", n: "Elasticsearch(transport)", lv: "high" },
    9418: { s: "git", n: "Git", lv: "medium", note: "git 协议暴露, 可拉取源码", noteEn: "git protocol exposed — source code can be cloned" },
    10000: { s: "webmin", n: "Webmin", lv: "high", note: "Webmin 历史未授权 RCE(CVE-2019-15107)", noteEn: "Webmin — historic unauthenticated RCE (CVE-2019-15107)" },
    11211: { s: "memcached", n: "Memcached", lv: "high", note: "Memcached 未授权 + UDP 反射放大", noteEn: "Memcached without auth plus UDP reflection amplification" },
    15672: { s: "rabbitmq-mgmt", n: "RabbitMQ 管理台", lv: "medium", note: "RabbitMQ 管理台默认 guest/guest", noteEn: "RabbitMQ management UI defaults to guest/guest" },
    27017: { s: "mongodb", n: "MongoDB", lv: "high", note: "MongoDB 未授权可直接拖库", noteEn: "Unauthenticated MongoDB — dump the whole database" },
    27018: { s: "mongodb", n: "MongoDB(shardsvr)", lv: "high" },
    88: { s: "kerberos", n: "Kerberos", lv: "low" },
    515: { s: "printer", n: "LPD 打印", lv: "low" },
    636: { s: "ldaps", n: "LDAPS", lv: "low" },
    1024: { s: "unknown", n: "动态端口", lv: "info" },
    3268: { s: "gc", n: "AD 全局编录", lv: "medium", note: "AD 全局编录可匿名枚举域内用户/主机", noteEn: "AD Global Catalog may allow anonymous enumeration of users and hosts" },
    3269: { s: "gc-ssl", n: "AD 全局编录(TLS)", lv: "low" },
    5060: { s: "sip", n: "SIP", lv: "low" },
    8088: { s: "http", n: "HTTP", lv: "low" },
    8090: { s: "http", n: "HTTP", lv: "low" },
    10250: { s: "kubelet", n: "Kubelet API", lv: "high", note: "Kubelet API 未授权 = 容器内命令执行", noteEn: "Unauthenticated Kubelet API — command execution inside containers" },
    10255: { s: "kubelet", n: "Kubelet(只读)", lv: "high", note: "Kubelet 只读端口可泄露 Pod 与环境信息", noteEn: "Kubelet read-only port leaks pods and environment details" },
    50000: { s: "db2", n: "DB2", lv: "high" },
    61616: { s: "activemq", n: "ActiveMQ(openwire)", lv: "high" }
  };

  /* 结果行里的服务标签别名 → 规范名 */
  var TAG_ALIAS = {
    http: "http", https: "https", ssl: "https", tls: "https",
    smb: "smb", smb2: "smb", netbios: "netbios", nbns: "netbios",
    ssh: "ssh", sftp: "ssh", telnet: "telnet", ftp: "ftp", ftps: "ftp",
    rdp: "rdp", winrm: "winrm", wmi: "wmi", ldap: "ldap", ldaps: "ldap",
    mysql: "mysql", mssql: "mssql", "ms-sql": "mssql", sqlserver: "mssql",
    oracle: "oracle", postgres: "postgres", postgresql: "postgres", pgsql: "postgres",
    redis: "redis", mongodb: "mongodb", mongo: "mongodb", memcached: "memcached",
    elastic: "elasticsearch", elasticsearch: "elasticsearch", es: "elasticsearch",
    docker: "docker", k8s: "k8s-api", kubernetes: "k8s-api",
    zookeeper: "zookeeper", kafka: "kafka", rabbitmq: "rabbitmq",
    vnc: "vnc", snmp: "snmp", smtp: "smtp", pop3: "pop3", imap: "imap", dns: "dns",
    rpc: "msrpc", msrpc: "msrpc", nfs: "nfs", rsync: "rsync",
    weblogic: "weblogic", tomcat: "tomcat", jboss: "jboss", ajp: "ajp",
    splunk: "splunk", activemq: "activemq", webmin: "webmin", cassandra: "cassandra",
    adb: "adb", socks: "socks", socks5: "socks", rmi: "rmi", db2: "db2"
  };

  /* ============================================================
   * 2. 操作系统指纹 + 生命周期(EOL)
   * ============================================================ */
  var TODAY = new Date().toISOString().slice(0, 10);

  /* Windows 各版本的支持终止日期(微软官方) */
  var WIN_EOL = {
    "win-xp": "2014-04-08",
    "win-vista": "2017-04-11",
    "win-2003": "2015-07-14",
    "win-7": "2020-01-14",
    "win-2008": "2020-01-14",
    "win-2008r2": "2020-01-14",
    "win-8": "2016-01-12",
    "win-8.1": "2023-01-10",
    "win-2012": "2023-10-10",
    "win-2012r2": "2023-10-10",
    "win-10": "2025-10-14",
    "win-2016": "2027-01-12",
    "win-2019": "2029-01-09",
    "win-11": "2031-10-14",
    "win-2022": "2031-10-14"
  };

  /* Windows 版本识别(顺序敏感: 具体在前) */
  var WIN_RULES = [
    { re: /windows\s*(?:server\s*)?2003(?:\s*r2)?/i, key: "win-2003", name: "Windows Server 2003" },
    { re: /windows\s*xp\b/i, key: "win-xp", name: "Windows XP" },
    { re: /windows\s*vista/i, key: "win-vista", name: "Windows Vista" },
    { re: /windows\s*server\s*2008\s*r2/i, key: "win-2008r2", name: "Windows Server 2008 R2" },
    { re: /windows\s*server\s*2008(?!\s*r2)/i, key: "win-2008", name: "Windows Server 2008" },
    { re: /windows\s*server\s*2012\s*r2/i, key: "win-2012r2", name: "Windows Server 2012 R2" },
    { re: /windows\s*server\s*2012(?!\s*r2)/i, key: "win-2012", name: "Windows Server 2012" },
    { re: /windows\s*server\s*2016/i, key: "win-2016", name: "Windows Server 2016" },
    { re: /windows\s*server\s*2019/i, key: "win-2019", name: "Windows Server 2019" },
    { re: /windows\s*server\s*2022/i, key: "win-2022", name: "Windows Server 2022" },
    { re: /windows\s*8\.1/i, key: "win-8.1", name: "Windows 8.1" },
    { re: /windows\s*8(?:\.0)?\b(?!\.1)/i, key: "win-8", name: "Windows 8" },
    { re: /windows\s*11\b/i, key: "win-11", name: "Windows 11" },
    { re: /windows\s*10\b/i, key: "win-10", name: "Windows 10" },
    { re: /windows\s*7\b(?!\s*(?:server|enterprise\s*7))/i, key: "win-7", name: "Windows 7" }
  ];

  /* 构建号 → 版本 */
  var BUILD_MAP = {
    2600: ["win-xp", "Windows XP"],
    3790: ["win-2003", "Windows Server 2003"],
    6000: ["win-vista", "Windows Vista / Server 2008"],
    6001: ["win-vista", "Windows Vista SP1 / Server 2008"],
    6002: ["win-vista", "Windows Vista SP2 / Server 2008"],
    7600: ["win-7", "Windows 7 / Server 2008 R2"],
    7601: ["win-7", "Windows 7 SP1 / Server 2008 R2 SP1"],
    9200: ["win-2012", "Windows Server 2012 / Windows 8"],
    9600: ["win-2012r2", "Windows Server 2012 R2 / Windows 8.1"],
    10240: ["win-10", "Windows 10 1507 / Server 2016"],
    14393: ["win-2016", "Windows 10 1607 / Server 2016"],
    15063: ["win-10", "Windows 10 1703"],
    16299: ["win-10", "Windows 10 1709"],
    17134: ["win-10", "Windows 10 1803"],
    17763: ["win-2019", "Windows 10 1809 / Server 2019"],
    18362: ["win-10", "Windows 10 1903"],
    18363: ["win-10", "Windows 10 1909"],
    19041: ["win-10", "Windows 10 2004"],
    19042: ["win-10", "Windows 10 20H2"],
    19043: ["win-10", "Windows 10 21H1"],
    19044: ["win-10", "Windows 10 21H2"],
    19045: ["win-10", "Windows 10 22H2"],
    20348: ["win-2022", "Windows Server 2022"],
    22000: ["win-11", "Windows 11 21H2"],
    22621: ["win-11", "Windows 11 22H2"],
    22631: ["win-11", "Windows 11 23H2"],
    26100: ["win-11", "Windows 11 24H2"]
  };

  /* IIS 主版本 → 对应 Windows 版本(只能间接推断) */
  var IIS_MAP = {
    "6.0": ["win-2003", "Windows Server 2003 (IIS 6.0)"],
    "7.0": ["win-2008", "Windows Server 2008 (IIS 7.0)"],
    "7.5": ["win-2008r2", "Windows Server 2008 R2 (IIS 7.5)"],
    "8.0": ["win-2012", "Windows Server 2012 (IIS 8.0)"],
    "8.5": ["win-2012r2", "Windows Server 2012 R2 (IIS 8.5)"],
    "10.0": ["win-2016", "Windows Server 2016+ (IIS 10.0)"]
  };

  /* Linux / Unix 发行版生命周期(主版本号 → 支持终止) */
  var DISTRO_EOL = {
    ubuntu: { "12.04": "2017-04-28", "14.04": "2019-04-25", "16.04": "2021-04-30", "18.04": "2023-05-31", "20.04": "2025-05-31", "22.04": "2027-04-29", "24.04": "2029-04-25" },
    centos: { "6": "2020-11-30", "7": "2024-06-30", "8": "2021-12-31", "9": "2027-05-31" },
    debian: { "8": "2020-06-30", "9": "2022-06-30", "10": "2024-06-30", "11": "2026-06-30", "12": "2028-06-30" },
    rhel: { "6": "2020-11-30", "7": "2024-06-30", "8": "2029-05-31", "9": "2032-05-31" },
    esxi: { "5.5": "2020-09-19", "6.0": "2022-03-12", "6.5": "2022-10-15", "6.7": "2022-10-15", "7.0": "2027-04-02", "8.0": "2029-10-11" }
  };

  /* 组件版本风险 */
  var COMP_RULES = [
    { id: "tomcat", re: /Tomcat[\/\s]?(\d+)\.(\d+)(?:\.(\d+))?/i, name: "Apache Tomcat", ver: 1,
      test: function (m) { return +m[1]; },
      bad: { 5: ["critical", "Tomcat 5.x 早已停止维护, 存在多个 RCE", "Tomcat 5.x is long unsupported with multiple RCEs"],
             6: ["critical", "Tomcat 6.x 已停止维护, 存在多个 RCE", "Tomcat 6.x is unsupported with multiple RCEs"],
             7: ["high", "Tomcat 7.x 已 EOL, 建议核对 CVE-2017-12615 等 PUT 上传漏洞", "Tomcat 7.x is EOL — check CVE-2017-12615 (PUT upload) and friends"],
             8: ["medium", "Tomcat 8.x 老分支, 建议升级到 9/10", "Tomcat 8.x is an old branch — upgrade to 9/10"] } },
    { id: "httpd", re: /Apache\/(\d+)\.(\d+)\.(\d+)/i, name: "Apache httpd", ver: 1,
      test: function (m) { return +m[1] * 100 + +m[2]; },
      bad: { 100: ["critical", "Apache 1.x 远古版本", "Apache 1.x is ancient"],
             200: ["high", "Apache 2.2 已 EOL", "Apache 2.2 is EOL"],
             201: ["medium", "Apache 2.4 早期版本, 存在多个 CVE(如 CVE-2021-41773)", "Early Apache 2.4 — multiple CVEs (e.g. CVE-2021-41773)"],
             202: ["low", "Apache 2.4 版本偏旧, 建议核对最新补丁", "Apache 2.4 is behind — check the latest patch level"] },
      bucket: function (v) { return v >= 204 ? 202 : v >= 201 ? 201 : v >= 200 ? 200 : 100; } },
    { id: "nginx", re: /nginx\/(\d+)\.(\d+)\.?(\d+)?/i, name: "nginx", ver: 1,
      test: function (m) { return +m[1] * 100 + +m[2]; },
      bad: { 100: ["low", "nginx 版本偏旧, 建议核对是否 1.24+", "nginx is behind — check whether 1.24+ is in use"] },
      bucket: function (v) { return v < 120 ? 100 : 0; } },
    { id: "openssh", re: /OpenSSH[_\s]?(\d+)\.(\d+)/i, name: "OpenSSH", ver: 1,
      test: function (m) { return +m[1]; },
      bad: { 5: ["high", "OpenSSH 5.x 极老, 存在多个提权/信息泄露漏洞", "OpenSSH 5.x is very old with several privilege-escalation flaws"],
             6: ["high", "OpenSSH 6.x 已老, 建议升级", "OpenSSH 6.x is old — upgrade"],
             7: ["medium", "OpenSSH 7.x 偏旧(注意 CVE-2018-15473 用户枚举)", "OpenSSH 7.x is behind (see CVE-2018-15473 user enumeration)"] } },
    { id: "openssl", re: /OpenSSL\/(\d+)\.(\d+)\.(\d+)/i, name: "OpenSSL", ver: 1,
      match: function (m) { return m[1] + "." + m[2] + "." + m[3]; },
      check: function (v) {
        if (/^1\.0\.1/.test(v)) return ["critical", "OpenSSL 1.0.1 存在 Heartbleed(CVE-2014-0160)", "OpenSSL 1.0.1 is vulnerable to Heartbleed (CVE-2014-0160)"];
        if (/^1\.0\./.test(v)) return ["high", "OpenSSL 1.0.x 已 EOL", "OpenSSL 1.0.x is EOL"];
        if (/^1\.1\.0/.test(v)) return ["medium", "OpenSSL 1.1.0 已 EOL", "OpenSSL 1.1.0 is EOL"];
        if (/^1\.1\.1/.test(v)) return ["low", "OpenSSL 1.1.1 已停止支持(2023-09)", "OpenSSL 1.1.1 reached end of life (Sep 2023)"];
        return null;
      } },
    { id: "php", re: /PHP\/(\d+)\.(\d+)\.?(\d+)?/i, name: "PHP", ver: 1,
      test: function (m) { return +m[1] * 10 + +m[2]; },
      bad: { 50: ["high", "PHP 5.x 已 EOL, 大量已知漏洞", "PHP 5.x is EOL with many known flaws"],
             70: ["medium", "PHP 7.0 ~ 7.3 已 EOL", "PHP 7.0–7.3 are EOL"] },
      bucket: function (v) { return v < 70 ? 50 : v < 74 ? 70 : 0; } },
    { id: "iis", re: /(?:Microsoft-)?IIS\/(\d+)\.(\d+)/i, name: "IIS", ver: 1,
      match: function (m) { return m[1] + "." + m[2]; },
      check: function (v) {
        if (v === "6.0") return ["high", "IIS 6.0 随 Windows Server 2003 EOL, 存在 WebDAV 等漏洞", "IIS 6.0 is EOL with Server 2003 (WebDAV flaws)"];
        if (v === "7.0" || v === "7.5") return ["medium", "IIS 7.x 随 2008/2008R2 EOL", "IIS 7.x is EOL with Server 2008/2008 R2"];
        if (v === "8.0" || v === "8.5") return ["low", "IIS 8.x 随 2012/2012R2 EOL", "IIS 8.x is EOL with Server 2012/2012 R2"];
        return null;
      } },
    { id: "vsftpd234", re: /vsftpd\s*2\.3\.4/i, name: "vsftpd 2.3.4", ver: 0,
      fixed: ["critical", "vsftpd 2.3.4 带笑脸后门(CVE-2011-2523)", "vsftpd 2.3.4 ships the smiley backdoor (CVE-2011-2523)"] },
    { id: "proftpd", re: /ProFTPD\s*1\.3\.[0-5]/i, name: "ProFTPD", ver: 0,
      fixed: ["medium", "ProFTPD 1.3.0~1.3.5 存在多个 RCE/信息泄露", "ProFTPD 1.3.0–1.3.5 has multiple RCE / info-leak flaws"] },
    { id: "weblogic", re: /WebLogic/i, name: "WebLogic", ver: 0,
      fixed: ["medium", "WebLogic 历史反序列化 RCE 较多, 建议核对补丁", "WebLogic has a long history of deserialization RCEs — verify patches"] },
    { id: "struts", re: /Struts2?/i, name: "Struts2", ver: 0,
      fixed: ["medium", "Struts2 历史 OGNL RCE 较多(S2-045/057 等)", "Struts2 has many OGNL RCEs (S2-045/057 and more)"] },
    { id: "shiro", re: /Shiro|rememberMe/i, name: "Apache Shiro", ver: 0,
      fixed: ["medium", "Shiro rememberMe 反序列化(默认密钥)高危面", "Shiro rememberMe deserialization with default keys is a serious risk"] },
    { id: "thinkphp", re: /ThinkPHP/i, name: "ThinkPHP", ver: 0,
      fixed: ["medium", "ThinkPHP 多个版本存在 RCE", "Several ThinkPHP releases have RCEs"] },
    { id: "jquery", re: /jQuery[\/\s]?([12])\./i, name: "jQuery", ver: 0,
      fixed: ["low", "老版本 jQuery(XSS 相关), 一般作为线索参考", "Old jQuery (XSS-related) — keep as a hint only"] },
    { id: "redis-old", re: /Redis[\/\s]?([2-5])\./i, name: "Redis", ver: 0,
      fixed: ["medium", "Redis 老版本(建议核对未授权与 Lua 沙箱逃逸)", "Old Redis — check unauthenticated access and Lua sandbox escapes"] },
    { id: "mysql", re: /MySQL[\/\s]?(\d+)\.(\d+)\.?(\d+)?/i, name: "MySQL", ver: 1,
      match: function (m) { return m[1] + "." + m[2]; },
      check: function (v) {
        var maj = +v.split(".")[0], min = +v.split(".")[1];
        if (maj === 5) return ["high", "MySQL 5.x 已 EOL(2023-10 起), 存在多个提权/注入类 CVE", "MySQL 5.x is EOL (since Oct 2023) with multiple privilege-escalation CVEs"];
        if (maj === 8 && min < 4) return ["low", "MySQL 8.0 早期补丁级别, 建议核对最新 CVE", "Early MySQL 8.0 patch level — check the latest CVEs"];
        return null;
      } }
  ];

  /* ============================================================
   * 3. 关键词
   * ============================================================ */
  var VULN_START_RE = /^(MS\d{2}-\d{3}|CVE-\d{4}-\d{3,7}|CNVD-\d{4}-\d{3,6}|CNNVD-\d{6,}-\d+|SMBGhost|BlueKeep|EternalBlue|PocScan|poc-yaml-[a-z0-9-]+)\b/i;
  var VULN_ANY_RE = /(MS\d{2}-\d{3}|CVE-\d{4}-\d{3,7}|CNVD-\d{4}-\d{3,6}|CNNVD-\d{6,}-\d+|SMB\s*Ghost|SMBGhost|BlueKeep|EternalBlue|poc-yaml-[a-z0-9-]+)/i;
  var UNAUTH_RE = /未授权|unauthoriz|no\s*auth|unauth|anonymous\s*access|without\s*auth|空口令|no\s*password|匿名/i;
  var ADMIN_RE = /后台|管理后台|管理登录|登录|sign[-_ ]?in|logon|admin[\s_-]?(?:login|panel|page)|\/login|\.git\/|phpinfo|swagger|actuator|console|manager\/html|api\/docs|jupyterhub/i;
  var HOSTNAME_RE = /([A-Z][A-Z0-9_-]{0,14})\\([A-Za-z0-9_$.-]{1,15})/;

  var LEVEL_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  var LEVEL_WEIGHT = { critical: 40, high: 25, medium: 12, low: 6, info: 0 };

  /* ============================================================
   * 4. 解析
   * ============================================================ */

  /* fscan v2.x 的模块名 → 服务标签 */
  var MODULE_TAGS = {
    SMBInfo: "smb", NetInfo: "", RDP: "rdp", LDAP: "ldap", MSSQL: "mssql",
    MySQL: "mysql", PostgreSQL: "postgres", Telnet: "telnet", Rsync: "rsync",
    Redis: "redis", FTP: "ftp", VNC: "vnc", Memcached: "memcached",
    Elasticsearch: "elasticsearch", MongoDB: "mongodb", SSH: "ssh",
    "SSH服务识别成功": "ssh", WebTitle: "http", SNMP: "snmp"
  };

  /* fscan 打印的原始服务标签 → 规范名(空串表示交给端口表判断) */
  var RAW_TAG_MAP = {
    "microsoft-ds": "smb", "ms-sql-s": "mssql", "netbios-ssn": "netbios",
    "domain": "dns", "ssl": "https", "printer": "printer", "sip": "sip",
    "kickstart": "", "genetec-5400": "", "spark": "", "unknown": ""
  };

  function cleanText(s) {
    return String(s == null ? "" : s)
      .replace(/\x1b\[[0-9;]*[A-Za-z]/g, "")
      .replace(/\r\n?/g, "\n");
  }

  function normTag(t) {
    var raw = String(t || "").toLowerCase().replace(/[:：]\s*$/, "").trim();
    if (!raw) return "";
    if (RAW_TAG_MAP.hasOwnProperty(raw)) return RAW_TAG_MAP[raw];
    var k = raw.replace(/[^a-z0-9-]/g, "");
    return TAG_ALIAS[k] || "";
  }

  function splitUrl(u) {
    var m = String(u).match(/^(https?):\/\/([^\/?#\s]+)(?:[\/?#].*)?$/i);
    if (!m) return null;
    var scheme = m[1].toLowerCase();
    var hostport = m[2];
    var hm = hostport.match(/^(\[[0-9a-f:]+\]|[^\s:]+)(?::(\d{1,5}))?$/i);
    if (!hm) return null;
    var host = hm[1];
    return {
      scheme: scheme,
      host: host,
      ip: isIp(host) ? host : "",
      port: hm[2] ? +hm[2] : (scheme === "https" ? 443 : 80)
    };
  }

  function isIp(s) { return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(s); }
  function validPort(n) { return n > 0 && n <= 65535; }

  /* 结构化字段(出现在消息里就说明这行不是"用户名:口令") */
  var STRUCT_KEY_RE = /\[?\b(?:OS|Build|Hostname|FQDN|DNSDomain|NetBIOSDomain|Product|Version|Banner|code|len|title|server|SMBv\d)\b\s*[:：]?/i;

  var CRED_TAGS = { ssh: 1, rdp: 1, mysql: 1, mssql: 1, oracle: 1, postgres: 1, redis: 1, mongodb: 1, ftp: 1, telnet: 1, vnc: 1, winrm: 1, smb: 1, smtp: 1, pop3: 1, imap: 1, snmp: 1, ldap: 1, adb: 1, webmin: 1 };

  /** 从消息里取 用户名:口令; 结构化行(OS:/Build:/...)一律不认, 避免把 [OS:Windows...] 当口令 */
  function detectCred(msg, tag) {
    if (!msg) return null;
    if (/\[?\b(?:OS|Build|Hostname|FQDN|DNSDomain|NetBIOSDomain)\s*[:：]/i.test(msg)) return null;
    if (/\[?(?:Product|Banner)\s*:\(?/i.test(msg)) return null;
    if (/[\[\]()]/.test(msg)) return null;                  // 带括号的是结构化描述
    var pairs = [];
    var re = /(?:^|[\s,，;；])([A-Za-z0-9_\-\\$@#.]{1,48})[:：]([^\s,，;；:：]{1,64})(?=$|[\s,，;；])/g;
    var m;
    while ((m = re.exec(msg)) !== null) pairs.push({ user: m[1], pass: m[2] });
    if (!pairs.length) return null;
    var explicit = /(?:weak\s*password|password|passwd|口令|密码|credential)/i.test(msg);
    var authed = tag && CRED_TAGS[tag];
    if (!explicit && !authed) {
      if (!/^[^\s:：]{1,48}[:：][^\s:：]{1,64}$/.test(msg.trim())) return null;
    }
    return pairs[0];
  }

  /* ---------- 字段提取 ---------- */

  function pickProduct(rest) {
    var out = { product: "", version: "" };
    var m = rest.match(/\[Product:([^\[\]]*)\]/);
    if (!m) return out;
    var parts = m[1].split(/\s*\|\|\s*Version:\s*/i);
    out.product = (parts[0] || "").trim();
    out.version = (parts[1] || "").trim();
    return out;
  }

  /** banner 里夹着大量二进制/证书原始字节(SMB 扩展、TLS 证书 dump), 这种不展示也不参与判定 */
  function bannerWorthless(b) {
    if (!b) return true;
    if (/DOWNGRD|not_defined_in_RFC|_in_RFC4178/i.test(b)) return true;
    var alnum = b.replace(/[^A-Za-z0-9]/g, "").length;
    return alnum / b.length < 0.55;
  }

  function pickBanner(rest) {
    var i = rest.indexOf("Banner:(");
    if (i === -1) return "";
    var b = rest.slice(i + 8).replace(/\)\s*$/, "").trim();
    if (bannerWorthless(b)) return "";
    return b.slice(0, 400);
  }

  function parseKvBlock(s) {
    var out = {};
    String(s || "").split(/,\s*/).forEach(function (kv) {
      var i = kv.indexOf(":");
      if (i > 0) out[kv.slice(0, i).trim().toLowerCase()] = kv.slice(i + 1).trim();
    });
    return out;
  }

  /** [OS:..., Build:...] / [Windows 8/Server 2012 (Build 9200)] → 系统线索 */
  function pickOsInfo(rest) {
    var out = {};
    var bm = rest.match(/\[OS:([^\]]+)\]/);
    if (bm) {
      var kv = parseKvBlock(bm[1]);
      var osText = kv.os || "";
      if (kv.build) osText += " (" + kv.build + ")";
      out.osText = osText.trim();
      if (kv.build) out.build = kv.build;
      if (kv.hostname) out.hostname = kv.hostname;
      if (kv.dnsdomain || kv.netbiosdomain) out.domain = kv.dnsdomain || kv.netbiosdomain;
      if (kv.fqdn) out.fqdn = kv.fqdn;
      return out;
    }
    var blocks = rest.match(/\[[^\]]*\]/g) || [];
    for (var i = 0; i < blocks.length; i++) {
      var inner = blocks[i].slice(1, -1);
      if (/^(Product|Version|Banner|code|len|title|server)\b/i.test(inner)) continue;
      if (/(?:Windows|Linux|Ubuntu|CentOS|Debian|Rocky|ESXi|Server\s*20)/i.test(inner)) { out.osText = inner; break; }
    }
    return out;
  }

  function copyOsFields(e, os) {
    if (!os) return;
    if (os.osText) e.osText = os.osText;
    if (os.build) e.build = os.build;
    if (os.hostname) e.hostname = os.hostname;
    if (os.domain) e.domain = os.domain;
    if (os.fqdn) e.fqdn = os.fqdn;
  }

  /** 普通 IP:PORT 行(含 v2 的 `[*] ip:port tag [Product:..] Banner:(..)`) */
  function entryService(ip, port, rest) {
    rest = String(rest || "").trim();
    var e = { t: "open", ip: ip, port: port, msg: "" };
    if (!validPort(port)) return null;
    if (!rest) return e;

    // 首次出现即把 Product / Version / Banner 收进来
    var prod = pickProduct(rest);
    if (prod.product) { e.product = prod.product; e.version = prod.version; e.t = "svc"; }
    var banner = pickBanner(rest);
    if (banner) { e.banner = banner; e.t = "svc"; }
    copyOsFields(e, pickOsInfo(rest));
    if (e.osText || e.hostname) e.t = "svc";

    // 服务标签 = 第一个单词
    var firstM = rest.match(/^([A-Za-z][A-Za-z0-9+_.-]{1,20})(?=\s|$)/);
    var first = firstM ? firstM[1] : "";
    var tag = normTag(first);
    if (tag) { e.tag = tag; e.t = "svc"; } else if (first && !/^(open|http|https|ssl)$/i.test(first)) { e.rawTag = first; }

    // 可读消息: 去掉字段块与服务名
    var msg = rest
      .replace(/\[Product:[^\]]*\]\s*/g, "")
      .replace(/Banner:\([\s\S]*\)\s*$/, "")
      .replace(/\[OS:[^\]]*\]\s*/g, "")
      .replace(/\[[^\]]*(?:Windows|Linux|Ubuntu|CentOS|Debian|Rocky|ESXi|Build)[^\]]*\]\s*/g, "")
      .trim();
    if (first && msg.toLowerCase().indexOf(first.toLowerCase()) === 0) msg = msg.slice(first.length).trim();
    if (/^(open|http|https|ssl|None)$/i.test(msg)) msg = "";
    e.msg = msg;

    // 消息里夹着 URL → 这是 Web 结果行(如 `[+] ip:80 http http://ip Title`)
    var wm = msg.match(/(https?:\/\/\S+)/);
    if (wm) {
      var ew = entryWeb(wm[1], msg.slice(msg.indexOf(wm[1]) + wm[1].length));
      if (ew) { if (!ew.port) ew.port = port; return ew; }
    }

    // WORKGROUP\HOST 形式的主机名
    var hmx = msg.match(/([A-Z][A-Z0-9_-]{0,14})\\([A-Za-z0-9_$.-]{1,15})/);
    if (hmx) {
      if (!e.domain) e.domain = hmx[1];
      if (!/^(WORKGROUP|MSHOME)$/i.test(hmx[2])) e.hostname = e.hostname || hmx[2];
    }

    // 分类: 漏洞 / 未授权 / 弱口令
    var vn = msg.match(VULN_ANY_RE);
    if (vn) return { t: "vuln", ip: ip, port: port || (/^MS17-010$/i.test(vn[1]) ? 445 : 0), name: vn[1], msg: msg };
    if (msg && UNAUTH_RE.test(msg)) { e.t = "unauth"; return e; }
    var cred = detectCred(msg, e.tag);
    if (cred) { e.t = "cred"; e.user = cred.user; e.pass = cred.pass; return e; }
    return e;
  }

  /** v2 的模块行: SMBInfo / NetInfo / RDP / MySQL / ... */
  function entryModule(mod, ip, port, rest) {
    rest = String(rest || "").trim();
    var tag = MODULE_TAGS[mod] || "";
    var e = { t: "svc", ip: ip, port: port, tag: tag, msg: "" };

    if (mod === "SMBInfo") {
      copyOsFields(e, pickOsInfo(rest));
      var tail = rest.replace(/\[[^\]]*\]/g, " ").replace(/\s+/g, " ").trim();
      var sm = tail.match(/SMBv\d/i);
      if (sm) e.smb = sm[0];
      var hn = tail.replace(/SMBv\d/gi, "").trim().split(/\s+/)[0];
      if (hn && /^[A-Za-z0-9_.$-]{2,40}$/.test(hn) && !e.hostname) e.hostname = hn;
      return e;
    }

    if (mod === "SNMP") {
      var cm = rest.match(/community\s*[:：]\s*([^\s|,，]+)/i);
      if (cm) e.community = cm[1];
      var bar = rest.search(/[|｜]/);
      var desc = bar >= 0 ? rest.slice(bar + 1).trim() : rest.replace(/community\s*[:：]\s*\S+/i, "").trim();
      if (/^\(type=\d+,\s*len=\d+\)$/.test(desc)) desc = "";
      e.msg = desc;
      e.proto = "udp";
      return e;
    }

    if (mod === "NetInfo") {
      var hm2 = rest.match(/\[([^\]]+)\]/);
      if (hm2) e.hostname = hm2[1].trim();
      var peer = rest.match(/->\s*((?:\d{1,3}\.){3}\d{1,3})/);
      if (peer) return { t: "peer", ip: ip, port: port, peer: peer[1] };
      e.msg = "";
      return e;
    }

    copyOsFields(e, pickOsInfo(rest));

    // RDP 摘要行: "RDP (Windows Server 2012/Windows 8, SERV-UVRI3)"
    var pm = rest.match(/\(([^)]*)\)\s*$/);
    if (pm && /(?:windows|linux|server)/i.test(pm[1])) {
      var seg = pm[1].split(/,\s*/);
      if (!e.osText && seg[0]) e.osText = seg[0];
      if (!e.hostname && seg[1]) e.hostname = seg[1].trim();
      e.msg = "";
      return e;
    }

    var msg = rest.replace(/\[[^\]]*\]/g, " ").replace(/\s+/g, " ").trim();
    e.msg = msg;
    if (msg && UNAUTH_RE.test(msg)) { e.t = "unauth"; return e; }
    var cred = detectCred(msg, tag);
    if (cred) { e.t = "cred"; e.user = cred.user; e.pass = cred.pass; return e; }
    return e;
  }

  /** v2 的 Web 行: `http://ip  code:200 len:123 title:X server:Y [tags]` / `http [Product:..] Banner:(..)` */
  function entryWeb(url, rest) {
    var u = splitUrl(url);
    if (!u) return null;
    var e = {
      t: "web", ip: u.ip || u.host, port: u.port, scheme: u.scheme, url: url,
      code: 0, len: 0, title: "", server: "", tags: [], banner: "", product: "", version: ""
    };
    var r = String(rest || "");
    var m;
    if ((m = r.match(/\bcode:(\d{1,3})/))) e.code = +m[1];
    if ((m = r.match(/\blen:(\d+)/))) e.len = +m[1];
    if ((m = r.match(/\btitle:([\s\S]*?)(?=\s{2,}|\s+server:|$)/))) e.title = m[1].trim();
    if ((m = r.match(/\bserver:(\S+(?:\s+\([^)]*\))?)/))) e.server = m[1].trim();
    var tagm = r.match(/\[([^\[\]]*)\]\s*$/);
    if (tagm && !/^Product:/i.test(tagm[1])) {
      e.tags = tagm[1].split(/\s+/).filter(Boolean).slice(0, 12);
    }
    var prod = pickProduct(r);
    e.product = prod.product;
    e.version = prod.version;
    var banner = pickBanner(r);
    if (banner) e.banner = banner;
    if (/^(none|null|undefined)$/i.test(e.title)) e.title = "";
    if (!e.title) {
      var plain = r
        .replace(/\[[^\]]*\]/g, " ")
        .replace(/Banner:\([\s\S]*\)\s*$/, "")
        .replace(/\b(?:code|len|title|server):\S+/g, " ")
        .replace(/\b(?:http|https|ssl)\b/gi, " ")
        .replace(/\s+/g, " ")
        .trim();
      if (plain && /[A-Za-z\u4e00-\u9fa5]/.test(plain) && plain.length <= 120) e.title = plain;
    }
    return e;
  }

  /** 漏洞名开头的行: `MS17-010 1.2.3.4 445` / `PocScan http://x poc-yaml-y` */
  function entryVuln(name, body) {
    if (/^SMB\s*Ghost$/i.test(name)) name = "CVE-2020-0796 (SMBGhost)";
    if (/^PocScan$/i.test(name)) {
      var real = body.match(/(poc-yaml-[a-z0-9-]+|CVE-\d{4}-\d{3,7})/i);
      if (real) name = real[1];
    }
    var urlm = body.match(/(https?:\/\/\S+)/);
    if (urlm) {
      var u = splitUrl(urlm[1]);
      if (u) return { t: "vuln", ip: u.ip || u.host, port: u.port, name: name, msg: body };
    }
    var tm = body.match(/((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?/);
    if (!tm) return null;
    return {
      t: "vuln", ip: tm[1], name: name,
      port: tm[2] ? +tm[2] : (/^MS17-010$/i.test(name) ? 445 : 0),
      msg: body
    };
  }

  var SKIP_RE = /^(?:\[\*\])?\s*(?:参数自适应|开始信息扫描|扫描开始|扫描完成|扫描结束|存活主机|用时|开始时间|目标|端口范围|密码爆破|插件扫描错误|\[\+\]\s*插件|\[完成\]|端口扫描中|扫描进度|root@[\s\S]*[#$]\s*$)/;

  /**
   * 解析 fscan 文本(兼容 v1.8 的 `ip:port open` 与 v2.x 的 `[*] ip:port ...`)
   */
  function parse(text) {
    var src = cleanText(text);
    var lines = src.split("\n");
    var res = { version: "", entries: [], unknown: [], notes: [], ignored: 0, blank: 0, total: lines.length };
    var vm = src.match(/fscan\s*[_-]?\s*version\s*[:：]?\s*v?([\d.]+)/i);
    if (vm) res.version = vm[1];
    var ctxIp = "";

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].replace(/\s+$/, "").trim();
      if (!line) { res.blank++; continue; }
      if (!/[A-Za-z0-9\u4e00-\u9fa5]/.test(line)) { res.ignored++; continue; }
      if (/^\[\s*[#=>\-.\s]*\d{1,3}(?:\.\d+)?%?\s*\]/.test(line) || /^\[\s*[#=>\s]{4,}\]/.test(line)) { res.ignored++; continue; }

      // nmap 上下文
      var nmp = line.match(/^Nmap scan report for\s+(?:(\S+)\s+)?\(?((?:\d{1,3}\.){3}\d{1,3}|[^\s()]+)\)?$/i);
      if (nmp) { ctxIp = nmp[2]; continue; }
      var nport = line.match(/^(\d{1,5})\/(tcp|udp)\s+open\b\s*(.*)$/i);
      if (nport && ctxIp && isIp(ctxIp)) {
        res.entries.push({
          t: "svc", ip: ctxIp, port: +nport[1], proto: nport[2].toLowerCase(),
          tag: normTag(String(nport[3] || "").split(/\s+/)[0] || ""), msg: String(nport[3] || "").trim()
        });
        continue;
      }

      // 剥掉 [+]/[*]/[-] 前缀
      var pm = line.match(/^\[([+*\-!])\]\s*(.*)$/);
      var mark = pm ? pm[1] : "";
      var body = pm ? pm[2] : line;
      if (!body) { res.ignored++; continue; }
      if (SKIP_RE.test(body)) { res.ignored++; continue; }
      if (/^(?:fscan|start\s+infoscan)\b/i.test(body)) { res.ignored++; continue; }

      var m;

      // 1) 端口开放 10.0.0.218:443 [http](HTTP探测)
      m = body.match(/^端口开放\s+((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\s*(.*)$/);
      if (m) {
        var e0 = entryService(m[1], +m[2], m[3].replace(/^\[|\]\(.*\)$/g, ""));
        if (e0) { e0.t = e0.t === "svc" ? "svc" : "open"; res.entries.push(e0); continue; }
      }

      // 2) Web 行(带 URL)
      m = body.match(/^(https?:\/\/\S+)\s*([\s\S]*)$/i);
      if (m) {
        var ew = entryWeb(m[1], m[2]);
        if (ew) { res.entries.push(ew); continue; }
      }

      // 3) 漏洞名开头
      var vstart = body.match(VULN_START_RE);
      if (vstart) {
        var ev = entryVuln(vstart[1], body);
        if (ev) { res.entries.push(ev); continue; }
        res.unknown.push(line); continue;
      }

      // 4) 模块行: SMBInfo / NetInfo / RDP / MySQL ...
      m = body.match(/^(SMBInfo|NetInfo|RDP|LDAP|MSSQL|MySQL|PostgreSQL|Telnet|Rsync|Redis|FTP|VNC|Memcached|Elasticsearch|MongoDB|SSH服务识别成功|SSH|SNMP|WebTitle)\s*[:：]?\s*((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?\s*([\s\S]*)$/);
      if (m) {
        var em = entryModule(m[1], m[2], m[3] ? +m[3] : 0, m[4]);
        if (em) { res.entries.push(em); continue; }
        res.unknown.push(line); continue;
      }

      // 5) IP[:PORT] 开头(v1.8 与 v2 主体)
      m = body.match(/^((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?:[\s,，;；]|$)([\s\S]*)$/);
      if (m) {
        var port = m[2] ? +m[2] : 0;
        var rest = m[3] || "";
        if (!port) {
          var vn0 = rest.match(VULN_ANY_RE);
          if (vn0) {
            res.entries.push({ t: "vuln", ip: m[1], port: /^MS17-010$/i.test(vn0[1]) ? 445 : 0, name: vn0[1], msg: rest.trim() });
            continue;
          }
          // 只有 IP: 当作"存活"线索, 不产生端口
          res.entries.push({ t: "svc", ip: m[1], port: 0, tag: "", msg: rest.trim() });
          continue;
        }
        var es = entryService(m[1], port, rest);
        if (es) { res.entries.push(es); continue; }
        res.unknown.push(line); continue;
      }

      // 6) 纯 IP + 文本(存活/别名等)
      m = body.match(/^((?:\d{1,3}\.){3}\d{1,3})\s+([\s\S]*)$/);
      if (m) {
        res.entries.push({ t: "svc", ip: m[1], port: 0, tag: "", msg: m[2].trim() });
        continue;
      }

      // 6.5) 兜底: 正文里出现漏洞编号(CVE / MS / CNVD / SMBGhost ...)就当命中
      var vany = body.match(VULN_ANY_RE);
      if (vany) {
        var evx = entryVuln(vany[1], body);
        if (evx) { res.entries.push(evx); continue; }
      }

      // 7) 状态行残留
      if (mark === "*" || mark === "-" || mark === "!") { res.ignored++; continue; }
      res.unknown.push(line);
    }

    return res;
  }

  /* ============================================================
   * 5. 操作系统推断
   * ============================================================ */

  function eolState(key, date) {
    if (!date) return { eol: false, eolDate: "", days: 0 };
    var diff = Math.round((Date.parse(date + "T00:00:00Z") - Date.parse(TODAY + "T00:00:00Z")) / 86400000);
    return { eol: diff < 0, eolDate: date, days: diff };
  }

  function winOs(key, name, evidence, extra) {
    var st = eolState(key, WIN_EOL[key]);
    return {
      key: key, family: "windows", name: name, nameEn: name,
      eol: st.eol, eolDate: st.eolDate, days: st.days,
      evidence: evidence || "", generic: !!(extra && extra.generic)
    };
  }

  function distroOs(family, key, name, nameEn, version, eolDate, evidence) {
    var st = eolState(key, eolDate);
    return {
      key: key, family: family, name: name, nameEn: nameEn, version: version || "",
      eol: st.eol, eolDate: st.eolDate, days: st.days, evidence: evidence || ""
    };
  }

  var BUILD_INLINE_RE = /build\s*[:：]?\s*(?:windows\s*)?([\d.]+)/i;
  var BUILD_BARE_RE = /\b(2600|3790|6000|6001|6002|7600|7601|9200|9600|10240|14393|15063|16299|17134|17763|18362|18363|19041|19042|19043|19044|19045|20348|22000|22621|22631|26100)\b/;

  /** 从 "Build 20348" / "Build:Windows 10.0.20348" / "(Build 7601)" 里取构建号 */
  function buildOs(text) {
    var m = text.match(BUILD_INLINE_RE);
    if (m) {
      var parts = String(m[1]).split(".");
      var last = parts[parts.length - 1];
      if (BUILD_MAP[last]) return BUILD_MAP[last];
    }
    var b = text.match(BUILD_BARE_RE);
    if (b && BUILD_MAP[b[1]]) return BUILD_MAP[b[1]];
    return null;
  }

  /** 在文本里找已知发行版版本号(只认白名单, 避免 "0ubuntu0.16.04" 这类噪声) */
  function pickKnown(t, dict) {
    var keys = Object.keys(dict).sort(function (a, b) { return b.length - a.length; });
    var i, re;
    // 第一轮: 严格边界(前后都不是数字/点), 适合 Debian "10"、CentOS "7" 这种单数字版本
    for (i = 0; i < keys.length; i++) {
      re = new RegExp("(?:^|[^\\d.])" + keys[i].replace(/\./g, "\\.") + "(?![\\d])");
      if (re.test(t)) return keys[i];
    }
    // 第二轮: 只对 "16.04" 这类带点的版本放宽("0ubuntu0.16.04.1" 这种写法)
    for (i = 0; i < keys.length; i++) {
      if (keys[i].indexOf(".") === -1) continue;
      re = new RegExp("(?:^|[^\\d])" + keys[i].replace(/\./g, "\\.") + "(?![\\d])");
      if (re.test(t)) return keys[i];
    }
    return "";
  }

  var WIN_CLIENT_KEYS = { "win-7": 1, "win-8": 1, "win-8.1": 1, "win-10": 1, "win-11": 1 };

  /** 从主机全部证据文本推断操作系统 */
  function detectOs(text) {
    var t = String(text || "");
    var m;

    // --- Windows: 明确的 Server / 老客户端版本优先 ---
    // v2 会把 2016/2019/2022 也标成 "Windows 10 (Build ...)", 所以客户端标签在有构建号时让位给构建号
    var hasBuild = !!buildOs(t);
    for (var i = 0; i < WIN_RULES.length; i++) {
      var r = WIN_RULES[i];
      if (hasBuild && WIN_CLIENT_KEYS[r.key]) continue;
      if (r.re.test(t)) {
        var mm = t.match(r.re);
        return winOs(r.key, r.name, mm[0]);
      }
    }
    // --- 构建号 ---
    var bo = buildOs(t);
    if (bo) return winOs(bo[0], bo[1], "build " + bo[1]);
    // --- IIS 版本间接推断 ---
    m = t.match(/(?:Microsoft-)?IIS\/(\d+\.\d+)/i);
    if (m && IIS_MAP[m[1]]) {
      var im = IIS_MAP[m[1]];
      return winOs(im[0], im[1], "IIS/" + m[1]);
    }
    // --- 仅知道是 Windows ---
    if (/\bwindows\b|microsoft-iis|\biis\b\s|ntlm|netbios.*workstation/i.test(t)) {
      var w = winOs("win-generic", "Windows(版本未知)", "Windows 关键词");
      w.nameEn = "Windows (version unknown)";
      w.generic = true;
      return w;
    }

    // --- VMware ESXi ---
    m = t.match(/vmware\s*esxi\s*(?:version\s*)?(\d+\.\d+)?/i);
    if (m) {
      var ev = m[1] || "";
      return distroOs("vmware", "esxi" + (ev ? "-" + ev : ""), "VMware ESXi" + (ev ? " " + ev : ""), "VMware ESXi" + (ev ? " " + ev : ""), ev, (DISTRO_EOL.esxi[ev] || ""), m[0]);
    }
    if (/vcenter/i.test(t)) return distroOs("vmware", "vcenter", "VMware vCenter", "VMware vCenter", "", "", "vCenter");

    // --- Linux 发行版(版本号只认白名单) ---
    if (/ubuntu/i.test(t)) {
      var uvRaw = (t.match(/0ubuntu(\d{1,2}\.\d{2})/i) || [])[1] || "";
      var uv = (uvRaw && DISTRO_EOL.ubuntu[uvRaw]) ? uvRaw : pickKnown(t, DISTRO_EOL.ubuntu);
      return distroOs("linux", "ubuntu" + (uv ? "-" + uv : ""), "Ubuntu" + (uv ? " " + uv : ""), "Ubuntu" + (uv ? " " + uv : ""), uv, uv ? (DISTRO_EOL.ubuntu[uv] || "") : "", "Ubuntu");
    }
    if (/debian|\bdeb\d{1,2}u?/i.test(t)) {
      var dv = (t.match(/\bdeb(\d{1,2})u?/i) || [])[1] || pickKnown(t, DISTRO_EOL.debian);
      return distroOs("linux", "debian" + (dv ? "-" + dv : ""), "Debian" + (dv ? " " + dv : ""), "Debian" + (dv ? " " + dv : ""), dv, dv ? (DISTRO_EOL.debian[dv] || "") : "", "Debian");
    }
    if (/centos/i.test(t)) {
      var cv = (t.match(/centos[-\s]?(?:linux\s*)?(?:release\s*)?(\d+)/i) || [])[1]
        || (t.match(/\bel(\d)\b/i) || [])[1] || "";
      return distroOs("linux", "centos" + (cv ? "-" + cv : ""), "CentOS" + (cv ? " " + cv : ""), "CentOS" + (cv ? " " + cv : ""), cv, cv ? (DISTRO_EOL.centos[cv] || "") : "", "CentOS");
    }
    if (/red\s*hat|rhel|rocky|alma/i.test(t)) {
      var rv = (t.match(/\bel(\d)\b/i) || [])[1] || (t.match(/(?:rhel|red\s*hat)[-\s]?(?:enterprise\s*linux)?[-\s]?(\d+)/i) || [])[1] || "";
      var isRocky = /rocky/i.test(t), isAlma = /alma/i.test(t);
      var rid = isRocky ? "rocky" : isAlma ? "alma" : "rhel";
      var rname = isRocky ? "Rocky Linux" : isAlma ? "AlmaLinux" : "RHEL";
      return distroOs("linux", rid + (rv ? "-" + rv : ""), rname + (rv ? " " + rv : ""), rname + (rv ? " " + rv : ""), rv, rv && !isRocky && !isAlma ? (DISTRO_EOL.rhel[rv] || "") : "", t.match(/rocky|alma|red\s*hat|rhel/i)[0]);
    }
    if (/euleros|open\s*euler/i.test(t)) return distroOs("linux", "euler", "openEuler / EulerOS(华为)", "openEuler / EulerOS", "", "", "EulerOS");
    if (/kylin|银河麒麟/i.test(t)) return distroOs("linux", "kylin", "银河麒麟 Kylin", "Kylin", "", "", "Kylin");
    if (/\buos\b|统信|deepin/i.test(t)) return distroOs("linux", "uos", "统信 UOS / Deepin", "UOS / Deepin", "", "", "UOS");
    if (/alpine/i.test(t)) return distroOs("linux", "alpine", "Alpine Linux", "Alpine Linux", "", "", "Alpine");
    if (/amazon\s*linux/i.test(t)) return distroOs("linux", "amzn", "Amazon Linux", "Amazon Linux", "", "", "Amazon Linux");
    if (/suse/i.test(t)) return distroOs("linux", "suse", "SUSE / openSUSE", "SUSE / openSUSE", "", "", "SUSE");
    m = t.match(/linux[-\s]?(\d+)\.(\d+)(?:\.(\d+))?/i);
    if (m) {
      var osK = distroOs("linux", "linux-" + m[1] + "." + m[2], "Linux 内核 " + m[1] + "." + m[2], "Linux kernel " + m[1] + "." + m[2], m[1] + "." + m[2], "", m[0]);
      osK.oldKernel = +m[1] < 4;
      return osK;
    }
    if (/\blinux\b|\bel7\b|\bel8\b|\bel9\b/i.test(t)) return distroOs("linux", "linux-generic", "Linux(发行版未知)", "Linux (unknown distro)", "", "", "Linux");

    // --- 网络设备 / 其它 ---
    if (/jetdirect|kyocera|laserjet|officejet|printing\s*system|hp\s*ethernet\s*multi|<xerox|canon\s*inc/i.test(t)) {
      return distroOs("network", "printer", "网络打印机 / 一体机", "Network printer / MFP", "", "", "SNMP 设备描述");
    }
    if (/cisco|ios[-\s]?xe?\b|asa\b/i.test(t)) return distroOs("network", "cisco", "Cisco IOS / ASA", "Cisco IOS / ASA", "", "", "Cisco");
    if (/huawei|华为|vrp\b/i.test(t)) return distroOs("network", "huawei", "华为 VRP", "Huawei VRP", "", "", "Huawei");
    if (/\bh3c\b|comware/i.test(t)) return distroOs("network", "h3c", "H3C Comware", "H3C Comware", "", "", "H3C");
    if (/juniper|junos/i.test(t)) return distroOs("network", "juniper", "Juniper Junos", "Juniper Junos", "", "", "Juniper");
    if (/mikrotik|routeros/i.test(t)) return distroOs("network", "mikrotik", "MikroTik RouterOS", "MikroTik RouterOS", "", "", "RouterOS");
    if (/fortinet|fortigate/i.test(t)) return distroOs("network", "fortinet", "Fortinet FortiGate", "Fortinet FortiGate", "", "", "FortiGate");
    if (/pfsense/i.test(t)) return distroOs("network", "pfsense", "pfSense", "pfSense", "", "", "pfSense");
    if (/sonicwall/i.test(t)) return distroOs("network", "sonicwall", "SonicWall", "SonicWall", "", "", "SonicWall");
    if (/palo\s*alto|pan-os/i.test(t)) return distroOs("network", "paloalto", "Palo Alto PAN-OS", "Palo Alto PAN-OS", "", "", "PAN-OS");
    if (/big-?ip|f5\s*networks/i.test(t)) return distroOs("network", "f5", "F5 BIG-IP", "F5 BIG-IP", "", "", "BIG-IP");
    if (/citrix|netscaler/i.test(t)) return distroOs("network", "citrix", "Citrix NetScaler", "Citrix NetScaler", "", "", "NetScaler");

    if (/freebsd/i.test(t)) return distroOs("unix", "freebsd", "FreeBSD", "FreeBSD", "", "", "FreeBSD");
    if (/solaris|sunos/i.test(t)) return distroOs("unix", "solaris", "Oracle Solaris", "Oracle Solaris", "", "", "Solaris");
    if (/\baix\b/i.test(t)) return distroOs("unix", "aix", "IBM AIX", "IBM AIX", "", "", "AIX");
    if (/darwin|mac\s*os/i.test(t)) return distroOs("unix", "macos", "macOS", "macOS", "", "", "macOS");

    return { key: "unknown", family: "unknown", name: "未识别", nameEn: "Unknown", version: "", eol: false, eolDate: "", evidence: "" };
  }

  /* ============================================================
   * 6. 组件版本检测
   * ============================================================ */
  function detectComponents(text) {
    var t = String(text || "");
    var out = [];
    for (var i = 0; i < COMP_RULES.length; i++) {
      var r = COMP_RULES[i];
      var m = t.match(r.re);
      if (!m) continue;
      var level = "", note = "", noteEn = "", version = "";
      if (r.fixed) {
        level = r.fixed[0]; note = r.fixed[1]; noteEn = r.fixed[2];
      } else if (r.check) {
        version = r.match ? r.match(m) : (m[1] || "");
        var res = r.check(version);
        if (res) { level = res[0]; note = res[1]; noteEn = res[2]; }
      } else if (r.bad) {
        var n = r.test(m);
        var bucket = r.bucket ? r.bucket(n) : n;
        if (r.bad[bucket]) {
          level = r.bad[bucket][0]; note = r.bad[bucket][1]; noteEn = r.bad[bucket][2];
          version = m[0];
        }
      }
      if (!level) continue;
      out.push({ id: r.id, name: r.name, version: version || m[0], level: level, note: note, noteEn: noteEn, evidence: m[0] });
    }
    return out;
  }

  /* ============================================================
   * 7. 分析
   * ============================================================ */

  /* 端口画像 → 操作系统倾向(没有系统 banner 时的兜底推断) */
  var WIN_PORT_SIGNAL = { 135: 2, 137: 1, 139: 2, 445: 3, 1433: 3, 1434: 1, 3389: 3, 5985: 3, 5986: 3, 47001: 2 };
  var LIN_PORT_SIGNAL = { 22: 2, 2222: 2, 6379: 2, 9200: 2, 9300: 2, 11211: 2, 2375: 2, 2376: 2, 5432: 2, 3306: 1, 6443: 1, 2181: 1, 9042: 1, 9092: 1, 10250: 3, 10255: 3, 873: 1 };

  function inferOsFromPorts(host) {
    var w = 0, l = 0, i;
    for (i = 0; i < host.ports.length; i++) {
      var p = host.ports[i].port;
      w += WIN_PORT_SIGNAL[p] || 0;
      l += LIN_PORT_SIGNAL[p] || 0;
    }
    var webTitles = host.web.map(function (x) { return x.title + " " + x.server; }).join(" ");
    if (/\basp\.?net|\.aspx|iis\b|microsoft-httpapi/i.test(webTitles)) w += 3;
    if (/php|wordpress|apache\/2\.2|nginx|ubuntu|debian|centos/i.test(webTitles)) l += 1;
    if (w >= 2 && w > l) {
      return { key: "win-inferred", family: "windows", name: "Windows(端口推测)", nameEn: "Windows (inferred)", version: "", eol: false, eolDate: "", evidence: "端口画像: SMB/RPC/RDP/MSSQL/WinRM", inferred: true, generic: true };
    }
    if (l >= 2 && l > w) {
      return { key: "linux-inferred", family: "linux", name: "Linux(端口推测)", nameEn: "Linux (inferred)", version: "", eol: false, eolDate: "", evidence: "端口画像: SSH + 数据库/中间件", inferred: true };
    }
    return null;
  }

  function analyze(parsed) {
    parsed = parsed || { entries: [], unknown: [], ignored: 0, total: 0, version: "" };
    var map = {}, order = [];

    function H(key) {
      var h = map[key];
      if (!h) {
        h = map[key] = {
          key: key, ip: key, hostname: "", domain: "", fqdn: "", smb: "",
          ports: [], portIdx: {}, creds: [], vulns: [], web: [], webIdx: {},
          peers: [], snmp: [], osTexts: [], evidence: [],
          components: [], findings: [], os: null,
          score: 0, level: "info", hits: 0
        };
        order.push(key);
      }
      return h;
    }
    function P(h, port) {
      if (!validPort(port)) return null;
      var p = h.portIdx[port];
      if (!p) {
        p = h.portIdx[port] = {
          port: port, proto: "tcp", tag: "", rawTag: "", service: "", label: "",
          title: "", url: "", scheme: "", code: 0, len: 0, server: "",
          product: "", version: "", smb: "", community: "", banner: "", msgs: [], level: "info"
        };
        h.ports.push(p);
      }
      return p;
    }
    function setHostInfo(h, e) {
      if (e.hostname && !h.hostname) h.hostname = e.hostname;
      if (e.domain && !h.domain) h.domain = e.domain;
      if (e.fqdn && !h.fqdn) h.fqdn = e.fqdn;
      if (e.smb && !h.smb) h.smb = e.smb;
      if (e.osText) {
        if (h.osTexts.indexOf(e.osText) === -1) h.osTexts.push(e.osText);
        h.evidence.push(e.osText);
      }
    }

    var entries = parsed.entries || [];
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (!e || !e.ip) continue;
      var h = H(e.ip);
      h.hits++;

      if (e.t === "peer") {
        if (e.peer && h.peers.indexOf(e.peer) === -1) h.peers.push(e.peer);
        continue;
      }

      if (e.t === "web") {
        var port0 = e.port || 80;
        var pw = P(h, port0);
        var rec = h.webIdx[e.url];
        if (!rec) {
          rec = h.webIdx[e.url] = {
            ip: h.ip, port: port0, scheme: e.scheme || "http", url: e.url,
            code: 0, len: 0, title: "", server: "", tags: [], banner: ""
          };
          h.web.push(rec);
        }
        if (e.code) rec.code = e.code;
        if (e.len) rec.len = e.len;
        if (e.title && !rec.title) rec.title = e.title;
        if (e.server && !rec.server) rec.server = e.server;
        if (e.tags && e.tags.length) rec.tags = e.tags;
        if (e.banner && !rec.banner) rec.banner = e.banner;
        if (pw) {
          if (!pw.scheme) pw.scheme = e.scheme || "http";
          if (e.code && !pw.code) pw.code = e.code;
          if (e.title && !pw.title) pw.title = e.title;
          if (e.server && !pw.server) pw.server = e.server;
          if (!pw.url) pw.url = e.url;
        }
        if (e.server) h.evidence.push("server " + e.server);
        if (e.title) h.evidence.push(e.title);
        if (e.tags && e.tags.length) h.evidence.push(e.tags.join(" "));
        if (e.banner) h.evidence.push(e.banner);
        if (e.host && !isIp(e.host) && !h.hostname) h.hostname = e.host;
        continue;
      }

      if (e.t === "cred") {
        var pc = P(h, e.port);
        if (pc && e.tag && !pc.tag) pc.tag = e.tag;
        var dup = h.creds.some(function (c) { return c.user === e.user && c.pass === e.pass && c.port === e.port; });
        if (!dup) {
          h.creds.push({ ip: h.ip, port: e.port, service: e.tag || (pc ? pc.tag : "") || "", user: e.user, pass: e.pass, msg: e.msg || "" });
        }
        h.evidence.push("weak password " + e.user + ":" + e.pass);
        continue;
      }

      if (e.t === "unauth") {
        var pu = P(h, e.port);
        if (pu) {
          if (e.tag && !pu.tag) pu.tag = e.tag;
          if (e.msg) pu.msgs.push(e.msg);
        }
        var dupU = h.vulns.some(function (v) { return v.kind === "unauth" && v.port === e.port; });
        if (!dupU) h.vulns.push({ name: "未授权访问", nameEn: "Unauthenticated access", port: e.port, msg: e.msg, level: "high", kind: "unauth" });
        if (e.msg) h.evidence.push(e.msg);
        continue;
      }

      if (e.t === "vuln") {
        var pv = e.port ? P(h, e.port) : null;
        if (pv && e.msg) pv.msgs.push(e.msg);
        if (e.msg) h.evidence.push(e.msg);
        var dupV = h.vulns.some(function (v) { return v.name === e.name && v.port === e.port; });
        if (!dupV) {
          h.vulns.push({
            name: e.name, port: e.port, msg: e.msg,
            level: /^MS1[0-9]-\d{3}$/i.test(e.name) || /^CVE-/i.test(e.name) ? "critical" : "high",
            kind: "vuln"
          });
        }
        continue;
      }

      // open / svc
      setHostInfo(h, e);
      var p = P(h, e.port);
      if (!p) continue;
      if (e.tag && !p.tag) p.tag = e.tag;
      if (e.rawTag && !p.rawTag) p.rawTag = e.rawTag;
      if (e.product && !p.product) p.product = e.product;
      if (e.version && !p.version) p.version = e.version;
      if (e.banner && !p.banner) p.banner = e.banner;
      if (e.smb && !p.smb) p.smb = e.smb;
      if (e.proto) p.proto = e.proto;
      if (e.community) {
        p.community = e.community;
        if (h.snmp.indexOf(e.community) === -1) h.snmp.push(e.community);
      }
      if (e.msg) {
        if (p.msgs.indexOf(e.msg) === -1) p.msgs.push(e.msg);
        if (e.msg.length > 2) h.evidence.push(e.msg);
      }
      if (e.banner) h.evidence.push(e.banner);
      if (e.product) h.evidence.push(e.product + " " + (e.version || ""));
    }

    /* ---- 逐主机收口 ---- */
    var hosts = [];
    for (var k = 0; k < order.length; k++) {
      var host = map[order[k]];
      host.ports.sort(function (a, b) { return a.port - b.port; });

      for (var pi = 0; pi < host.ports.length; pi++) {
        var p = host.ports[pi];
        var info = PORT_MAP[p.port];
        var tagSvc = p.tag || "";
        // ssl/http 这类只是探测方式, 端口表里有更准确的服务名(RDP/VNC/...)时以端口表为准
        if (info && (tagSvc === "http" || tagSvc === "https") && info.s !== "http" && info.s !== "https") tagSvc = "";
        p.service = tagSvc || (info ? info.s : (p.rawTag ? p.rawTag : "unknown"));
        p.label = info ? info.n : (p.rawTag ? p.rawTag : "未知服务");
        p.level = info ? info.lv : "info";
      }

      // 操作系统: 先看系统 banner(RDP/SMBInfo), 再看全部证据, 最后端口画像
      var osBlob = host.osTexts.join(" \n ");
      host.os = detectOs(osBlob);
      if (host.os.family === "unknown") host.os = detectOs(host.evidence.join(" \n "));
      if (host.os.family === "unknown") {
        var inf = inferOsFromPorts(host);
        if (inf) host.os = inf;
      }

      var evAll = host.evidence.join(" \n ");
      host.components = detectComponents(evAll);
      host.findings = [];

      // 系统版本 / EOL
      if (host.os && host.os.family !== "unknown") {
        if (host.os.eol) {
          host.findings.push({
            kind: "os-eol", level: "critical", ip: host.ip,
            title: host.os.name, titleEn: host.os.nameEn,
            detail: "该系统已过微软/发行版支持期(" + host.os.eolDate + "), 无法再获得安全补丁; 若存在 Nday 基本不可修复",
            detailEn: "Out of vendor support since " + host.os.eolDate + " — no further security patches, so known Ndays stay exploitable",
            evidence: host.os.evidence
          });
        } else if (host.os.days > 0 && host.os.days < 365) {
          host.findings.push({
            kind: "os-old", level: "medium", ip: host.ip,
            title: host.os.name, titleEn: host.os.nameEn,
            detail: "系统将在 " + host.os.eolDate + " 停止支持(剩余 " + host.os.days + " 天), 建议提前规划",
            detailEn: "Support ends on " + host.os.eolDate + " (in " + host.os.days + " days) — plan an upgrade",
            evidence: host.os.evidence
          });
        } else if (host.os.generic && !host.os.inferred && host.osTexts.length === 0) {
          host.findings.push({
            kind: "os-old", level: "low", ip: host.ip,
            title: host.os.name, titleEn: host.os.nameEn,
            detail: "只能确认是 Windows, 版本未知; 可用 nxc smb --gen-relay-list / smbclient 或 fscan 的 NetBIOS 模块补充版本",
            detailEn: "Only Windows is confirmed; version unknown — collect it via NetBIOS/SMB (nxc smb, smbclient) or fscan's netbios module",
            evidence: host.os.evidence
          });
        }
        if (host.os.oldKernel) {
          host.findings.push({
            kind: "old-comp", level: "medium", ip: host.ip,
            title: "Linux 内核 " + host.os.version, titleEn: "Linux kernel " + host.os.version,
            detail: "内核版本偏旧(< 4.x), 存在 Dirty COW / 提权类 Nday",
            detailEn: "Old kernel (< 4.x) — Dirty COW and other local privilege-escalation Ndays apply",
            evidence: host.os.evidence
          });
        }
      }

      // SMBv1
      if (/^SMBv1$/i.test(host.smb)) {
        host.findings.push({
          kind: "smb-v1", level: "high", ip: host.ip, port: 445,
          title: "SMBv1 已启用", titleEn: "SMBv1 enabled",
          detail: "SMBv1 是 MS17-010(永恒之蓝)/WannaCry 的攻击面, 优先确认补丁状态",
          detailEn: "SMBv1 is the attack surface for MS17-010 (EternalBlue) / WannaCry — verify patch level first",
          evidence: "SMBv1"
        });
      }

      // SNMP 团体字
      if (host.snmp.length) {
        var weakCom = host.snmp.filter(function (c) { return /^(public|private)$/i.test(c); });
        if (weakCom.length) {
          host.findings.push({
            kind: "snmp-public", level: "high", ip: host.ip, port: 161,
            title: "SNMP community: " + weakCom.join(" / "),
            titleEn: "SNMP community: " + weakCom.join(" / "),
            detail: "默认团体字可读取设备型号/序列号/接口与网络信息, 也是内网测绘入口",
            detailEn: "Default community string leaks model, serial, interfaces and network details — also a mapping entry point",
            evidence: "community: " + weakCom.join(", ")
          });
        } else {
          host.findings.push({
            kind: "snmp-public", level: "medium", ip: host.ip, port: 161,
            title: "SNMP community: " + host.snmp.join(" / "),
            titleEn: "SNMP community: " + host.snmp.join(" / "),
            detail: "SNMP 团体字可读, 建议确认其可读范围",
            detailEn: "SNMP community readable — verify its scope",
            evidence: "community: " + host.snmp.join(", ")
          });
        }
      }

      // 弱口令
      for (var ci = 0; ci < host.creds.length; ci++) {
        var c = host.creds[ci];
        var svc = c.service || (PORT_MAP[c.port] ? PORT_MAP[c.port].s : "服务");
        var anon = /^(anonymous|ftp|guest|nobody)$/i.test(c.user);
        host.findings.push({
          kind: "weak-pass", level: anon ? "high" : "critical", ip: host.ip, port: c.port,
          title: (svc || "服务") + " " + c.user + ":" + c.pass,
          titleEn: (svc || "service") + " " + c.user + ":" + c.pass,
          detail: anon ? "匿名/默认账号可直接登录, 无需爆破" : "弱口令可直接登录, 优先用它横向",
          detailEn: anon ? "Anonymous/default account logs in directly — no brute force needed" : "Weak password grants direct login — use it for lateral movement first",
          evidence: c.msg
        });
      }

      // 漏洞 / 未授权
      for (var vi = 0; vi < host.vulns.length; vi++) {
        var v = host.vulns[vi];
        host.findings.push({
          kind: v.kind || "vuln", level: v.level || "high", ip: host.ip, port: v.port,
          title: v.name + (v.port ? " · " + v.port : ""),
          titleEn: (v.nameEn || v.name) + (v.port ? " · " + v.port : ""),
          detail: v.kind === "unauth" ? "服务未做认证, 可直接读写数据/配置" : "POC 已命中, 需人工复核利用条件",
          detailEn: v.kind === "unauth" ? "Service has no authentication — data and config are directly accessible" : "POC matched — verify exploitation prerequisites manually",
          evidence: v.msg
        });
      }

      // 高危端口
      for (var pj = 0; pj < host.ports.length; pj++) {
        var pp = host.ports[pj];
        var pi2 = PORT_MAP[pp.port];
        if (!pi2 || (pi2.lv !== "high" && pi2.lv !== "medium")) continue;
        host.findings.push({
          kind: "danger-port", level: pi2.lv, ip: host.ip, port: pp.port,
          title: pp.port + "/" + (pp.service || pi2.s) + " " + (pi2.n || ""),
          titleEn: pp.port + "/" + (pp.service || pi2.s) + " " + (pi2.n || ""),
          detail: pi2.note || "高危端口暴露", detailEn: pi2.noteEn || "High-risk port exposed",
          evidence: pp.title || pp.banner || (pp.msgs[0] || "")
        });
      }

      // 组件过旧
      for (var cj = 0; cj < host.components.length; cj++) {
        var cp = host.components[cj];
        if (!cp.level || cp.level === "info") continue;
        host.findings.push({
          kind: "old-comp", level: cp.level, ip: host.ip, port: 0,
          title: cp.name + (cp.version ? " " + cp.version : ""),
          titleEn: cp.name + (cp.version ? " " + cp.version : ""),
          detail: cp.note, detailEn: cp.noteEn, evidence: cp.evidence
        });
      }

      // 后台/敏感页面
      for (var wi = 0; wi < host.web.length; wi++) {
        var w = host.web[wi];
        if (!ADMIN_RE.test(w.title + " " + w.url)) continue;
        host.findings.push({
          kind: "web-admin", level: "medium", ip: host.ip, port: w.port,
          title: (w.title || "登录/管理入口") + " · " + w.url,
          titleEn: (w.title || "login/admin entry") + " · " + w.url,
          detail: "暴露后台/调试接口, 可尝试默认口令与历史漏洞",
          detailEn: "Admin or debug interface exposed — try default credentials and historical CVEs",
          evidence: w.url
        });
      }

      // 评分
      var score = 0, worst = "info";
      var seenKind = {};
      for (var fi = 0; fi < host.findings.length; fi++) {
        var f = host.findings[fi];
        var w2 = LEVEL_WEIGHT[f.level] || 0;
        if (f.kind === "danger-port") w2 = Math.min(8, w2);
        if (f.kind === "web-admin") w2 = Math.min(8, w2);
        if (f.kind === "smb-v1") w2 = 20;
        if (f.kind === "snmp-public") w2 = 20;
        var cnt = seenKind[f.kind] || 0;
        seenKind[f.kind] = cnt + 1;
        score += cnt === 0 ? w2 : Math.round(w2 * 0.5);
        if (LEVEL_RANK[f.level] > LEVEL_RANK[worst]) worst = f.level;
      }
      host.score = Math.min(100, score);
      var lvl = host.score >= 70 ? "critical" : host.score >= 50 ? "high" : host.score >= 25 ? "medium" : host.score > 0 ? "low" : "info";
      if (worst === "critical" && LEVEL_RANK[lvl] < LEVEL_RANK.high) lvl = "high";
      host.level = lvl;

      host.tags = [];
      if (host.creds.length) host.tags.push({ k: "creds", v: host.creds.length });
      if (host.vulns.length) host.tags.push({ k: "vulns", v: host.vulns.length });
      if (host.web.length) host.tags.push({ k: "web", v: host.web.length });
      if (host.peers.length) host.tags.push({ k: "peers", v: host.peers.length });

      hosts.push(host);
    }

    hosts.sort(function (a, b) { return b.score - a.score || a.ip.localeCompare(b.ip); });

    /* ---- 汇总 ---- */
    var allFindings = [];
    for (var hi = 0; hi < hosts.length; hi++) {
      for (var fj = 0; fj < hosts[hi].findings.length; fj++) allFindings.push(hosts[hi].findings[fj]);
    }
    allFindings.sort(function (a, b) {
      return (LEVEL_RANK[b.level] - LEVEL_RANK[a.level]) || String(a.ip).localeCompare(String(b.ip));
    });

    /* ---- 按操作系统分组 ---- */
    var gmap = {}, gorder = [];
    for (hi = 0; hi < hosts.length; hi++) {
      var hh = hosts[hi];
      var oskey = hh.os ? hh.os.key : "unknown";
      if (!gmap[oskey]) {
        gmap[oskey] = {
          key: oskey,
          name: hh.os ? hh.os.name : "未识别",
          nameEn: hh.os ? hh.os.nameEn : "Unknown",
          family: hh.os ? hh.os.family : "unknown",
          eol: hh.os ? !!hh.os.eol : false,
          eolDate: hh.os ? hh.os.eolDate : "",
          hosts: [], maxScore: 0
        };
        gorder.push(oskey);
      }
      gmap[oskey].hosts.push(hh);
    }
    var osGroups = gorder.map(function (k) { return gmap[k]; });
    for (var gi = 0; gi < osGroups.length; gi++) {
      var g = osGroups[gi];
      g.count = g.hosts.length;
      g.maxScore = g.hosts.reduce(function (m, x) { return Math.max(m, x.score); }, 0);
      g.hosts.sort(function (a, b) { return b.score - a.score; });
    }
    var FAMILY_ORDER = { windows: 0, linux: 1, unix: 2, vmware: 3, network: 4, unknown: 5 };
    osGroups.sort(function (a, b) {
      if (a.eol !== b.eol) return a.eol ? -1 : 1;
      var fa = FAMILY_ORDER[a.family] == null ? 9 : FAMILY_ORDER[a.family];
      var fb = FAMILY_ORDER[b.family] == null ? 9 : FAMILY_ORDER[b.family];
      if (fa !== fb) return fa - fb;
      return b.count - a.count;
    });

    /* ---- 端口矩阵 ---- */
    var pmap = {};
    for (hi = 0; hi < hosts.length; hi++) {
      for (var pii = 0; pii < hosts[hi].ports.length; pii++) {
        var pp2 = hosts[hi].ports[pii];
        if (!pmap[pp2.port]) {
          var inf = PORT_MAP[pp2.port];
          pmap[pp2.port] = {
            port: pp2.port,
            service: inf ? inf.s : (pp2.tag || "unknown"),
            label: inf ? inf.n : (pp2.tag ? pp2.tag.toUpperCase() : "未知服务"),
            level: inf ? inf.lv : "info",
            note: inf ? (inf.note || "") : "",
            noteEn: inf ? (inf.noteEn || "") : "",
            hosts: []
          };
        }
        pmap[pp2.port].hosts.push(hosts[hi]);
      }
    }
    var portMatrix = Object.keys(pmap).map(function (p) { return pmap[p]; });
    portMatrix.sort(function (a, b) { return b.hosts.length - a.hosts.length || a.port - b.port; });

    /* ---- 邻接 IP 线索(NetInfo) ---- */
    var peers = [], peerSeen = {};
    for (hi = 0; hi < hosts.length; hi++) {
      for (var qi = 0; qi < hosts[hi].peers.length; qi++) {
        var to = hosts[hi].peers[qi];
        var key = hosts[hi].ip + ">" + to;
        if (peerSeen[key]) continue;
        peerSeen[key] = 1;
        var a = String(hosts[hi].ip).split(".").slice(0, 3).join(".");
        var b = String(to).split(".").slice(0, 3).join(".");
        peers.push({ from: hosts[hi].ip, to: to, cross: a !== b, hostname: hosts[hi].hostname || "" });
      }
    }

    /* ---- 统计 ---- */
    var totalPorts = 0, eolHosts = 0, credHosts = 0, vulnHosts = 0, webCount = 0, unknownOs = 0, smbV1 = 0;
    for (hi = 0; hi < hosts.length; hi++) {
      totalPorts += hosts[hi].ports.length;
      if (hosts[hi].os && hosts[hi].os.eol) eolHosts++;
      if (hosts[hi].os && hosts[hi].os.family === "unknown") unknownOs++;
      if (hosts[hi].creds.length) credHosts++;
      if (hosts[hi].vulns.length) vulnHosts++;
      if (/^SMBv1$/i.test(hosts[hi].smb)) smbV1++;
      webCount += hosts[hi].web.length;
    }

    var stats = {
      hosts: hosts.length,
      ports: totalPorts,
      portsUnique: portMatrix.length,
      creds: hosts.reduce(function (a, x) { return a + x.creds.length; }, 0),
      vulns: hosts.reduce(function (a, x) { return a + x.vulns.length; }, 0),
      web: webCount,
      eolHosts: eolHosts,
      credHosts: credHosts,
      vulnHosts: vulnHosts,
      unknownOs: unknownOs,
      smbV1: smbV1,
      peers: peers.length,
      osGroups: osGroups.length,
      findings: allFindings.length,
      critical: allFindings.filter(function (f) { return f.level === "critical"; }).length,
      high: allFindings.filter(function (f) { return f.level === "high"; }).length
    };

    return {
      version: parsed.version || "",
      hosts: hosts,
      findings: allFindings,
      osGroups: osGroups,
      portMatrix: portMatrix,
      peers: peers,
      stats: stats,
      unknown: parsed.unknown || [],
      ignored: parsed.ignored || 0,
      totalLines: parsed.total || 0,
      entries: entries.length
    };
  }

  /* ============================================================
   * 8. 导出(Markdown / JSON)
   * ============================================================ */
  var KIND_LABEL = {
    "os-eol": { zh: "系统已停止支持", en: "OS end-of-life" },
    "os-old": { zh: "系统版本偏旧", en: "Old OS version" },
    "weak-pass": { zh: "弱口令", en: "Weak password" },
    unauth: { zh: "未授权访问", en: "Unauthenticated access" },
    vuln: { zh: "已知漏洞", en: "Known vulnerability" },
    "danger-port": { zh: "高危端口", en: "High-risk port" },
    "old-comp": { zh: "组件版本过旧", en: "Outdated component" },
    "web-admin": { zh: "后台/敏感页面", en: "Admin/sensitive page" },
    "smb-v1": { zh: "SMBv1 已启用", en: "SMBv1 enabled" },
    "snmp-public": { zh: "SNMP 默认团体字", en: "SNMP default community" }
  };

  function code(s) { return s == null || s === "" ? "-" : "`" + String(s).replace(/`/g, "'") + "`"; }
  function cell(s) { return String(s == null ? "" : s).replace(/\|/g, "\\|").replace(/\n/g, " "); }

  function toMarkdown(model, lang) {
    var en = lang === "en";
    var L = [];
    var t = function (zh, enS) { return en ? enS : zh; };
    var s = model.stats;

    L.push(en ? "# fscan Report Analysis" : "# fscan 结果分析报告");
    L.push("");
    L.push("> " + t("由 Fscan Report Inspector 在浏览器本地生成 · tasklist.cxaqhq.cn/fscan.html",
      "Generated locally in the browser by Fscan Report Inspector · tasklist.cxaqhq.cn/fscan.html"));
    L.push("");
    L.push("- " + t("生成时间", "Generated at") + ": " + code(new Date().toISOString().replace("T", " ").slice(0, 19)));
    L.push("- " + t("fscan 版本", "fscan version") + ": " + code(model.version || t("未知", "unknown")));
    L.push("- " + t("规模", "Scale") + ": " + s.hosts + " hosts / " + s.ports + " ports / " + s.findings + " findings");
    L.push("- " + t("弱口令 / 未授权+漏洞 / Web / SMBv1", "Weak creds / unauth+vulns / web / SMBv1") +
      ": " + s.creds + " / " + s.vulns + " / " + s.web + " / " + s.smbV1);
    L.push("");

    L.push("## " + t("一、按操作系统划分", "1. Grouped by operating system"));
    L.push("");
    for (var i = 0; i < model.osGroups.length; i++) {
      var g = model.osGroups[i];
      var nm = en ? g.nameEn : g.name;
      L.push("### " + nm + " (" + g.count + t(" 台", " hosts") + (g.eol ? " · " + t("已 EOL", "EOL") + " " + g.eolDate : "") + ")");
      L.push("");
      L.push(t("| IP | 主机名 | 开放端口/服务 | 风险 | 弱点摘要 |", "| IP | Hostname | Ports/services | Risk | Findings |"));
      L.push("| --- | --- | --- | --- | --- |");
      for (var j = 0; j < g.hosts.length; j++) {
        var h = g.hosts[j];
        var ports = h.ports.map(function (p) { return p.port + "/" + (p.service || "?"); }).join(" ");
        var brief = h.findings.slice(0, 3).map(function (f) { return en ? f.titleEn : f.title; }).join("; ");
        L.push("| " + code(h.ip) + " | " + cell(h.hostname || "-") + " | " + code(ports || "-") + " | " +
          h.score + " (" + h.level + ") | " + cell(brief || "-") + " |");
      }
      L.push("");
    }

    L.push("## " + t("二、按 IP 划分", "2. Grouped by IP"));
    L.push("");
    for (i = 0; i < model.hosts.length; i++) {
      var hh = model.hosts[i];
      L.push("### " + code(hh.ip) + (hh.hostname ? " · " + hh.hostname : "") + " — " + (en ? hh.os.nameEn : hh.os.name));
      L.push("");
      var meta = [];
      meta.push(t("系统", "OS") + ": " + (en ? hh.os.nameEn : hh.os.name) + (hh.os.eol ? " (" + t("已 EOL", "EOL") + " " + hh.os.eolDate + ")" : ""));
      if (hh.domain) meta.push(t("域", "Domain") + ": " + hh.domain);
      if (hh.fqdn) meta.push("FQDN: " + hh.fqdn);
      if (hh.smb) meta.push("SMB: " + hh.smb);
      meta.push(t("风险", "Risk") + ": " + hh.score + " (" + hh.level + ")");
      L.push("- " + meta.join(" · "));
      if (hh.peers.length) L.push("- " + t("邻接/内网线索", "Adjacent/internal IPs") + ": " + hh.peers.map(code).join(" "));
      L.push("");

      if (hh.ports.length) {
        L.push(t("| 端口 | 服务 | 产品/版本 | 标题/横幅 | 风险 |", "| Port | Service | Product/version | Title/banner | Risk |"));
        L.push("| --- | --- | --- | --- | --- |");
        for (j = 0; j < hh.ports.length; j++) {
          var p2 = hh.ports[j];
          var prod = [p2.product, p2.version].filter(Boolean).join(" ");
          var extra = p2.title || p2.banner || p2.msgs.slice(0, 2).join(" · ");
          L.push("| " + code(p2.port + "/" + (p2.proto || "tcp")) + " | " + code(p2.service || p2.label || "?") +
            " | " + cell(prod || "-") + " | " + cell(String(extra || "-").slice(0, 120)) + " | " + p2.level + " |");
        }
        L.push("");
      }

      if (hh.web.length) {
        L.push(t("**Web 资产**", "**Web assets**") + ":");
        L.push("");
        L.push(t("| URL | 状态码 | 标题 | Server | 指纹 |", "| URL | Code | Title | Server | Tags |"));
        L.push("| --- | --- | --- | --- | --- |");
        for (j = 0; j < hh.web.length; j++) {
          var w = hh.web[j];
          L.push("| " + code(w.url) + " | " + (w.code || "-") + " | " + cell(w.title || "-") + " | " +
            cell(w.server || "-") + " | " + cell((w.tags || []).join(" ") || "-") + " |");
        }
        L.push("");
      }

      if (hh.creds.length) {
        L.push(t("**弱口令**", "**Weak credentials**") + ":");
        for (j = 0; j < hh.creds.length; j++) {
          L.push("- " + code(hh.creds[j].port + "/" + (hh.creds[j].service || "?")) + " " +
            code(hh.creds[j].user + ":" + hh.creds[j].pass));
        }
        L.push("");
      }
      if (hh.vulns.length) {
        L.push(t("**漏洞 / 未授权**", "**Vulns / unauth**") + ":");
        for (j = 0; j < hh.vulns.length; j++) {
          L.push("- " + code(hh.vulns[j].name) + " " + code(hh.vulns[j].port || ""));
        }
        L.push("");
      }
    }

    L.push("## " + t("三、按弱点划分", "3. Grouped by weakness"));
    L.push("");
    var byKind = {};
    for (i = 0; i < model.findings.length; i++) {
      var f = model.findings[i];
      if (!byKind[f.kind]) byKind[f.kind] = [];
      byKind[f.kind].push(f);
    }
    var kinds = Object.keys(byKind);
    kinds.sort(function (a, b) { return byKind[b].length - byKind[a].length; });
    for (i = 0; i < kinds.length; i++) {
      var kk = kinds[i];
      var lab = KIND_LABEL[kk] ? (en ? KIND_LABEL[kk].en : KIND_LABEL[kk].zh) : kk;
      L.push("### " + lab + " (" + byKind[kk].length + ")");
      L.push("");
      for (j = 0; j < byKind[kk].length; j++) {
        var ff = byKind[kk][j];
        L.push("- **" + ff.level + "** " + code(ff.ip + (ff.port ? ":" + ff.port : "")) + " " +
          (en ? ff.titleEn : ff.title) + " — " + (en ? ff.detailEn : ff.detail));
      }
      L.push("");
    }

    L.push("## " + t("四、端口矩阵", "4. Port matrix"));
    L.push("");
    L.push(t("| 端口 | 服务 | 主机数 | 说明 |", "| Port | Service | Hosts | Note |"));
    L.push("| --- | --- | --- | --- |");
    for (i = 0; i < model.portMatrix.length && i < 60; i++) {
      var pm = model.portMatrix[i];
      L.push("| " + code(pm.port) + " | " + cell(pm.label) + " | " + pm.hosts.length + " | " + cell(en ? pm.noteEn : pm.note) + " |");
    }
    L.push("");

    if (model.peers.length) {
      L.push("## " + t("五、内网 / 邻接 IP 线索", "5. Internal / adjacent IPs"));
      L.push("");
      for (i = 0; i < model.peers.length; i++) {
        var pe = model.peers[i];
        L.push("- " + code(pe.from) + (pe.hostname ? " (" + pe.hostname + ")" : "") + " → " + code(pe.to) +
          (pe.cross ? " · **" + t("跨网段", "cross-subnet") + "**" : ""));
      }
      L.push("");
    }

    if (model.unknown.length) {
      L.push("## " + t("六、未识别的原始行 (" + model.unknown.length + ")", "6. Unparsed lines (" + model.unknown.length + ")"));
      L.push("");
      for (i = 0; i < model.unknown.length && i < 60; i++) L.push("- " + code(model.unknown[i].slice(0, 200)));
      L.push("");
    }

    L.push("---");
    L.push("");
    L.push(t("> 仅供授权的安全测试与资产盘点使用。", "> For authorized security testing and asset inventory only."));
    return L.join("\n");
  }

  function toJson(model) {
    return JSON.stringify({
      meta: { tool: "Fscan Report Inspector", generatedAt: new Date().toISOString(), fscanVersion: model.version },
      stats: model.stats,
      osGroups: model.osGroups.map(function (g) {
        return { key: g.key, name: g.name, family: g.family, eol: g.eol, eolDate: g.eolDate, count: g.count, ips: g.hosts.map(function (h) { return h.ip; }) };
      }),
      hosts: model.hosts.map(function (h) {
        return {
          ip: h.ip, hostname: h.hostname, domain: h.domain, fqdn: h.fqdn, smb: h.smb,
          os: h.os, score: h.score, level: h.level, peers: h.peers,
          ports: h.ports.map(function (p) {
            return { port: p.port, proto: p.proto, service: p.service, product: p.product, version: p.version, title: p.title, url: p.url, code: p.code, server: p.server, smb: p.smb, level: p.level, banner: p.banner, msgs: p.msgs };
          }),
          creds: h.creds, vulns: h.vulns, web: h.web, findings: h.findings
        };
      }),
      portMatrix: model.portMatrix.map(function (p) { return { port: p.port, service: p.service, label: p.label, level: p.level, count: p.hosts.length, hosts: p.hosts.map(function (h) { return h.ip; }) }; }),
      peers: model.peers,
      unknown: model.unknown
    }, null, 2);
  }

  /* ============================================================
   * 8.5 简单清单(纯文本, 直接可贴)
   * ============================================================ */
  var FAMILY_LIST_LABEL = {
    windows: { zh: "Windows 机器", en: "Windows hosts" },
    linux: { zh: "Linux 机器", en: "Linux hosts" },
    unix: { zh: "Unix / 其它", en: "Unix / other" },
    vmware: { zh: "虚拟化平台", en: "Virtualization" },
    network: { zh: "网络设备", en: "Network devices" },
    unknown: { zh: "未识别", en: "Unknown" }
  };

  /** 显示宽度: CJK 字符按 2 列算, 保证等宽对齐 */
  function dispWidth(v) {
    var s = String(v == null ? "" : v), w = 0;
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if ((c >= 0x1100 && c <= 0x115f) || (c >= 0x2e80 && c <= 0xa4cf) ||
          (c >= 0xac00 && c <= 0xd7a3) || (c >= 0xf900 && c <= 0xfaff) ||
          (c >= 0xfe30 && c <= 0xfe6f) || (c >= 0xff00 && c <= 0xff60) ||
          (c >= 0xffe0 && c <= 0xffe6)) w += 2;
      else w += 1;
    }
    return w;
  }

  function padW(v, n) {
    var s = String(v == null ? "" : v), w = dispWidth(s);
    while (w < n) { s += " "; w++; }
    return s;
  }

  function ipSorted(hosts) {
    return hosts.slice().sort(function (a, b) {
      var pa = String(a.ip).split("."), pb = String(b.ip).split(".");
      if (pa.length === 4 && pb.length === 4) {
        for (var i = 0; i < 4; i++) {
          var d = (+pa[i] || 0) - (+pb[i] || 0);
          if (d) return d;
        }
        return 0;
      }
      return String(a.ip).localeCompare(String(b.ip));
    });
  }

  /**
   * 纯文本清单: 按系统分组, 一行一台机器
   *   Windows 机器 (5)
   *   10.0.0.11   SRV-CORP5   Windows Server 2012
   */
  function toSimpleList(model, lang) {
    var en = lang === "en";
    var fams = ["windows", "linux", "unix", "vmware", "network", "unknown"];
    var out = [];
    for (var f = 0; f < fams.length; f++) {
      var list = model.hosts.filter(function (h) { return (h.os ? h.os.family : "unknown") === fams[f]; });
      if (!list.length) continue;
      list = ipSorted(list);
      var lab = FAMILY_LIST_LABEL[fams[f]];
      out.push((en ? lab.en : lab.zh) + " (" + list.length + ")");
      var wIp = 4, wHost = 4, i;
      for (i = 0; i < list.length; i++) {
        wIp = Math.max(wIp, dispWidth(list[i].ip));
        wHost = Math.max(wHost, dispWidth(list[i].hostname || "-"));
      }
      for (i = 0; i < list.length; i++) {
        var h = list[i];
        out.push(padW(h.ip, wIp + 2) + padW(h.hostname || "-", wHost + 2) + (en ? h.os.nameEn : h.os.name));
      }
      out.push("");
    }
    return out.join("\n").replace(/\s+$/, "") + "\n";
  }

  /**
   * 纯文本 IP 清单: 一行一台, 带端口/服务
   *   10.0.0.3   SRV-CORP3   Windows Server 2012   53/dns 80/http 445/smb 3389/rdp
   */
  function toSimpleIpList(model, lang) {
    var en = lang === "en";
    var list = ipSorted(model.hosts);
    var wIp = 4, wHost = 4, wOs = 4, i;
    for (i = 0; i < list.length; i++) {
      wIp = Math.max(wIp, dispWidth(list[i].ip));
      wHost = Math.max(wHost, dispWidth(list[i].hostname || "-"));
      wOs = Math.max(wOs, dispWidth(en ? list[i].os.nameEn : list[i].os.name));
    }
    wOs = Math.min(wOs, 34);
    var out = [];
    for (i = 0; i < list.length; i++) {
      var h = list[i];
      var osName = en ? h.os.nameEn : h.os.name;
      var ports = h.ports.map(function (p) { return p.port + "/" + (p.service || "?"); }).join(" ");
      // 系统名超过对齐宽度时不补空格, 但要留出分隔
      var osCell = dispWidth(osName) >= wOs ? osName + "  " : padW(osName, wOs + 2);
      out.push(padW(h.ip, wIp + 2) + padW(h.hostname || "-", wHost + 2) + osCell + (ports || "-"));
    }
    return out.join("\n") + "\n";
  }

  /* ============================================================
   * 8.6 按服务分类(Web / SSH / 数据库 / 远程管理 / 文件共享 / 其它)
   * ============================================================ */
  var SERVICE_CATS = [
    { key: "web", zh: "Web 服务", en: "Web services",
      ports: { 80: 1, 81: 1, 443: 1, 3000: 1, 5000: 1, 6000: 1, 8000: 1, 8008: 1, 8080: 1, 8081: 1, 8088: 1, 8090: 1, 8443: 1, 9000: 1, 9090: 1 },
      svc: { http: 1, https: 1 } },
    { key: "ssh", zh: "SSH 服务", en: "SSH services",
      ports: { 22: 1, 2222: 1 }, svc: { ssh: 1 } },
    { key: "db", zh: "数据库服务", en: "Database services",
      ports: { 1433: 1, 1521: 1, 3306: 1, 5432: 1, 6379: 1, 9200: 1, 9300: 1, 11211: 1, 2181: 1, 27017: 1, 27018: 1, 9042: 1, 50000: 1 },
      svc: { mssql: 1, mysql: 1, oracle: 1, postgres: 1, redis: 1, elasticsearch: 1, memcached: 1, mongodb: 1, cassandra: 1, db2: 1, zookeeper: 1 } },
    { key: "remote", zh: "远程管理", en: "Remote admin",
      ports: { 3389: 1, 5985: 1, 5986: 1 }, svc: { rdp: 1, winrm: 1 } },
    { key: "smb", zh: "文件共享", en: "File sharing",
      ports: { 135: 1, 137: 1, 139: 1, 445: 1 }, svc: { smb: 1, netbios: 1, msrpc: 1 } },
    { key: "other", zh: "其它服务", en: "Other services", ports: {}, svc: {} }
  ];

  /** 每台主机按服务类别归组(一台机器可能同时出现在多个类别里) */
  function serviceGroups(model) {
    var hosts = ipSorted(model.hosts);
    var matched = {}, covered = {}, i, j, c, p;
    for (c = 0; c < SERVICE_CATS.length; c++) {
      var cat = SERVICE_CATS[c];
      if (cat.key === "other") continue;
      for (i = 0; i < hosts.length; i++) {
        var h = hosts[i];
        var hit = [];
        for (j = 0; j < h.ports.length; j++) {
          p = h.ports[j];
          if (cat.ports[p.port] || (p.service && cat.svc[p.service])) hit.push(p);
        }
        if (!hit.length) continue;
        matched[cat.key + "|" + h.ip] = hit;
        covered[h.ip] = covered[h.ip] || {};
        for (j = 0; j < hit.length; j++) covered[h.ip][hit[j].port] = 1;
      }
    }
    var groups = [];
    for (c = 0; c < SERVICE_CATS.length; c++) {
      var ct = SERVICE_CATS[c];
      var items = [];
      for (i = 0; i < hosts.length; i++) {
        var hh = hosts[i], rest = [], m;
        if (ct.key === "other") {
          for (j = 0; j < hh.ports.length; j++) {
            if (!(covered[hh.ip] && covered[hh.ip][hh.ports[j].port])) rest.push(hh.ports[j]);
          }
          if (rest.length) items.push({ host: hh, ports: rest });
        } else {
          m = matched[ct.key + "|" + hh.ip];
          if (m) items.push({ host: hh, ports: m });
        }
      }
      if (!items.length) continue;
      groups.push({ key: ct.key, label: ct.zh, labelEn: ct.en, items: items });
    }
    return groups;
  }

  /**
   * 纯文本服务清单: 按服务类别分组
   *   Web 服务 (12)
   *   10.0.0.3   SERV-UVRI3   Windows Server 2012   80/http 443/https
   */
  function toServiceList(model, lang) {
    var en = lang === "en";
    var groups = serviceGroups(model);
    var out = [];
    for (var g = 0; g < groups.length; g++) {
      var gr = groups[g];
      out.push((en ? gr.labelEn : gr.label) + " (" + gr.items.length + ")");
      var wIp = 4, wHost = 4, wOs = 4, i;
      for (i = 0; i < gr.items.length; i++) {
        wIp = Math.max(wIp, dispWidth(gr.items[i].host.ip));
        wHost = Math.max(wHost, dispWidth(gr.items[i].host.hostname || "-"));
        wOs = Math.max(wOs, dispWidth(en ? gr.items[i].host.os.nameEn : gr.items[i].host.os.name));
      }
      wOs = Math.min(wOs, 34);
      for (i = 0; i < gr.items.length; i++) {
        var it = gr.items[i];
        var osName = en ? it.host.os.nameEn : it.host.os.name;
        var osCell = dispWidth(osName) >= wOs ? osName + "  " : padW(osName, wOs + 2);
        var ports = it.ports.map(function (x) { return x.port + "/" + (x.service || "?"); }).join(" ");
        out.push(padW(it.host.ip, wIp + 2) + padW(it.host.hostname || "-", wHost + 2) + osCell + ports);
      }
      out.push("");
    }
    return out.join("\n").replace(/\s+$/, "") + "\n";
  }

  /** TXT / 「复制全部」的内容: 机器清单 + 服务清单 + IP 清单 */
  function toTxtList(model, lang) {
    var sep = "------------------------------------------------------------";
    return toSimpleList(model, lang) + "\n" +
      sep + "\n\n" +
      toServiceList(model, lang) + "\n" +
      sep + "\n\n" +
      toSimpleIpList(model, lang);
  }

  /* ============================================================
   * 9. 导出
   * ============================================================ */
  var API = {
    PORT_MAP: PORT_MAP,
    TAG_ALIAS: TAG_ALIAS,
    WIN_EOL: WIN_EOL,
    DISTRO_EOL: DISTRO_EOL,
    COMP_RULES: COMP_RULES,
    KIND_LABEL: KIND_LABEL,
    LEVEL_RANK: LEVEL_RANK,
    parse: parse,
    analyze: analyze,
    run: function (text) { return analyze(parse(text)); },
    detectOs: detectOs,
    detectComponents: detectComponents,
    splitUrl: splitUrl,
    toMarkdown: toMarkdown,
    toJson: toJson,
    toSimpleList: toSimpleList,
    toSimpleIpList: toSimpleIpList,
    serviceGroups: serviceGroups,
    toServiceList: toServiceList,
    toTxtList: toTxtList,
    SERVICE_CATS: SERVICE_CATS
  };

  root.FscanParser = API;
  if (typeof module !== "undefined" && module.exports) module.exports = API;
})(typeof window !== "undefined" ? window : globalThis);
