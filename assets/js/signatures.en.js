/*!
 * TaskList Inspector - English translations for the signature database
 * ---------------------------------------------------------------
 * 键(key)格式: "<cat>|<中文名称>" (与 signatures.js 中的 name 完全一致)
 * 值(value): 字符串 = 仅英文描述; 对象 = { name, desc }(当中文名称需要英文化时)
 * 新增签名时: 在 signatures.js 添加条目后, 尽量同时在本文件补充英文翻译;
 *             缺失翻译时界面会自动回退显示中文描述(fallback)。
 * 自测脚本 test/selftest.js 会校验英文覆盖率。
 */
(function (root) {
  "use strict";

  /* 厂商名英文化(仅列中文厂商) */
  var VENDOR_EN = {
    "奇虎 360": "Qihoo 360",
    "腾讯": "Tencent",
    "金山": "Kingsoft",
    "火绒": "Huorong",
    "瑞星": "Rising",
    "安全狗": "SafeDog",
    "深信服": "Sangfor",
    "阿里巴巴": "Alibaba",
    "搜狗": "Sogou",
    "宝塔": "BT Panel",
    "飞致云": "FIT2CLOUD",
    "腾讯云": "Tencent Cloud",
    "阿里云": "Alibaba Cloud",
    "华为": "Huawei",
    "华硕": "ASUS",
    "开源": "Open Source",
    "长亭科技": "Chaitin",
    "网易": "NetEase",
    "酷狗": "Kugou",
    "酷我": "Kuwo",
    "迅雷": "Xunlei",
    "百度": "Baidu",
    "金山办公": "Kingsoft Office",
    "卡巴斯基": "Kaspersky",
    "趋势科技": "Trend Micro"
  };

  /* 签名英文化: "<cat>|<中文名>" -> "desc" | { name, desc } */
  var SIG_EN = {

    /* ---------- 浏览器 ---------- */
    "browser|Google Chrome": "Google Chrome browser (incl. crashpad helper processes)",
    "browser|Microsoft Edge": "Microsoft Edge browser",
    "browser|Edge WebView2": "Edge WebView2 runtime (embedded browser component)",
    "browser|Mozilla Firefox": "Mozilla Firefox browser",
    "browser|Internet Explorer": "Internet Explorer (common on legacy systems)",
    "browser|Opera": "Opera browser",
    "browser|Brave": "Brave browser",
    "browser|Vivaldi": "Vivaldi browser",
    "browser|360 浏览器": { name: "360 Browser", desc: "Qihoo 360 Safe/Extreme browser" },
    "browser|搜狗高速浏览器": { name: "Sogou Explorer", desc: "Sogou browser" },
    "browser|QQ 浏览器": { name: "QQ Browser", desc: "Tencent QQ browser" },
    "browser|傲游浏览器": { name: "Maxthon", desc: "Maxthon browser" },
    "browser|2345 浏览器": { name: "2345 Browser", desc: "2345 browser" },
    "browser|UC 浏览器": { name: "UC Browser", desc: "UC Browser" },
    "browser|猎豹浏览器": { name: "Liebao Browser", desc: "Kingsoft Cheetah browser" },

    /* ---------- 终端安全 / AV / EDR ---------- */
    "av|Windows Defender": "Microsoft built-in anti-malware service / network inspection",
    "av|Microsoft Defender for Endpoint": "Microsoft enterprise EDR agent",
    "av|Windows 安全中心": { name: "Windows Security Center", desc: "Windows Security UI/service" },
    "av|Kaspersky": "Kaspersky consumer/enterprise security",
    "av|ESET": "ESET NOD32 / endpoint security",
    "av|Avast": "Avast antivirus",
    "av|Avira": "Avira antivirus",
    "av|Symantec / Norton": "Symantec Endpoint / Norton",
    "av|McAfee / Trellix": "McAfee/Trellix endpoint protection components",
    "av|Trend Micro": "Trend Micro OfficeScan / Apex One",
    "av|Sophos": "Sophos endpoint protection (incl. HitmanPro.Alert)",
    "av|Panda Security": "Panda Security endpoint protection",
    "av|Bitdefender": "Bitdefender antivirus",
    "av|CrowdStrike Falcon": "CrowdStrike Falcon EDR sensor",
    "av|SentinelOne": "SentinelOne EDR agent",
    "av|Cylance": "Cylance endpoint protection",
    "av|Palo Alto Cortex XDR": "Cortex XDR endpoint agent",
    "av|Tanium": "Tanium endpoint management & security platform",
    "av|Qualys Cloud Agent": "Qualys asset/vulnerability scanning agent",
    "av|Rapid7 Insight Agent": "Rapid7 vulnerability management agent",
    "av|Malwarebytes": "Malwarebytes anti-malware",
    "av|360 安全卫士/杀毒": { name: "360 Total Security (AV)", desc: "360 Safe Guard / Antivirus / active defense" },
    "av|腾讯电脑管家": { name: "Tencent PC Manager", desc: "Tencent PC Manager (incl. real-time protection)" },
    "av|火绒安全": { name: "Huorong Security", desc: "Huorong security suite" },
    "av|金山毒霸": { name: "Kingsoft Antivirus", desc: "Kingsoft Antivirus (Dubar)" },
    "av|瑞星杀毒": { name: "Rising Antivirus", desc: "Rising antivirus" },
    "av|Zscaler": "Zscaler enterprise security proxy (web control)",
    "av|Elastic Defend": "Elastic endpoint security (EDR)",
    "av|Sysmon": "Sysmon system call monitoring (often paired with SIEM)",
    "av|ClamAV": "Open-source antivirus engine (scanner/updater processes)",
    "av|Wazuh HIDS": "Wazuh host intrusion detection agent",
    "av|Snort IDS": "Network intrusion detection (IDS)",
    "av|Suricata": "Network intrusion detection/prevention (IDS/IPS)",
    "av|Zeek": "Network security monitoring (NSM)",
    "av|安全狗": { name: "SafeDog", desc: "SafeDog server protection (Linux host hardening)" },
    "av|Nessus": "Nessus scanner / agent",
    "av|ESET 管理代理": { name: "ESET Management Agent", desc: "ESET PROTECT / Remote Administrator agent" },
    "av|auditd": "Linux audit service (syscall auditing)",
    "av|fail2ban": "Brute-force protection (hardening in place)",

    /* ---------- 远程控制 ---------- */
    "remote|TeamViewer": "TeamViewer remote control (incl. service components)",
    "remote|向日葵远程控制": { name: "Sunlogin Remote Control", desc: "Oray Sunlogin remote control" },
    "remote|AweSun (向日葵国际版)": { name: "AweSun (Sunlogin)", desc: "Oray Sunlogin remote control (international)" },
    "remote|ToDesk": "ToDesk remote control",
    "remote|AnyDesk": "AnyDesk remote control",
    "remote|RustDesk": "RustDesk open-source remote control",
    "remote|RDP 客户端": { name: "RDP Client", desc: "Windows Remote Desktop client (outbound RDP connection present)" },
    "remote|RDP 会话组件": { name: "RDP Session Components", desc: "RDP clipboard/logon components (indicates an RDP session)" },
    "remote|WinRM 远程管理宿主": { name: "WinRM Host", desc: "PowerShell Remoting / WinRM session host (remote management connection)" },
    "remote|VNC Server": "VNC remote desktop server",
    "remote|Citrix Workspace": "Citrix virtual desktop/app client (VDI environment clue)",
    "remote|xrdp": "RDP server on Linux",
    "remote|OpenSSH 服务端": { name: "OpenSSH Server", desc: "SSH service (remote login entry — mind the listening port)" },
    "remote|SSH 客户端": { name: "SSH Client", desc: "Outbound SSH connection/session (lateral movement clue)" },
    "remote|Dropbear SSH": "Lightweight SSH service (common on embedded/IoT)",

    /* ---------- 隧道 / 代理 ---------- */
    "tunnel|frp": "Reverse proxy / intranet tunneling tool (verify usage)",
    "tunnel|ngrok": "Tunneling / public port mapping tool",
    "tunnel|Cloudflare Tunnel": "Cloudflare tunnel client",
    "tunnel|Chisel": "HTTP tunneling tool (common in security testing)",
    "tunnel|Proxifier": "Forced application-level proxy tool",
    "tunnel|V2Ray": "Proxy software core",
    "tunnel|Xray": "Xray proxy core (may also be the security assessment tool)",
    "tunnel|Clash": "Proxy client",

    /* ---------- VPN / 零信任 ---------- */
    "vpn|Cisco AnyConnect / Secure Client": "Cisco SSL VPN client",
    "vpn|Palo Alto GlobalProtect": "Enterprise SSL VPN client",
    "vpn|FortiClient": "Fortinet VPN/endpoint client",
    "vpn|深信服 EasyConnect": { name: "Sangfor EasyConnect", desc: "Sangfor SSL VPN client" },
    "vpn|深信服 aTrust": { name: "Sangfor aTrust", desc: "Sangfor zero-trust access client" },
    "vpn|OpenVPN": "OpenVPN client/server",
    "vpn|Tailscale": "WireGuard-based mesh VPN",
    "vpn|ZeroTier": "Virtual networking tool",
    "vpn|strongSwan": "IPsec VPN daemon",
    "vpn|xl2tpd": "L2TP VPN service",
    "vpn|pppd": "PPP/VPN dial-up process",
    "vpn|OpenConnect": "AnyConnect-compatible VPN client",

    /* ---------- 数据库 ---------- */
    "db|Microsoft SQL Server": "MSSQL database engine",
    "db|MySQL / MariaDB": "MySQL family database",
    "db|PostgreSQL": "PostgreSQL database (incl. background workers)",
    "db|Redis": "Redis cache/database",
    "db|MongoDB": "MongoDB database",
    "db|Oracle Database": "Oracle database instance / background processes",
    "db|Oracle TNS Listener": "Oracle TNS listener",
    "db|Memcached": "In-memory cache service",
    "db|InfluxDB": "Time-series database",
    "db|ClickHouse": "Column-oriented analytics database",
    "db|TiDB": "Distributed database component",
    "db|TiKV": "TiDB storage layer component",
    "db|etcd": "Distributed key-value store (K8s & infra component)",
    "db|Consul": "Service discovery / configuration center",

    /* ---------- Web 服务 ---------- */
    "web|IIS 工作进程": { name: "IIS Worker Process", desc: "IIS application pool worker (web site running)" },
    "web|IIS Express": "IIS Express development server",
    "web|Nginx": "Nginx web / reverse proxy service",
    "web|Apache HTTP Server": "Apache web server",
    "web|PHP": "PHP runtime / FastCGI process (common on LNMP / BT Panel)",
    "web|Apache Tomcat": "Tomcat application server",
    "web|Caddy": "Caddy web server",
    "web|Lighttpd": "Lightweight web server",
    "web|HAProxy": "Load balancer / reverse proxy",
    "web|Traefik": "Cloud-native reverse proxy",
    "web|Envoy": "Service mesh data-plane proxy",
    "web|Varnish": "HTTP cache service",
    "web|Gunicorn": "Python WSGI server",
    "web|uWSGI": "Python WSGI server",
    "web|Puma": "Ruby web server",
    "web|Gitea": "Self-hosted Git service",
    "web|GitLab Runner": "GitLab CI runner",

    /* ---------- 运行时 / 中间件 ---------- */
    "midware|Java 应用": { name: "Java Runtime/App", desc: "Java runtime (check the command line — could be middleware or a business app)" },
    "midware|Python": "Python runtime (ops scripts / web apps / security tools)",
    "midware|Node.js": "Node.js runtime/service",
    "midware|Perl": "Perl runtime (common in system scripts)",
    "midware|Ruby": "Ruby runtime",
    "midware|.NET 运行时": { name: ".NET Runtime", desc: ".NET application host" },
    "midware|Erlang VM": "Erlang VM (RabbitMQ/EMQX etc.)",
    "midware|RabbitMQ": "Message queue service",
    "midware|Apache Kafka": "Message queue / stream processing platform",
    "midware|Apache ZooKeeper": "Distributed coordination service",

    /* ---------- 容器 / 编排 ---------- */
    "container|Docker": "Docker engine/components (dockerd, docker-proxy etc.)",
    "container|containerd": "Container runtime (incl. containerd-shim)",
    "container|Docker Engine": "Docker daemon",
    "container|runc": "OCI container runtime",
    "container|Podman": "Daemonless container engine",
    "container|Kubernetes 组件": { name: "Kubernetes Components", desc: "K8s components (kubelet/kube-proxy etc.) — this host is a node" },
    "container|K3s": "Lightweight Kubernetes distribution",
    "container|Calico": "K8s network plugin",
    "container|Flannel": "K8s network plugin",
    "container|Cilium": "K8s networking/security component",

    /* ---------- 虚拟化 ---------- */
    "vm|VMware Tools": "VMware tools (host likely runs inside a VMware VM)",
    "vm|VMware Workstation 虚拟机进程": { name: "VMware VM Process (vmware-vmx)", desc: "Host is running VMware virtual machines" },
    "vm|VMware Workstation": "VMware virtualization software UI",
    "vm|VirtualBox": "VirtualBox components (host or guest)",
    "vm|QEMU": "QEMU virtual machine process (host may be a hypervisor)",
    "vm|QEMU Guest Agent": "QEMU guest agent (system likely a QEMU/KVM guest)",
    "vm|vmmem": "Virtual machine memory process (WSL2/Hyper-V VM running)",
    "vm|Hyper-V 虚拟机进程": { name: "Hyper-V VM Worker (vmwp)", desc: "Hyper-V virtual machine worker (host role)" },
    "vm|WSL": "Windows Subsystem for Linux",
    "vm|libvirt": "KVM virtualization management daemon (host may be a hypervisor)",
    "vm|LXD/LXC": "System container / virtualization management",

    /* ---------- 开发工具 ---------- */
    "dev|Visual Studio": "Visual Studio IDE",
    "dev|Visual Studio Code": "VS Code editor",
    "dev|Cursor": "Cursor AI editor",
    "dev|JetBrains IDE": "JetBrains IDEs (IntelliJ/PyCharm/GoLand etc.)",
    "dev|Android Studio": "Android development IDE",
    "dev|Eclipse": "Eclipse IDE",
    "dev|Notepad++": "Text editor",
    "dev|Sublime Text": "Text editor",
    "dev|HBuilderX": "Front-end development IDE",
    "dev|Postman": "API debugging tool",
    "dev|ChromeDriver": "Browser automation driver (scraping/automation clue)",
    "dev|Jenkins": "CI/CD service",
    "dev|GCC/Make": "Compiler toolchain (compilation in progress, or dev/embedded environment)",
    "dev|Vim/Neovim": "Command-line editor session",
    "dev|nano": "Command-line editor session",

    /* ---------- 网络分析工具 ---------- */
    "net|Wireshark": "Network packet capture & analysis tool",
    "net|tshark": "Wireshark command-line version",
    "net|dumpcap": "Wireshark capture engine",
    "net|tcpdump": "Command-line packet capture tool",
    "net|Fiddler": "HTTP capture/debugging tool",

    /* ---------- 安全测试工具 ---------- */
    "tool|Nmap": "Port/service scanner (common for both admins and pentesters)",
    "tool|Zenmap": "Nmap GUI",
    "tool|Masscan": "High-speed port scanner",
    "tool|Netcat": "Network swiss army knife (debugging/reverse shells — verify usage)",
    "tool|socat": "Multi-purpose network forwarding tool (verify usage)",
    "tool|Hydra": "Network login brute-forcer",
    "tool|Hashcat": "Password hash cracking tool",
    "tool|Mimikatz": "Credential extraction tool (verify usage)",
    "tool|PsExec": "Remote execution tool (often used for lateral movement — verify usage)",
    "tool|Rubeus": "Kerberos attack tool (verify usage)",
    "tool|SharpHound": "BloodHound data collector (AD enumeration)",
    "tool|Seatbelt": "Host survey/collection tool",
    "tool|CrackMapExec / NetExec": "AD penetration toolkit",
    "tool|fscan": "Intranet scanning tool (verify usage)",
    "tool|Nuclei": "Template-based vulnerability scanner",
    "tool|Web 目录爆破工具": { name: "Web Fuzzing Tools", desc: "Web content/directory brute-force tools" },
    "tool|xray": "Security assessment tool (may also be a proxy core — verify)",
    "tool|AntSword 中国蚁剑": { name: "AntSword", desc: "WebShell management tool" },
    "tool|Behinder 冰蝎": { name: "Behinder", desc: "WebShell management tool" },
    "tool|Godzilla 哥斯拉": { name: "Godzilla", desc: "WebShell management tool" },
    "tool|Sliver": "C2 framework (verify usage)",
    "tool|Evil-WinRM": "WinRM remote management tool (often abused)",
    "tool|Certipy": "AD CS attack tool (verify usage)",
    "tool|IDA Pro": "Reverse engineering tool",
    "tool|调试器 (x64dbg/OllyDbg)": { name: "Debugger (x64dbg/OllyDbg)", desc: "Program debugging/reversing tool" },
    "tool|dnSpy": ".NET decompiler/debugger",
    "tool|PC Hunter (PCHunter)": "Anti-rootkit system analysis tool (verify usage)",

    /* ---------- 系统工具 ---------- */
    "sysutil|Process Explorer": "Process viewer",
    "sysutil|Process Monitor": "System call monitoring tool",
    "sysutil|Autoruns": "Autostart entry checker",
    "sysutil|Process Hacker": "Process analysis tool",
    "sysutil|System Informer": "Process/system analysis tool (formerly Process Hacker)",
    "sysutil|Everything": "Instant file search tool",
    "sysutil|KeePass": "Password manager (a vault exists on this host)",
    "sysutil|Navicat": "Database client tool",
    "sysutil|SQL Server Management Studio": "MSSQL management client",
    "sysutil|PuTTY": "SSH/Telnet client",
    "sysutil|WinSCP": "SFTP/SCP client",
    "sysutil|FileZilla": "FTP/SFTP client",
    "sysutil|Xshell": "SSH client",
    "sysutil|Xftp": "SFTP client",
    "sysutil|SecureCRT": "Terminal/SSH client",
    "sysutil|MobaXterm": "All-in-one terminal (incl. SSH/X forwarding)",
    "sysutil|阿里系列保护服务": { name: "Alibaba Protect Service", desc: "Resident protection service bundled with Alibaba software" },
    "sysutil|搜狗输入法": { name: "Sogou IME", desc: "Sogou input method components" },
    "sysutil|Apple Bonjour": "Bonjour/mDNS LAN device discovery service",
    "sysutil|华为手机助手 (HiSuite)": { name: "Huawei HiSuite", desc: "Huawei HiSuite/USB device service (phone connection traces)" },
    "sysutil|NovaPDF": "Virtual printer (PDF generation tool)",
    "sysutil|Canon 打印机服务": { name: "Canon Printer Service", desc: "Canon inkjet printer background service (suspected)" },
    "sysutil|Intel 显卡组件": { name: "Intel Graphics Components", desc: "Intel iGPU driver services/tray (igfxCUIService, igfxEM etc.)" },
    "sysutil|Realtek 音频管理器": { name: "Realtek Audio Manager", desc: "Realtek sound card manager" },
    "sysutil|ASUS 主板工具组件": { name: "ASUS Motherboard Utility", desc: "ASUS AI Suite / ATK driver component (suspected)" },
    "sysutil|Intel USB 3.0 监视器": { name: "Intel USB 3.0 Monitor", desc: "Intel USB 3.0 monitor program" },

    /* ---------- 办公软件 ---------- */
    "office|Microsoft Office": "Office components (Word/Excel/PPT/Outlook etc.)",
    "office|Microsoft Visio": "Visio diagramming tool",
    "office|Office 后台服务": { name: "Office Background Service", desc: "Office Click-to-Run service" },
    "office|WPS Office": "WPS Office (incl. cloud/update components)",
    "office|WPS Office 组件": { name: "WPS Office Component", desc: "WPS Spreadsheets/Presentation" },
    "office|Adobe Acrobat/Reader": "PDF viewer/editor",
    "office|福昕 PDF": { name: "Foxit PDF", desc: "Foxit Reader/PDF editor" },

    /* ---------- 通讯 / 会议 ---------- */
    "im|腾讯 QQ / TIM": { name: "Tencent QQ / TIM", desc: "QQ/TIM client and components" },
    "im|微信": { name: "WeChat", desc: "WeChat (incl. mini-program processes)" },
    "im|企业微信": { name: "WeCom", desc: "WeCom (Enterprise WeChat)" },
    "im|钉钉": { name: "DingTalk", desc: "DingTalk" },
    "im|飞书": { name: "Feishu / Lark", desc: "Feishu / Lark" },
    "im|阿里旺旺": { name: "AliWangWang", desc: "AliWangWang messenger" },
    "im|千牛": { name: "Qianniu", desc: "Qianniu seller workbench" },
    "im|Telegram": "Telegram",
    "im|Skype": "Skype",
    "im|Slack": "Slack",
    "im|Microsoft Teams": "Teams meetings/collaboration",
    "im|Zoom": "Zoom video conferencing",
    "im|Discord": "Discord",

    /* ---------- 娱乐 / 多媒体 ---------- */
    "media|PotPlayer": "Video player",
    "media|VLC": "VLC player",
    "media|QQ 音乐": { name: "QQ Music", desc: "QQ Music" },
    "media|网易云音乐": { name: "NetEase Cloud Music", desc: "NetEase Cloud Music" },
    "media|酷狗音乐": { name: "Kugou Music", desc: "Kugou Music" },
    "media|酷我音乐": { name: "Kuwo Music", desc: "Kuwo Music" },
    "media|迅雷": { name: "Thunder", desc: "Thunder downloader (P2P download activity — mind internal networks)" },
    "media|百度网盘": { name: "Baidu Netdisk", desc: "Baidu Netdisk (data egress channel — worth attention)" },
    "media|Steam": "Steam gaming platform",
    "media|WeGame": "WeGame gaming platform",
    "media|Free Download Manager": "Download tool",
    "media|RealPlayer 套件": { name: "RealPlayer Suite", desc: "RealPlayer player and update/download components" },

    /* ---------- 备份 / 同步 ---------- */
    "backup|Microsoft OneDrive": "OneDrive cloud sync",
    "backup|Dropbox": "Dropbox cloud sync",
    "backup|rclone": "Cloud storage sync tool (common for admins, also a data egress risk)",
    "backup|备份工具 (restic/borg/duplicity)": { name: "Backup tools (restic/borg/duplicity)", desc: "Linux backup tools" },
    "backup|Syncthing": "P2P file synchronization",
    "backup|Nero BackItUp": "Nero backup service (suspected)",

    /* ---------- Windows 系统进程 ---------- */
    "system|System Idle Process": "System idle process",
    "system|System": "Windows kernel process",
    "system|Registry": "Registry process",
    "system|MemCompression": "Memory compression process (appears under memory pressure)",
    "system|Secure System": "Virtualization-based security (VBS) process",
    "system|smss.exe": "Session manager",
    "system|csrss.exe": "Client/server runtime subsystem",
    "system|wininit.exe": "Windows initialization process",
    "system|winlogon.exe": "Logon manager",
    "system|services.exe": "Service control manager",
    "system|lsass.exe": "Local security authority (credential-related — attacker focus)",
    "system|svchost.exe": "Service host (multiple instances are normal)",
    "system|fontdrvhost.exe": "Font driver host",
    "system|dwm.exe": "Desktop Window Manager",
    "system|explorer.exe": "Windows Explorer (desktop shell)",
    "system|taskhostw.exe": "Task host process",
    "system|RuntimeBroker.exe": "UWP permission broker",
    "system|SearchIndexer.exe": "Windows Search indexer",
    "system|Windows 搜索 UI": { name: "Windows Search UI", desc: "Search interface process" },
    "system|Shell 体验宿主": { name: "Shell Experience Host", desc: "Start menu / shell UI process" },
    "system|ApplicationFrameHost.exe": "UWP application frame host",
    "system|TextInputHost.exe": "Input method / touch keyboard host",
    "system|spoolsv.exe": "Print spooler (printing service present)",
    "system|conhost.exe": "Console host (command-line window present)",
    "system|sihost.exe": "Shell infrastructure host",
    "system|ctfmon.exe": "Input method service",
    "system|dllhost.exe": "COM Surrogate",
    "system|WmiPrvSE.exe": "WMI provider host",
    "system|任务管理器": { name: "Task Manager", desc: "Task Manager (someone is inspecting processes)" },
    "system|audiodg.exe": "Audio device graph isolation",
    "system|SmartScreen": "Windows SmartScreen protection",
    "system|CompatTelRunner.exe": "Compatibility telemetry task",
    "system|lsm.exe": "Local Session Manager (Windows 7/2008 specific)",
    "system|taskeng.exe": "Task Scheduler engine (Windows 7/2008)",
    "system|UI0Detect.exe": "Interactive services detection (Windows 7)",
    "system|WUDFHost.exe": "User-mode driver framework host",
    "system|WPF 字体缓存服务": { name: "WPF Font Cache Service", desc: "PresentationFontCache (.NET WPF)" },
    "system|Windows 筛选平台监视器": { name: "Windows Filtering Platform Monitor", desc: "WFP network filtering monitor (Win7)" },
    "system|WMP 网络共享服务": { name: "WMP Network Sharing Service", desc: "Windows Media Player Network Sharing" },
    "system|splwow64.exe": "32-bit print spooler proxy",

    /* ---------- 命令行 / 脚本宿主 ---------- */
    "shell|cmd.exe": "Command prompt (command-line session present)",
    "shell|Windows PowerShell": "PowerShell session/script",
    "shell|PowerShell 7": "PowerShell Core session",
    "shell|WMIC": "WMI command-line tool (often used for recon/lateral movement)",
    "shell|mshta.exe": "HTML application host (often abused to run scripts)",
    "shell|rundll32.exe": "DLL execution host (often abused)",
    "shell|regsvr32.exe": "Component registration tool (often abused)",
    "shell|certutil.exe": "Certificate tool (often abused for download/encoding)",
    "shell|Windows Script Host": "VBS/JS script host",
    "shell|tasklist.exe": "Task list command (produced this output itself)",
    "shell|screen": "Terminal multiplexer session (persistence/ops clue)",
    "shell|tmux": "Terminal multiplexer session (persistence/ops clue)",
    "shell|bash": "Bash shell session",
    "shell|sh": "Shell script session",
    "shell|zsh": "zsh session",
    "shell|dash": "dash session",

    /* ---------- Linux 系统 / 内核 ---------- */
    "system|systemd": "System and service manager (PID 1)",
    "system|init": "System initialization process (PID 1)",
    "system|kthreadd": "Kernel thread manager",
    "system|kworker": "Kernel worker thread (normal)",
    "system|ksoftirqd": "Softirq handling thread",
    "system|migration": "CPU migration kernel thread",
    "system|rcu_sched": "RCU kernel thread",
    "system|cpuhp": "CPU hotplug thread",
    "system|watchdog": "Kernel watchdog thread",
    "system|kswapd": "Memory reclaim thread",
    "system|kauditd": "Kernel audit thread",
    "system|systemd-journald": "Journal/log service",
    "system|systemd-udevd": "Device management service",
    "system|systemd-logind": "Login session management",
    "system|systemd-resolved": "DNS resolution service",
    "system|systemd-networkd": "Network management service",
    "system|systemd-timesyncd": "Time sync service",
    "system|systemd-oomd": "OOM protection service",
    "system|D-Bus": "Message bus",
    "system|polkitd": "Policy authorization service",
    "system|udisksd": "Disk management service",
    "system|agetty": "Terminal login program",
    "system|cron": "Scheduled tasks (crontab) service",
    "system|crond": "Scheduled tasks service",
    "system|atd": "One-off scheduled tasks service",
    "system|irqbalance": "IRQ load balancing service",
    "system|haveged": "Entropy source service",
    "system|smartd": "Disk SMART monitoring",
    "system|acpid": "Power management service",
    "system|snapd": "Snap package management service",
    "system|PackageKit": "Package management service",
    "system|tuned": "System performance tuning service",

    /* ---------- Linux 网络基础服务 ---------- */
    "infra|NetworkManager": "Network management service",
    "infra|wpa_supplicant": "Wireless authentication (WiFi connection present)",
    "infra|dhclient": "DHCP client",
    "infra|DHCP Server": "DHCP server (host may be a gateway/router)",
    "infra|dnsmasq": "Lightweight DNS/DHCP service",
    "infra|BIND DNS": "DNS server",
    "infra|Unbound DNS": "Recursive DNS service",
    "infra|CoreDNS": "DNS service (common in K8s)",
    "infra|chrony": "NTP time sync",
    "infra|NTP daemon": "Time sync service",
    "infra|rsyslog": "System logging service",
    "infra|multipathd": "Multipath storage service (SAN storage clue)",
    "infra|SSSD": "Domain/LDAP integration (enterprise unified auth clue)",
    "infra|MIT Kerberos": "Kerberos KDC (may be a domain controller / auth server)",
    "infra|FreeRADIUS": "RADIUS authentication service",
    "infra|avahi": "mDNS/DNS-SD service",
    "infra|CUPS": "Printing service",

    /* ---------- 文件 / 共享服务 ---------- */
    "file|Samba smbd": "SMB/CIFS file sharing service",
    "file|Samba nmbd": "Samba NetBIOS service",
    "file|Samba winbindd": "Samba domain integration (AD environment clue)",
    "file|NFS Server": "NFS file sharing service",
    "file|rpcbind": "RPC port mapper (NFS dependency)",
    "file|vsftpd": "FTP service",
    "file|ProFTPD": "FTP service",
    "file|Pure-FTPd": "FTP service (common with BT Panel / shared hosting)",

    /* ---------- 邮件服务 ---------- */
    "mail|Dovecot": "IMAP/POP3 mail service",
    "mail|Exim": "Mail transfer agent (MTA)",
    "mail|Postfix": "Mail transfer agent (MTA) components",

    /* ---------- 云厂商组件 ---------- */
    "cloud|阿里云盾 Agent": { name: "Alibaba Cloud Shield Agent", desc: "Alibaba Cloud Security Center client (cloud host clue)" },
    "cloud|阿里云助手": { name: "Alibaba Cloud Assistant", desc: "Alibaba Cloud ops channel (Cloud Assistant)" },
    "cloud|阿里云助手守护": { name: "Alibaba Cloud Assistant Daemon", desc: "Alibaba Cloud Assistant daemon" },
    "cloud|腾讯云监控 Agent": { name: "Tencent Cloud Monitor Agent", desc: "Tencent Cloud monitoring component (cloud host clue)" },
    "cloud|腾讯云安全 Agent": { name: "Tencent Cloud Security Agent", desc: "Tencent Cloud host security component" },
    "cloud|腾讯云镜": { name: "Tencent Cloud YunJing", desc: "Tencent Cloud workload protection (YunJing)" },

    /* ---------- 运维 / 监控 ---------- */
    "ops|Zabbix": "Zabbix monitoring (agent/server)",
    "ops|Nagios": "Nagios monitoring",
    "ops|NRPE": "Nagios remote plugin executor",
    "ops|Prometheus Exporter": "Prometheus metrics exporter",
    "ops|Prometheus": "Monitoring system",
    "ops|Grafana": "Visualization dashboard",
    "ops|Telegraf": "Metrics collection agent",
    "ops|collectd": "System metrics collection",
    "ops|Netdata": "Real-time performance monitoring",
    "ops|Datadog Agent": "Cloud monitoring agent",
    "ops|Elastic Beats": "Log/metric/audit shippers",
    "ops|Elastic Agent": "Elastic unified collection agent",
    "ops|SCCM 管理代理": { name: "SCCM Agent", desc: "Microsoft SCCM/ConfigMgr client agent (enterprise management clue)" },
    "ops|osquery": "SQL-based system information collection (common in security monitoring)",
    "ops|Supervisor": "Process supervisor (manages business processes)",
    "ops|Monit": "Process/resource monitoring daemon",
    "ops|PM2": "Node.js process manager",
    "ops|SaltStack": "Configuration management / bulk ops",
    "ops|Puppet": "Configuration management",
    "ops|Chef": "Configuration management",
    "ops|Ansible": "Automation/ops tool",
    "ops|Cockpit": "Web-based admin panel",
    "ops|宝塔面板 (BT Panel)": { name: "BT Panel", desc: "Server ops panel (web-based admin entry)" },
    "ops|1Panel": "Modern server ops panel",

    /* ---------- 桌面环境 ---------- */
    "desktop|Xorg": "X11 display service (graphical desktop present)",
    "desktop|Xwayland": "X11 compatibility layer on Wayland",
    "desktop|GNOME Shell": "GNOME desktop environment",
    "desktop|KDE Plasma": "KDE desktop environment",
    "desktop|KWin": "KDE window manager",
    "desktop|GDM": "GNOME display manager",
    "desktop|LightDM": "Lightweight display manager",
    "desktop|SDDM": "KDE display manager",
    "desktop|Cinnamon": "Cinnamon desktop environment",

    /* ---------- 更新组件 ---------- */
    "update|Google 更新组件": { name: "Google Update Components", desc: "Chrome updater/crash reporter (Chrome-family product installed)" },
    "update|Edge 更新组件": { name: "Edge Update", desc: "Edge updater" },
    "update|Java 更新程序": { name: "Java Updater", desc: "Java auto-updater" },
    "update|TrustedInstaller": "Windows Modules Installer (system updating)",
    "update|unsecapp.exe": "WMI event sink process",
    "update|HP 软件更新": { name: "HP Software Update", desc: "HP update scheduled task" }
  };

  /* 命令行关键字描述英文化: 键为 CMD_KEYWORDS 的 n 字段 */
  var CMD_EN = {
    "Burp Suite": "Web pentest proxy tool",
    "SQLMap": "Automated SQL injection tool",
    "Metasploit": "Penetration testing framework",
    "Cobalt Strike": "C2 framework (red team)",
    "Sliver": "C2 framework (red team)",
    "BloodHound": "AD attack path analysis tool",
    "secretsdump (Impacket)": "Credential dumping script",
    "Responder": "LLMNR/NBT-NS poisoning tool",
    "mitmproxy": "Intercepting proxy / MITM tool",
    "ProxyChains": "Proxy chaining tool",
    "Certipy": "AD CS attack tool",
    "Evil-WinRM": "WinRM remote management tool",
    "宝塔面板 (BT Panel)": { name: "BT Panel", desc: "Server ops panel (web-based admin entry)" },
    "xray": "Security assessment tool (may also be a proxy core)"
  };

  /* ---------- 查找辅助 ---------- */
  function sigEntry(sig) {
    return sig ? SIG_EN[sig.cat + "|" + sig.name] : null;
  }

  /** 按当前语言返回签名显示名 */
  function sigName(sig) {
    var e = sigEntry(sig);
    if (root.I18N && root.I18N.isEn() && e) {
      if (typeof e === "object" && e.name) return e.name;
    }
    return sig.name;
  }

  /** 按当前语言返回签名描述(英文缺失时回退中文) */
  function sigDesc(sig) {
    var e = sigEntry(sig);
    if (e && root.I18N && root.I18N.isEn()) {
      return (typeof e === "string" ? e : e.desc) || sig.desc;
    }
    return sig.desc;
  }

  /** 按当前语言返回厂商显示名 */
  function vendorName(vendor) {
    if (root.I18N && root.I18N.isEn() && VENDOR_EN[vendor]) return VENDOR_EN[vendor];
    return vendor;
  }

  /** 命令行关键字: 显示名 */
  function cmdName(kw) {
    var e = CMD_EN[kw.n];
    if (root.I18N && root.I18N.isEn() && e && typeof e === "object" && e.name) return e.name;
    return kw.n;
  }

  /** 命令行关键字: 描述 */
  function cmdDesc(kw) {
    var e = CMD_EN[kw.n];
    if (e && root.I18N && root.I18N.isEn()) {
      return (typeof e === "string" ? e : e.desc) || kw.d;
    }
    return kw.d;
  }

  /** 仅按标签(如 宝塔面板 (BT Panel))翻译命令行动态标签 */
  function cmdTagName(tag) {
    var e = CMD_EN[tag];
    if (root.I18N && root.I18N.isEn() && e && typeof e === "object" && e.name) return e.name;
    return tag;
  }

  root.SIG_EN = SIG_EN;
  root.CMD_EN = CMD_EN;
  root.VENDOR_EN = VENDOR_EN;
  root.sigName = sigName;
  root.sigDesc = sigDesc;
  root.vendorName = vendorName;
  root.cmdName = cmdName;
  root.cmdDesc = cmdDesc;
  root.cmdTagName = cmdTagName;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { SIG_EN: SIG_EN, CMD_EN: CMD_EN, VENDOR_EN: VENDOR_EN };
  }
})(typeof window !== "undefined" ? window : globalThis);
