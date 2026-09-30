/*!
 * TaskList Inspector - 内置示例数据(用于演示与自测)
 */
(function (root) {
  "use strict";

  var SAMPLES = {
    /* 中文 Windows 的 tasklist 默认输出(节选, 含 typosquat 演示) */
    windows: [
      "映像名称                       PID 会话名              会话#       内存使用",
      "========================= ======== ================ =========== ============",
      "System Idle Process              0 Services                   0         24 K",
      "System                           4 Services                   0        144 K",
      "Registry                       140 Services                   0     14,288 K",
      "smss.exe                       524 Services                   0      1,232 K",
      "csrss.exe                      712 Services                   0      4,616 K",
      "wininit.exe                    804 Services                   0      5,348 K",
      "csrss.exe                      836 Console                    1      5,908 K",
      "winlogon.exe                   880 Console                    1      7,472 K",
      "services.exe                   948 Services                   0      8,716 K",
      "lsass.exe                      964 Services                   0     19,248 K",
      "svchost.exe                   1024 Services                   0     25,312 K",
      "fontdrvhost.exe               1068 Services                   0      3,844 K",
      "svchost.exe                   1104 Services                   0     16,908 K",
      "dwm.exe                       1244 Console                    1     92,104 K",
      "svchost.exe                   1408 Services                   0     38,552 K",
      "MsMpEng.exe                   2384 Services                   0    186,204 K",
      "avp.exe                       3712 Console                    1    118,436 K",
      "SecurityHealthSystray.exe     4296 Console                    1     12,780 K",
      "explorer.exe                  4372 Console                    1     98,320 K",
      "svchost.exe                   4588 Services                   0     31,264 K",
      "svch0st.exe                   5120 Console                    1      9,412 K",
      "QQ.exe                        6216 Console                    1    268,340 K",
      "QQProtect.exe                 6232 Console                    1     24,108 K",
      "WeChat.exe                    7844 Console                    1    231,576 K",
      "DingTalk.exe                  8120 Console                    1    312,884 K",
      "wps.exe                       9356 Console                    1    195,432 K",
      "chrome.exe                   10288 Console                    1    298,764 K",
      "chrome.exe                   11024 Console                    1    327,552 K",
      "msedge.exe                   11840 Console                    1    204,116 K",
      "ToDesk.exe                   12604 Console                    1    112,308 K",
      "sunloginclient.exe           13552 Console                    1     86,440 K",
      "rdpclip.exe                  14208 Console                    1      9,860 K",
      "taskmgr.exe                  15012 Console                    1     28,764 K"
    ].join("\n"),

    /* Linux ps aux 输出(节选) */
    linux: [
      "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
      "root         1  0.0  0.1 225380  9620 ?        Ss   Aug12   0:42 /sbin/init",
      "root         2  0.0  0.0      0     0 ?        S    Aug12   0:00 [kthreadd]",
      "root       712  0.0  0.3 108324 12740 ?        S<s  Aug12   0:19 /lib/systemd/systemd-journald",
      "root       925  0.0  0.1  19592 10688 ?        Ss   Aug12   0:12 /usr/sbin/sshd -D -p 22",
      "root      1044  0.0  0.1  19948  9024 ?        Ss   Aug12   0:09 /lib/systemd/systemd-resolved",
      "root      1108  0.0  0.4 262108 17264 ?        Ss   Aug12   0:04 nginx: master process /usr/sbin/nginx -g daemon on;",
      "www-data  1109  0.0  0.4 262208 17380 ?        S    Aug12   0:04 nginx: worker process",
      "mysql     2380  0.3  6.4 1864204 258932 ?      Ssl  Aug12   4:22 /usr/sbin/mysqld",
      "www-data  2451  0.0  1.2 522416 50212 ?        S    Aug12   0:18 php-fpm: pool www",
      "root      3012  0.1  0.6 718928 26456 ?        Sl   Aug12   0:25 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock",
      "root      3308  0.2  1.8 1283764 74820 ?       Ssl  Aug12   1:10 kubelet --config=/var/lib/kubelet/config.yaml",
      "root      3520  0.0  0.2 153204  8440 ?        Ss   Aug12   0:03 /usr/sbin/cron -f",
      "root      4102  0.0  0.6 552316 26244 ?        Ssl  Aug12   0:11 /usr/local/aegis/AliYunDun",
      "root      4510  0.0  0.2 142024  6840 ?        Ss   Aug12   0:00 /usr/sbin/clamd --foreground",
      "root      5120  0.0  0.9 892340 38924 ?        Ssl  Aug12   0:16 python3 /www/server/panel/BT-Panel",
      "root      5678  0.0  0.1  10584  4932 ?        Ss   Aug12   0:00 ./frps -c /etc/frp/frps.ini",
      "root      6012  0.0  0.1  64208  6124 ?        Ss   Aug12   0:02 /usr/bin/dbus-daemon --system --address=systemd:",
      "root      7004  0.0  0.2  91204  8876 ?        Ssl  Aug12   0:06 /opt/agent/corp-mon-agent --daemon"
    ].join("\n"),

    /* NetExec / CrackMapExec 带日志前缀的输出(脏数据) */
    netexec: [
      "SMB         192.168.9.92    445    AS-PC            [+] Executed command via atexec",
      "SMB         192.168.9.92    445    AS-PC            Image Name                     PID Session Name        Session#    Mem Usage",
      "SMB         192.168.9.92    445    AS-PC            ========================= ======== ================ =========== ============",
      "SMB         192.168.9.92    445    AS-PC            System Idle Process              0 Services                   0         24 K",
      "SMB         192.168.9.92    445    AS-PC            System                           4 Services                   0      2,296 K",
      "SMB         192.168.9.92    445    AS-PC            smss.exe                       316 Services                   0      1,196 K",
      "SMB         192.168.9.92    445    AS-PC            lsass.exe                      704 Services                   0     12,396 K",
      "SMB         192.168.9.92    445    AS-PC            svchost.exe                    804 Services                   0     10,912 K",
      "SMB         192.168.9.92    445    AS-PC            ekrn.exe                       868 Services                   0    128,392 K",
      "SMB         192.168.9.92    445    AS-PC            vmtools.exe                   2364 Services                   0     11,984 K",
      "SMB         192.168.9.92    445    AS-PC            cmd.exe                       4208 Services                   0      2,624 K",
      "SMB         192.168.9.92    445    AS-PC            conhost.exe                   3048 Services                   0      2,908 K",
      "SMB         192.168.9.92    445    AS-PC            chrome.exe                    6512 Console                    1     27,804 K",
      "SMB         192.168.9.92    445    AS-PC            tasklist.exe                  6124 Services                   0      5,604 K"
    ].join("\n")
  };

  root.SAMPLES = SAMPLES;
  if (typeof module !== "undefined" && module.exports) module.exports = SAMPLES;
})(typeof window !== "undefined" ? window : globalThis);
