---
layout: post
author: PLM
title: "Say Chesse! - HTB Business CTF 2024 The Vault Of Hope"
date: 2024-05-22
categories: [CTF, Web]
background_image: assets/cheese.jpg
title_color: "#ffffff"
---

**Url : [HackTheBox Business CTF 2024](https://ctf.hackthebox.com/event/details/htb-business-ctf-2024-the-vault-of-hope-1474)**  
**Challenge :  Say Cheese!**  
**Date : flag le 22/05/2024 à 2h00**

![](/assets/posts/Say-Chesse/1.png)

Un script python 'client.py' nous est fournit : 
```python
import socket
import json

def exchange(hex_list, value=0):

    # Configure according to your setup
    host = '127.0.0.1'  # The server's hostname or IP address
    port = 1337        # The port used by the server
    cs=0 # /CS on A*BUS3 (range: A*BUS3 to A*BUS7)
    
    usb_device_url = 'ftdi://ftdi:2232h/1'

    # Convert hex list to strings and prepare the command data
    command_data = {
        "tool": "pyftdi",
        "cs_pin":  cs,
        "url":  usb_device_url,
        "data_out": [hex(x) for x in hex_list],  # Convert hex numbers to hex strings
        "readlen": value
    }
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        
        # Serialize data to JSON and send
        s.sendall(json.dumps(command_data).encode('utf-8'))
        
        # Receive and process response
        data = b''
        while True:
            data += s.recv(1024)
            if data.endswith(b']'):
                break
                
        response = json.loads(data.decode('utf-8'))
        #print(f"Received: {response}")
    return response


# Example command
jedec_id = exchange([0x9F], 3)
print(jedec_id)
```

Cela semble à première vu être un programme coté client qui vient interagir et requêter une puce de mémoire flash, l'énoncé nous indique que c'est une flash SPI et plus précisément la W25Q128FV

![](/assets/posts/Say-Chesse/2.png)

dont voici la datasheet : https://www.pjrc.com/teensy/W25Q128FV.pdf

Dans le script python nous remarquons la présence de cette variable : 
```python
# Example command
jedec_id = exchange([0x9F], 3)
print(jedec_id)
```

>JEDEC (Joint Electron Device Engineering Council) est un organisme de normalisation qui élabore des normes pour l'industrie microélectronique.
>JEDEC ID  est un identifiant unique attribué à chaque puce par le fabricant selon les normes JEDEC. 

Regardons plus précisément ce que fait la commande : 
La commande appelle la fonction exchange avec comme paramètres 0x9F et 3 
- 0x9F : Valeur hexadécimale représentant la commande pour demander le JEDEC ID du périphérique de mémoire flash. (voir screen ci dessous)
- 3 : paramètre qui indique le nombre d'octets à lire. 

Le résultat de cette commande est donc printé grace au ```print(jedec_id)```
![](/assets/posts/Say-Chesse/3.png)

donc si nous exécutons notre script client.py pour requêter le JEDEC ID : 
```bash
┌──(plm㉿oppida)-[~/home/CTF/say_cheese]
└─$ python client.py 
[239, 64, 24]
```

> La liste de tout les autres paramètre peut se trouver en ligne.

mais il y en a un qui nous intéresse tout particulièrement : 
![](/assets/posts/Say-Chesse/4.png)

l'instruction ```read data``` permet de lire de la data séquentiellement depuis la mémoire
par exemple en envoyant : 
```python
jedec_id = exchange([0x03, 0x00, 0x00, 0x00], 128 )
print(jedec_id)
```
nous lisons les 128 premiers bytes de la mémoire à partir de 0x000000 
résultat : 
```bash
┌──(plm㉿oppida)-[~/home/CTF/say_cheese]
└─$ python client.py
[39, 5, 25, 86, 86, 44, 137, 202, 102, 68, 161, 42, 0, 169, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 154, 11, 173, 5, 5, 5, 0, 106, 122, 95, 102, 119, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 39, 5, 25, 86, 111, 89, 72, 244, 94, 204, 163, 59, 0, 29, 26, 157, 128, 1, 0, 0, 128, 66, 24, 112, 216, 252, 221, 250, 5, 5, 2, 3, 76, 105, 110, 117, 120, 45, 51, 46, 49, 48, 46, 49, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

Lorsque nous passons ces bytes dans cyberchef.
![](/assets/posts/Say-Chesse/5.png)
nous devinons qu'il s'agit d'une image LZMA compressé 

j'ai passé beaucoup de temps à essayer de lire des adresses mémoire afin de voir si le flag n'était stocké en claire quelque part, mais au bout de plusieurs heures, j'ai compris qu'il fallait extract l'entièreté du firmware. 
pour ceci : 

```python
import socket
import json
from pwn import * 

def exchange(hex_list, value=0):
    # Configure according to your setup
    host = '83.136.248.205'  # The server's hostname or IP address
    port = 37104        # The port used by the server
    cs=0 # /CS on A*BUS3 (range: A*BUS3 to A*BUS7)
    
    usb_device_url = 'ftdi://ftdi:2232h/1'
    # Convert hex list to strings and prepare the command data
    command_data = {
        "tool": "pyftdi",
        "cs_pin":  cs,
        "url":  usb_device_url,
        "data_out": [hex(x) for x in hex_list],  # Convert hex numbers to hex strings
        "readlen": value
    }
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        
        # Serialize data to JSON and send
        s.sendall(json.dumps(command_data).encode('utf-8'))
        
        # Receive and process response
        data = b''
        while True:
            data += s.recv(1024)
            if data.endswith(b']'):
                break
                
        response = json.loads(data.decode('utf-8'))
        #print(f"Received: {response}")
    return response

# Dump du firmware
f = open("dump.bin", "wb")
for i in range(256):
	print(i)
	jedec = exchange([0x03,i,0,0], 65536)
	for i in jedec:
		f.write(p8(i))
f.close()
```

- **`p8(i)`** : Convertit l'entier `i` en un octet unique.
- **`f.write(p8(i))`** : Écrit cet octet dans le fichier binaire.

Une fois la fin du script, nous avons un firmware correcte 
```bash
┌──(plm㉿oppida)-[~/home/CTF/say_cheese]
└─$ file dump.bin 
dump.bin: u-boot legacy uImage, jz_fw, Linux/MIPS, Firmware Image (Not compressed), 11075584 bytes, Wed May 15 11:48:58 2024, Load Address: 00000000, Entry Point: 00000000, Header CRC: 0X562C89CA, Data CRC: 0XE89A0BAD
```

Exécution de la commande binwalk sur le système afin d'extraire la data :
```bash
┌──(plm㉿oppida)-[~/home/CTF/say_cheese]
└─$ binwalk -e dump.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes, header CRC: 0x562C89CA, created: 2024-05-15 11:48:58, image size: 11075584 bytes, Data Address: 0x0, Entry Point: 0x0, data CRC: 0xE89A0BAD, OS: Linux, CPU: MIPS, image type: Firmware Image, compression type: none, image name: "jz_fw"
64            0x40            uImage header, header size: 64 bytes, header CRC: 0x6F5948F4, created: 2020-05-26 05:03:55, image size: 1907357 bytes, Data Address: 0x80010000, Entry Point: 0x80421870, data CRC: 0xD8FCDDFA, OS: Linux, CPU: MIPS, image type: OS Kernel Image, compression type: lzma, image name: "Linux-3.10.14"
128           0x80            LZMA compressed data, properties: 0x5D, dictionary size: 33554432 bytes, uncompressed size: -1 bytes
2097216       0x200040        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 3289996 bytes, 414 inodes, blocksize: 131072 bytes, created: 2024-05-15 11:42:45
5570624       0x550040        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 593566 bytes, 13 inodes, blocksize: 131072 bytes, created: 2020-08-20 09:14:54
6225984       0x5F0040        JFFS2 filesystem, little endian
6230340       0x5F1144        Zlib compressed data, compressed
6258764       0x5F804C        JFFS2 filesystem, little endian
6625136       0x651770        JFFS2 filesystem, little endian
6626980       0x651EA4        JFFS2 filesystem, little endian
[...]
```


```bash
┌──(plm㉿oppida)-[~/home/CTF/say_cheese/_dump.bin.extracted/]
└─$ ls -la
total 3277396
drwxr-xr-x  4 plm plm    24576 May 22 11:00 .
drwxr-xr-x  3 plm plm     4096 May 22 11:00 ..
-rw-r--r--  1 plm plm  3289996 May 22 11:00 200040.squashfs
-rw-r--r--  1 plm plm   593566 May 22 11:00 550040.squashfs
-rw-r--r--  1 plm plm 10551232 May 22 11:00 5F0040.jffs2
-rw-r--r--  1 plm plm    47012 May 22 11:00 5F1144
-rw-r--r--  1 plm plm 10546876 May 22 11:00 5F1144.zlib
-rw-r--r--  1 plm plm 10518452 May 22 11:00 5F804C.jffs2
-rw-r--r--  1 plm plm 10152080 May 22 11:00 651770.jffs2
-rw-r--r--  1 plm plm     2762 May 22 11:00 A86BF8
-rw-r--r--  1 plm plm  5739528 May 22 11:00 A86BF8.zlib
-rw-r--r--  1 plm plm  5737608 May 22 11:00 A87378.jffs2
-rw-r--r--  1 plm plm      435 May 22 11:00 A87EDC
-rw-r--r--  1 plm plm  5734692 May 22 11:00 A87EDC.zlib
-rw-r--r--  1 plm plm  5734324 May 22 11:00 A8804C.jffs2
drwxrwxrwx 25 plm plm     4096 Apr 20  2020 squashfs-root
drwxrwxrwx  2 plm plm     4096 Aug 20  2020 squashfs-root-0
```
Affichage du flag dans le ```etc/init.d/rcS``` : 
```bash
┌──(plm㉿oppida)-[~/home/CTF/say_cheese/_dump.bin.extracted/squashfs-root]
└─$ cat etc/init.d/rcS | grep HTB
# HTB{SPI_t0_b4ckd00r1ng_4_cam3r4_ismart12}
```

Il y a également une ligne au dessus du flag une vidéo Youtube très interessante sur le backdoring de caméra IP :  
```bash
┌──(plm㉿oppida)-[~/home/CTF/say_cheese/_dump.bin.extracted/squashfs-root]
└─$ cat etc/init.d/rcS | grep HTB -B 1
# https://www.youtube.com/watch?v=hV8W4o-Mu2o
# HTB{SPI_t0_b4ckd00r1ng_4_cam3r4_ismart12}
```
