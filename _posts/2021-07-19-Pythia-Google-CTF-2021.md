---
layout: post
author: FPI
title: "Pythia - Google CTF 2021"
date: 2021-07-19
categories: [CTF, Crypto]
background_image: assets/aes-encryption.jpg
title_color: "#ffffff"
---


Nous avons accès à un oracle de déchiffrement, mais l'algorithme utilisé est AES-GCM. L'oracle indique si le message est valide ou non. Les requêtes sont très limitées donc nous pouvons utiliser un oracle de partitionnement pour réduire le nombre de requêtes et récupérer les clés.

## Détails

- Catégorie : crypto
- Points : 173
- Résolutions : 65

### Description

"Yet another oracle, but the queries are costly and limited so be frugal with them."

`nc pythia.2021.ctfcompetition.com 1337`

Code source :

```python
#!/usr/bin/python -u
import random
import string
import time

from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

max_queries = 150
query_delay = 10

passwords = [bytes(''.join(random.choice(string.ascii_lowercase) for _ in range(3)), 'UTF-8') for _ in range(3)]
flag = open("flag.txt", "rb").read()

def menu():
    print("What you wanna do?")
    print("1- Set key")
    print("2- Read flag")
    print("3- Decrypt text")
    print("4- Exit")
    try:
        return int(input(">>> "))
    except:
        return -1

print("Welcome!\n")

key_used = 0

for query in range(max_queries):
    option = menu()

    if option == 1:
        print("Which key you want to use [0-2]?")
        try:
            i = int(input(">>> "))
        except:
            i = -1
        if i >= 0 and i <= 2:
          key_used = i
        else:
          print("Please select a valid key.")
    elif option == 2:
        print("Password?")
        passwd = bytes(input(">>> "), 'UTF-8')

        print("Checking...")
        # Prevent bruteforce attacks...
        time.sleep(query_delay)
        if passwd == (passwords[0] + passwords[1] + passwords[2]):
            print("ACCESS GRANTED: " + flag.decode('UTF-8'))
        else:
            print("ACCESS DENIED!")
    elif option == 3:
        print("Send your ciphertext ")

        ct = input(">>> ")
        print("Decrypting...")
        # Prevent bruteforce attacks...
        time.sleep(query_delay)
        try:
            nonce, ciphertext = ct.split(",")
            nonce = b64decode(nonce)
            ciphertext = b64decode(ciphertext)
        except:
            print("ERROR: Ciphertext has invalid format. Must be of the form \"nonce,ciphertext\", where nonce and ciphertext are base64 strings.")
            continue

        kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1, backend=default_backend())
        key = kdf.derive(passwords[key_used])
        try:
            cipher = AESGCM(key)
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
        except:
            print("ERROR: Decryption failed. Key was not correct.")
            continue

        print("Decryption successful")
    elif option == 4:
        print("Bye!")
        break
    else:
        print("Invalid option!")
    print("You have " + str(max_queries - query) + " trials left...\n")
```

## Méthodologie

### Comprendre le problème

Le serveur génère 3 mots de passe composés de 3 lettres minuscules et en dérive 3 clés.

Nous pouvons soumettre des messages chiffrés en AES-GCM et le serveur vérifiera si le déchiffrement a réussi ou non. Nous pouvons également spécifier laquelle des 3 clés le serveur doit utiliser lors du déchiffrement.

Pour obtenir le flag, nous devons récupérer les 3 mots de passe. Pour éviter les attaques par force brute, nous n'avons qu'un total de 150 requêtes et chacune d'entre elles met 10 secondes pour répondre.


### Résoudre le problème

Le serveur agit clairement comme un oracle de déchiffrement, mais contrairement au mode CBC, il ne vérifie pas que le padding est valide (parce qu'il n'y en a pas), mais plutôt que le tag du mode GCM est valide. Ce type d'oracles sont appelés oracles de partitionnement. Ils ne sont pas limités à AES-GCM et peuvent affecter d'autres schémas de chiffrement authentifiés (AEAD). L'attaque est présentée dans [ce document](https://eprint.iacr.org/2020/1491.pdf). En particulier, le chapitre 3.1 décrit une façon de construire un texte chiffré avec un tag et un nonce donnés, qui sera valide pour un ensemble de clés différentes. Ils appellent cela une attaque par collision multiples de clés et fournissent même [une implémentation opensource](https://github.com/julialen/key_multicollision/blob/main/collide_gcm.sage).


Dans notre cas, il n'y a que 26^3 mots de passe possibles, donc notre espace de clé est plutôt restreint. Nous pourrions utiliser l'attaque par collision multiples pour forger un texte chiffré valide pour la moitié des clés et interroger l'oracle. Si l'oracle dit que le déchiffrement est valide, nous pouvons en déduire que la vraie clé doit être l'une de celles que nous avons utilisées pour forger notre texte chiffré. Nous pouvons alors diviser à nouveau par deux l'espace de recherche et récupérer la vraie clé en utilisant un simple algorithme de recherche binaire. Cette opération devrait être effectuée trois fois, pour récupérer les trois clés et, à partir de celles-ci, récupérer les mots de passe.


On peut s'attendre à ce que notre recherche binaire récupère complètement une seule clé en environ log2(26^3) = 14 étapes, ce qui fait que l'attaque globale prend moins de 50 requêtes. Cependant, nous aurions besoin de calculer un texte chiffré qui est valide sous 26^3/2 = 8788 clés, ce qui prendrait beaucoup trop de temps. La complexité temporelle de la recherche d'un tel texte chiffré est d'environ O(k^2), k étant la taille de l'espace des clés.

A la place, nous pouvons diviser la recherche par blocs de 500 clés, ce qui nécessitera plus de requêtes mais prendra moins de temps pour forger des textes chiffrés valides.

Nous devrons chercher dans 36 blocs au maximum. Si nous trouvons que la clé se trouve dans un bloc, nous pouvons alors utiliser la recherche binaire pour la récupérer, ajoutant 9 requêtes supplémentaires. De cette façon, nous pouvons récupérer une seule clé en 45 requêtes au maximum, ce qui rend l'attaque complète possible en moins de 150 requêtes.


### Implémentation de la solution

#### Construction du jeu de clé

```python
import pickle
import itertools
import string
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# build all keys and pickle them for next time
try:
    keys = pickle.load(open("keys.pickle", "rb"))
    except FileNotFoundError:
        keys = {}
        for t in itertools.product(string.ascii_lowercase, repeat=3):
            pwd = "".join(t).encode()
            print(pwd)
            kdf = Scrypt(salt=b'', length=16, n=2 ** 4, r=8, p=1, backend=default_backend())
            keys[kdf.derive(pwd)] = pwd
            pickle.dump(keys, open("keys.pickle", "wb"))
```

Nous pouvons créer un dictionnaire stockant toutes les clés possibles et leur mot de passe associé. Cela facilitera le processus de récupération du mot de passe, car nous n'aurons qu'à chercher une entrée dans le dictionnaire. Pickle est utilisé pour stocker le résultat, ainsi nous n'avons pas à tout recalculer si nous relançons le script (ce qui arrive souvent pendant les tests).

#### Implémentation de l'attaque par collisions multiples

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from bitstring import BitArray
import functools

P = PolynomialRing(GF(2), "x")
x = P.gen()
p = x ** 128 + x ** 7 + x ** 2 + x + 1
GH = GF(2 ** 128, "a", modulus=p)

def bytes_to_GH(data):
    """Simply convert bytes to field elements"""
    return GH([int(v) for v in BitArray(data).bin])

def GH_to_bytes(element):
    """Simply convert field elements to bytes"""
    return BitArray(element.polynomial().list()).tobytes().ljust(16, b'\x00')

def multi_collide_gcm(keyset, nonce, tag):
    R = PolynomialRing(GH, "r")
    L = bytes_to_GH(long_to_bytes(128 * len(keyset), 16))
    N = nonce + b'\x00\x00\x00\x01'
    T = bytes_to_GH(tag)
    interpolation_pts = []
    for key in keyset:
        H = bytes_to_GH(AES.new(key, AES.MODE_ECB).encrypt(b'\x00' * 16))
        B = ((L * H) + bytes_to_GH(AES.new(key, AES.MODE_ECB).encrypt(N)) + T) * H**-2
        interpolation_pts.append((H, B))
    sol = R.lagrange_polynomial(interpolation_pts)
    C_blocks = [GH_to_bytes(c) for c in sol.list()[::-1]]
    return b''.join(C_blocks) + tag

# cache the results for speedup, could have precomputed them but it's not that slow
@functools.lru_cache(maxsize=None)
def forge(start, end):
    keyset = list(keys.keys())[start:end]
    r = multi_collide_gcm(keyset, b'\x00'*12, b'\x01'*16)
    return r
```

Cette implémentation est une réécriture de [l'implémentation opensource](https://github.com/julialen/key_multicollision/blob/main/collide_gcm.sage) fournie dans l'article. Nous utilisons la mémoïsation pour accélérer le calcul des textes chiffrés forgés lorsque l'un d'entre eux a déjà été forgé pour les mêmes clés.

Nous pouvons maintenant diviser notre espace de clé en blocs et utiliser la recherche binaire pour récupérer la clé par la suite.


#### Script complet

```python
import pickle
import itertools
import string
import base64
from sage.all import *
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from pwn import *
import functools
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from bitstring import BitArray

def bytes_to_GH(data):
    """Simply convert bytes to field elements"""
    return GH([int(v) for v in BitArray(data).bin])

def GH_to_bytes(element):
    """Simply convert field elements to bytes"""
    return BitArray(element.polynomial().list()).tobytes().ljust(16, b'\x00')

def multi_collide_gcm(keyset, nonce, tag):
    R = PolynomialRing(GH, "r")
    L = bytes_to_GH(long_to_bytes(128 * len(keyset), 16))
    N = nonce + b'\x00\x00\x00\x01'
    T = bytes_to_GH(tag)
    interpolation_pts = []
    for key in keyset:
        H = bytes_to_GH(AES.new(key, AES.MODE_ECB).encrypt(b'\x00' * 16))
        B = ((L * H) + bytes_to_GH(AES.new(key, AES.MODE_ECB).encrypt(N)) + T) * H**-2
        interpolation_pts.append((H, B))
    sol = R.lagrange_polynomial(interpolation_pts)
    C_blocks = [GH_to_bytes(c) for c in sol.list()[::-1]]
    return b''.join(C_blocks) + tag

# cache the results for speedup, could have precomputed them but it's not that slow
@functools.lru_cache(maxsize=None)
def forge(start, end):
    keyset = list(keys.keys())[start:end]
    r = multi_collide_gcm(keyset, b'\x00'*12, b'\x01'*16)
    return r

def setKey(i):
    conn.sendline(b"1")
    conn.recvuntil(b">>> ")
    conn.sendline(f"{i}".encode())
    conn.recvuntil(b">>> ")

def decrypt(c):
    conn.sendline(b"3")
    conn.recvuntil(b">>> ")
    t = f"{nonce.decode()},{base64.b64encode(c).decode()}"
    conn.sendline(t.encode())
    conn.recvline()
    r = conn.recvline()
    conn.recvuntil(b">>> ")
    if b"Decryption failed." in r:
        return False
    return True

def bsearch(start, end):
    global tries
    mid = (end + start)//2
    if end - start == 1:
        return start
    tries -= 1
    print(f"tries left : {tries}")
    if decrypt(forge(start, mid)):
        return bsearch(start, mid)
    else:
        return bsearch(mid, end)

    
if __name__ == "__main__":
    # build all keys and pickle them for next time
    try:
        keys = pickle.load(open("keys.pickle", "rb"))
    except FileNotFoundError:
        keys = {}
        for t in itertools.product(string.ascii_lowercase, repeat=3):
            pwd = "".join(t).encode()
            print(pwd)
            kdf = Scrypt(salt=b'', length=16, n=2 ** 4, r=8, p=1, backend=default_backend())
            keys[kdf.derive(pwd)] = pwd
        pickle.dump(keys, open("keys.pickle", "wb"))

    # global variables
    P = PolynomialRing(GF(2), "x")
    x = P.gen()
    p = x ** 128 + x ** 7 + x ** 2 + x + 1
    GH = GF(2 ** 128, "a", modulus=p)

    tries = 150
    N = 26**3
    B = 500
    nonce = base64.b64encode(b'\x00' * 12)

    # recover the passwords and get the flag
    conn = remote("pythia.2021.ctfcompetition.com", 1337)
    # local testing
    # conn = process("./pythia.py")
    conn.recvuntil(b">>> ")

    password = b''
    # 3 passwords in total
    for j in range(3):
        # search in chunks
        for i in range(0, N, B):
            # if key is in this chunk
            if decrypt(forge(i, i + B)):
                print("Entering binary search...")
                index = bsearch(i, i+B)
                pwd = keys[list(keys.keys())[index]]
                password += pwd
                print(f"Found password : {pwd}")
                break
            tries -= 1
            print(f"tries left : {tries}")
        if j < 2:
            setKey(j+1)
            tries -= 1
            print(f"tries left : {tries}")
    print(f"full password = {password.decode()}")
    conn.sendline(b"2")
    conn.recvuntil(b">>> ")
    conn.sendline(password)
    conn.recvuntil(b"ACCESS GRANTED: ")
    print(f"Flag : {conn.recvline().decode()}")
    conn.close()
```

L'exécution de celui-ci produit la sortie suivante :

```
[x] Opening connection to pythia.2021.ctfcompetition.com on port 1337
[x] Opening connection to pythia.2021.ctfcompetition.com on port 1337: Trying 34.77.25.116
[+] Opening connection to pythia.2021.ctfcompetition.com on port 1337: Done
tries left : 149
tries left : 148
tries left : 147
tries left : 146
tries left : 145
tries left : 144
tries left : 143
tries left : 142
tries left : 141
tries left : 140
tries left : 139
tries left : 138
tries left : 137
tries left : 136
tries left : 135
tries left : 134
tries left : 133
tries left : 132
tries left : 131
tries left : 130
tries left : 129
tries left : 128
tries left : 127
tries left : 126
tries left : 125
tries left : 124
tries left : 123
tries left : 122
tries left : 121
tries left : 120
tries left : 119
tries left : 118
Entering binary search...
tries left : 117
tries left : 116
tries left : 115
tries left : 114
tries left : 113
tries left : 112
tries left : 111
tries left : 110
tries left : 109
Found password : b'xvw'
tries left : 108
tries left : 107
tries left : 106
tries left : 105
tries left : 104
tries left : 103
tries left : 102
tries left : 101
tries left : 100
tries left : 99
tries left : 98
tries left : 97
tries left : 96
tries left : 95
tries left : 94
tries left : 93
tries left : 92
tries left : 91
tries left : 90
tries left : 89
tries left : 88
tries left : 87
tries left : 86
tries left : 85
tries left : 84
tries left : 83
tries left : 82
tries left : 81
tries left : 80
tries left : 79
tries left : 78
Entering binary search...
tries left : 77
tries left : 76
tries left : 75
tries left : 74
tries left : 73
tries left : 72
tries left : 71
tries left : 70
tries left : 69
Found password : b'woc'
tries left : 68
tries left : 67
tries left : 66
tries left : 65
tries left : 64
tries left : 63
tries left : 62
tries left : 61
tries left : 60
tries left : 59
Entering binary search...
tries left : 58
tries left : 57
tries left : 56
tries left : 55
tries left : 54
tries left : 53
tries left : 52
tries left : 51
tries left : 50
Found password : b'hcj'
full password = xvwwochcj
Flag : CTF{gCm_1s_n0t_v3ry_r0bust_4nd_1_sh0uld_us3_s0m3th1ng_els3_h3r3}

[*] Closed connection to pythia.2021.ctfcompetition.com port 1337
```

Flag : **CTF{gCm_1s_n0t_v3ry_r0bust_4nd_1_sh0uld_us3_s0m3th1ng_els3_h3r3}**
