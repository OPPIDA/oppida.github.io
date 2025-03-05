---
title: Désobfuscation de VM, une méthode générale
date: 2025-03-04
categories: [Articles, Reverse]
tags: []
comments: false
description: Mise en oeuvre de désobfuscation de VM, en empruntant le chemin dur et long (mais général).
author: [SBA]
math: false
image:
  path: /assets/posts/2025-03-04-Desobfuscation-VM/splash.jpg
---

Quelle aproche un reverseur doit-il adopter face à un code obfusqué par la technique de la machine virtuelle (VM) ? Cette méthode d'obfuscation est parmi les plus avancées, et les plus difficiles à défaire, du moment. Ainsi, ce qui est généralement recommandé est autant que possible de refuser l'obstacle et de ne pas tenter de désobfusquer : vous éviterez de perdre des jours qui deviennent des semaines. Vous n'aurez alors plus à votre disposition que les méthodes d'analyse comportementales dont on espère qu'elles vous donneront les informations dont vous avez besoin. 

Vous êtes encore là ? Nous en déduisons qu'une simple analyse comportementale n'a pas suffi à donner réponse à vos questions, et que vous êtes déterminés à en faire une analyse approfondie. 

Comment donc se lancer dans une analyse de VM approfondie ? L'objectif final consiste à revenir au problème du reverse engineering habituel, c'est à dire à ce doter des outils usuels de reverse engineering : 
- un désassembleur (pour lire le code)
- un assembleur (pour le modifier)
- un débugger (pour l'analyse dynamique). 

Une fois le temps investi pour créer ces outils, l'analyse revient à faire ce dont on a l'habiture en reverse engineering, simplement sur une architecture nouvelle.

Voici une méthodologie globale :
- 1) Analyser statiquement la VM, [Tim Blazytko fournit un exemple de cette étape dans cette vidéo](https://www.youtube.com/watch?v=b6udPT79itk), notamment : 
  - identifier la boucle Fetch-Decode-Execute
  - décrire la représentation des registres, stack, pointeurs d'instructions virtuels, etc. 
  - énumérer les méthodes de *hardening* de VM appliquées (plus de détails à la fin de l'article)
  - expliciter le jeu d'instructions (intruction set) implémenté par la VM, en particulier : 
    - identifier les OPcodes correspondant à chaque instruction
    - reverser chaque handler d'instruction
- 2) **écrire un assembleur et un désassembleur**
- 3) **écrire un émulateur, et y incorporer des éléments de débugger**

Dans cet article, nous détaillerons **les deux dernières étapes**, en partant de l'exemple d'une obfuscation par VM simple conçue pour un challenge du stand Oppida à l'ECW.

## Le cas d'étude : Challenge d'Oppida sur le stand de l'European Cyber Week.
A titre d'**exemple d'implémentation des outils d'analyse**, nous mettons en oeuvre la méthodologie décrite par l'article sur un challenge créé par Oppida. C'est un logiciel obfusqué par VM compilé pour une architecture ARM. Si vous voulez tenter de résoudre le challenge, vous pouvez télécharger le binaire ici : [LIEN CHALLENGE OPPIDA ECW]({{ site.url }}/assets/posts/2025-03-04-Desobfuscation-VM/challenge-oppida). Ce binaire est conçu pour s'exécuter sur une RaspberryPi branchée sur une installation physique : considérez simplement que le challenge est résolu si la fonction main renvoie 0.

Nous allons passer très rapidement sur l'étape 1) d'analyse initiale . Il s'agit de faire une analyse statique (puisque c'est la seule technique à notre disposition à cette étape) du fonctionnement interne de la VM.

### Analyse initiale : identification des éléments de la VM et rétroconception des handlers
On identifie la fonction qui implémente la boucle *Fetch-Decode-Execute* (FDE) de la VM :
![FDE_loop](assets/posts/2025-03-04-Desobfuscation-VM/FDE_loop.PNG)
- Le *Decode* est implémenté en tant que switch-case sur la valeur pointée par `r3`, avec l'offset contenu en  @[0x13228]. `r3`contient donc l'adresse du bytecode et @[0x13228] le pointeur d'instruction virtuel !
![switch_case](assets/posts/2025-03-04-Desobfuscation-VM/switch_case.PNG)
    
On identifie de la même manière les autres éléments de la VM (stack virtuelle, stack pointer virtuel, registres virtuels, etc.)
- Chaque handler d'instruction est contenu dans une fonction séparée, qui est appelée par la boucle FDE.
  
Après avoir reversé chaque handler, nous avons tous les éléments permettant de passer aux étapes d'implémentation des outils d'analyse.


## Création de l'assembleur et désassembleur
### analyse détaillée du jeu d'instructions
La première étape pour écrire un assembleur et désassembleur est d'avoir une connaissance aussi fine et complète possible du jeu d'instructions. 
Les informations minimales à obtennir lors du reverse des handlers sont l'OPcode, la sémantique (même approximative), et les arguments (leur taille, type et rôle) de chaque instruction. Nous avons représenté ces informations dans un dictionnaire python : 

```python
opcodes = {
    "call":{"op":0x0,"args":["line_nbr"]},
    "jump":{"op":0x2,"args":["line_nbr"]},
    "mov_reg_reg":{"op":0x3,"args":["reg", "reg"]},
    "mov_reg_imm":{"op":0x9,"args":["reg", "dword"]},
    "push":{"op":0xa,"args":["reg"]},
    "pop":{"op":0xc,"args":["reg"]},
    "ret":{"op":0xd,"args":[]},
    "operation":{"op":0x19,"args":["operation", "reg", "reg"]},
    "cmp_reg_reg":{"op":0x1c,"args":["reg","reg"]},
    "random":{"op":0x1e,"args":[]},
    "break":{"op":0x3d,"args":[]},
    "je":{"op":0x3e,"args":["line_nbr"]},
    "check_result":{"op":0xff-0x21, "args":[]}
}

operations = {
    "or":0x7c,
    "xor":0x5e,
    "shr":0x3e,
    "shl":0x3c,
    "and":0x26
}

registers = {"r0":0, "r1":1, "r2":2, "r3":3, "r4":4, "r5":5, "r6":6, "r7":7}
```
*Code 1*

Comme toutes les architectures de VMs servant à l'obfuscation, celle-ci présente des aspects étranges. On peut noter : 
- l'absence d'instructions permettant des opérations algébriques (+, -, *)
- l'utilisation d'une seule instruction pour toutes les opérations logiques (l'opération est précisée en argument)
- l'utilisation à la fois de registres et d'une stack

Il est aussi utile de créer les distionaires inverses (où la clé n'est pas le nom (ou mnémonique) de l'instruction mais son opcode).

```python
dis_opcodes = {}
for mnemonic in opcodes.keys():
    dis_opcodes[opcodes[mnemonic]["op"]] = {"mnemonic":mnemonic, "args":opcodes[mnemonic]["args"]}

dis_operations = {}
for operation_name in operations.keys():
    dis_operations[operations[operation_name]] = operation_name

dis_registers = {}
for register_name in registers.keys():
    dis_registers[registers[register_name]] = register_name
```
*Code 2*

### Désassembleur
L'élément le plus essentiel à construire est le désassembleur. Il s'agit de parcourir le bytecode en identifiant chaque instruction et ses arguments

```python
def disassemble(bytecode):
    cursor = 0
    code_lines = []
    while cursor < len(bytecode):
        # lecture de l'instruction depuis l'OPcode
        op = arch.dis_opcodes[int.from_bytes(bytecode[cursor:cursor+1], arch.endianness)]
        code_lines.append({"offset":cursor, "op": op["mnemonic"], "args":[]})
        cursor += 1
        
        # lecture des arguments, selon leur type
        for arg_type in op["args"]:
            if arg_type == "reg":
                reg_code = int.from_bytes(bytecode[cursor:cursor+1], arch.endianness)
                code_lines[-1]["args"].append({"type":"reg", "value":arch.dis_registers[reg_code]})
                cursor += 1
            elif arg_type == "dword":
                imm_value = int.from_bytes(bytecode[cursor:cursor+4], arch.endianness)
                code_lines[-1]["args"].append({"type":"dword", "value":hex(imm_value)})
                cursor += 4
            elif arg_type == "operation":
                operation_code = int.from_bytes(bytecode[cursor:cursor+1], arch.endianness)
                code_lines[-1]["args"].append({"type":"operation", "value":arch.dis_operations[operation_code]})
                cursor += 1
            elif arg_type == "line_nbr":
                jump_addr = int.from_bytes(bytecode[cursor:cursor+4], arch.endianness)
                code_lines[-1]["args"].append({"type":"line_nbr", "value":jump_addr})
                cursor += 4
    
    return(code_lines)
```
*Code 3*

En appliquant ce désassembleur à un bytecode conçu pour cette VM (et qui est le programme que l'on cherche à analyser !), on obtient un bytecode désassemblé : 
```
line offset instruction
  0    0    random
  1    1    mov_reg_reg r1 r0
  2    4    mov_reg_reg r2 r0
  3    7    mov_reg_imm r3 0x10
  4    13   mov_reg_imm r4 0xffff
  5    19   operation shr r1 r3
  6    23   operation and r1 r4
  7    27   operation and r2 r4
  8    31   call 70
  9    36   mov_reg_reg r5 r0
  10   39   call 175

  [...]

  80   288  cmp_reg_reg r3 r1
  81   291  je 301
  82   296  jump 209
  83   301  pop r5
  84   303  pop r4
  85   305  pop r3
  86   307  pop r2
  87   309  pop r1
  88   311  ret
```
*Résultat 1*

Le désassemblé est satisfaisant... à l'exception des instructions `jump` et `call` qui prennent comme arguments des offsets dans le code : il serait mieux d'avoir des labels afin de bien visualiser les destinations. Pour cela, on ajoute une simple fonction qui résoud les adresses de destination des `jump` et `call`, et on insère les labels qui vont bien.

```python
def resolve_jump_lines(disassembly):
    labels = []
    for line in disassembly:
        for arg in line["args"]:
            if arg["type"] == "line_nbr" and "label_resolved" not in arg:
                # pour les lignes qui font référence à une autre adresse dans le code
                for line_number, target_line in enumerate(disassembly):
                    # on trouve la ligne référée
                    if target_line["offset"] ==  arg["value"]:
                        label = "lab_" + str(line_number)

                        # ajout de l'indicateur de label
                        if (label, line_number) not in labels:
                            labels.append((label, line_number))
                        
                        # modification de l'instruction jump ou call
                        arg["label_resolved"] = True
                        arg["value"] = "@"+label
                        break
    for label, line_number in labels :
        disassembly.insert(line_number-1, {"label":label, "offset": None, "args":[]})
                    
def pretty_print(disassembly):
    print("line offset instruction")
    for line_number, line in enumerate(disassembly):
        if "label" in line:
            print("\n", end='')
            print(f'lab {line["label"]}')
        else: 
            print(f'  {line_number}    {line["offset"]}    {line["op"]} ', end='')
            for arg in line["args"]:
                print(arg["value"] + " ", end='')
            print("\n", end='')
```
*Code 4*

Cela permet d'avoir un désassemblé plus agréable à lire : 

```
line offset instruction

[...]
  7    27    operation and r2 r4
  8    31    call @lab_19
  9    36    mov_reg_reg r5 r0
  10   39    call @lab_50
  11   44    mov_reg_reg r6 r0
  12   47    mov_reg_reg r1 r6
  13   50    call @lab_41
  14   55    mov_reg_reg r7 r0
  15   58    mov_reg_reg r1 r5
  16   61    mov_reg_reg r2 r7
  17   64    call @lab_19

lab lab_19
  19   69    check_result
  20   70    push r1
  21   72    push r2
  22   74    push r3 
  23   76    push r4

lab lab_25
  25   78    mov_reg_imm r4 0x0
  26   84    mov_reg_imm r0 0x0

[...]

  34   120   cmp_reg_reg r2 r3

lab lab_35
  36   123   je @lab_35
  37   128   jump @lab_25
  38   133   mov_reg_reg r0 r1
  39   136   pop r4
  40   138   pop r3
  41   140   pop r2

[...]
```
*Résultat 2*

Une autre possibilité est d'implémenter un [Processor IDA Pro](https://hex-rays.com/blog/scriptable-processor-modules/) pour intégrer la nouvelle architecture à l'outil. La tâche est compliquée mais [quelques](https://blog.quarkslab.com/ida-processor-module.html) [blogposts](https://wuffs.org/blog/mouse-adventures-part-7) ont débroussaillé le travail. Cela permet de profiter de tous les avantages qu'offre IDA, et en premier lieu, l'affichage en graphe des blocs du désassemblé.

### Assembleur
Créer un assembleur pourrait *a priori* sembler superflu, puisque l'objectif du reverseur est la lecture du code et non son écriture. Toutefois, on se rend vite compte qu'avoir la possibilité de modifier un code est primordiale pour l'analyse, en particulier lorsque des mécanismes de défense contre l'analyse dynamique ou comportementale sont présents. Réécrire le code permet alors de les contourner.

L'assembleur implémente le mécanisme opposé au désassembleur : 
- on commence par enlever les commentaires, lignes vides, etc.
- on enlève les labels et on les remplace par des numéros de ligne
- on assemble chaque ligne de code
- on résoud les adresses des jumps

```python
def assemble(assembly):
    """Prend un code assembleur, retourne le binaire assemblé."""
    commented_lines = assembly.split("\n")
    
    labeled_lines = remove_comments(commented_lines)
    lines = resolve_labels(labeled_lines) # remplacement des labels par le numéro de ligne correspondant
    
    # après cette étape, toutes les lignes de code restantes sont à compiler
    binary_lines = []
    for number, line in enumerate(lines):
        tokens = [t for t in line.split(" ") if t != '']
        
        opcode = arch.opcodes[tokens[0]]
        bin_line += (opcode["op"] + 0x21).to_bytes(1, arch.endianness)
        
        if len(tokens) -1 != len(opcode["args"]):
            print(f"ERROR at line {number} : \n{line} , incorrect arguments")
            exit()
        
        for arg_type, arg in zip(opcode["args"], tokens[1:]):
            if arg_type == "reg":
                bin_line += arch.registers[arg].to_bytes(1,arch.endianness)
            if arg_type == "dword":
                bin_line += int(arg, 0).to_bytes(4, arch.endianness)
            if arg_type == "line_nbr":
                bin_line = (bin_line, arg) # l'offset correspondant à la ligne sera calculé plus tard
            if arg_type == "operation":
                bin_line += arch.operations[arg].to_bytes(1, arch.endianness)
                
        binary_lines.append(bin_line)

    # calcul des offsets pour les jumps et calls
    binary_with_offsets = []
    for line in binary_lines:
        if type(line) == tuple:
            # Si un argument est un tuple, c'est une adresse de jump à calculer
            tokens = list(line)
            jump_dest_line_number = int(tokens[1])
            tokens[1] = resolve_addr(jump_dest_line_number, binary_lines).to_bytes(4, arch.endianness)
            binary_with_offsets.append(b''.join(tokens))
        else:
            # Sinon, on garde la ligne sans modification.
            binary_with_offsets.append(line)

    # concaténation du binaire
    raw = b''.join(binary_with_offsets)
    return(raw)
```
*Code 5*

Comme pour le désassembleur, il faut gérer les labels : 

```python
def resolve_labels(lines):
    """Transforme les labels en numéros de lignes (syntaxe = @lab) en numéros de ligne"""
    labels = {}
    no_label_lines = []
    for line, number in zip(lines, range(len(lines))):
        tokens = [t for t in line.split(" ") if t != '']
        if tokens[0] == "lab":
            labels[tokens[1]] = str(number - len(labels)) # Un label occupe une ligne, donc il faut décaler
        else : 
            no_label_lines.append(line)

    for line, number in zip(no_label_lines, range(len(no_label_lines))):
        tokens = [t for t in line.split(" ") if t != '']
        if len(tokens)>1 and "@" in tokens[1]: # hypothèse : seul le premier argument peut être un label
            tokens[1] = labels[tokens[1].replace('@', '')] # récupère le numéro de ligne correspondant
            no_label_lines[number] = ' '.join(tokens) # modifie la ligne

    return(no_label_lines)


def resolve_addr(line_nbr, binary):
    """Prend une liste de lignes binaires et numéro de ligne, renvoie l'offset du numéro de la ligne dans le binaire final."""
    addr = 0
    for i in range(line_nbr):
        addr += len(binary[i]) # l'offset est la somme des tailles des instructions précédentes
    return(addr)
```
*Code 6*

Pour un code assembleur dont voici un extrait :
```
# objective : calculate (h + l) - (h * l)

lab main
    random
    #r1 is high
    mov_reg_reg r1 r0
    #r2 is low
    mov_reg_reg r2 r0
    mov_reg_imm r3 0x10
    mov_reg_imm r4 0xffff
    # create high
    operation shr r1 r3
    operation and r1 r4
    # create low
    operation and r2 r4

    call @plus
    mov_reg_reg r5 r0

    call @multiply
    mov_reg_reg r6 r0

    mov_reg_reg r1 r6
    call @minus 
    mov_reg_reg r7 r0

    mov_reg_reg r1 r5
    mov_reg_reg r2 r7
    call @plus

    check_result
```
*Résultat 3*

On obtient un binaire, que l'on peut désassembler pour vérifier (cf *Résultat 2*)

## Environnement d'exécution
A ce stade, nous disposons des outils nécessaires à l'analyse statique et comportementale du code obfusqué, mais manque à notre arsenal l'analyse dynamique, méthode incontournable !

Pour qu'un outil permette l'analyse dynamique, le minimum syndical est qu'il dispose des fonctionnalités suivantes :
- capture des traces d'exécution
- lecture / écriture de la mémoire et des registres
- mise en place de breakpoints

La VM étant elle-même compilée pour une architecture ARM, nous allons émuler son exécution grâce à MIASM. La fonctionnalité *Sandbox* de MIASM permet d'éviter d'écrire une majorité du code *boilerplate*. La sandbox MIASM récupère les arguments passés au programme python : il faut le lancer avec `python environnement_exec.py -a $adresse_initiale binaire` où :
- `environnement_exec.py` est le programme python qui suit
- `$adresse_initiale` a pour valeur le point d'entrée désiré (pour nous le début de la fonction implémentant la VM)
- `binaire` est le binaire obfusqué.

```python
from pdb import pm
from miasm.analysis.sandbox import Sandbox_Linux_arml
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, EXCEPT_SYSCALL
from miasm.core.utils import decode_hex

from arch import opcodes

# Parse arguments
parser = Sandbox_Linux_arml.parser(description="""Sandbox an elf binary with arm
 engine (ex: jit_arm.py samples/md5_arm -a A684)""")
parser.add_argument("filename", help="ELF Filename")
options = parser.parse_args()

# Create sandbox
loc_db = LocationDB()
sb = Sandbox_Linux_arml(loc_db, options.filename, options, globals())
```
*Code 7*

Il faut ensuite initialiser l'appel à la VM, en plaçant tous les éléments, et le bytecode en premier lieu, aux localisations appropriées.

```python
# lecture du bytecode à exécuter
with open("program", 'rb') as f :
    program = f.read()

# allouer une page pour le bytecode et l'y stocker
program_addr = 0x60000
sb.jitter.vm.add_memory_page(program_addr, PAGE_READ | PAGE_WRITE, program)

# R0 doit pointer vers le début du bytecode
sb.jitter.cpu.R0 = program_addr

# @[0x1322c] doit contenir la taille du bytecode : 0X400
sb.jitter.vm.set_mem(0x1322c, 0x400.to_bytes(4, "little"))
```
*Code 8*

On peut ensuite lancer l'exécution de la VM ! Un breakpoint stratégiquement placé dans la boucle *Fetch-Decode-Execute* (au moment du *Fetch*) permet de récupérer la main avant l'exécution de chaque instruction. La fonction `do_each_loop(jitter)` sera exécutée à chaque levée de ce breakpoint, donc pour chaque exécution d'une instruction de la VM.

```python
# break on start of vm loop
vm_loop_addr = 0x11ba0
sb.jitter.set_breakpoint(vm_loop_addr, do_each_loop)

sb.run()
```
*Code 9*

### Lecure / écriture de la mémoire et des registres
Grâce à l'analyse réalisée au tout début du travail de désobfuscation, nous savons comment sont représentés les différents éléments de registre et mémoire de la VM. On peut donc écrire les fonctions d'accès à ces valeurs : 
```python
# les valeurs des adresses ont été obtenues au moment de l'analyse initiale
def get_virtual_stack_pointer(jitter):
    return(jitter.vm.get_mem(0x13068, 4))

def set_virtual_stack_pointer(jitter, hex_value):
    jitter.vm.set_mem(0x13068, decode_hex(hex_value))

def get_register_value(jitter, reg_number):
    registers = jitter.vm.get_mem(0x13200, 32)
    return(registers[reg_number*4:reg_number*4+4])

def set_register_value(jitter, reg_number, hex_value):
    jitter.vm.set_mem(0x13200 + reg_number*4, decode_hex(hex_value))

# et ainsi du reste : virtual instruction pointer, virtual_eflags, virtual_stack...
```
*Code 10*

### Capture de la trace d'exécution

Il suffit d'assembler (pun intented) ce qu'on a fait jusqu'ici : à chaque boucle FDE, on imprime l'état des registres, stack, etc. On désassemble aussi l'instruction en cours.

```python
import disassembler

def do_each_loop(jitter):
    return(print_state(jitter))

def print_state(jitter):
    # print eflag
    print(f"eflag: {get_flags(jitter)}")

    # print vSP
    vSP = int.from_bytes(get_virtual_stack_pointer(jitter), 'little')
    print(f"vSP : {hex(vSP)}")

    # print registers 
    print(f"registers :")
    for i in range(8) : 
        val = get_register_value(jitter, i)
        print(f"r{i} = {val}")

    # print stack
    print(f"stack : ")
    for i in range(6):
        if i == vSP:
            print(f"vSP --> {hex(i*4)} : {get_stack(jitter, i*4)}")
        else :
            print(f"        {hex(i*4)} : {get_stack(jitter, i*4)}")
    
    print("\n", end='')
    # print vIP
    vIP = get_virtual_instruction_pointer(jitter)
    instruction_bytes = jitter.vm.get_mem(program_addr + int.from_bytes(vIP, "little"), 10)
    # désassemblage de l'instruction en cours d'exécution
    disass = disassembler.disassemble_single_line(instruction_bytes)
    print(f"vIP : {int.from_bytes(vIP, arch.endianness)} > {disass['op']} ", end='')
    for arg in disass["args"]:
        print(str(arg["value"]) + " ", end='')
    print("\n", end='')

    # on retourne True pour continuer l'exécution
    return(True)
```
*Code 11*

Le résultat est une trace d'exécution austère mais fonctionnelle :

```
vIP : 291 > je 301 
eflag: b'\x01'
vSP : 0x5
registers :
r0 = b'\x00\x00\x00\x00'
r1 = b'\x00\x00\x00\x00'
r2 = b'\x00\x00\x00\x00'
r3 = b'\x00\x00\x00\x00'
r4 = b'\xff\xff\xff\xff'
r5 = b'\x00\x00\x00\x00'
r6 = b'\x00\x00\x00\x00'
r7 = b'\x00\x00\x00\x00'
stack : 
        0x0 : b',\x00\x00\x00'
        0x4 : b'\x00\x00\x00\x00'
        0x8 : b'\x00\x00\x00\x00'
        0xc : b'\x10\x00\x00\x00'
        0x10 : b'\xff\xff\x00\x00'
vSP --> 0x14 : b''

vIP : 301 > pop r5 
eflag: b'\x01'
vSP : 0x4
registers :
r0 = b'\x00\x00\x00\x00'
r1 = b'\x00\x00\x00\x00'
r2 = b'\x00\x00\x00\x00'
r3 = b'\x00\x00\x00\x00'
r4 = b'\xff\xff\xff\xff'
r5 = b'\x00\x00\x00\x00'
r6 = b'\x00\x00\x00\x00'
r7 = b'\x00\x00\x00\x00'
stack : 
        0x0 : b',\x00\x00\x00'
        0x4 : b'\x00\x00\x00\x00'
        0x8 : b'\x00\x00\x00\x00'
        0xc : b'\x10\x00\x00\x00'
vSP --> 0x10 : b'\xff\xff\x00\x00'
        0x14 : b''
```
*Résultat 4*

### Breakpoints
Reste à implémenter les breakpoints. On pourrait créer une instruction spéciale par laquelle on remplacerait celle sur laquelle on souhaite breaker (comme c'est le cas pour l'OPcode `INT3` / `0xCC` sur x86), mais puisque nous avons à disposition un émulateur, on peut faire mieux et plus simple :

```python
breakpoints = []

# avant de lancer l'émulation, l'utilisateur peut placer un bp
while True:
    user_input = input("place breakpoint ? (give an address or say 'go')\n>")
    if user_input == 'go':
        break
    breakpoints.append(int(user_input))

def do_each_loop(jitter):
    vIP = get_virtual_instruction_pointer(jitter)
    print_state(jitter)
    if int(int.from_bytes(vIP, arch.endianness)) in breakpoints:
        handle_breakpoint(jitter)
    return(True)
```
*Code 12* 

Avant le début de l'exécution, on demande à l'utilisateur de placer des breakpoints, puis à chaque instruction exécutée, si un breakpoint est placé, on passe en mode gestion de breakpoints avec `handle_breakpoint`, qui est définie ainsi : 

```python
def handle_breakpoint(jitter):
    print(f"\nReached breakpoint at {get_virtual_instruction_pointer(jitter)}")
    print("add breakpoint (b), read value (r), write value(w), go (go) ?")
    while True:
        user_input = input(">")
        if user_input == 'go':
            print('\n', end='')
            break
        tokens = user_input.split(" ")
        if tokens[0] == 'b':
            breakpoints.append(int(tokens[1]))
            continue
        if tokens[0] == 'r' or 'w':
            if tokens[1][0] == 'r': # il s'agit d'un registre
                reg_number = tokens[1][1]
                if tokens[0] == 'r':
                    print(f"r{reg_number} = {get_register_value(jitter, int(reg_number))}")
                if tokens[0] == 'w':
                    set_register_value(jitter, int(reg_number), tokens[2])
            continue
        print("illegal instruction")
```
*Code 13*

Dans l'exemple d'exécution suivant, on place un breakpoint à l'adresse 4, on lit puis on écrit (avec la valeur `b'ABCD'`) le registre virtuel `r1`, et on place un autre breakpoint à l'instruction suivante (adresse 7) avant de reprendre l'exécution.

```
place breakpoint ? (give an address or say 'go')
>4
place breakpoint ? (give an address or say 'go')
>go

[...]

vIP : 4 > mov_reg_reg r2 r0 

Reached breakpoint at b'\x04\x00\x00\x00'
add breakpoint (b), read value (r), write value(w), go (go) ?
>b 7
>r r1
r1 = b'\x00\x00\x00\x00'
>w r1 41424344
>r r1
r1 = b'ABCD'
>go

eflag: b'\x00'
vSP : 0xffffffff
registers :
r0 = b'\x00\x00\x00\x00'
r1 = b'ABCD'
r2 = b'\x00\x00\x00\x00'
r3 = b'\x00\x00\x00\x00'
r4 = b'\x00\x00\x00\x00'
r5 = b'\x00\x00\x00\x00'
r6 = b'\x00\x00\x00\x00'
r7 = b'\x00\x00\x00\x00'
stack : 
        0x0 : b'\x00\x00\x00\x00'
        0x4 : b'\x00\x00\x00\x00'
        0x8 : b'\x00\x00\x00\x00'
        0xc : b'\x00\x00\x00\x00'
        0x10 : b'\x00\x00\x00\x00'
        0x14 : b''

vIP : 7 > mov_reg_imm r3 0x10 

 reached breakpoint at b'\x07\x00\x00\x00'
add breakpoint (b), read value (r), write value(w), go (go) ?
>

```
*Résultat 5*

## Conclusion
Avec ces outils, un reverseur peut déployer sa méthodologie habituelle pour analyser le bytecode de la VM, avec malgré tout la difficulté supplémentaire de l'architecture nouvelle. Il peut lire, écrire le bytecode, et l'exécuter avec une instrumentation minimale .

Le travail pour la mise en place des outils est conséquent, mais c'est l'unique méthode qui permette d'effectuer un réel travail de rétro-conception, et donc de défaire l'obfuscation par VM. Il faut donc être certain que l'analyse approfondie soit effectivement indispensable ! 

### Pour aller plus loin : VMs *hardenées*
Vous vous en êtes rendus compte : la VM utilisée dans cette obfuscation est très simple. Dans la vraie vie, les obfuscations par VM sont bien plus méchantes. Pour finir, nous allons donc exposer certaintes méthodes de *hardening* de VM.

#### Ajout de difficultés dans le reverse de la VM
Cette catégories de *hardenings* de VMs consistent à puiser dans d'autres méthodes d'obfuscation pour rendre difficile la première étape, l'analyse statique de la VM. 

Parmi ces méthodes, on peut compter : 
- la multiplication des instructions et des handlers (et donc la multiplication du travail de reverse)
- obfuscation des handlers
- obfuscation des la boucle FDE

Ces techniques ont pour objectif de ralentir l'analyse initiale de la VM, et bien qu'elles donnent beaucoup de travail au reverseur, elles ne remettent pas fondamentalement en question la méthodologie présentée ici : il faudra simplement utiliser d'autres méthodes de désobfuscation à l'étape d'analyse statique.

#### Inlining du décodeur ou *threaded code* ***
Le *threaded code* consiste à ne plus utiliser de boucle FDE qui centralise l'exécution de la VM, mais à ajouter une unique itération de FDE à la fin de chaque handler, c'est donc chaque handler qui appelle le suivant, sans repasser par une étape commune ! Autrement dit, le FDE est dupliqué autant de fois qu'il y a d'instructions.

Là ce se complique : on ne peut pas mettre notre breakpoint émulateur au du FDE. Malgré tout, l'adaptation reste simple, il suffit de mettre un breakpoint à la fin chaque instruction, dans l'unique itération du FDE. La méthode est brutale, mais on n'est pas limités en breakpoints dans n émulateur...

#### Chiffrement du bytecode dépendant du flot d'exécution
Cette méthode d'obfuscation n'est implémentée que dans les VMs les plus difficiles. Si vous la rencontrez, c'est que le développeur n'a vraiment, mais alors vraiment pas envie que vous rétroconceviez son code.

La méthode consiste à ce que le bytecode lui-même soit chiffré, et que le déchiffrement se fasse *just-in-time*. Chaque handler d'instruction contient alors à la fin de son code une routine de déchiffrement, dont il se sera pour déchiffrer uniquement l'instruction suivante, avec une clé qui dépend de l'exécution (l'instruction précédente, ses paramètres, etc.).

La bonne nouvelle, c'est que la réalisation d'une trace d'exécution telle qu'on l'a mise en place plus haut n'est pas ou peu affectée. C'est toutefois la seule bonne nouvelle. En effet : 
- Le désassemblage devient très difficile, et a probablement besoin d'une trace d'exécution afin de posséder les clés de déchiffrement de chaque instruction dans le bytecode
- l'assemblage devient lui aussi très difficile car il faut chiffrer les instructions en respectant le mécanisme implémenté dans la VM
- la mise en place du débugging est quasiment impossible, puisque toute modification de l'exécution du bytecode entrave son déchiffrement.

Une approche envisageable serait un déchiffrement complet du bytecode (à l'aide de la trace), puis une modification de la VM pour supprimer le chiffrement.

Si vous tombez sur ce genre de VM-là, nous vous souhaitons bien du courage !
