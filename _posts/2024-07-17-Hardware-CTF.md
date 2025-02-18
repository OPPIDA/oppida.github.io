---
layout: post
author: [PLM]
title: "CTF - Hardware"
date: 2024-07-17
categories: [CTF, Hardware]
image: assets/Tridroid-Banner.jpg
title_color: "#ffffff"
---

Objectifs :
- Apprentissage de la recherche documentaire (Datasheet)
- Découverte d’un maximum de protocoles (SPI,UART,I2C, …)
- Découverte d’outils (analyseur logique, oscilloscope)
- Manipulations (breadboard, branchement des pins, glitch)
- Sélection simple des exercices
- Rappeler qu’avec quelques Ko on peut faire des trucs funs

Résultats :
- 9 Flags
- Occupation 50% ROM et 90% de RAM
- Des heures de fun (ou pas ☺ )
- Multi platform -> ESP32-WROOM

Ce projet est réalisé par [samuel.marrazzo](https://twitter.com/EnlargeYourGeek)

Repo Github : [CTF-Hardware](https://github.com/smarrazzo/CTF-Hardware)

Plusieurs devices sont possible pour heberger ce challenge, mais pour cet article, les exerice ont été réalisé sur une ATmega32U4:  
![](assets/posts/2024-07-17-Hardware-CTF/1.png)

## Soudure  
<img src="assets/posts/2024-07-17-Hardware-CTF/2.png" alt="2" width="350" height="350" />

## Flash + Accès au menu

Procédure pour flasher une ATmega32U4 :

```
python3 reset.py /dev/ttyACM0
```

```
avrdude "-Cavrdude.conf" -v -V -patmega32u4 -cavr109 "-P/dev/ttyACM1" -b57600 -D "-Uflash:w:CTF_Leonardo.hex:i"
```


L'accès au menu se fait par une connexion en serie sur le port USB de l'ATmega :

![](assets/posts/2024-07-17-Hardware-CTF/3.png)  

```
Menu :>?

1 - Donne moi le flag !
2 - Je crois que nous avons affaire à un serial killer!
3 - Mosi et Miso sont sur un bateau ...
4 - Appel moi maître !
5 - Oui Maître !
6 - Une histoire d'écoute.
7 - Le sens de la vie.
8 - En sortie, l'union fait la force.
9 - Jouons à sha!
a - Bincat
b - Touch me !
? - Help

Menu :>
```


## Installation sur une breadboard
Une breadboard est composée de trous espacés de 2.54mm permettant d’enfoncer des composants afin de les relier ensemble sans avoir à les souder, ce qui permet de faire des tests très facilement et très rapidement.

Les trous qui appartiennent à une même ligne, sont reliés électriquement.


![](assets/posts/2024-07-17-Hardware-CTF/6.png)

> mise en place de l'ATmega32U4 sur la breadboard : 

<img src="assets/posts/2024-07-17-Hardware-CTF/44.png" alt="44" width="550" height="550" />

## ____________________________________________________________________

## Exercice 1 :  Donne moi le flag !

En démarrant l'exercice 1, le flag est affiché à l'écran  
![](assets/posts/2024-07-17-Hardware-CTF/7.png)

```
USB_S3Ri@l_1s_T0_3@sY
```

## Exercice 2 :  Je crois que nous avons affaire à un serial killer!

![](assets/posts/2024-07-17-Hardware-CTF/8.png)

Cette phrase nous indique qu'il mapper les pins A0 sur **True** et A1 sur **False** :  
<img src="assets/posts/2024-07-17-Hardware-CTF/9.png" alt="9" width="350" height="350" />


![](assets/posts/2024-07-17-Hardware-CTF/10.png)

Le message : "Tu bluffes Martoni ! " apparait. 
Nous avons donc réussi à mapper les bon pins, mais le flag n'apparait pas.
L'énoncé nous parle de série, avec un Analyseur logique, il faut écouter TX et RX : 

<img src="assets/posts/2024-07-17-Hardware-CTF/11.png" alt="11" width="350" height="350" />


Lors de l'écoute, la capture permet de voir ceci : 

![](assets/posts/2024-07-17-Hardware-CTF/12.png)

Calcul du Baudrate avec l'extention "Baud Rate Estimate " 

![](assets/posts/2024-07-17-Hardware-CTF/13.png)

Ajustement de la configuration de l'analyse :

<img src="assets/posts/2024-07-17-Hardware-CTF/14.png" alt="14" width="350" height="350" />

Le flag apparait en ASCII :  
![](assets/posts/2024-07-17-Hardware-CTF/15.png)

```
The flag is : S3ri@L_1S_FuN!
```

## Exercice 3 :  Mosi et Miso sont sur un bateau

![](assets/posts/2024-07-17-Hardware-CTF/16.png)

L'énoncé indique MOSI / MISO, ce qui nous fait penser au SPI : 
Le bus SPI utilise quatre signaux logiques :
- **SCLK** => Serial Clock, Horloge (généré par le maître)
- **MOSI**  => Master Output, Slave Input (généré par le maître)
- **MISO** => Master Input, Slave Output (généré par l'esclave)
- **SS** => Slave Select (optionel)

 Dans la datasheet de l'ATemaga32 nous pouvons identifier les PINS du SPI : 

<img src="assets/posts/2024-07-17-Hardware-CTF/17.png" alt="17" width="350" height="350" />



Avec l'analyseur logique : 

![](assets/posts/2024-07-17-Hardware-CTF/18.png)

il y a bien 3 flux : 
- Le chanel 2 en rouge, nous identifions bien la clock (un signal régulier)
- Le chanel 0 en orange : MOSI  
- Le chanel 1 en blanc : MISO 


![](assets/posts/2024-07-17-Hardware-CTF/19.png)
```
0x37 0x7A 0xBC 0xAF 0x27 0x1C
```

![](assets/posts/2024-07-17-Hardware-CTF/20.png)


si nous copions donc l'entiéreté des data du flux :  
![](assets/posts/2024-07-17-Hardware-CTF/21.png)


<img src="assets/posts/2024-07-17-Hardware-CTF/22.png" alt="22" width="350" height="350" />

Nous n'avons malheureusement pas encore le mot de passe pour ouvrir cette archive :( 
peut être dans un futur exercice... 
## Exercice 4/5 : Appel moi maître !

Fonctionnement de l'I2C : 
I2C : Inter-Integrated Circuit 

Les échanges ont toujours lieu entre un maître et un ou plusieurs esclave(s): 
- SCL = clock 
- SDA = la data 
![](assets/posts/2024-07-17-Hardware-CTF/23.png)


![](assets/posts/2024-07-17-Hardware-CTF/24.png)

![](assets/posts/2024-07-17-Hardware-CTF/25.png)

je suis longtemps resté bloqué sur ce chall jusqu'a ce que j'ai un hint du créateur du chall : 
![](assets/posts/2024-07-17-Hardware-CTF/26.png)

je dois donc m'aider d'un autre exercice pour résoudre celui ci, 
Si l'on regarde donc l'exo d'après :  
![](assets/posts/2024-07-17-Hardware-CTF/27.png)

nous avons bien à faire à un esclave, cela est donc cohérent.  
![](assets/posts/2024-07-17-Hardware-CTF/28.png)

Les pins de l'atmega32 correspondant à l'I2C sont donc les 2 et 3
2 pour la data et 3 pour la clock. 

Lorsque le maitre envoie ses commandes I2C : 
aucune réponse de slave ne lui est renvoyé donc 0x2A NAK :  
![](assets/posts/2024-07-17-Hardware-CTF/29.png)

mais par contre lorsqu'on connecte un autre atémega3 et qu'on le lance l'exo 5, on le passe donc en mode slave. 
L'échange est beaucoup plus important et l'on voit de la data passer :  

![](assets/posts/2024-07-17-Hardware-CTF/30.png)

- Le câble SDA Maitre sur le SDA Escale (Data)
- Le câble SCL Maitre sur le SCL Maitre (Clock)  
  
<img src="assets/posts/2024-07-17-Hardware-CTF/31.png" alt="31" width="350" height="350" />

Durant la capture : 

![](assets/posts/2024-07-17-Hardware-CTF/32.png)

Utilisation d'un script python pour convertir la data extraite de la capture en GIF :   

```
data = r"W[*]GIF89aP\0\n\0\x91\0\0\xFF\xFF\xFF\0\0\0\xFF\xFF\xFF\0\0\0!\xF9\x04\x05\0\0\x02W[*]\0,\0\0\0\0P\0\n\0\0\x02l\x8C\x8F\xA9\xCB\xED\x0F\x0F\x98\xD2L\x90.\r\x98\xDB\xFBu\xDE\x08W[*]V#\xD2m\x12\xB5\xA5V#\x92\xAF'\xBA\xB4-g9\x97\xC6\xB3\x8F\n\xE60\xB5\xDFI\x08\x8C\x15M\xADW[*]\xD0BY\xD2\x9Cl\xC4\xCFJe:*\x99\xB3'\xF2\x85\xA3N\xB9\xBA\xAEV|,\x1BeKWs\xFDEW[*]\xB9U8\xC5v\xE8\]\xE3A\xE9>\x02\x18(8H\xC8\x83U\x88\xE8\x17Q\0\0;\0\0\0\0\0"

# Suppression des séquences "W[*]"
cleaned_data = data.replace('W[*]', '')

byte_data = cleaned_data.encode('latin1').decode('unicode_escape').encode('latin1')

# Écriture des octets dans un fichier GIF
with open('output.gif', 'wb') as f:
    f.write(byte_data)

print("GIF sauvegardé dans > output.gif")
```

<img src="assets/posts/2024-07-17-Hardware-CTF/33.png" alt="33" width="350" height="350" />


nous pouvons donc maintenant décoder notre archive 7z avec ce password : 

<img src="assets/posts/2024-07-17-Hardware-CTF/34.png" alt="34" width="350" height="350" />

```
SPI_1S_US3FU77
```

## Exercice 6 : Une histoire d'écoute 

![](assets/posts/2024-07-17-Hardware-CTF/35.png)

Branchement donc sur le pin 10 

<img src="assets/posts/2024-07-17-Hardware-CTF/36.png" alt="36" width="350" height="350" />



Puis écoute d'une communication à l'analyseur logique : 

Les "bits" de synchro du début nous montrent comment reconnaitre un long (-) et un court (.) :  
![](assets/posts/2024-07-17-Hardware-CTF/37.png)
Entièreté de la communication :   
![](assets/posts/2024-07-17-Hardware-CTF/38.png)

puis décodage : 
```
-.-. ----- ..- -.-. ----- ..- ..--.- - ..- ..--.- ...- ...-- ..- -..- ..--.- ...- ----- .. .-. ...-- ..--.- -- ----- -. ..--.- -- ----- .-. ..... ...-- ..--.- ..--..
```

Ce qui donne en décodant le morse : 
```
C0UC0U_TU_V3UX_V0IR3_M0N_M0R53_?
```

## Exercice 7 : Le sens de la vie 

Lorsque l'on lance l'exercice 7 : 

<img src="assets/posts/2024-07-17-Hardware-CTF/39.png" alt="39" width="350" height="350" />

Après de nombreuse manipulation, je comprend que si l'on mappe certain pin entre eux, le binaire change et donc le résultat en décimal change : 
par exemple le CVV et la 4 :   
<img src="assets/posts/2024-07-17-Hardware-CTF/40.png" alt="40" width="350" height="350" />
  
![](assets/posts/2024-07-17-Hardware-CTF/41.png)  
l'exercice 7 nous fais comprendre par sa phrase : "Connais tu la réponse ultime ?" 
qu'il attend le nombre 42 : Essayons donc de lui donner. 

Lorsqu'on mappe les pins : VCC + 3 

<img src="assets/posts/2024-07-17-Hardware-CTF/42.png" alt="42" width="350" height="350" />

<img src="assets/posts/2024-07-17-Hardware-CTF/43.png" alt="43" width="350" height="350" />

```
The flag is :F33L_Th3_P0w3r_0f_B1n@rY
```

## Exercice 8 - En sortie, l'union fait la force

```
Menu :>8
A plusieurs on est toujours plus fort !
Quand vous êtes prêts, appuyer sur Entrer

Menu :>
```
Après analyse de tout les pins, seul, les pins de 0 à 7 sortent de la data.
<img src="assets/posts/2024-07-17-Hardware-CTF/45.png" alt="45" width="350" height="350" />


Branchement et analyse de cette data à l'aide de l'analyseur logique. 
<img src="assets/posts/2024-07-17-Hardware-CTF/46.png" alt="46" alt="46" width="550" height="550" />

Cela semble être du binaire classique (0 en bas, et 1 en haut)

> Après encore un hint du créateur du chall : 

```
Des fois c'est bien de changer de perspectives
```

Si le sens de la capture change, et qu'on la regarde "d'une autre perspective" : 
<img src="assets/posts/2024-07-17-Hardware-CTF/47.png" alt="47" width="450" height="450" />

Le premier octet commence par : 01000100 => ce qui correspond à un D en ascii. 


Extraction du flag en faisant ça sur toute la capture : 
<img src="assets/posts/2024-07-17-Hardware-CTF/48.png" alt="48" width="450" height="450" />

Extraction de toute la data : 
```
01000100
00110001
01000111
00110001
01110100
01000000
00110111
01011111
01001001
00110000
01110011
01011111
01000000
01110010
00110011
01011111
00110001
01101101
01110000
00110000
01110010
01010100
01000000
01101110
01110100
01011111
00100001
```

Ce qui une fois décodé donne : 
```
D1G1t@7_I0s_@r3_1mp0rT@nt_!
```

## Exercice b - Touch me !

j'ai mis du temps avant de comprendre ce qu'il fallait faire pour cet exercice : 

L'idée est de regarder la datasheet et de voir que certain pin ne sont pas utilisé et non connecter a la carte.

<img src="assets/posts/2024-07-17-Hardware-CTF/54.png" alt="54" width="450" height="450" />

il faut donc allez les toucher directement sur la puce avec un petit bout de papier humide (afin de faire contact mais sans faire de court circuit)
Les pins non utilisé etant A4 / A5 
Ces pins se situe la sur l'ATmega32u4 : (petit points verts)

<img src="assets/posts/2024-07-17-Hardware-CTF/55.png" alt="55" width="450" height="450" />

Pour cet exos nos meilleurs amis seront un petit verre d'eau et un bout de papier : 

<img src="assets/posts/2024-07-17-Hardware-CTF/56.png" alt="56" alt="56" width="450" height="450" />


bout de papier que l'on vient poser directement entre la pin A4 et A5 pour faire contact
<img src="assets/posts/2024-07-17-Hardware-CTF/57.png" alt="57" width="450" height="450" />

Sur notre terminal le nombre satisfaction monte en flèche jusqu'à ce que le flag apparaisse : 

```
Satisfaction :225
Satisfaction :223
Satisfaction :229
Satisfaction :227
Satisfaction :228
Satisfaction :227
Satisfaction :484
Satisfaction :766
ThX_1_@m_50_Sa7i5f1ed_N0w_!
```

```
ThX_1_@m_50_Sa7i5f1ed_N0w_!
```


## Exercice c - Hide and seek 

<img src="assets/posts/2024-07-17-Hardware-CTF/51.png" alt="51" width="550" height="550" />

Encore un hint du créateur qui nous dit : 
```à l'origine il fallait les passer au UV pour les effacer```

je comprend donc que c'est dans l'eeprom que le flag se trouve.
Et pour dump une eeprom, nous pouvons utiliser l'outil [avrdude](https://github.com/avrdudes/avrdude) :   
```
┌──(plm㉿oppida)-[~/CTF-Hardware/]
└─$ python3 reset.py /dev/ttyACM1
```

```
┌──(plm㉿oppida)-[~/CTF-Hardware/]
└─$ avrdude "-Cavrdude.conf" -v -V -patmega32u4 -cavr109 -P /dev/ttyACM0 -b57600 -U eeprom:r:eeprom_dimp:i 
```

```
┌──(plm㉿oppida)-[~/CTF-Hardware/_eeprom_dimp.extracted]
└─$ strings 0.hex      
:2000000044306E5F545F4630724733745F70337253317354346E63335F53743052346733A9
:2000200021FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBE
:20004000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC0
:20006000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA0
:20008000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80
:2000A000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF60
:2000C000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40
:2000E000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
```
Print du flag en Hexa : 
```
┌──(plm㉿oppida)-[~/CTF-Hardware/_eeprom_dimp.extracted]
└─$ strings 0.hex | xxd -r -p
 D0n_T_F0rG3t_p3rS1sT4nc3_St0R4g3! ��������������������������������
@��������������������������������� `��������������������������������� ���������������������������������� ���������������������������������` ���������������������������������@ ���������������������������������  ���������������������������������  ��������������������������������� @��������������������������������� `��������������������������������� 
```

```
D0n_T_F0rG3t_p3rS1sT4nc3_St0R4g3!
```

## Exercice 9 - Jouons à sha !

Lancement de l'exercice 9 : 
```
Donner le sha256 de la concaténations des flags : sha256(1:2:3:4:6:7:8:b:c)
En utilisant 16 bits IO dans l'ordre croissant
```

Donc je concatène et fais le sha256 de l'ensemble de mes flags : 

```
 ┌──(plm㉿oppida)-[CTF-Hardware/]
 └─$ printf 'USB_S3Ri@l_1s_T0_3@sY:S3ri@L_1S_FuN!:SPI_1S_US3FU77:GIF_THROUGH_I2C:C0UC0U_TU_V3UX_V0IR3_M0N_M0R53_?:F33L_Th3_P0w3r_0f_B1n@rY:D1G1t@7_I0s_@r3_1mp0rT@nt_!:ThX_1_@m_50_Sa7i5f1ed_N0w_!:D0n_T_F0rG3t_p3rS1sT4nc3_St0R4g3!' | sha256sum
 
8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad96774cc  -
```

je pense qu'il faut ensuite utiliser l'exercice 'a' pour résoudre l'exercice 9, un peu comme l'exercice 5 avec le 4.

L'énoncé de l'exercice 'a' dis : ```BinCat attend 2 Octets au format HEX, via le terminal```

je comprend donc qu'il faut découper notre le sha256 de comme ceci : 
```
8fc2
1809
73AE
2bc2
9a7b
a53e
e342
1e5a
0d57
02ff
155b
6a56
e03f
a0aa
d967
74cc
```

Et ensuite l'envoyer par un moyen que je ne connait pas encore. 
Si c'est comme l'exercice 4 et 5, il faut un deuxième device qui va envoyer la data à notre premier. 
Et vu que l'exercice stipule qu'il faut utiliser les 16 bits IO dans l'ordre croissant je fais un montage qui relie chaque pin de 1 à 16 du premier device au second comme ceci : 

<img src="assets/posts/2024-07-17-Hardware-CTF/52.png" alt="52" width="550" height="550" />

Maintenant, l'atmega à droite écoute et celui de gauche envoie,lorsque j'envoie 2 octet en Hexa dans mon premier device, le deuxieme recupère bien mes données. 

<img src="assets/posts/2024-07-17-Hardware-CTF/53.png" alt="53" width="650" height="650" />

je n'ai plus qu'a faire ca sur l'ensemble de ma chaine de charactère sha256 : 

```
Donner le sha256 de la concaténations des flags : sha256(1:2:3:4:6:7:8:b:c)
En utilisant 16 bits IO dans l'ordre croissant
Appuyer sur Entrer pour valider les 2 octetsQ/q pour quitter
sha : e3c0
sha : e3c6
sha : 0000
sha : 0000
sha : 0000
sha : 8fc3
sha : 8fc3
sha : 8fc2
sha : 8fc2
sha : 8fc2
octets : 0 et 1 validés
sha : 8fc28fc2
sha : 8fc28fc2
sha : 8fc21809
sha : 8fc21809
sha : 8fc21809
sha : 8fc21809
sha : 8fc21809
sha : 8fc21809
octets : 2 et 3 validés
sha : 8fc218091809
sha : 8fc218091809
sha : 8fc2180973af
sha : 8fc2180973af
sha : 8fc2180973ae
sha : 8fc2180973ae
octets : 4 et 5 validés
sha : 8fc2180973ae73ae
sha : 8fc2180973ae73ae
sha : 8fc2180973ae73ae
sha : 8fc2180973ae73ae
sha : 8fc2180973ae73ae
sha : 8fc2180973ae2bc2
sha : 8fc2180973ae2bc2
sha : 8fc2180973ae2bc2
octets : 6 et 7 validés
sha : 8fc2180973ae2bc22bc2
sha : 8fc2180973ae2bc22bc2
sha : 8fc2180973ae2bc22bc2
sha : 8fc2180973ae2bc29a7b
sha : 8fc2180973ae2bc29a7b
sha : 8fc2180973ae2bc29a7b
sha : 8fc2180973ae2bc29a7b
sha : 8fc2180973ae2bc29a7b
octets : 8 et 9 validés
sha : 8fc2180973ae2bc29a7b9a7b
sha : 8fc2180973ae2bc29a7b9a7b
sha : 8fc2180973ae2bc29a7ba53f
sha : 8fc2180973ae2bc29a7ba53f
sha : 8fc2180973ae2bc29a7ba53e
sha : 8fc2180973ae2bc29a7ba53e
sha : 8fc2180973ae2bc29a7ba53e
sha : 8fc2180973ae2bc29a7ba53e
sha : 8fc2180973ae2bc29a7ba53e
sha : 8fc2180973ae2bc29a7ba53e
octets : 10 et 11 validés
sha : 8fc2180973ae2bc29a7ba53ea53e
sha : 8fc2180973ae2bc29a7ba53ea53e
sha : 8fc2180973ae2bc29a7ba53ee342
sha : 8fc2180973ae2bc29a7ba53ee342
sha : 8fc2180973ae2bc29a7ba53ee342
sha : 8fc2180973ae2bc29a7ba53ee342
sha : 8fc2180973ae2bc29a7ba53ee342
sha : 8fc2180973ae2bc29a7ba53ee342
octets : 12 et 13 validés
sha : 8fc2180973ae2bc29a7ba53ee342e342
sha : 8fc2180973ae2bc29a7ba53ee342e342
sha : 8fc2180973ae2bc29a7ba53ee342e342
sha : 8fc2180973ae2bc29a7ba53ee3421e5a
sha : 8fc2180973ae2bc29a7ba53ee3421e5a
octets : 14 et 15 validés
sha : 8fc2180973ae2bc29a7ba53ee3421e5a1e5a
sha : 8fc2180973ae2bc29a7ba53ee3421e5a1e5a
sha : 8fc2180973ae2bc29a7ba53ee3421e5a1e5a
sha : 8fc2180973ae2bc29a7ba53ee3421e5a1e5a
sha : 8fc2180973ae2bc29a7ba53ee3421e5a1e5a
sha : 8fc2180973ae2bc29a7ba53ee3421e5a1e5a
sha : 8fc2180973ae2bc29a7ba53ee3421e5a1e5a
sha : 8fc2180973ae2bc29a7ba53ee3421e5a1e5a
sha : 8fc2180973ae2bc29a7ba53ee3421e5a1e5a
sha : 8fc2180973ae2bc29a7ba53ee3421e5a1e5a
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d57
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d57
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d57
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d57
octets : 16 et 17 validés
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d570d57
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d570d57
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff
octets : 18 et 19 validés
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff02ff
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff02ff
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff02ff
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b
octets : 20 et 21 validés
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b155b
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a57
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a57
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56
octets : 22 et 23 validés
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a566a56
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a566a56
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03f
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03f
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03f
octets : 24 et 25 validés
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fe03f
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0ab
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0ab
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aa
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aa
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aa
octets : 26 et 27 validés
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aaa0aa
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad967
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad967
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad967
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad967
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad967
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad967
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad967
octets : 28 et 29 validés
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad967d967
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad96774cc
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad96774cc
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad96774cc
sha : 8fc2180973ae2bc29a7ba53ee3421e5a0d5702ff155b6a56e03fa0aad96774cc
octets : 30 et 31 validés
Shatrapé : S1R@S_3sT_Un_S@D1Qu3_!

Menu :>
```

```
S1R@S_3sT_Un_S@D1Qu3_!
```
