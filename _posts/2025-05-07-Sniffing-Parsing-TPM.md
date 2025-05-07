---
title: Sniffing, Parsing et Déscellement TPM
date: 2025-05-07
categories: [Articles, Cryptographie, Hardware]
tags: []
comments: false
description: Interception de communications SPI et parsing de commandes TPM pour déchiffrer un sceau tpm-tools.
author: [PAN]
math: false
image:
  path: /assets/posts/2025-05-07-Sniffing-Parsing-TPM/unseal_tpm_banner.png
---

Les TPM (Trusted Platform Module) sont des composants de sécurité omniprésents dans les ordinateurs. Bien connus comme des composants intervenant dans les solutions de chiffrement de disque grand public comme BitLocker sur Windows ou LUKS sur Linux, ils permettent notamment :

- de stocker et manipuler des clés de manière sécurisée ;
- de réaliser un démarrage mesuré.

Le démarrage mesuré (*Measured Boot*) consiste à faire accumuler au TPM des empreintes cryptographiques des composants logiciels chargés au fur et à mesure du démarrage, avant leur exécution.  Plus tard, le TPM peut alors comparer l'état qu'il a ainsi mesuré du système à un état attendu, et en conséquence accepter ou refuser de procéder à des opérations sensibles comme un déchiffrement de disque[^quote]. Une donnée dont l'accès est lié à l'intégrité du système est dite scellée (*sealed*).

Dans cet article, on réalise l'interception SPI des communications entre un système et son TPM, puis procède à un parsing exhaustif de celles-ci, afin de parvenir à désceller un fichier généré par un outil standard.

Il existe 2 versions principales des spécifications des TPM. La version [TPM 1.2][TPM12_SPEC], rétrocompatible à celles qui précèdent, et la version [TPM 2.0][TPM20_SPEC], non rétrocompatible. On s'intéresse dans cet article principalement à TPM 1.2.

## Usage du TPM

L'utilisation du TPM se fait par l'usage de protocoles et structures de données spécifiés par le TCG (*Trusted Computing Group*) ; pour autant il existe des outils pour facilement réaliser les tâches les plus courantes.

Dans le cas de TPM 1.2, la suite [TrouSerS][TROUSERS] d'IBM est la principale implémentation des logiciels permettant l'usage des TPM, et son paquet Linux [`tpm-tools`][TPM_TOOLS] offre des commandes facilement lancées depuis Bash.

Un usage qui a été observé en pratique est celui des commandes `tpm_sealdata` et `tpm_unsealdata` pour sceller et désceller un fichier sensible, devant être conservé sur un stockage auquel pourrait accéder un attaquant :

```bash
$ tpm_sealdata -z -p 0 -p 1 -i /tmp/secret_file.txt -o /opt/secret_file.enc

$ tpm_unsealdata -z -o /tmp/secret_file.txt -i /opt/secret_file.enc
```

La première commande crée un sceau du contenu du fichier `/tmp/secret_file.txt`, qui est lié à la valeur actuelle des PCR[^pcr] 0 et 1.

La seconde commande récupère le contenu du fichier, après que le TPM ait confirmé la valeur attendue des PCR 0 et 1. Elle échouera par exemple si un attaquant redémarre le système après avoir remplacé son BIOS.

Concrètement, le contenu du fichier est stocké sur le système après chiffrement symétrique, via une clé générée par la première commande. C'est cette clé dont le TPM crée ensuite un sceau, et qui sera déscellée par la seconde commande pour enfin déchiffrer le fichier.

## Sniffing

Le TPM est généralement modélisé comme un composant sécurisé et inviolable ; pour autant il échange typiquement avec le reste du système sur un bus qui fait rarement l'objet de protections particulières.

Il est relativement connu que cette communication peut être interceptée, permettant par exemple à un attaquant ayant volé un PC sécurisé par BitLocker[^bitlocker] de le déchiffrer. Ces attaques se contentent généralement de reconnaître la structure de la clé transitant en clair dans le flux d'octets échangés entre le TPM et le système. Dans notre cas, la donnée qui nous intéresse est une clé symétrique aléatoire qui n'est donc pas trivialement reconnaissable au milieu du flux d'informations.

Le TPM considéré utilise une interface SPI pour la communication. Après avoir identifié les pins associés au bus SPI sur lequel le TPM communique, on peut leur connecter un analyseur logique et intercepter les transactions réalisées entre le TPM et le système :

![](assets/posts/2025-05-07-Sniffing-Parsing-TPM/unseal_spi.png)
_Extrait de la capture des communications SPI déclenchées par `tpm_unsealdata`. L'extrait fait 2ms et la capture fait près de 800ms._

En l'état, ces communications sont difficilement exploitables. La commande exécutée correspond à la réalisation de plusieurs commandes et réponses avec le TPM, pour notamment :

- initialiser et utiliser une session permettant une communication avec autorisation[^auth-mdp] ;
- charger dans le TPM une bi-clé RSA[^chargement-rsa] ;
- réaliser le déscellement ;
- libérer les ressources chargées et les sessions mises en place.

Qui plus est, ces échanges de commandes et réponses ont lieu par dessus un protocole de communication plus bas-niveau [défini par les spécifications des TPM][TIS_SPEC], qui lui-même a lieu par dessus la communication SPI. On fait donc face à une quantité significative de données échangées, 2 couches plus bas que les échanges qui nous intéressent. La capture totalise près de 10 Kio échangés via SPI dans lesquels on cherche 32 octets de clé.

L'analyseur public [TPM SPI Transaction][TPM_SPI_TRANSACTION] permet de facilement décoder le protocole immédiatement au dessus de SPI :

![](assets/posts/2025-05-07-Sniffing-Parsing-TPM/unseal_tis.png)
_Extrait de la capture des communications TIS déclenchées par `tpm_unsealdata`. L'extrait fait 2ms et la capture fait près de 800ms. Les commandes TPM transitent dans le registre `TPM_DATA_FIFO_0`._

Le protocole en question est une interface dite FIFO. Dans ce contexte, des registres sont exposés par le TPM, et son utilisateur peut les lire où y écrire. En particulier, ce premier décodage permet de se focaliser sur les opérations du registre `TPM_DATA_FIFO_0` où transitent toutes les données applicatives du protocole. Sur la capture précédente, on peut reconnaître le début d'une commande TPM en hexadécimal.

Ce premier décodage est suffisant pour par exemple identifier une donnée en clair contigue avec une structure reconnaissable, telle qu'une clé BitLocker. L'outil utilisé a été créé [dans ce but][TPM_SPI_BITLOCKER].

Pour réellement observer et analyser le flux de commandes et réponses échangées entre le TPM et le système, il nous faut aller plus loin et décoder ces dernières.

L'analyseur public [TPM SPI Command][TPM_SPI_COMMAND] se base sur l'analyseur précédent pour offrir une identification et un découpage basique des commandes et réponses échangées. Cependant l'outil ne supporte que TPM 2.0, et des échanges applicatifs par blocs de 1 octet.

Dans notre cas, c'est TPM 1.2 qui est utilisé, et les données circulent plutôt par blocs de 32 octets. L'interface FIFO supporte en effet des blocs de 1 à 64 octets.

Nous avons donc levé cette limitation de l'outil et surtout implémenté le support de TPM 1.2 qui nous permet de séparer et observer le flux des commandes avec succès : 

![](assets/posts/2025-05-07-Sniffing-Parsing-TPM/unseal_tpm.png)
_Extrait de la capture des commandes et réponses TPM déclenchées par `tpm_unsealdata`. L'extrait porte sur la réponse à la commande `TPM_Unseal`._

Le fork de l'outil est [disponible sur notre GitHub][TPM_SPI_COMMAND_GITHUB].

## Parsing

Maintenant que les commandes et réponses sont clairement identifiées et séparées, on est libre de cibler celles qui nous intéressent, et de décoder celles-ci en profondeur. Dans notre cas, on cible la commande `TPM_Unseal` et surtout sa réponse, qui devrait contenir la donnée déchiffrée par le TPM.

Pour cela on peut implémenter un parser de commandes et réponses TPM, et des structures associées. Ce travail a été fait pour le cas de la commande ciblée, dans l'outil [`tpm_parser` mis à disposition sur notre GitHub][tpm_parser_GITHUB].

```python
import pandas as pd
from tpm_parser import parse_packets

df = pd.read_csv('unseal_capture.csv')

unseal_row = df[df.Code == 'TPM_Unseal']
response_row = df.iloc[unseal_row.index + 1]

unseal_pkt = ''.join(unseal_row[['Header', 'Body']].values[0])
response_pkt = ''.join(response_row[['Header', 'Body']].values[0])

pkt_stream = bytes.fromhex(unseal_pkt + response_pkt)

print(parse_packets(pkt_stream))
```

![](assets/posts/2025-05-07-Sniffing-Parsing-TPM/parsed_packets.png)
_Le contenu de la commande TPM\_Unseal et sa réponse. `inData.ver` est `1.1.0.0` et `secret` est donc en clair._

Dans le cas présent, le secret transmis en réponse par le TPM est directement en clair, ce que l'on peut conclure de la structure utilisée : `TPM_STORED_DATA` avec un champ `ver` valant `1.1.0.0`, qui ne permet pas un chiffrement de la réponse d'après la [spécification de la commande `TPM_Unseal`][TPM_SPEC_COMMANDS].

Nous pouvons ainsi directement exploiter la donnée interceptée. Dans le cas de `tpm_unsealdata`, il s'agit d'une clé qui chiffre localement la donnée avec AES-256-CBC et un IV constant.

```python
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from tpm_parser import parse_packets

# champ secret du paquet de réponse
unsealed_key = parse_packets(pkt_stream)[1].body.body.secret

# champ -----ENC DAT----- du sceau créé par tpm_sealdata
enc_dat = b64decode(b'...')

# https://github.com/srajiv/tpm-tools/blob/master/include/tpm_seal.h#L35
TPMSEAL_IV = b"IBM SEALIBM SEAL"

cipher = AES.new(unsealed_key, AES.MODE_CBC, iv=TPMSEAL_IV)

decrypted = cipher.decrypt(enc_dat)
data = unpad(decrypted, 16)

# contenu du fichier secret_file.txt
print(f"{data = }")
```

Observer passivement les communications entre le TPM et le système suffit donc à déchiffrer un fichier scellé avec `tpm-tools`.

## Comment s'en protéger ?

La contremesure principale est de ne plus utiliser la famille de standards TPM 1.2 et `tpm-tools` dont les dernières versions remontent à 2011 et 2020 respectivement, mais plutôt de se mettre à jour en passant au nouveau standard TPM 2.0 et aux nouveaux outils associés. En particulier, cette nouvelle version supporte le [chiffrement des paramètres][TPM_PARAMETER_ENCRYPTION] qui permettrait ici de chiffrer la valeur déscellée de sorte qu'elle ne transite pas en clair.

Cependant ceci n'est pas forcément suffisant pour offrir une protection satisfaisante. De nombreuses hypothèses doivent être respectées pour pouvoir réellement bénéficier des garanties de sécurité offertes par un TPM. Outre la transmission d'une donnée sensible en clair sur le bus, d'autres problèmes exhibés par l'usage ciblé incluent par exemple :

- l'absence de secret pour autoriser le déchiffrement ;
- l'absence de protection contre le rejeu ;
- une politique (ici une liste de PCR) insuffisante pour détecter une manipulation malveillante de la plateforme.

Un composant TPM dédié (*dTPM*) communiquant avec le système via bus souffre presque par design d'attaques physiques, notamment quant à la mesure de l'intégrité de la plateforme qui admet interceptions et resets matériels voire logiciels. Pour autant, il convient de se protéger d'attaques passives comme celle présentée ici dont la sophistication est plus abordable. Par ailleurs, mêmes des attaques physiques actives poussées ne permettent pas de déjouer des communications correctement protégées entre le TPM et son utilisateur à l'aide de secrets correctement gérés.

## Références

[//]: # "NOTE: pas grave de changer les numéros dans le code, seul l'ordre compte"

1. [Remote Platform Integrity Attestation][REMOTE_ATTESTATION], TCG, juin 2022
1. [TPM 1.2 Main Specification][TPM12_SPEC], TCG, mars 2011
1. [TPM 2.0 Library][TPM20_SPEC], TCG, mars 2025
1. [TrouSerS - The open-source TCG Software Stack][TROUSERS], IBM, octobre 2008
1. [TrouSerS - tpm-tools][TPM_TOOLS], IBM, novembre 2020
1. [TCG PC Client Specific TPM Interface Specification (TIS)][TIS_SPEC], TCG, mars 2013
1. [bitlocker-spi-toolkit - TPM-SPI-Transaction][TPM_SPI_TRANSACTION], WithSecure Labs, mars 2022
1. [TPM SPI Command][TPM_SPI_COMMAND], 6f70, décembre 2022
1. [TPM SPI Command - fork][TPM_SPI_COMMAND_GITHUB], Oppida, mai 2025
1. [tpm_parser][tpm_parser_GITHUB], Oppida, mai 2025
1. [TPM Main Part 3 Commands][TPM_SPEC_COMMANDS], TCG, mai 2011
1. [Trusted Platform Module 2.0 Library Part 1: Architecture - 19 Session-based encryption][TPM_PARAMETER_ENCRYPTION], TCG, mars 2025

---

[//]: # "NOTE: Markdown non présenté à partir de cette ligne"

[//]: # "NOTE: Acronymes"

*[TPM]: Trusted Platform Module
*[TIS]: TPM Interface Specification
*[PCR]: Platform Configuration Register
*[TCG]: Trusted Computing Group
*[dTPM]: discrete TPM

[//]: # "NOTE: Liens utilisés à travers le texte"

[REMOTE_ATTESTATION]: https://trustedcomputinggroup.org/remote-platform-integrity-attestation/

[TPM12_SPEC]: https://trustedcomputinggroup.org/resource/tpm-main-specification/

[TPM20_SPEC]: https://trustedcomputinggroup.org/resource/tpm-library-specification/

[TROUSERS]: https://trousers.sourceforge.net/

[TPM_TOOLS]: https://sourceforge.net/projects/trousers/files/tpm-tools/

[TIS_SPEC]: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientTPMInterfaceSpecification_TIS__1-3_27_03212013.pdf

[TPM_SPI_TRANSACTION]: https://github.com/WithSecureLabs/bitlocker-spi-toolkit/tree/main/TPM-SPI-Transaction

[TPM_SPI_BITLOCKER]: https://labs.withsecure.com/publications/sniff-there-leaks-my-bitlocker-key

[TPM_SPI_COMMAND]: https://github.com/6f70/TPM-SPI-Command/

[TPM_SPI_COMMAND_GITHUB]: https://github.com/OPPIDA/TPM-SPI-Command/

[tpm_parser_GITHUB]: https://github.com/OPPIDA/tpm_parser/

[TPM_SPEC_COMMANDS]: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-3-Commands_v1.2_rev116_01032011.pdf

[TPM_PARAMETER_ENCRYPTION]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#section.19

[//]: # "NOTE: Notes de bas de page"

[^quote]: Les mesures obtenues peuvent aussi être signées et communiquées à d'autres machines afin de [prouver l'intégrité de la plateforme][REMOTE_ATTESTATION].
[^pcr]: Les PCR sont les registres du TPM contenant les accumulations cryptographiques des mesures du système. Ils sont séparés selon le type des composants qu'ils mesurent. Les détails de fonctionnement et d'usage des PCR sont hors de la visée de cet article.
[^bitlocker]: Cette attaque fonctionne seulement sur un usage de BitLocker TPM-only, ou en ayant également obtenu les informations nécessitées par les autres modes.
[^auth-mdp]: L'accès à la ressource est autorisé par mot de passe, dont le hash SHA-1 transite comme preuve. L'usage présenté utilise l'argument `-z` de `tpm-tools` pour spécifier d'utiliser un secret "Well-known" en mot de passe, à savoir une constante de l'outil. Sans cet argument, un mot de passe est demandé à l'utilisateur. On note qu'un secret "Well-known" pourra directement être utilisé par un attaquant actif, et qu'un hash observé par sniffing pourra être rejoué.
[^chargement-rsa]: A la création du sceau, `tpm_sealdata` ordonne au TPM la création d'une bi-clé RSA avec laquelle est ensuite scellée la clé symétrique. Le TPM étant limité en mémoire, elle est seulement stockée dans le fichier de sceau, et doit être rechargée. Hors du TPM, la clé privée est chiffrée symétriquement par une clé connue du TPM seulement.