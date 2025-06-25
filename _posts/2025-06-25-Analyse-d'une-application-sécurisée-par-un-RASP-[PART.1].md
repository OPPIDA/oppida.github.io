---
layout: post
author: [NRO]
title: "Analyse d'une application sécurisée par un RASP [PART.1]"
date: 2025-06-25
categories: [Articles, Mobile]
image: assets/IOS.png
title_color: "#ffffff"
---

# Exploration d'une application mobile sécurisée 

## PART.1 - Jailbreak

### Introduction

Lors d'une analyse de sécurité mobile iOS, nous avons été confronté à une application intéressante. Elle intégrait des mécanismes de protection avancés de type R.A.S.P. (RunTime Application Self-Protection). Nous avons dû repenser nos approches et développer des outils spécifiques pour contourner ces défenses.

Dans cette partie, nous explorerons les enjeux liés à l’utilisation d’un environnement jailbreak, et notre approche pour tenter de contourner les mécanismes de sécurité mis en œuvre par l'application afin de préparer un environnement propice à la recherche de vulnérabilités au sein des applications iOS. L'objectif final étant d'explorer les différentes étapes et techniques nécessaires pour mener des analyses de sécurité efficaces sur mobile.

Dans le cadre de l'analyse, l'une des premières étapes consiste à installer l'application dans un environnement de test jailbreaké, ce qui nous offre la possibilité de manipuler plus facilement l'application de manière dynamique (Injection de code, débogueurs, inspection mémoire...).

### Démarrage de l'application

L'application cible à notre disposition est relativement volumineuse au regard de ses fonctionnalités. Lors de son exécution sur un appareil jailbreaké, celle-ci cesse immédiatement de fonctionner. La première étape consiste en l'analyse du journal des crashs afin de recueillir davantage d'informations sur la cause. Cela nous a permis d'obtenir les informations suivantes :

* Service Foreground : Le service est bien exécuté en premier plan
* Type d'erreur : EXC_BAD_ACCESS
* Signal : SIGSEV (Segmentation fault)
* Code d'erreur : KERN_INVALID_ADDRESS at 0x0000000000000000

![log_crash](assets/posts/IOS/log_crash.png)

_<div style="text-align: center;">Extrait du fichier des journaux de crash_</div>

Il apparaît que l'application a tenté d'accéder à l'adresse mémoire `0x00`, une pratique couramment utilisée par les applications pour terminer leur exécution. Le programme tente délibérément d'écrire dans des zones de mémoire incorrectes.

De plus, une analyse dynamique des logs systèmes est effectuée. On remarquer que l'application vérifie la présence de fichiers liés au jailbreak.

![image-20250507151756144](assets/posts/IOS/log-jb.png)

_<div style="text-align: center;">Extrait de logs_</div>

On peut en conclure que l’application embarque des mécanismes spécifiques destinés à détecter et à réagir à un environnement jailbreaké. Cependant, les logs ne fournissent qu'un très petit échantillon des éléments véritablement vérifié par l'application pour détecter le jailbreak.

## Obfuscation du code

Afin de mieux cerner la nature de l’application et d’identifier les protections embarquées, nous avons procédé à une analyse statique.

La plupart des méthodes et chaines de caractères du programmes sont chiffrées, ce qui empêche d'identifier les fonctions sensibles et d'intérêt.

![image-20250514101715116](assets/posts/IOS/methodes.png)

_<div style="text-align: center;">Analyse des méthodes avec l'outil pagestuff_</div>

Ces chaines sont déchiffrées à la volée uniquement au moment de leurs utilisations. Le binaire ne révèle aucune chaîne intéressante pouvant nous aider à identifier les mécanismes de détection de jailbreak.

Les différentes fonctions de sécurités mise en place sont donc complémentaire. D'une part, l'obfuscation statique empêche d'accéder aux chaînes de caractères. D'autre part, les mécanismes de protections empêche l'analyse dynamique et provoquent immédiatement le crash de l'application,  ce qui nous empêche de récupérer le contenu de la mémoire du processus et d'y retrouver les chaînes déchiffrées.

### Identification des protections anti-jailbreak

En analysant le code de l'application, il a été possible d'identifier certaines techniques utilisées par l'application pour détecter le jailbreak.

Comme pour la plupart des détections de jailbreak, une première étape consiste en la vérification de la présence d'un fichier, effectuée à l'aide de la fonction `fopen()`.

![fopen2](assets/posts/IOS/fopen2.PNG)

_<div style="text-align: center;">Utilisation de fopen() pour détecter le jailbreak_</div>

En effet, la valeur `&DAT_10367eda0` pointe vers une chaine de caractère correspondant à l'argument `r` du fopen(). 

Quant à la valeur `&DAT_10369c828`, elle correspond au chemin de fichier que le programme tente d'ouvrir. Cependant sa valeur est chiffrée, et il n'est pas possible, dans l'état actuel, de connaître son contenu. En fonction du résultat de l'ouverture de fichier (via la variable `local_27c`), le programme détermine s'il est exécuté dans un environnement de jailbreak ou non. 

Ce schéma de détection se répète de manière récurrente dans le code. Il est également possible de noter l'utilisation de la fonction `utime()` pour identifier un environnement jailbreaké. En effet cette fonction permet de modifier les heures de dernier accès et de modification du fichier. 

![image-20241119162517514](assets/posts/IOS/utime.png)

_<div style="text-align: center;">Alternative de détection de jailbreak avec utime()_</div>

Ainsi, l'application tente de manipuler l'horodatage des fichiers de jailbreak pouvant être présents sur le système afin d'identifier leur présence.

De plus, une méthode de détection plus complexe de jailbreak a pu être identifiée. Cette méthode est particulièrement efficace pour détecter un jailbreak et  consiste à recourir directement à des appels système. L'architecture ARM dispose de l'instruction `SVC` (Supervisor Call). Une application peut ainsi appeler directement l'instruction `SVC` au lieu de s'appuyer sur des bibliothèques, permettant au noyau de vérifier la présence d'un fichier sans passer par des bibliothèques partagées.

Ainsi, les mécanismes de détection moderne utilise les appels système via `SVC 0x80` afin d'éviter de passer par les bibliothèques standards, qui peuvent être instrumentées ou modifiées sur un appareil jailbreaké pour masquer le jailbreak. En accédant directement aux fonctionnalités du noyau, une application peut contourner ces protections et détecter des signes de jailbreak.

Cette utilisation enfreint en principe [les politiques de publication d'applications](https://developer.apple.com/app-store/review/guidelines/#:~:text=Software%20Requirements) sur l'App Store, qui imposent l'utilisation exclusive des API publiques. Néanmoins, Apple semble tolérer cette pratique, et aucune sanction n'a encore été appliquée aux applications qui l'adoptent.

Dans notre cas, nous analysons le programme pour identifier les appels directs à l'instruction `SVC 0x80`.

![SVC_call](assets/posts/IOS/SVC_call.PNG)

_<div style="text-align: center;">Utilisation des appels système via SVC_</div>

De multiples occurrences de l'appel `SVC` sont présentes dans le code, comme montré ci-dessus.

Ces appels ont pour objectif de détecter la présence du jailbreak. Les chaînes de caractères utilisées sont systématiquement chiffrées de manière statique et déchiffrées à la volée.

Pour contourner cette problématique, l'une des approches consiste à remplacer les instructions `SVC` afin d'éviter la vérification. Cependant, une protection de vérification d'intégrité est présente et détecte ce changement tout en provoquant un crash de l'application.

L'objectif à ce stade est de dissimuler la présence des fichiers et répertoires liés au jailbreak aux appels systèmes. L’instrumentation de l’application échoue en raison de protections supplémentaires qui la détectent et bloquent son exécution.

![image-20250514101826234](assets/posts/IOS/frida.png)

_<div style="text-align: center;">Logs de crash lié à Frida_</div>

 Une solution alternative repose sur la modification des `vnodes`. En effet, le noyau utilise des vnodes pour interagir avec le système de fichiers. En modifiant les adresses des vnodes associées aux fichiers de jailbreak, ceux-ci seront dissimulés, empêchant leur accès par le système. De plus, les appels système renverront des résultats normaux, comme "fichier inexistant".

### Fonctionnement des Vnodes 

Afin de mieux comprendre la suite de l'article, un bref résumé du fonctionnement des vnodes est présenté ci-dessous.

Les vnodes (pour **Virtual Node**) sont des objets utilisés dans les systèmes d'exploitation Unix pour représenter des fichiers ou des répertoires dans le système de fichiers. Ils servent de lien entre les appels systèmes des applications et les opérations réalisées sur les systèmes de fichiers sous-jacents (APFS, HFS+, ...).

Leur fonction principale est de permettre au noyau de gérer différents types de systèmes de fichiers (locaux, réseau, ...) via une interface commune. Cela permet à une application, ou au noyau, de ne pas avoir à connaître le système de fichiers avec lequel elle interagit.  

![vnodes](assets/posts/IOS/vnodes.png)

_<div style="text-align: center;">Schéma du fonctionnement des vnodes_</div>

Ainsi, ils servent de point d'entrée pour des opérations telles que l'ouverture de fichiers, la lecture de répertoires ou le changement de permissions.

##  Contournement des appels systèmes 

À travers cette approche, nous souhaitons explorer comment l'exploitation des vnodes peut constituer un outil puissant pour garantir la furtivité de notre jailbreak face aux mécanismes de détection de l'application.

Par ailleurs, un `Tweak` nommé `vnodebypass` a déjà été conçu pour répondre à cette problématique. C'est à partir de celui-ci que nos recherches se concentreront.

### Analyse VnodeBypass

* Outil réalisé par Ichitaso

Le tweak `vnodebypass` sur iOS est conçu pour contourner les mécanismes de détection de jailbreak. Afin de mieux comprendre son fonctionnement et les mécanismes de détection qu'il vise à contourner, nous procéderons à une analyse approfondie de son code source.

Tout d'abord, `vnodebypass` repose sur une liste de fichiers et de répertoires à énumérer, située à l'emplacement `/usr/share/{process_name}/hidePathList.plist`. Par défaut, cette liste contient 70 chemins liés au jailbreak que le tweak cherche à dissimuler.

![image-20241122095224291](assets/posts/IOS/hidePath.png)

_<div style="text-align: center;">Extrait du contenu de hidePathList.plist_</div>

Pour fonctionner, l'application `vnodebypass` utilise deux fonctions principales.

La première, `save_vnode()`, commence par parcourir les vnodes répertoriés dans le fichier `hidePathList.plist`.

![image-20241122104839068](assets/posts/IOS/save_vnode.png)

_<div style="text-align: center;">extrait du code de save_vnode()_</div>

La fonction crée alors un fichier temporaire à l'emplacement `/tmp/vnodeMem.txt`. Elle procède ensuite à l'énumération des différents chemins listés dans `hidePathList.plist` que `vnodebypass` souhaite dissimuler. Le tweak résout l'adresse des chemins présents dans `hidePathList.plist` à l'aide de la fonction `get_vnode_with_file_index()`, puis les sauvegarde dans le fichier temporaire `/tmp/vnodeMem.txt`.

La seconde fonction, `hidevnode()`, récupère chaque adresse de vnode, une par une, à partir du fichier `/tmp/vnodeMem.txt`, et exécute la fonction `hide_path()` pour chacune d'entre elles.

![image-20241120162956236](assets/posts/IOS/vishadow.png)

_<div style="text-align: center;">Utilisation de la fonction hide_path()_</div>

La fonction `hide_path()` lit en mémoire la valeur du champ `v_flag` du vnode qui lui est transmis.

Le champ `v_flag` fait partie de la structure du vnode et sert à stocker des indicateurs décrivant l'état de ce dernier. Ce champ est vérifié lors des opérations d'entrée/sortie effectuées sur le vnode.

Ensuite, la fonction effectue une opération logique `OR` avec la valeur `VISSHADOW` sur le champ `v_flag` du vnode pour lui affecter le nouvel attribut. En effet, `VISSHADOW` permet de spécifier que le vnode est un "*shadow file*". Cette indication signifie que le vnode n'est pas directement lié à un fichier ou répertoire mais à un objet superposé, représentant une copie temporaire ou virtuelle. Le vnode ne pointe alors plus vers la ressource de départ, ce qui empêche le système d'accéder au fichier recherché.

Ainsi, `vnodebypass` atteint son objectif principal en dissimulant aux systèmes les vnodes des fichiers et répertoires spécifiés dans le fichier `hidePathList.plist`.

Cependant, malgré l'installation et l'utilisation du tweak, l'application cible continue de cesser de fonctionner au démarrage, car elle détecte toujours certains éléments liés au jailbreak. Il convient néanmoins de noter que certaines applications, comme l'application bancaire `HSBC UK`, qui détectait auparavant le jailbreak, ne le détecte plus après l'utilisation de `vnodebypass`.

### Modification vnodebypass

Nous avons alors entrepris une recherche des éléments liés au jailbreak présents sur notre appareil afin de les répertorier. Par exemple, nous avons identifié le répertoire `/Library/MobileSubstrate/DynamicLibraries/`, contenant plusieurs bibliothèques partagées (*dylib*) associées au jailbreak.

En parallèle, nous avons également cherché à identifier plusieurs listes noires publiques utilisées par les techniques de détection de jailbreak des applications (notamment dans les domaines des jeux ou des services bancaires), afin de compléter la liste `hidePathList.plist`.

Au terme de nos recherches, nous avons réussi à répertorier plus de 400 éléments uniques potentiellement liés au jailbreak, que nous avons ajoutés au fichier `hidePathList.plist`. Cela permet une dissimulation des vnodes plus large et optimisée, tout en veillant à préserver la fiabilité du système. En effet, les vnodes, étant des objets critiques du noyau, ils doivent être modifiés avec prudence pour éviter tout risque pour le système.

![path_hidepath](assets/posts/IOS/path_hidepath.png)

_<div style="text-align: center;">Modification de la liste des vnodes sur l'appareil_</div>

Ainsi, après avoir modifié la liste sur notre appareil et exécuté le tweak `vnodebypass`, notre application de test a pu se lancer avec succès dans l'environnement jailbreaké. De plus, toutes les applications installées parallèlement permettant d'évaluer la détection de jailbreak (telles que Pokémon Go, HSBC UK, PayPal, etc.) ont également pu être contournées grâce à cette modification du tweak.

En effet, dans sa configuration par défaut, `vnodebypass` ne permettait pas de contourner les mécanismes de détection de toutes ces applications.

Désormais, il nous est possible d'exécuter notre application cible dans un environnement jailbreaké et d'exercer des actions tel qu'un dump de la mémoire du processus. 

![image-20241121113823653](assets/posts/IOS/dump.png)

_<div style="text-align: center;">Dump mémoire du processus_</div>

Cette extraction permet d'accéder à de nombreuses informations sensibles, y compris des données déchiffrées de l'application.

### Conclusion

Après avoir analysé l’application et menés quelques recherches, nous avons pu comprendre le fonctionnement des mécanismes de détection de jailbreak ainsi qu’une méthode efficace pour les contourner. Malgré tout, la protection est jugé robuste. Son efficacité réside dans le fait de ne pas connaitre les valeurs chiffrées présente dans l'application. De plus, elle intègre d'autres mécanismes de sécurités tel que l'anti-debugger. Nous approfondirons leurs analyses dans les prochains articles. 

Les améliorations apportées à la liste des vnodes du `Tweak vnodebypass` seront publiées sur le Github de [d'Oppida](https://github.com/oppida).

Enfin, vous trouverez en annexe une liste non exhaustives de certaines valeurs récupérées dans le dump mémoire utilisées par le RASP lors de la détection de jailbreak.

#### Annexe

![image-20241120171906072](assets/posts/IOS/annexe.png)

_<div style="text-align: center;">Fichiers et répertoires utilisés pour la détection de jailbreak_</div>
