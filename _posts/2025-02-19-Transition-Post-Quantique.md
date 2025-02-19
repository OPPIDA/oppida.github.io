---
title: Bien gérer la transition post-quantique de son produit certifié
date: 2025-02-19
categories: [Articles, Cryptographie]
tags: []
comments: false
description: L'avènement de l'ordinateur quantique menace déjà les produits actuels.
author: [PAN, ERI, CLE]
math: false
image:
  path: /assets/posts/2025-02-19-Transition-Post-Quantique/qubits.jpg
---

Les progrès réalisés dans le domaine de l'informatique quantique représentent une menace pour la cryptographie déployée actuellement sur nos systèmes d'information.

La menace est déjà présente : dès aujourd'hui, il est possible d'intercepter et stocker la plupart des communications HTTPS, SSH, IKE et bien d'autres, afin de pouvoir les déchiffrer à l'avènement d'un ordinateur quantique suffisamment puissant[^store-now]. L'arrivée d'un tel ordinateur quantique (abrégé en CRQC, pour *Cryptographically Relevant Quantum Computer*) est considérée réaliste à moyen terme par les experts.

> Le [BSI estime conservativement][BSI_CRQC_REPORT] la réalisation d'un CRQC d'ici 16 ans.
>
> La dernière [étude du GRI][QUANTUM_THREAT] conclut à une "chance significative" dans les 10 prochaines années.
{: .prompt-warning}

La cryptographie post-quantique (PQC) consiste en l'utilisation d'algorithmes différents qui résistent aux ordinateurs quantiques ; en plus de toujours résister aux ordinateurs classiques. 

Pour protéger les données actuelles, certains acteurs majeurs la prennent déjà en compte, par exemple :
- Cloudflare : depuis le support par défaut sur Chrome de la PQC, [~30% des requêtes vers Cloudflare utilisent la PQC hybride][CLOUDFLARE],
- iMessage (Apple) avec [PQ3][IMESSAGE],
- Signal avec [PQXDH][SIGNAL],
- OpenSSH à partir de la [version 9.0][OPENSSH],
- IKE avec les [Multiple Key Exchanges][IKE].

Les certifications aussi évoluent : [fin janvier][INFINEON], Infineon a annoncé la certification Common Criteria EAL6 d'un contrôleur de sécurité mettant en oeuvre un algorithme post-quantique.

Les principaux algorithmes post-quantique aujourd'hui considérés sont ceux standardisés par le NIST à l'issue d'une [sélection qui s'est déroulée de 2016 à 2022][NIST_PQC].

Pour toutes ces raisons, [en 2022][AVIS_ANSSI] l'ANSSI a mis en place un plan de transition à la cryptographie post-quantique qui prévoit son intégration dans les visas de sécurité. Plus précisément, l'ANSSI prévoit une transition en trois phases :

> - *Phase 1 (aujourd’hui) : hybridation pour fournir une défense en profondeur post-quantique supplémentaire à l’assurance de sécurité pré-quantique.*
> - *Phase 2 (probablement après 2025) : hybridation pour fournir une assurance de sécurité post-quantique tout en évitant toute régression de sécurité pré-quantique.*
> - *Phase 3 (probablement après 2030) : hybridation optionnelle.*

Concrètement pour l'ANSSI, la phase 2 constitue la délivrance de visas de sécurité reconnaissant la présence de protections post-quantique à l'état de l'art dans des produits. [Fin 2023][ADDENDUM_AVIS_ANSSI], l'ANSSI a déclaré accélérer son agenda pour entamer cette phase plus tôt, vers 2024-2025.

C'est pourquoi, dans cet article, nous allons présenter les différents aspects techniques liés à l'intégration de la cryptographie post-quantique dans les systèmes d'information. Notre article se base principalement sur les deux notes de l'ANSSI ([2022][AVIS_ANSSI] et [2023][ADDENDUM_AVIS_ANSSI]) ainsi que sur notre expertise.

## Protéger les données actuelles

> **Points à retenir**
>
> - De nouveaux algorithmes, les KEM post-quantique, peuvent remplacer les algorithmes actuels menacés.
> - Ils doivent absolument être combinés aux algorithmes actuels, par hybridation, pour éviter une régression.
> - Réaliser l'hybridation de façon sécurisée n'est pas évident, et doit être fait avec une méthode reconnue. 
{: .prompt-tip}

De nos jours, les données sont généralement protégées en confidentialité par chiffrement symétrique, à l'aide d'un algorithme comme AES. Un algorithme de chiffrement à clé publique comme RSA ou d'échange de clé comme Diffie-Hellman, moins performant, est utilisé en amont pour que les deux parties s'accordent sur une même clé symétrique afin d'échanger en sécurité ; sans qu'un observateur puisse retrouver la clé symétrique et déchiffrer.

Ce sont essentiellement ces mécanismes de distribution de clé qui sont ici menacés par un ordinateur quantique, qui peut permettre de retrouver la clé symétrique en observant les échanges. Ils doivent donc être remplacés. Les acteurs majeurs cités précédemment utilisent tous un KEM post-quantique pour établir leurs clés de session.

### Mécanismes d'encapsulation de clé (KEM)

Les principaux remplaçants de ces algorithmes sont des mécanismes d'encapsulation de clé (KEM, pour *Key Encapsulation Mechanism*). Il s'agit d'un mécanisme qui permet d'encapsuler une clé symétrique (en la chiffrant avec la clé publique) et de la décapsuler (en la déchiffrant avec la clé privée). Contrairement au chiffrement à clé publique classique, où l'on chiffre des données de son choix, un KEM chiffre uniquement une clé symétrique aléatoire.

![](assets/posts/2025-02-19-Transition-Post-Quantique/kem.png)
_Usage d'un KEM. La même clé symétrique k est obtenue par les deux participants._

> L'illustration ci-dessus ne constitue pas un protocole sécurisé et ne devrait pas être utilisée telle quelle. La clé publique doit être authentifiée.
{: .prompt-danger}

Cette formalisation du KEM est privilégiée par le NIST car elle permet l'essentiel des usages concrets du chiffrement à clé publique : partager une clé symétrique ; tout en permettant assez facilement d'offrir un meilleur niveau de sécurité. Les candidats à la [sélection du NIST][NIST_PQC], et son vainqueur, ont dû suivre ce format dans leurs spécifications.

### Hybridation

Les KEM post-quantique peuvent remplacer les algorithmes actuels. Pour autant, ces algorithmes sont encore nouveaux et moins étudiés, et n'ont pas encore fait leurs preuves dans la durée. Il est aujourd'hui toujours envisageable que de nouvelles attaques aux conséquences graves soient trouvées contre ces derniers, et ce même après leur standardisation et utilisation dans l'industrie. 

> Le KEM SIKE offre de très bonnes performances et a été un candidat important des cinq ans de sélection NIST dont il est finaliste et membre du tour additionnel. Il a été [cassé en 2022][SIKE_BROKEN], son paramétrage le plus fort résiste désormais [à peine une heure][SIKE_GITHUB] à un ordinateur portable.
{: .prompt-info}

De plus, non seulement les algorithmes doivent être sécurisés, mais également leurs implémentations. Celles-ci doivent résister à une surface d'attaque plus grande que celle couverte par la théorie. De nos jours, les algorithmes classiques courants disposent de nombreuses implémentations relativement éprouvées dans divers écosystèmes, tandis que les implémentations des algorithmes post-quantique sont encore récentes, rares, et moins étudiées.

> Des implémentations de référence, conçues par les auteurs des algorithmes, ont déjà pu faire l'objet d'attaques. Par exemple par canal auxiliaire de temps contre [FrodoKEM en 2020][FRODO_FO] ou [ML-KEM en 2024][KYBERSLASH].
{: .prompt-info}

Il est donc crucial de s'assurer que la transition à des algorithmes post-quantique n'abaisse pas le niveau de sécurité des systèmes actuels. Un remplacement unilatéral des algorithmes classiques s'exposerait gravement à d'éventuelles percées cryptanalytiques.

> La cryptomonnaie Abcmint s'est historiquement reposée sur la signature post-quantique Rainbow, uniquement. Celle-ci a été [cassée en 2022][RAINBOW_BROKEN], et [des chercheurs ont alors pu retrouver la clé privée d'une adresse][BREAKING_ABC], qui peut permettre de forger des transactions. 
{: .prompt-info}

Pour réaliser la transition sans introduire de régression, l'approche [actuellement privilégiée par l'ANSSI][ADDENDUM_AVIS_ANSSI] et de nombreux autres acteurs du domaine, appelée *hybridation*, consiste à combiner un algorithme classique (vulnérable à une attaque quantique mais éprouvé par le temps) avec un algorithme post-quantique (résistant à une attaque quantique mais moins éprouvé). Cette hybridation est faite de telle sorte que si l'un des deux schémas cède, leur combinaison reste sécurisée.

L'impact sur la performance de l'approche hybride est souvent faible comparé à un algorithme post-quantique seul, étant donné que ce dernier est généralement moins performant que les alternatives classiques, et constitue donc l'essentiel du coût dans l'approche hybride.

> Lors d'une connexion HTTPS utilisant X25519MLKEM768, qui combine le mécanisme classique X25519 (ECDH) au mécanisme post-quantique ML-KEM-768, les données cryptographiques échangées pour X25519 représentent [moins de 3%][MLKEM_VS_X25519] du total échangé pour les deux mécanismes en hybridation.  
{: .prompt-info}

#### Modes d'hybridation

L'hybridation de KEM repose sur l'échange de deux clés en parallèle : l'un est réalisé avec un KEM pré-quantique, l'autre avec un KEM post-quantique. L'objectif est ensuite de combiner ces deux clés symétriques obtenus tout en garantissant que la clé combinée reste secrète même si l'un des deux KEM venait à être compromis.

> Attention, les deux modes ci-dessous ne devraient pas être utilisés.
{: .prompt-danger }

##### Concaténation

Une première idée naïve serait de concaténer les deux clés symétriques pour en créer une autre. Bien qu'intuitive, cette méthode a un grave problème : si un des deux KEM est vulnérable, alors il sera possible de connaître la moitié de la clé, ce qui réduit considérablement les possibilités, et risque d'invalider certaines hypothèses nécessaires à la sécurité.

##### XOR 

On peut essayer de corriger le problème du mode précédent en faisant un XOR entre les deux clés plutôt qu'une concaténation. En effet, cela résout le problème du mode précédent : il faut toujours trouver l'intégralité de la deuxième clé, si la première fuite, pour compromettre l'intégralité de la clé combinée. Le niveau de sécurité atteint par ce mode est cependant insuffisant à celui offert par les KEM utilisés et généralement considéré insuffisant ; il est en particulier vulnérable aux attaques adaptatives dites "Mix and Match".

> Réaliser une hybridation de façon sécurisée n'est donc pas complètement évident. Des modes offrant une meilleure sécurité, standardisés, et repris par l'ANSSI, sont présentés dans [un article séparé](/posts/Hybridation-Post-Quantique/).
{: .prompt-tip }

## Protéger les systèmes futurs

> **Points à retenir**
>
> - De nouveaux algorithmes de signature peuvent remplacer les actuels menacés.
> - Ils doivent absolument être combinés aux algorithmes actuels, par hybridation, pour éviter une régression.
> - Il n'est pas encore universellement déterminé comment transitionner les infrastructures à clés publiques et certificats.
{: .prompt-tip}

Nous avons vu précédemment comment les KEM post-quantique pouvaient être déployés en hybridation avec les algorithmes actuels pour protéger les communications actuelles. Cependant, ceci ne répond pas à toutes les menaces posées par un ordinateur quantique suffisamment puissant (CRQC).

Un futur attaquant avec un CRQC à sa disposition pourrait non seulement déchiffrer les communications passées et présentes, mais aussi : 

- usurper des identités,
- dynamiquement intercepter et manipuler des communications.

Ces attaques sont évitées par une assurance cryptographique d'authenticité. De nos jours, celle-ci est le plus souvent réalisée à l'aide d'algorithmes de signature électronique, intégrée à des mécanismes plus larges comme les certificats et infrastructures à clés publiques (PKI). Et un CRQC est capable de casser les mécanismes de signature classiques.

> Les exemples de Cloudflare, iMessage et les autres cités précédemment sont toujours sujets à cette menace quantique : ils ne font actuellement qu'intégrer un KEM post-quantique, mais se reposent toujours sur des signatures classiques.
>
> Rien n'empêcherait[^pq-attack] quelqu'un avec un CRQC sous la main d'intercepter et manipuler le trafic que ces protocoles sécurisent. 
{: .prompt-warning}

De même que les KEM post-quantique, il existe désormais plusieurs algorithmes de signature qui sont considérés post-quantique, et ils peuvent être utilisés en hybridation avec les algorithmes actuels pour répondre à cette menace.

> Plus d'informations sur l'hybridation sécurisée de signatures est présentée dans [un article séparé](/posts/Hybridation-Post-Quantique/).
{: .prompt-tip }

## Certifier sans hybridation ?

> **Points à retenir**
>
> - Un produit final doit obligatoirement hybrider sa cryptographie post-quantique pour viser un visa de sécurité.
> - Un produit intermédiaire, comme une bibliothèque logicielle ou un coprocesseur cryptographique, peut être certifié en exposant de la cryptographie post-quantique sans hybridation ; à la condition de recommander expressément l'hybridation à l'utilisateur final.
{: .prompt-tip}

Nous avons vu qu'il est fortement recommandé de déployer des algorithmes post-quantique en hybridation, car ces derniers sont pour la plupart encore trop peu éprouvés pour être utilisés seuls. [Pour un visa de sécurité de l'ANSSI, c'est même obligatoire][AVIS_ANSSI] :

> *Phase 2 : l’ANSSI pourra délivrer des visas de sécurité assurant une sécurité à long terme pré-quantique et éventuellement post-quantique (toujours avec hybridation obligatoire)*

> L'exception qui confirme la règle est la famille des signatures basées sur les fonctions de hachage. Celles-ci sont considérés éprouvées, et leur hybridation est facultative. C'est notamment le cas de [SLH-DSA](#slh-dsa).
{: .prompt-info}

À long terme, une fois que les algorithmes auront été suffisamment éprouvés par l'usage, l'obligation d'hybridation devrait devenir optionnelle pour l'ANSSI :

> *Phase 3 (probablement après 2030) : hybridation optionnelle.*

Ces obligations portent sur la sécurité d'un produit ou système final. Ainsi, il n'est pas strictement nécessaire que toutes ses composantes exposent exclusivement de la cryptographie post-quantique hybride, tant qu'une hybridation est à terme réalisée par une couche supérieure.

C'est pourquoi l'ANSSI permet explicitement la délivrance de visas de sécurité à des produits dits produits intermédiaires ou produits-plateforme, qui mettraient à disposition d'un produit final des algorithmes post-quantique sans hybridation.

Afin de bénéficier de ce scénario, il reste obligatoire d'encourager l'hybridation, et un tel produit devrait donc dans ses différents guides utilisateur explicitement recommander que ses mécanismes post-quantique soient exclusivement utilisés en hybridation. De plus lors de l'évaluation précédant la certification, les évaluateurs devront se voir fournis un exemple d'application qui utilise ces mécanismes du produit en hybridation.

## Les algorithmes

De nombreux algorithmes sont aujourd'hui considérés comme des alternatives post-quantique aux chiffrements à clé publique et algorithmes de signature actuels. Utilisant des techniques voire des mathématiques assez différentes, et spécifiés avec divers paramétrages, ils présentent des compromis variés :

- niveau de sécurité visé,
- taille de clé publique,
- taille de chiffré ou signature,
- taille de clé secrète,
- temps d'exécution des différentes opérations,
- nombre maximal d'utilisations d'une clé,
- usage de clés éphémères,
- exemption d'hybridation possible,
- complexité d'implémentation sécurisée,
- contraintes opérationnelles particulières,
- standardisé, et recommandé par l'ANSSI, le BSI, le NIST...
- etc.

En conséquence il est ardu de les comparer exhaustivement sans considérer des contraintes en particulier. De plus, l'ANSSI s'attache à ne pas fournir de liste fermée d'algorithmes autorisés ou non. Pour autant, on peut déjà identifier les principaux algorithmes à considérer.

Tous les algorithmes présentés plus loin sont repris par l'ANSSI [dans son avis officiel][ADDENDUM_AVIS_ANSSI], où ils font l'objet de premières recommandations importantes, certaines trop techniques pour être rappelées dans cet article.

### Mécanismes d'encapsulation de clé (KEM)

Les deux principaux algorithmes à considérer et [repris par l'ANSSI][ADDENDUM_AVIS_ANSSI] sont basés sur les réseaux euclidiens. ML-KEM est le vainqueur de la [sélection du NIST][NIST_PQC], et FrodoKEM un candidat plus conservateur mais moins performant.

#### ML-KEM

Initialement connu sous le nom de CRYSTALS-Kyber, ce schéma a été standardisé par le NIST dans [FIPS 203][FIPS_203], dont la version finale a été publiée en août 2024. Il s'agit du seul et unique KEM standardisé par le NIST. Il devrait donc être utilisé dans la majorité des scénarios.

#### FrodoKEM

Ce schéma est une variante plus conservatrice de ML-KEM : le problème mathématique sous-jacent a lieu dans un réseau non structuré, et donc plus sûr en théorie. Cet avantage de sécurité se paye dans la performance et la taille des clés. Il est en cours de standardisation par ISO/IEC JTC 1/SC 27/WG 2, et sa [dernière spécification][ISO_FRODO] est donc encore préliminaire.

Ces deux standards définissent trois paramétrages de niveaux[^niveau-nist] 1, 3 et 5, et [l'ANSSI recommande préférablement le niveau 5, ou le niveau 3][ADDENDUM_AVIS_ANSSI].

---

Le schéma suivant illustre les dimensions des deux schémas, vis-à-vis de celles du schéma classique ECDH instancié avec la courbe NIST P-521.

![alt text](assets/posts/2025-02-19-Transition-Post-Quantique/enc_sizes.png)
_Comparaison des dimensions de KEM au niveau[^niveau-nist] de sécurité 5. Les tailles sont en octets._

Ce graphique se veut seulement illustratif. En particulier, les dimensions indiquées pour les clés privées seront amenées à varier en pratique, pouvant être stockées en moins d'espace, et ayant une plus grande empreinte à l'utilisation.

### Signatures

Comme suggéré précédemment, la situation des signatures est plus complexe. Différents algorithmes offrent différents avantages et inconvénients sans un clair gagnant pour toutes les situations. Comme la menace est également moins urgente, de nouvelles approches continuent d'être proposées. Le NIST conduit d'ailleurs [un processus de standardisation d'algorithmes supplémentaires pour la signature][NIST_ADD_SIG], dont le deuxième tour annoncé en octobre 2024 en compte encore 14 soumis à l'évaluation. Néanmoins comme pour les KEM, on peut identifier les principaux qui peuvent aujourd'hui être déployés dans la plupart des systèmes :

#### ML-DSA

Initialement connu sous le nom de CRYSTALS-Dilithium, ce schéma a été standardisé par le NIST dans [FIPS 204][FIPS_204], dont la version finale a été publiée en août 2024. Issu de la même suite que ML-KEM, il devrait être utilisé pour la plupart des besoins de signature.

Le standard définit trois paramétrages de niveaux[^niveau-nist] 2, 3 et 5, et [l'ANSSI recommande préférablement le niveau 5, ou le niveau 3][ADDENDUM_AVIS_ANSSI].

#### FN-DSA

Initialement connu sous le nom de Falcon, ce schéma est en cours de standardisation par le NIST pour être à terme défini dans FIPS 206 ; pour l'heure, sa dernière spécification est [sur le site de ses créateurs][FALCON_SPEC]. Ce schéma offre de très bonnes performances à la fois en taille des clés et signatures, mais aussi en vitesse. Sa mise en œuvre est cependant complexe, ce qui explique pourquoi le draft du futur standard n'a toujours pas été publié, deux ans après son annonce et alors que les trois autres standards annoncés en même temps ont déjà été finalisés en août 2024. Le schéma est de plus particulièrement difficile à sécuriser contre les attaques par canaux auxiliaires, auxquelles il est très sensible, ce qui devrait être pris en compte avant de le déployer dans des produits où elles sont considérées, tels que les produits embarqués.

Le standard ne définit que deux paramétrages de niveaux[^niveau-nist] 1 et 5, et [l'ANSSI ne recommande que le niveau 5][ADDENDUM_AVIS_ANSSI].

#### SLH-DSA

Initialement connu sous le nom de SPHINCS+, ce schéma a été standardisé par le NIST dans [FIPS 205][FIPS_205], dont la version finale a été publiée en août 2024. Pour chaque niveau de sécurité, deux paramétrages standards existent, l'un optimisant la taille des signatures (**s**hort), l'autre la vitesse de signature (**f**ast).

À la différence des deux schémas précédents, basés sur les réseaux euclidiens, ce schéma est plutôt basé sur la sécurité des fonctions de hachage. À ce titre, cette famille d'algorithmes étant considérée éprouvée, son hybridation est facultative. Cette différence explique aussi ses tailles différentes : une très petite clé publique et de très grandes signatures.

Le standard définit trois ensembles de paramétrages de niveaux[^niveau-nist] 1, 3 et 5, et [l'ANSSI ne recommande que le niveau 5][ADDENDUM_AVIS_ANSSI].

#### XMSS et LMS

Ces deux schémas similaires ont été spécifiés par l'IRTF dans [RFC 8391][RFC8391] en mai 2018 et [RFC 8554][RFC8554] en avril 2019, et font l'objet de spécifications additionnelles par le NIST dans [SP 800-208][SP_800_208]. Ils peuvent être vus comme des versions plus simples de SLH-DSA, permettant de meilleures performances et mieux paramétrables selon leur besoin d'utilisation.

Contrairement à tous les schémas précédents, ils ont l'important problème de devoir maintenir un état interne qui évolue au fur et à mesure des signatures, et dont l'intégrité est absolument critique pour leur sécurité. Ces schémas peuvent être adaptés dans des contextes où très peu de signatures sont réalisées, et générées dans un environnement très contrôlé ; la signature de paquets de mise à jour est un exemple d'application potentielle.

Les spécifications de ces schémas permettent une multitude de paramétrages, et l'ANSSI recommande d'utiliser le niveau de sécurité le plus haut possible. Les définitions exactes qui répondent à ce critère sont trop techniques pour cet article. 

Etant donné leurs contraintes particulières et leur multitude de paramétrages possibles, ces algorithmes sont omis du graphique qui suit ; essentiellement, leurs dimensions sont comparables à celles de SLH-DSA.

---

Le schéma suivant illustre les dimensions des trois premiers schémas, vis-à-vis de celles du schéma classique ECDSA instancié avec la courbe NIST P-521.

![alt text](assets/posts/2025-02-19-Transition-Post-Quantique/sig_sizes.png)
_Comparaison des dimensions de schémas de signature au niveau[^niveau-nist] de sécurité 5. Les tailles sont en octets._

Ce graphique se veut seulement illustratif. En particulier, les dimensions indiquées pour les clés privées seront amenées à varier en pratique, pouvant être stockées en moins d'espace, et ayant une plus grande empreinte à l'utilisation par certains algorithmes.

## La cryptographie symétrique (chiffrement et hachage)

> **Points à retenir**
>
> La menace quantique ne pèse pas autant sur la cryptographie symétrique.
>
> Il est encouragé d'utiliser :
> - un chiffrement symétrique au moins aussi robuste que AES-256, soit des clés de 256 bits ou plus.
> - une fonction de hachage au moins aussi robuste que SHA-384, soit des empreintes de 384 bits ou plus.
>
> Une hybridation peut être réalisée via des clés pré-partagées.
{: .prompt-tip}

Nous avons jusqu'ici seulement parlé de remplacer les algorithmes de chiffrement à clé publique, d'échange de clé ou encore de signature ; tous sont dits *asymétriques*. Qu'en est-il de la cryptographie dite *symétrique* ?

Des ordinateurs quantiques suffisamment puissants pourraient théoriquement aussi attaquer la cryptographie symétrique un peu plus efficacement que des ordinateurs classiques. Moins dévastatrice et plus incertaine, l'ampleur de cette potentielle menace ne fait actuellement pas consensus parmi les experts ; plusieurs estimations actuelles des coûts ([1][GROVER_1], [2][GROVER_2]) avec les méthodes aujourd'hui connues en informatique quantique conduisent à des attaques quantiques du même ordre que les attaques classiques, et les méthodes pour dériver ces estimations pourraient à l'avenir changer de façon moins prévisible.

En conséquence, l'ANSSI a adopté [la position suivante][ADDENDUM_AVIS_ANSSI] :

>  *Par mesure de prudence, l'ANSSI encourage également à dimensionner les paramètres des primitives symétriques de manière à assurer une sécurité post-quantique conjecturée.*

Le dimensionnement encouragé étant :
- au moins le même niveau de sécurité que AES-256 pour le chiffrement ; 
- au moins le même niveau de sécurité que SHA-384 pour les fonctions de hachage.

Le [BSI émet le même encouragement][BSI_SIZE] pour les systèmes avec des besoins élevés ou long-terme de protection, ou destinés à opérer longtemps, et le [NIST n'émet pas cet encouragement][NIST_SIZE].

### Clés pré-partagées (PSK)

Plutôt que de déployer un tout nouvel algorithme post-quantique, une autre possibilité pour se prémunir des ordinateurs quantiques est l'hybridation d'un algorithme classique avec à une clé pré-partagée (PSK).

Cette technique garantit une résistance post-quantique, car repose sur le paradigme de la cryptographie symétrique moins impactée par les CRQC, et en fonction du contexte cette technique peut être une bonne idée. Cependant, [l'ANSSI émet les avertissements suivants][ADDENDUM_AVIS_ANSSI] : 

> *1. La confidentialité et l'intégrité de la clé pré-partagée sont des conditions préalables essentielles.*
>
> *2. Chaque clé pré-partagée ne doit être partagée que par deux parties et non pas par un groupe de trois parties ou plus.*
>
> *3. La confidentialité parfaite dans le temps (abrégé par PFS en anglais) n'est pas garantie contre les adversaires quantiques (car la sécurité reposera sur un secret long-terme).*

L'absence de PFS de cette approche signifie que la moindre compromission de la PSK par un adversaire ayant un CRQC lui permettrait de déchiffrer toutes les communications passées. Le même problème a causé la suppression des suites `TLS_RSA` dans TLS 1.3, qui en souffraient également.

Comme expliqué précédemment, des méthodes particulières d'hybridation doivent être employées et correctement implémentées pour garantir la sécurité de cette approche, et sa résilience en cas de compromission de l'un des deux mécanismes.

> Plus d'informations sur l'usage et l'hybridation de clés pré-partagées à des fins post-quantique sont présentées dans [un article séparé](/posts/Hybridation-Post-Quantique/).
{: .prompt-tip}

---

![](/assets/LOGO_RECT.jpg){: width="200em" .w-40 .right}
En tant que CESTI agréé par l'ANSSI et cabinet indépendant d'audits et de conseil, Oppida peut vous accompagner dans la transition post-quantique de vos produits, et les évaluer afin que l'ANSSI les certifie. [Contactez-nous !](javascript:location.href%20=%20'mailto:'%20+%20%5B'commercial','oppida.fr'%5D.join('@'))

## Références

[//]: # "NOTE: pas grave de changer les numéros dans le code, seul l'ordre compte"

1. [Status of quantum computer development][BSI_CRQC_REPORT], BSI, août 2024
1. [Quantum Threat Timeline Report 2024][QUANTUM_THREAT], Global Risk Institute, décembre 2024
2. [Post-Quantum Cryptography Standardization][NIST_PQC], NIST, janvier 2017
3. [Adoption & Usage][CLOUDFLARE], Cloudflare
4. [iMessage with PQ3: The new state of the art in quantum-secure messaging at scale][IMESSAGE], Apple, février 2024
5. [The PQXDH Key Agreement Protocol][SIGNAL], Signal, mai 2023
6. [openssh.com/txt/release-9.0][OPENSSH], OpenSSH, avril 2022
7. [Multiple Key Exchanges in the Internet Key Exchange Protocol Version 2 (IKEv2)][IKE], IETF, mai 2023
8. [Infineon and the BSI pave the way for a quantum-resilient future: World's first Common Criteria Certification for post-quantum cryptography algorithm on a security controller][INFINEON], Infineon, janvier 2025
9. [Avis scientifique et technique de l’ANSSI sur la migration vers la cryptographie post-quantique][AVIS_ANSSI], ANSSI, avril 2022
10. [Avis de l'ANSSI sur la migration vers la cryptographie post-quantique (suivi 2023)][ADDENDUM_AVIS_ANSSI], ANSSI, décembre 2023
11. [The SIKE teams acknowledges that SIKE and SIDH are insecure and should not be used][SIKE_BROKEN], sike.org, septembre 2022
12. [Castryck-Decru Key Recovery Attack on SIDH][SIKE_GITHUB], G. Pope, août 2022
13. [Breaking Rainbow Takes a Weekend on a Laptop][RAINBOW_BROKEN], W. Beullens, juin 2022
14. [Breaking Abcmint using Beullens' attack on Rainbow][BREAKING_ABC], M. J. Kannwischer, juillet 2022
15. [The state of the post-quantum Internet][MLKEM_VS_X25519], Cloudflare, mars 2024
16. [Module-Lattice-Based Key-Encapsulation Mechanism Standard][FIPS_203], NIST, août 2024
17. [Module-Lattice-Based Digital Signature Standard][FIPS_204], NIST, août 2024
18. [Stateless Hash-Based Digital Signature Standard][FIPS_205], NIST, août 2024
19. [FrodoKEM: Learning With Errors Key Encapsulation Preliminary Standardization Proposal][ISO_FRODO], frodokem.org, décembre 2024
19. [Submission Requirements and Evaluation Criteria for the Post-Quantum Cryptography Standardization Process][NIST_CFP], NIST, décembre 2016
20. [Post-Quantum Cryptography: Additional Digital Signature Schemes][NIST_ADD_SIG], NIST, août 2022
21. [Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU][FALCON_SPEC], falcon-sign.org, décembre 2020
22. [XMSS: eXtended Merkle Signature Scheme][RFC8391], IRTF, mai 2018
23. [Leighton-Micali Hash-Based Signatures][RFC8554], IRTF, avril 2019
24. [Recommendation for Stateful Hash-Based Signature Schemes][SP_800_208], NIST, octobre 2020
25. [Implementing Grover Oracles for Quantum Key Search on AES and LowMC][GROVER_1], EUROCRYPT, mai 2020
26. [On the practical cost of Grover for AES key recovery][GROVER_2], NCSC, mars 2024
27. [Cryptographic Mechanisms: Recommendations and Key Lengths][BSI_SIZE], BSI, février 2024
28. [To protect against the threat of quantum computers, should we double the key length for AES now?][NIST_SIZE], NIST, novembre 2018

[//]: # "NOTE: Markdown non présenté à partir de cette ligne"

[//]: # "NOTE: Acronymes"

*[CRQC]: Cryptographically Relevant Quantum Computer
*[PQC]: Post-Quantum Cryptography
*[KEM]: Key Encapsulation Mechanism
*[PKI]: Public Key Infrastructure
*[PSK]: Pre-Shared Key

[//]: # "NOTE: Liens utilisés à travers le texte"

[BSI_CRQC_REPORT]: https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Quantentechnologien-und-Post-Quanten-Kryptografie/Entwicklungsstand-Quantencomputer/entwicklungsstand-quantencomputer_node.html
[QUANTUM_THREAT]: https://globalriskinstitute.org/publication/2024-quantum-threat-timeline-report/

[NIST_PQC]: https://csrc.nist.gov/pqc-standardization

[CLOUDFLARE]: https://radar.cloudflare.com/adoption-and-usage
[IMESSAGE]: https://security.apple.com/blog/imessage-pq3/
[SIGNAL]: https://signal.org/docs/specifications/pqxdh/
[OPENSSH]: https://www.openssh.com/txt/release-9.0
[IKE]: https://www.rfc-editor.org/rfc/rfc9370.txt

[INFINEON]: https://www.infineon.com/cms/en/about-infineon/press/press-releases/2025/INFCSS202501-043.html

[AVIS_ANSSI]: https://cyber.gouv.fr/publications/avis-de-lanssi-sur-la-migration-vers-la-cryptographie-post-quantique
[ADDENDUM_AVIS_ANSSI]: https://cyber.gouv.fr/publications/avis-de-lanssi-sur-la-migration-vers-la-cryptographie-post-quantique-0

[SIKE_BROKEN]: https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/submissions/sike-team-note-insecure.pdf
[SIKE_GITHUB]: https://github.com/GiacomoPope/Castryck-Decru-SageMath

[KYBERSLASH]: https://kyberslash.cr.yp.to
[FRODO_FO]: https://eprint.iacr.org/2020/743

[RAINBOW_BROKEN]: https://eprint.iacr.org/2022/214.pdf
[BREAKING_ABC]: https://github.com/mkannwischer/breaking-abc

[MLKEM_VS_X25519]: https://blog.cloudflare.com/pq-2024/#ml-kem-versus-x25519

[FIPS_203]: https://doi.org/10.6028/NIST.FIPS.203
[FIPS_204]: https://doi.org/10.6028/NIST.FIPS.204
[FIPS_205]: https://doi.org/10.6028/NIST.FIPS.205

[ISO_FRODO]: https://frodokem.org/files/FrodoKEM_standard_proposal_20241205.pdf

[NIST_CFP]: https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/call-for-proposals-final-dec-2016.pdf

[NIST_ADD_SIG]: https://csrc.nist.gov/projects/pqc-dig-sig/

[FALCON_SPEC]: https://falcon-sign.info/falcon.pdf

[FALCON_COMPRESS]: https://falcon-sign.info/

[RFC8391]: https://datatracker.ietf.org/doc/html/rfc8391
[RFC8554]: https://datatracker.ietf.org/doc/html/rfc8554
[SP_800_208]: https://doi.org/10.6028/NIST.SP.800-208

[GROVER_1]: https://doi.org/10.1007/978-3-030-45724-2_10
[GROVER_2]: https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/on-practical-cost-of-grover.pdf

[BSI_SIZE]: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile
[NIST_SIZE]: https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs#question_LVQL

[//]: # "NOTE: inutilisé"

[RFC5487]: https://datatracker.ietf.org/doc/html/rfc5487
[RFC5489]: https://datatracker.ietf.org/doc/html/rfc5489
[TLS13_PSK]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9

[ETSI_KDF]: https://www.etsi.org/deliver/etsi_ts/103700_103799/103744/01.01.01_60/ts_103744v010101p.pdf#%5B%7B%22num%22%3A55%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C381%5D
[ETSI_SIG]: https://www.etsi.org/deliver/etsi_tr/103900_103999/103966/01.01.01_60/tr_103966v010101p.pdf#%5B%7B%22num%22%3A82%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C676%5D
[ETSI_SIG_ID]: https://www.etsi.org/deliver/etsi_tr/103900_103999/103966/01.01.01_60/tr_103966v010101p.pdf#%5B%7B%22num%22%3A82%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22FitH%22%7D%2C261%5D


[//]: # "NOTE: Notes de bas de page"

[^store-now]: Le nom de cette méthode est *store now, decrypt later*.
[^pq-attack]: Certains de ces protocoles supportent l'usage de clés pré-partagées (PSK) à fin d'authentification, qui peut constituer un moyen de déjouer cette attaque.
[^niveau-nist]: Pour [sa sélection][NIST_PQC], le NIST a défini 5 niveaux pour les algorithmes post-quantique dans son [appel à propositions][NIST_CFP]. Les niveaux 1,3,5 doivent nécessiter autant d'efforts qu'essayer toutes les clés AES-128, AES-192 et AES-256 par force brute, et les niveaux 2 et 4 doivent nécessiter autant d'efforts que la recherche d'une collision SHA-256 et SHA-384.