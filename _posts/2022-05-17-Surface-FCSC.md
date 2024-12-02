---
layout: post
author: FPI
title: "Surface - FCSC 2022"
date: 2022-05-17
categories: [CTF, Crypto]
background_image: assets/zoneindus.jpg
title_color: "#ffffff"
---


Dans ce challenge, nous devons résoudre le problème des nombres congruents pour récupérer une clé AES.

## Détails

- Catégorie : crypto
- Points : 477
- Résolutions : 10

### Description

Ce script implémente une manière exotique de générer une clé AES qui protège le flag. Pourrez-vous retrouver cette clé ?

Code source :

```python
import os
import json
import gmpy2
from fractions import Fraction
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt(n):
	IV = os.urandom(16)
	FLAG = open("flag.txt", "rb").read()

	k = int.to_bytes(n, 32, "big")
	aes = AES.new(k, AES.MODE_CBC, iv = IV)
	ctxt = aes.encrypt(pad(FLAG, 16))
	output = {
		"iv": IV.hex(),
		"ciphertext": ctxt.hex(),
	}
	return output

if __name__ == "__main__":

	try:
		a = Fraction(input(">>> a = "))
		b = Fraction(input(">>> b = "))
		
		c = a ** 2 + b ** 2
		assert gmpy2.is_square(c.numerator)
		assert gmpy2.is_square(c.denominator)
		assert a * b == 20478

		n = int(gmpy2.isqrt(c.numerator))
		
		output = encrypt(n)
		print(json.dumps(output))

	except:
		print("Error: check your inputs.")
# {"iv": "a79ec4a60d33eae0e0d9e06f8b309348", "ciphertext": "29d4c8dceecb461cfc7c06242d25879cdcf47fca47ded512ea830d09613ecd497a9720231cb423e95ed2463f5f74d8f5c4c9b75704ff738fe48475191b62f14280f32c05daf9300ab1d692d8717371dc"}
```

## Méthodologie

### Comprendre le problème

Après de nombreuses recherches en ligne, ce problème est connu sous le nom de [problème des nombres congruents](https://fr.wikipedia.org/wiki/Nombre_congruent).

Le but est de trouver deux côtés rationnels d'un triangle pour que l'aire soit égale à 10239.

Vous vous demandez peut-être quel est le rapport avec la cryptographie. La réponse est : Les courbes elliptiques !

![](images/ellcurve.png)

### Résoudre le problème

Je dois avouer que je n'ai trouvé la relation avec les courbes elliptiques qu'après plusieurs heures de recherche.

En commençant par les deux équations du problème : `a^2 + b^2 = c^2` et `1/2ab = n`. Si vous mettez `x = n(a+c)/b` et `y = 2n^2(a+c)/b^2`, vous pouvez dériver l'équation d'une courbe Elliptique : `y^2 = x^3 - n^2x`.
Convertir un point en côtés de triangle peut être fait en calculant `a = (x^2 - n^2)/y` et `b = 2nx/y`.

Résoudre le problème des nombres congruents revient à trouver des points entiers sur la courbe ci-dessus, dont les coordonnées Y sont non nulles.

Heureusement, Sage a une fonction intégrée pour cela !

Essayons-la :

```python
E=EllipticCurve([-5**2, 0])
E.integral_points()
# [(-5 : 0 : 1), (-4 : 6 : 1), (0 : 0 : 1), (5 : 0 : 1), (45 : 300 : 1)]
```

Si nous convertissons les points (-4, 6) et (45, 300) en côtés du triangle, nous obtenons :

```python
from fractions import Fraction
def convert(x, y, n):
	a = abs(x**2-n**2)
	b = abs(2*n*x)
	a = Fraction(f"{a}/{y}")
	b = Fraction(f"{b}/{y}")
	return a, b

convert(-4, 6, 5)
# (Fraction(3, 2), Fraction(20, 3))
convert(45, 300, 5)
# (Fraction(20, 3), Fraction(3, 2))
```
C'est exactement le résultat attendu. Nous devons juste faire cela pour la valeur du challenge :

```python
E=EllipticCurve([-10239**2, 0]) 
E.integral_points()                                                                                                                                                                                          
---------------------------------------------------------------------------
RuntimeError                              Traceback (most recent call last)
/usr/lib/python3/dist-packages/sage/schemes/elliptic_curves/ell_rational_field.py in integral_points(self, mw_base, both_signs, verbose)
   5810             try:
-> 5811                 mw_base = self.gens()
   5812             except RuntimeError:

/usr/lib/python3/dist-packages/sage/schemes/elliptic_curves/ell_rational_field.py in gens(self, proof, **kwds)
   2229 
-> 2230         gens, proved = self._compute_gens(proof, **kwds)
   2231         self.__gens = (gens, proved)

/usr/lib/python3/dist-packages/sage/schemes/elliptic_curves/ell_rational_field.py in _compute_gens(self, proof, verbose, rank1_search, algorithm, only_use_mwrank, use_database, descent_second_limit, sat_bound)
   2337                 del self.__mwrank_curve
-> 2338                 raise RuntimeError("Unable to compute the rank, hence generators, with certainty (lower bound=%s, generators found=%s).  This could be because Sha(E/Q)[2] is nontrivial."%(C.rank(),G) + \
   2339                       "\nTry increasing descent_second_limit then trying this command again.")

RuntimeError: Unable to compute the rank, hence generators, with certainty (lower bound=0, generators found=[]).  This could be because Sha(E/Q)[2] is nontrivial.
Try increasing descent_second_limit then trying this command again.

During handling of the above exception, another exception occurred:

RuntimeError                              Traceback (most recent call last)
<ipython-input-1-0352cc7046c9> in <module>
      1 E=EllipticCurve([-Integer(10239)**Integer(2), Integer(0)])
----> 2 E.integral_points()

/usr/lib/python3/dist-packages/sage/schemes/elliptic_curves/ell_rational_field.py in integral_points(self, mw_base, both_signs, verbose)
   5811                 mw_base = self.gens()
   5812             except RuntimeError:
-> 5813                 raise RuntimeError("Unable to compute Mordell-Weil basis of {}, hence unable to compute integral points.".format(self))
   5814             r = len(mw_base)
   5815         else:

RuntimeError: Unable to compute Mordell-Weil basis of Elliptic Curve defined by y^2 = x^3 - 104837121*x over Rational Field, hence unable to compute integral points.
```

Bon… Utilisons Magma alors :

```python
E := EllipticCurve([-10239*10239, 0]);
IntegralPoints(E);
# [ (-10239 : 0 : 1), (0 : 0 : 1), (10239 : 0 : 1) ]
# [ <(-10239 : 0 : 1), 1>, <(0 : 0 : 1), 1>, <(10239 : 0 : 1), 1> ]
```
Pas de crash, mais pas de résultats non plus... Même chose avec Pari/GP...

![](images/sagemagma.png)

Retour à la case départ !

Après de nombreuses heures à chercher une autre solution, je suis tombé sur [cet article](https://arxiv.org/pdf/2106.07373.pdf), qui donne une autre façon de calculer de tels points dans la section 4 :

```python
N = 10239
E = EllipticCurve([-N*N, 0])
pari(E).ellheegner()
# 737343773862301088045509418793921869066076/10893159238600577313677917228652511841, 625862116444448047393458603029555713662450024330982757172975030/35952639365198540562613869494033558726733788804390127889
```

Le calcul ci-dessus n'a pris QUE 3 heures pour donner un résultat.

### Implémentation de la solution

A partir du résultat de `ellheegner()`, il suffit de convertir les deux fractions en côtés du triangle.

Le script complet de la solution est donné ci-dessous :

```python
from sage.all import gcd, QQ
from fractions import Fraction
import gmpy2
from Crypto.Cipher import AES

def decrypt(x, y):

	a = Fraction(x)
	b = Fraction(y)

	c = a ** 2 + b ** 2
	n = int(gmpy2.isqrt(c.numerator))
	k = int.to_bytes(n, 32, "big")
	iv = bytes.fromhex("a79ec4a60d33eae0e0d9e06f8b309348")
	flag = bytes.fromhex("29d4c8dceecb461cfc7c06242d25879cdcf47fca47ded512ea830d09613ecd497a9720231cb423e95ed2463f5f74d8f5c4c9b75704ff738fe48475191b62f14280f32c05daf9300ab1d692d8717371dc")
	aes = AES.new(k, AES.MODE_CBC, iv=iv)
	print(aes.decrypt(flag))

# https://arxiv.org/pdf/2106.07373.pdf
N = 10239
#E = EllipticCurve([-N*N, 0])
#pari(E).ellheegner()
# 737343773862301088045509418793921869066076/10893159238600577313677917228652511841, 625862116444448047393458603029555713662450024330982757172975030/35952639365198540562613869494033558726733788804390127889
# s/t, u/v
s = QQ(737343773862301088045509418793921869066076)
t = QQ(10893159238600577313677917228652511841)
u = QQ(625862116444448047393458603029555713662450024330982757172975030)
v = QQ(35952639365198540562613869494033558726733788804390127889)
x = abs(s/t)
y = abs(u/v)
a = abs(x**2 - N**2)
b = 2*N*x
g_a = gcd(a,y);
g_b = gcd(b, y);
a = a/g_a;
d = y/g_a;
b = b/g_b;
e = y/g_b;
print(a, b, d, e)
decrypt(f"{a}/{d}", f"{b}/{e}")
```

Flag : **FCSC{67084c2bc8acfbf5e8a0d5e2809e230d092ab56630713dbe33ca42b8430a992b}**
