# Compte rendu TP1 INFO 001 : Cryptographie appliquée, TLS/SSL et PKI

**Binôme :** Clément PALANCA · Kylian GRANDY

---

## Sommaire

- [Contexte et objectifs](#contexte-et-objectifs)
- [2. Questions préliminaires](#2-questions-préliminaires)
  - [Question 1 : Chiffrement et déchiffrement RSA](#question-1-chiffrement-et-déchiffrement-rsa)
  - [Question 2 : Rôle de Diffie-Hellman](#question-2-rôle-de-diffie-hellman)
  - [Question 3 : Informations contenues dans un certificat](#question-3-informations-contenues-dans-un-certificat)
  - [Question 4 : Authentification du site d’Alice par Bob](#question-4-authentification-du-site-dalice-par-bob)
- [3. Accès aux machines virtuelles](#3-accès-aux-machines-virtuelles)
- [4. Étude du chiffrement RSA](#4-étude-du-chiffrement-rsa)
  - [4.1 Génération de clés RSA](#41-génération-de-clés-rsa)
    - [Question 5 : longueur de n et exposant public](#question-5)
    - [Question 6 : chiffrer une clé publique ou privée](#question-6)
    - [Question 7 : encodage PEM](#question-7)
    - [Question 8 : intérêt d'un fichier de clé publique](#question-8)
  - [4.2 Chiffrement asymétrique](#42-chiffrement-asymétrique)
    - [Question 9 : clé utilisée pour la confidentialité](#question-9)
    - [4.2.1 Partage de la clé publique avec un voisin (installation de httpd)](#421-partage-de-la-clé-publique-avec-un-voisin-installation-de-httpd)
    - [4.2.2 Chiffrement avec la clé publique](#422-chiffrement-avec-la-clé-publique)
      - [Question 10 : chiffrement avec pkeyutl](#question-10)
      - [Question 11 : chiffrés différents pour un même message](#question-11)
- [5. Analyse du contenu d'un certificat](#5-analyse-du-contenu-dun-certificat)
  - [5.1 En ligne de commande avec openssl s_client](#51-en-ligne-de-commande-avec-openssl-s_client)
    - [Question 12 : option -showcerts et nombre de certificats](#question-12)
    - [Question 13 : norme X.509, sujet et émetteur](#question-13)
    - [Question 14 : lignes s: et i:](#question-14)
    - [Question 15 : contenu du certificat du serveur](#question-15)
    - [Question 16 : formule de la signature](#question-16)
    - [Question 17 : certificat de la CA intermédiaire](#question-17)
    - [Question 18 : validation de la chaîne](#question-18)
    - [Question 19 : certificat racine auto-signé](#question-19)
  - [5.2 Dans un navigateur](#52-dans-un-navigateur)
- [6. Mise en place d'une PKI](#6-mise-en-place-dune-pki)
  - [6.1 Présentation de la PKI](#61-présentation-de-la-pki)
  - [6.2 Étude de la CA racine (CN=Root Lorne)](#62-étude-de-la-ca-racine-cnroot-lorne)
    - [Question 20 : certificat de Root Lorne](#question-20)
  - [6.3 Création d'une autorité de certification intermédiaire](#63-création-dune-autorité-de-certification-intermédiaire)
    - [Question 21 : paramètre dir et emplacements](#question-21)
    - [Question 22 : création de la clé de la CA](#question-22)
    - [Question 23 : signature de la demande de certificat](#question-23)
  - [6.4 Création du certificat du serveur](#64-création-du-certificat-du-serveur)
    - [Question 24 : machine de génération de la clé du serveur](#question-24)
- [7. Mise en place d'un reverse proxy](#7-mise-en-place-dun-reverse-proxy)
  - [7.1 Installation de Docker et Git](#71-installation-de-docker-et-git)
  - [7.2 Mise en place des conteneurs pour l'infrastructure](#72-mise-en-place-des-conteneurs-pour-linfrastructure)
  - [7.3 Mise en place de SSL](#73-mise-en-place-de-ssl)
    - [7.3.1 Configuration de Nginx](#731-configuration-de-nginx)
    - [7.3.2 Mise en place de la chaîne de confiance de certificat](#732-mise-en-place-de-la-chaîne-de-confiance-de-certificat)
      - [Question 25 : pourquoi faire confiance à la CA racine](#question-25)
      - [Question 26 : modification du fichier hosts](#question-26)
- [8. Développement d'un client Web](#8-développement-dun-client-web)
  - [Question 27 : scénario de tests du client](#question-27)
- [Conclusion](#conclusion)

---

## Contexte et objectifs

Ce TP met en œuvre le protocole SSL/TLS et une infrastructure à clés publiques (PKI) sur deux machines virtuelles Alma Linux : `tls-ca-palancac` (autorité de certification) et `tls-serv-palancac` (serveur).

Objectifs du TP :

1. Générer des clés asymétriques RSA et s'en servir pour chiffrer et déchiffrer des messages.
2. Analyser le contenu d'un certificat X.509.
3. Mettre en place une PKI (CA racine, CA intermédiaire).
4. Créer et déployer des certificats pour des serveurs.
5. Configurer des clients pour qu'ils acceptent les certificats présentés par les serveurs.

---

## 2. Questions préliminaires

### Question 1: Chiffrement et déchiffrement RSA

> _On veut garantir la confidentialité d'un message M avec RSA, on note C le message chiffré. Rappeler le calcul de chiffrement et l'opération inverse._

RSA repose sur la difficulté de factoriser un grand nombre produit de deux nombres premiers. Les paramètres sont construits ainsi :

1. Choisir deux grands nombres premiers distincts $p$ et $q$
2. Calculer le modulus $n = p \times q$ et l'indicatrice d'Euler $\varphi(n) = (p-1)(q-1)$
3. Choisir l'exposant public $e$, premier avec $\varphi(n)$ (en pratique $e = 65537$)
4. Calculer l'exposant privé $d$, inverse de $e$ modulo $\varphi(n)$ : $e \times d \equiv 1 \pmod{\varphi(n)}$

La **clé publique** est le couple $(n, e)$, la **clé privée** est $(n, d)$.

**Chiffrement :** Pour envoyer M de façon confidentielle à Bob, Alice utilise la _clé publique de Bob_ :

```math
C = M^{e} \bmod n
```

**Déchiffrement :** Seul Bob, qui détient $d$, peut effectuer l'opération inverse avec sa _clé privée_ :

```math
M = C^{d} \bmod n
```

Cela fonctionne car $(M^e)^d = M^{ed} \equiv M \pmod n$, d'après le théorème d'Euler et la relation $e \times d \equiv 1 \pmod{\varphi(n)}$.

**Exemple avec de petits nombres :** $p = 5$, $q = 11$, donc $n = 55$ et $\varphi(n) = 40$. Avec $e = 3$, on trouve $d = 27$ (car $3 \times 27 = 81 \equiv 1 \pmod{40}$). Pour $M = 2$ : $C = 2^3 \bmod 55 = 8$, puis $8^{27} \bmod 55 = 2$. On retrouve bien M.

En pratique, on ne chiffre jamais M « brut » : un nombre aléatoire est ajouté avant le calcul, ce qui rend le chiffrement non déterministe (Si on chiffre deux fois le même message on n'aura pas le même résultat).

### Question 2: Rôle de Diffie-Hellman

Diffie-Hellman permet à deux parties de **se mettre d'accord sur une clé secrète commune en n'échangeant que des valeurs publiques**, sur un canal non sûr. Ce n'est ni un algorithme de chiffrement ni un algorithme de signature : c'est un protocole d'échange de clés. La clé obtenue sert ensuite à un chiffrement symétrique (AES,...), beaucoup plus rapide que RSA.

| Étape                    | Alice             | Canal public                     | Bob               |
| ------------------------ | ----------------- | -------------------------------- | ----------------- |
| 1. Paramètres publics    |                   | $p$ premier, $g$ générateur      |                   |
| 2. Secret tiré au hasard | $a$               |                                  | $b$               |
| 3. Valeur publique       | $A = g^a \bmod p$ | $A \rightarrow$ · $\leftarrow B$ | $B = g^b \bmod p$ |
| 4. Secret commun         | $K = B^a \bmod p$ |                                  | $K = A^b \bmod p$ |

Les deux calculs donnent $K = g^{ab} \bmod p$. Un attaquant qui observe $p$, $g$, $A$ et $B$ devrait résoudre le problème du logarithme discret pour retrouver $a$ ou $b$, ce qui est infaisable pour de grands paramètres.

_Exemple :_ $p = 23$, $g = 5$, $a = 6$, $b = 15$ donnent $A = 8$, $B = 19$ et $K = 2$ des deux côtés.

### Question 3: Informations contenues dans un certificat

Un certificat X.509 lie une identité à une clé publique. Cette liaison est garantie par la signature d'une autorité de certification (CA). Quatre informations essentielles :

| Champ                                             | Contenu                                                                                       | Utilité                                                                   |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| **Sujet** (_Subject_) et noms alternatifs (_SAN_) | Identité du titulaire, par ex. `CN=www.alice.com`, et liste des noms DNS couverts             | Le client vérifie que le nom du site demandé figure dans le certificat    |
| **Clé publique de l'entité**                      | Algorithme (RSA, ECDSA…), taille et valeur de la clé                                          | Sert à vérifier les signatures du serveur ou à échanger la clé de session |
| **Émetteur** (_Issuer_) et **signature**          | Nom de la CA signataire, algorithme (ex. `sha256WithRSAEncryption`) et valeur de la signature | Permet de vérifier l'authenticité et l'intégrité du certificat            |
| **Période de validité**                           | Dates _Not Before_ et _Not After_                                                             | Un certificat expiré ou pas encore valide est refusé                      |

### Question 4: Authentification du site d’Alice par Bob

> _Bob se connecte en HTTPS à `www.alice.com`. Le certificat d'Alice a été délivré par `ca1`, et celui de `ca1` par `root-ca`. Détailler les étapes de l'authentification du site._

La chaîne de confiance est la suivante. Seul le certificat de `root-ca` est déjà présent chez Bob, dans le magasin de certificats de son navigateur ou de son système :

```text
root-ca  (auto-signé, dans le magasin de confiance de Bob)
   └── signe →  ca1  (CA intermédiaire)
                   └── signe →  www.alice.com  (certificat serveur)
```

Les étapes de l'authentification sont :

1. **Connexion et ClientHello :** Bob résout `www.alice.com` en adresse IP, ouvre une connexion TCP sur le port 443 et envoie un `ClientHello` : versions TLS et suites cryptographiques supportées, un nombre aléatoire, et le nom du site demandé (extension SNI).
2. **Réponse du serveur :** Le serveur répond par un `ServerHello` (suite choisie, son propre aléa) puis envoie sa chaîne de certificats : le certificat de `www.alice.com` et celui de `ca1`. Le certificat racine n'a pas besoin d'être envoyé.
3. **Construction de la chaîne :** Le navigateur part du certificat d'Alice, lit son émetteur (`ca1`), trouve le certificat de `ca1`, lit son émetteur (`root-ca`) et cherche `root-ca` dans son magasin local de CA de confiance. Si la racine n'y est pas, la connexion est refusée.
4. **Vérification des signatures, du haut vers le bas :**
   - Avec la clé publique de `root-ca` (issue du magasin local), Bob vérifie la signature du certificat de `ca1`.
   - Avec la clé publique de `ca1` (désormais de confiance), il vérifie la signature du certificat d'Alice.
   - Vérifier une signature RSA consiste à recalculer le haché $H$ du contenu du certificat et à vérifier que $\text{sig}^{e} \bmod n = H(\text{certificat})$, avec $(n, e)$ la clé publique de l'émetteur.
5. **Vérification des champs de chaque certificat :**
   - Période de validité : la date courante est comprise entre _Not Before_ et _Not After_
   - Nom : `www.alice.com` figure dans le SAN (ou le CN) du certificat d'Alice
   - Contraintes : `root-ca` et `ca1` ont `Basic Constraints: CA:TRUE` et l'usage `keyCertSign`, le certificat d'Alice autorise l'usage `serverAuth`
   - Révocation : aucun certificat de la chaîne n'est révoqué
6. **Preuve de possession de la clé privée :** Un certificat est public : n'importe qui peut le renvoyer. Le serveur doit donc prouver qu'il détient la clé privée correspondante. Il signe l'échange de clés et les messages de la poignée de main (`CertificateVerify`). Bob vérifie cette signature avec la clé publique du certificat d'Alice. Bob chiffre le _pre-master secret_ avec cette clé publique, et seul le vrai serveur peut le déchiffrer.
7. **Finalisation :** Les deux parties dérivent les clés de session symétriques et échangent des messages `Finished`, qui contiennent un MAC de toute la poignée de main. Cela garantit qu'aucun message n'a été modifié. Le cadenas s'affiche : le site est authentifié et la suite des échanges HTTP est chiffrée.

Si une seule de ces vérifications échoue (signature invalide, racine inconnue, nom différent, certificat expiré ou révoqué), le navigateur affiche un avertissement de sécurité au lieu d'établir la connexion de confiance.

---

## 3. Accès aux machines virtuelles

La connexion SSH aux deux machines, le changement du mot de passe du compte `etudiant` et le renommage des hôtes en `tls-ca-palancac` et `tls-serv-palancac` ont été réalisés sans difficulté particulière.

## 4. Étude du chiffrement RSA

### 4.1 Génération de clés RSA

OpenSSL n'étant pas présent sur l'image, nous l'avons d'abord installé :

```bash
sudo dnf install -y openssl
```

La page de manuel (`man openssl-genpkey`) indique que la sous-commande `genpkey` génère une bi-clé, et que la taille d'une clé RSA se règle avec l'option `-pkeyopt rsa_keygen_bits:<taille>`. La commande du sujet demandait 512 bits. Nous l'avons corrigée pour générer une clé de 1024 bits :

```bash
openssl genpkey -algorithm RSA -out rsa_keys.pem -pkeyopt rsa_keygen_bits:1024
```

Une fois la clé générée, on peut consulter son contenu :

```console
[etudiant@tls-ca-palancac ~]$ openssl rsa -in rsa_keys.pem -text -noout
Private-Key: (1024 bit, 2 primes)
modulus:
    00:bd:0e:44:06:07:96:6d:b6:45:07:ee:b9:79:e6:
    65:e3:36:72:d0:d4:aa:35:28:34:e0:aa:23:23:c1:
    ca:51:68:3f:bc:39:06:32:2b:dc:a7:3a:a0:e9:3b:
    00:0b:39:56:9a:2c:d9:8b:3b:eb:9c:1c:e8:48:af:
    55:63:91:e8:fb:56:ab:54:92:b2:b5:12:60:4d:3f:
    c7:39:68:49:e4:8b:80:8c:83:ba:29:72:04:b2:dd:
    ab:49:55:60:c8:15:ae:0a:ae:8d:67:2a:67:f0:af:
    82:45:5a:63:7b:bb:e6:ac:ed:e0:62:ef:a3:2d:85:
    00:14:33:10:2f:9c:6e:b2:c3
publicExponent: 65537 (0x10001)
privateExponent:
    [masqué]
prime1:
    [masqué]
prime2:
    [masqué]
exponent1:
    [masqué]
exponent2:
    [masqué]
coefficient:
    [masqué]
```

Les champs privés (`privateExponent`, `prime1`, `prime2`, `exponent1`, `exponent2`, `coefficient`) sont masqués : seuls `modulus` (n) et `publicExponent` (e) sont publics.

### Question 5

> _Quelle est la longueur du « n » généré ? Rappeler les calculs de chiffrement et de déchiffrement. Le `publicExponent` est-il difficile à deviner pour un pirate ? Est-ce problématique ?_

**Longueur de n :** Le module (`modulus`) fait **1024 bits**, soit 128 octets. La sortie en affiche 129 car le `00` initial est un octet de signe ajouté par l'encodage ASN.1, pour que le nombre reste positif.

Chaque champ de la sortie correspond à un paramètre RSA :

| Champ                                   | Paramètre                                                                                  |
| --------------------------------------- | ------------------------------------------------------------------------------------------ |
| `modulus`                               | n = p × q                                                                                  |
| `publicExponent`                        | e                                                                                          |
| `privateExponent`                       | d                                                                                          |
| `prime1`, `prime2`                      | p et q                                                                                     |
| `exponent1`, `exponent2`, `coefficient` | d mod (p−1), d mod (q−1), q⁻¹ mod p : valeurs précalculées pour accélérer le déchiffrement |

**Calculs :** Comme vu à la question 1 : chiffrement $C = M^e \bmod n$ avec la clé publique, déchiffrement $M = C^d \bmod n$ avec la clé privée.

**Exposant public :** Il vaut 65537 (0x10001), la valeur utilisée par quasiment toutes les clés RSA : il est donc trivial à deviner. Ce n'est pas un problème, car e fait partie de la clé publique et n'a pas à être secret. La sécurité repose sur d, qu'on ne peut pas calculer sans factoriser n. La valeur 65537 = 2¹⁶ + 1 est choisie parce qu'elle ne contient que deux bits à 1 (chiffrement rapide) tout en évitant les attaques connues sur les très petits exposants comme e = 3.

### Chiffrement de la bi-clé

Le fichier `rsa_keys.pem` contient la clé privée en clair : toute personne qui y accède peut l'utiliser. Pour le protéger, nous l'avons chiffré avec l'algorithme symétrique AES 128 bits, en utilisant notre login comme passphrase. La commande du sujet se terminait par un point, que nous avons retiré pour que le fichier s'appelle bien `rsa_keys_cyphered.pem` :

```console
[etudiant@tls-ca-palancac ~]$ openssl rsa -in rsa_keys.pem -aes128 -out rsa_keys_cyphered.pem
writing RSA key
Enter pem pass phrase:
Verifying - Enter pem pass phrase:
```

La passphrase est saisie de façon interactive pour ne pas apparaître dans l'historique du shell. On vérifie que le fichier est bien chiffré :

```console
[etudiant@tls-ca-palancac ~]$ head -1 rsa_keys.pem rsa_keys_cyphered.pem
==> rsa_keys.pem <==
-----BEGIN PRIVATE KEY-----

==> rsa_keys_cyphered.pem <==
-----BEGIN ENCRYPTED PRIVATE KEY-----
```

Le fichier en clair n'étant plus utile, nous l'avons supprimé avec `rm rsa_keys.pem`. Toutes les commandes suivantes utilisent la version chiffrée et redemandent la passphrase.

### Question 6

> _Y a-t-il un intérêt à chiffrer une clé publique ? À chiffrer une clé privée ?_

Chiffrer une clé publique n'a aucun intérêt : elle est faite pour être diffusée, et la connaître ne permet ni de déchiffrer ni de signer à la place de son propriétaire.

Chiffrer une clé privée est au contraire essentiel. Si le fichier est volé (accès au disque, sauvegarde, dépôt Git…), l'attaquant ne peut pas s'en servir sans la passphrase. Ici, le fichier contient la bi-clé complète, et c'est la partie privée qu'on protège.

### Extraction de la clé publique

Pour pouvoir diffuser notre clé publique sans exposer la clé privée, nous l'avons extraite dans un fichier séparé. L'option `-pubout` demande à OpenSSL de n'écrire que la partie publique. Comme la bi-clé est chiffrée, la passphrase est demandée pour la lire.

```console
[etudiant@tls-ca-palancac ~]$ openssl rsa -in rsa_keys_cyphered.pem -pubout -out pub.pem
Enter pass phrase for rsa_keys_cyphered.pem:
writing RSA key
[etudiant@tls-ca-palancac ~]$ cat pub.pem
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9DkQGB5ZttkUH7rl55mXjNnLQ
1Ko1KDTgqiMjwcpRaD+8OQYyK9ynOqDpOwALOVaaLNmLO+ucHOhIr1Vjkej7VqtU
krK1EmBNP8c5aEnki4CMg7opcgSy3atJVWDIFa4Kro1nKmfwr4JFWmN7u+as7eBi
76MthQAUMxAvnG6ywwIDAQAB
-----END PUBLIC KEY-----
```

Ce fichier ne contient que n et e : il peut être publié sans risque.

### Question 7

> _Quel est l'encodage utilisé pour la clé ? Quel est l'avantage de cet encodage ?_

La clé est au format **PEM** (_Privacy-Enhanced Mail_). La structure de la clé est d'abord décrite en ASN.1 puis sérialisée en binaire (format **DER**). Ce binaire est ensuite encodé en **Base64**, découpé en lignes de 64 caractères et encadré par les balises `-----BEGIN PUBLIC KEY-----` et `-----END PUBLIC KEY-----`.

Cet encodage a deux avantages :

- **Le fichier est du texte ASCII pur.** On peut le copier-coller, l'envoyer par mail ou le publier sur un serveur web sans risque de corruption, ce qui n'est pas garanti pour un fichier binaire.
- **Les balises indiquent la nature du contenu** (clé publique, clé privée chiffrée, certificat…). On peut aussi mettre plusieurs objets à la suite dans un même fichier, par exemple une chaîne de certificats.

L'inconvénient est une taille environ 33 % plus grande que le DER binaire, à cause du Base64.

### Lecture de la clé publique interprétée

L'option `-pubin` indique que le fichier contient une clé publique seule (aucune passphrase n'est demandée) :

```console
[etudiant@tls-ca-palancac ~]$ openssl rsa -pubin -in pub.pem -text -noout
Public-Key: (1024 bit)
Modulus:
    00:bd:0e:44:06:07:96:6d:b6:45:07:ee:b9:79:e6:
    65:e3:36:72:d0:d4:aa:35:28:34:e0:aa:23:23:c1:
    ca:51:68:3f:bc:39:06:32:2b:dc:a7:3a:a0:e9:3b:
    00:0b:39:56:9a:2c:d9:8b:3b:eb:9c:1c:e8:48:af:
    55:63:91:e8:fb:56:ab:54:92:b2:b5:12:60:4d:3f:
    c7:39:68:49:e4:8b:80:8c:83:ba:29:72:04:b2:dd:
    ab:49:55:60:c8:15:ae:0a:ae:8d:67:2a:67:f0:af:
    82:45:5a:63:7b:bb:e6:ac:ed:e0:62:ef:a3:2d:85:
    00:14:33:10:2f:9c:6e:b2:c3
Exponent: 65537 (0x10001)
```

### Question 8

> _Retrouve-t-on bien les éléments attendus ? Pourquoi est-il intéressant de disposer d'un fichier à part contenant uniquement la clé publique ?_

Oui. On retrouve exactement les deux éléments de la clé publique RSA :

- le **module n** (`Modulus`), identique octet pour octet au `modulus` affiché à la question 5 (il commence par `00:bd:0e:44` et finit par `2f:9c:6e:b2:c3`) ;
- l'**exposant public e** (`Exponent`), qui vaut toujours 65537.

Les champs privés (d, p, q et les valeurs précalculées) n'apparaissent plus : ils n'ont pas été copiés dans `pub.pem`.

Disposer d'un fichier séparé est intéressant pour plusieurs raisons :

- **On peut le diffuser librement** (serveur web, mail, dépôt Git) sans jamais exposer la clé privée.
- **Il est lisible sans passphrase**, ce qui est indispensable pour que d'autres personnes puissent s'en servir.
- **C'est ce dont ont besoin nos correspondants** : chiffrer un message qu'ils nous destinent, ou vérifier une signature que nous avons produite. C'est aussi ce qu'une CA place dans un certificat.

Le fichier a ensuite été renommé avec le login `palancac`, pour qu'il ne se confonde pas avec celui de Kylian lors de l'échange :

```bash
mv pub.pem pub.palancac.pem
```

### 4.2 Chiffrement asymétrique

Le couple de clés généré précédemment va maintenant servir à échanger des messages chiffrés avec un voisin.

### Question 9

> _Quelle clé doit-on utiliser pour chiffrer un message RSA lorsqu'on veut l'envoyer de manière confidentielle ?_

Pour envoyer un message confidentiel, on le chiffre avec la **clé publique du destinataire**. Seul le destinataire possède la clé privée correspondante, il est donc le seul à pouvoir déchiffrer le message.

Dans mon cas, pour écrire à Kylian, je dois récupérer sa clé publique (`pub.kgrandy.pem`). Lui utilisera la mienne (`pub.palancac.pem`) pour me répondre. C'est pour cela que la première étape consiste à s'échanger les clés publiques.

À l'inverse, chiffrer avec sa propre clé privée ne protège pas la confidentialité : n'importe qui pourrait déchiffrer avec la clé publique. Ce mécanisme sert à la **signature**, qui prouve l'origine du message, et non à le garder secret.

#### 4.2.1 Partage de la clé publique avec un voisin (installation de httpd)

Pour que Kylian et moi échangions nos clés publiques de façon réaliste, j'ai installé le serveur web Apache (`httpd`) sur la machine `tls-ca-palancac` et j'y ai publié ma clé :

```console
[etudiant@tls-ca-palancac ~]$ sudo dnf install -y httpd
[...]
Installing:
 httpd                    x86_64     2.4.63-13.el10_2.8       appstream     54 k
[...]
Install  12 Packages
[...]
Complete!
[etudiant@tls-ca-palancac ~]$ sudo systemctl start httpd
[etudiant@tls-ca-palancac ~]$ sudo firewall-cmd --add-port 80/tcp --permanent
success
[etudiant@tls-ca-palancac ~]$ sudo firewall-cmd --reload
success
[etudiant@tls-ca-palancac ~]$ sudo cp pub.palancac.pem /var/www/html/pub.palancac.pem
```

| Commande                                     | Rôle                                                                                                   |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `dnf install -y httpd`                       | Installe le serveur web Apache                                                                         |
| `systemctl start httpd`                      | Démarre le service                                                                                     |
| `firewall-cmd --add-port 80/tcp --permanent` | Ouvre le port 80 (HTTP) dans le pare-feu, de façon persistante                                         |
| `firewall-cmd --reload`                      | Applique la règle : `--permanent` seul ne modifie que la configuration enregistrée, pas celle en cours |
| `cp … /var/www/html/`                        | Copie la clé dans la racine du site, le dossier publié par Apache                                      |

On vérifie que la clé est bien servie, puis on relève l'adresse IP :

```console
[etudiant@tls-ca-palancac ~]$ curl http://localhost/pub.palancac.pem
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9DkQGB5ZttkUH7rl55mXjNnLQ
1Ko1KDTgqiMjwcpRaD+8OQYyK9ynOqDpOwALOVaaLNmLO+ucHOhIr1Vjkej7VqtU
krK1EmBNP8c5aEnki4CMg7opcgSy3atJVWDIFa4Kro1nKmfwr4JFWmN7u+as7eBi
76MthQAUMxAvnG6ywwIDAQAB
-----END PUBLIC KEY-----
[etudiant@tls-ca-palancac ~]$ hostname -I
192.168.170.85
```

J'ai ensuite récupéré la clé publique depuis le poste de Kylian (`kgrandy`, machine `192.168.170.219`) à partir de l'adresse IP et du nom de fichier :

```console
[etudiant@tls-ca-palancac ~]$ curl -fO http://192.168.170.219/pub.kgrandy.pem
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   272  100   272    0     0   100k      0 --:--:-- --:--:-- --:--:--  132k
[etudiant@tls-ca-palancac ~]$ cat pub.kgrandy.pem
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3nAKmIYSiEZhZC9DcOFXuqpjV
+4fsNIqg3tmLJiDBaNP66AKU0Wk/SMsGavsvK0OQD4xjLyyuqtE3M82qS10fr3G1
J+B+mhPM6epuzVS8e/XY2t7llL0cEtTiqRGW3beRGY2dYTiv3p5PHLag5/CouJ+r
0Any9LFAzFeDm1jckQIDAQAB
-----END PUBLIC KEY-----
```

L'option `-O` enregistre le fichier sous son nom d'origine, et `-f` fait échouer `curl` en cas d'erreur HTTP (sinon une page d'erreur serait enregistrée à la place de la clé).

Kylian a récupéré ma clé publique de la même façon :

```console
[etudiant@tls-ca-kgrandy ~]$ curl -fO http://192.168.170.85/pub.palancac.pem
100   272  100   272    0     0  53872      0 --:--:-- --:--:-- --:--:-- 54400
```

Publier une clé publique ne pose aucun problème de sécurité. En revanche, rien ne garantit ici que la clé récupérée appartient bien au voisin : c'est le rôle des certificats, étudiés dans la suite du TP.

#### 4.2.2 Chiffrement avec la clé publique

### Question 10

> _Rechercher tous les paramètres de la commande `openssl pkeyutl -encrypt …` pour chiffrer un message. Le message en clair sera dans un fichier nommé `clair.txt` et contiendra « Bonjour de votre_nom ». Le message chiffré devra s'appeler `cipher.bin`._

D'après la page de manuel (`man openssl-pkeyutl`), la sous-commande `pkeyutl` réalise des opérations avec une clé asymétrique : chiffrement, déchiffrement, signature et vérification. Pour chiffrer, on a besoin des paramètres suivants :

| Option                   | Rôle                                                                                                                          |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| `-encrypt`               | Chiffre les données d'entrée avec une clé publique                                                                            |
| `-pubin`                 | Indique que le fichier passé à `-inkey` contient une clé publique. Sans cette option, OpenSSL attend une clé privée et échoue |
| `-inkey pub.kgrandy.pem` | La clé utilisée : celle du **destinataire**, comme expliqué à la question 9                                                   |
| `-in clair.txt`          | Le fichier contenant le message en clair                                                                                      |
| `-out cipher.bin`        | Le fichier dans lequel est écrit le message chiffré, au format binaire                                                        |

J'ai d'abord créé le message en clair, puis je l'ai chiffré avec la clé publique de Kylian :

```console
[etudiant@tls-ca-palancac ~]$ echo "Bonjour de Clément PALANCA" > clair.txt
[etudiant@tls-ca-palancac ~]$ openssl pkeyutl -encrypt -pubin -inkey pub.kgrandy.pem -in clair.txt -out cipher.bin
```

Le fichier est binaire : je l'affiche avec `hexdump -C` (hexadécimal et ASCII) :

```console
[etudiant@tls-ca-palancac ~]$ hexdump -C cipher.bin
00000000  64 21 83 14 48 27 35 ae  fe c3 38 74 e4 d8 75 bb  |d!..H'5...8t..u.|
00000010  25 f8 b7 e4 53 7c 63 a3  e9 cf 32 bf 5c 33 fa f8  |%...S|c...2.\3..|
00000020  2d 23 47 4e 86 d0 27 ca  f5 61 c1 31 59 40 a2 44  |-#GN..'..a.1Y@.D|
00000030  f9 eb 68 43 a3 b6 56 f1  3b 6a 71 bd 66 46 dd e0  |..hC..V.;jq.fF..|
00000040  26 f0 99 fa cb 39 95 95  05 b7 bb 3b 46 67 f9 bb  |&....9.....;Fg..|
00000050  38 c9 37 64 52 20 d4 7e  1d 3a ca 6b b5 4b 2c a6  |8.7dR .~.:.k.K,.|
00000060  37 a7 aa e1 04 41 9e b9  35 7d 81 43 89 5c 3c e2  |7....A..5}.C.\<.|
00000070  fc ac 64 15 3c 62 7c f5  0e 53 1e 52 cf 5d 33 13  |..d.<b|..S.R.]3.|
00000080
```

Le contenu est illisible : aucun fragment du message n'apparaît dans la colonne ASCII.

### Question 11

> _Chiffrer plusieurs fois le même fichier `clair.txt`, et enregistrer le résultat dans les fichiers `cipher.bin.1`, `cipher.bin.2`. Comparer les contenus des différents messages chiffrés. Sont-ils identiques ? Est-ce normal ? Justifier._

J'ai chiffré deux fois de plus le même fichier, avec la même clé, puis comparé les trois résultats :

```console
[etudiant@tls-ca-palancac ~]$ openssl pkeyutl -encrypt -pubin -inkey pub.kgrandy.pem -in clair.txt -out cipher.bin.1
[etudiant@tls-ca-palancac ~]$ openssl pkeyutl -encrypt -pubin -inkey pub.kgrandy.pem -in clair.txt -out cipher.bin.2
[etudiant@tls-ca-palancac ~]$ ls -l cipher.bin*
-rw-r--r--. 1 etudiant etudiant 128 Nov 16 08:30 cipher.bin
-rw-r--r--. 1 etudiant etudiant 128 Nov 16 08:31 cipher.bin.1
-rw-r--r--. 1 etudiant etudiant 128 Nov 16 08:31 cipher.bin.2
[etudiant@tls-ca-palancac ~]$ cmp cipher.bin.1 cipher.bin.2
cipher.bin.1 cipher.bin.2 differ: byte 1, line 1
[etudiant@tls-ca-palancac ~]$ sha256sum cipher.bin cipher.bin.1 cipher.bin.2
5c16a50f12660b2e13fa6a090319eaecbfe9c4b558b675393b28d68e36e6dab6  cipher.bin
8680ce89c5827e6ec4ffdeead44cdf0e0d1a990531df4d4fbeb0c98f714924e3  cipher.bin.1
061b9a8b83ce4fef0c183df3d0a58602fc4555fe41e146e1e0956118fa4dfcfa  cipher.bin.2
```

Les trois fichiers ont la même taille (128 octets), mais leur contenu est **différent**. `cmp` signale une différence dès le premier octet, et les trois empreintes SHA-256 n'ont rien en commun.

**C'est normal, et c'est même voulu.** Avant d'appliquer le calcul $C = M^e \bmod n$, OpenSSL ne chiffre pas le message brut : il le complète avec un **remplissage** (_padding_ PKCS#1 v1.5) qui contient des octets aléatoires. Le bloc réellement chiffré a la forme suivante :

```text
00 | 02 | PS (au moins 8 octets aléatoires non nuls) | 00 | message
```

PS est tiré au hasard à chaque chiffrement, donc le chiffré change à chaque fois. Le remplissage est retiré au déchiffrement.

Sans cet aléa, RSA serait **déterministe** : un même message donnerait toujours le même chiffré, ce qui poserait deux problèmes :

- **Un attaquant pourrait reconnaître les messages répétés** en comparant simplement les chiffrés qui circulent sur le réseau.
- **Il pourrait deviner le contenu d'un message.** La clé publique étant connue de tous, il lui suffirait de chiffrer les messages probables (« oui », « non », « Bonjour de … ») et de comparer le résultat au chiffré intercepté.

#### Échange et déchiffrement des messages

J'ai publié mon chiffré sur le serveur web, sous un nom contenant mon login pour qu'il ne se confonde pas avec celui de Kylian :

```bash
sudo cp cipher.bin /var/www/html/cipher.palancac.bin
```

Kylian l'a téléchargé et déchiffré avec sa clé privée :

```console
[etudiant@tls-ca-kgrandy ~]$ openssl pkeyutl -decrypt -inkey rsa_keys_cyphered.pem -in cipher.palancac.bin -out dechiffre.txt
Enter pass phrase for rsa_keys_cyphered.pem:
[etudiant@tls-ca-kgrandy ~]$ cat dechiffre.txt
Bonjour de Clément PALANCA
```

J'ai récupéré le chiffré de Kylian et l'ai déchiffré avec ma clé privée (`-decrypt`, sans `-pubin` puisque la bi-clé contient la clé privée) :

```console
[etudiant@tls-ca-palancac ~]$ curl -fO http://192.168.170.219/cipher.kgrandy.bin
100   128  100   128    0     0  33648      0 --:--:-- --:--:-- --:--:-- 42666
[etudiant@tls-ca-palancac ~]$ openssl pkeyutl -decrypt -inkey rsa_keys_cyphered.pem -in cipher.kgrandy.bin -out dechiffre.txt
Enter pass phrase for rsa_keys_cyphered.pem:
[etudiant@tls-ca-palancac ~]$ cat dechiffre.txt
Bonjour de GRANDY Kylian
```

Les deux messages sont retrouvés à l'identique : l'échange confidentiel fonctionne dans les deux sens, alors que les chiffrés ont transité en clair via HTTP. En revanche, rien ne prouve l'origine d'un message : n'importe qui connaissant la clé publique de Kylian aurait pu lui écrire. Il faudrait signer le message avec la clé privée de l'expéditeur.

## 5. Analyse du contenu d'un certificat

Les manipulations sont faites depuis `tls-ca-palancac`.

### 5.1 En ligne de commande avec `openssl s_client`

`openssl s_client` est un client TLS minimal qui affiche le déroulement de la poignée de main :

```console
[etudiant@tls-ca-palancac ~]$ openssl s_client -showcerts -connect www.univ-grenoble-alpes.fr:443
Connecting to 195.83.24.194
CONNECTED(00000003)
depth=2 C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
verify return:1
depth=1 C=GR, O=Hellenic Academic and Research Institutions CA, CN=GEANT TLS RSA 1
verify return:1
depth=0 C=FR, ST=Auvergne-Rhône-Alpes, L=Saint-Martin-d'Hères, O=Université Grenoble Alpes, CN=*.univ-grenoble-alpes.fr
verify return:1
---
Certificate chain
 0 s:C=FR, ST=Auvergne-Rhône-Alpes, L=Saint-Martin-d'Hères, O=Université Grenoble Alpes, CN=*.univ-grenoble-alpes.fr
   i:C=GR, O=Hellenic Academic and Research Institutions CA, CN=GEANT TLS RSA 1
   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: Oct 20 09:03:04 2026 GMT; NotAfter: May  7 09:03:03 2027 GMT
-----BEGIN CERTIFICATE-----
MIIG/TCCBWWgAwIBAgIQCzgLFUhf5RQqoukVSN7tPTANBgkqhkiG9w0BAQsFADBg
[...]
1S05jJYrsTJlbu8L3jNs8gk=
-----END CERTIFICATE-----
 1 s:C=GR, O=Hellenic Academic and Research Institutions CA, CN=GEANT TLS RSA 1
   i:C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
   a:PKEY: RSA, 3072 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: Jan  3 11:15:00 2025 GMT; NotAfter: Dec 31 11:14:59 2039 GMT
-----BEGIN CERTIFICATE-----
[...]
-----END CERTIFICATE-----
 2 s:C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
   i:C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions RootCA 2015
   a:PKEY: RSA, 4096 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: Sep  2 07:41:55 2021 GMT; NotAfter: Aug 31 07:41:54 2029 GMT
-----BEGIN CERTIFICATE-----
[...]
-----END CERTIFICATE-----
---
Server certificate
subject=C=FR, ST=Auvergne-Rhône-Alpes, L=Saint-Martin-d'Hères, O=Université Grenoble Alpes, CN=*.univ-grenoble-alpes.fr
issuer=C=GR, O=Hellenic Academic and Research Institutions CA, CN=GEANT TLS RSA 1
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: rsa_pss_rsae_sha256
Peer Temp Key: X25519, 253 bits
---
SSL handshake has read 5640 bytes and written 1636 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Server public key is 2048 bit
[...]
Verify return code: 0 (ok)
---
[...]
closed
```

Les blocs Base64 et les tickets de session ont été coupés (`[...]`). La chaîne est vérifiée (`Verify return code: 0 (ok)`), la session utilise TLS 1.3 avec `TLS_AES_256_GCM_SHA384`, et la clé de session est échangée avec `X25519` (Diffie-Hellman sur courbe elliptique, question 2).

### Question 12

> _Lire dans la page de manuel de `s_client` le rôle de l'option `-showcerts`. Expliquer le rôle de cette option. Après avoir parcouru le résultat de la commande, indiquer le nombre de certificats envoyés par le serveur._

D'après `man openssl-s_client`, l'option `-showcerts` affiche **toute la chaîne de certificats envoyée par le serveur**, chacun au format PEM. Sans cette option, `s_client` n'affiche que le certificat du serveur lui-même. Elle permet donc de récupérer les certificats des autorités intermédiaires, que l'on ne possède pas forcément localement.

Le serveur a envoyé **3 certificats**, numérotés de 0 à 2 dans la section `Certificate chain` :

| N° | Sujet (CN)                    | Rôle                                                                            | Clé      |
| -- | ----------------------------- | ------------------------------------------------------------------------------- | -------- |
| 0  | `*.univ-grenoble-alpes.fr`    | Certificat du serveur                                                           | RSA 2048 |
| 1  | `GEANT TLS RSA 1`             | CA intermédiaire, qui a signé le certificat 0                                   | RSA 3072 |
| 2  | `HARICA TLS RSA Root CA 2021` | CA racine, ici sous forme de certificat signé par l'ancienne racine HARICA 2015 | RSA 4096 |

Le serveur envoie donc son certificat, mais aussi ceux des autorités qui permettent de remonter jusqu'à une racine de confiance. Le certificat 2 est particulier : `HARICA TLS RSA Root CA 2021` est une racine, mais la version envoyée par le serveur n'est pas auto-signée. Elle est signée par l'ancienne racine `Hellenic Academic and Research Institutions RootCA 2015`. On parle de **certificat croisé** (_cross-certificate_) : il permet aux clients plus anciens, qui ne connaissent que la racine de 2015, de valider quand même la chaîne.

Le début de la sortie (`depth=2`, `depth=1`, `depth=0`) montre l'ordre dans lequel OpenSSL a vérifié la chaîne, de la racine jusqu'au serveur. `verify return:1` indique que chaque niveau est valide. La vérification s'arrête à `depth=2` et ne remonte pas jusqu'à la racine de 2015, car `HARICA TLS RSA Root CA 2021` est déjà présente dans le magasin de confiance de la machine.

#### Extraction et lecture du certificat du serveur

Plutôt que de copier-coller le bloc PEM à la main, nous avons extrait chaque certificat de la chaîne dans un fichier séparé (`cert0.pem` pour le serveur, `cert1.pem` et `cert2.pem` pour les CA) :

```bash
openssl s_client -showcerts -connect www.univ-grenoble-alpes.fr:443 </dev/null > uga.txt 2>&1
awk '/BEGIN CERTIFICATE/{n++; f="cert" n-1 ".pem"} f{print > f} /END CERTIFICATE/{f=""}' uga.txt
```

`</dev/null` ferme l'entrée de `s_client` pour qu'il se termine, et `awk` écrit chaque bloc PEM dans un fichier séparé. Nous affichons ensuite le certificat du serveur :

```console
[etudiant@tls-ca-palancac ~]$ openssl x509 -in cert0.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0b:38:0b:15:48:5f:e5:14:2a:a2:e9:15:48:de:ed:3d
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=GR, O=Hellenic Academic and Research Institutions CA, CN=GEANT TLS RSA 1
        Validity
            Not Before: Oct 20 09:03:04 2026 GMT
            Not After : May  7 09:03:03 2027 GMT
        Subject: C=FR, ST=Auvergne-Rhône-Alpes, L=Saint-Martin-d'Hères, O=Université Grenoble Alpes, CN=*.univ-grenoble-alpes.fr
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:a8:3b:ac:3f:bf:77:c4:e2:3c:f4:ce:e4:eb:be:
                    [...]
                    1c:c5
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Authority Key Identifier:
                86:01:72:3F:8C:A9:70:E2:31:06:53:16:CE:01:5F:5B:79:C8:3C:3B
            Authority Information Access:
                CA Issuers - URI:http://crt.harica.gr/HARICA-GEANT-TLS-R1.cer
            X509v3 Subject Alternative Name:
                DNS:*.univ-grenoble-alpes.fr, DNS:univ-grenoble-alpes.fr
            X509v3 Certificate Policies:
                Policy: 2.23.140.1.2.2
                Policy: 0.4.0.2042.1.7
                Policy: 1.3.6.1.4.1.26513.1.1.1.2
            X509v3 Extended Key Usage:
                TLS Web Client Authentication, TLS Web Server Authentication
            X509v3 CRL Distribution Points:
                Full Name:
                  URI:http://crl.harica.gr/HARICA-GEANT-TLS-R1.crl
            X509v3 Subject Key Identifier:
                97:DD:13:BA:7F:CC:52:79:B5:76:BE:3A:83:EF:90:38:60:C3:AD:CB
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            CT Precertificate SCTs:
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 60:4C:9A:AF:7A:7F:77:5F:01:D4:06:FC:92:0D:C8:99:
                                EB:0B:1C:7D:F8:C9:52:1B:FA:FA:17:77:3B:97:8B:C9
                    Timestamp : Oct 20 09:13:06.546 2026 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                [...]
                [2 autres Signed Certificate Timestamp]
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        37:86:2b:6c:20:b1:9e:62:a9:2f:cb:f2:ec:3e:b0:38:90:b7:
        [...]
        0b:de:33:6c:f2:09
```

Le module et la signature ont été raccourcis. Seule la première des trois preuves SCT (_Certificate Transparency_ : enregistrement du certificat dans des journaux publics) est affichée.

### Question 13

> _Que signifie le x509 dans la commande saisie ? Quel est le sujet du certificat ? Expliquer complètement la notation utilisée dans le sujet. Que signifie CN ? Quel est l'organisme qui a délivré le certificat ?_

**x509** désigne la norme **X.509** de l'UIT-T, qui définit le format des certificats à clé publique utilisés par TLS. La sous-commande `openssl x509` sert à lire, afficher et convertir des certificats dans ce format. Le certificat est ici en version 3 (`Version: 3`), la seule à autoriser les extensions (`X509v3 ...`) comme le SAN.

**Le sujet** du certificat est :

```text
C=FR, ST=Auvergne-Rhône-Alpes, L=Saint-Martin-d'Hères, O=Université Grenoble Alpes, CN=*.univ-grenoble-alpes.fr
```

Cette notation est un **_Distinguished Name_ (DN)**, hérité de l'annuaire X.500 dont fait partie X.509. Il s'agit d'une suite d'attributs `clé=valeur`, qui décrivent le titulaire du plus général au plus précis :

| Attribut | Signification                          | Valeur                      |
| -------- | -------------------------------------- | --------------------------- |
| `C`      | _Country_ : pays, code ISO à 2 lettres | `FR`                        |
| `ST`     | _State or Province_ : région           | `Auvergne-Rhône-Alpes`      |
| `L`      | _Locality_ : ville                     | `Saint-Martin-d'Hères`      |
| `O`      | _Organization_ : organisme titulaire   | `Université Grenoble Alpes` |
| `CN`     | _Common Name_ : nom commun             | `*.univ-grenoble-alpes.fr`  |

**CN** signifie _Common Name_. Pour un certificat de serveur, il contient le nom de domaine du site. Ici, c'est un nom **générique** (_wildcard_) : `*` remplace un niveau de sous-domaine, donc le certificat est valable pour `www.univ-grenoble-alpes.fr`, mais aussi pour `ent.univ-grenoble-alpes.fr` ou tout autre sous-domaine direct.

**L'organisme qui a délivré le certificat** est indiqué dans le champ `Issuer` : il s'agit de l'autorité de certification `GEANT TLS RSA 1`, exploitée par HARICA, basée en Grèce (`C=GR`).

### Question 14

> _Que représente le « s », le « i » ?_

Dans la section `Certificate chain`, chaque certificat est précédé de quatre lignes de résumé :

| Ligne | Signification                                                     | Exemple pour le certificat 0  |
| ----- | ----------------------------------------------------------------- | ----------------------------- |
| `s:`  | _subject_ : le **sujet**, c'est-à-dire le titulaire du certificat | `CN=*.univ-grenoble-alpes.fr` |
| `i:`  | _issuer_ : l'**émetteur**, c'est-à-dire la CA qui l'a signé       | `CN=GEANT TLS RSA 1`          |

Ces lignes permettent de suivre la chaîne d'un coup d'œil : **l'émetteur (`i:`) du certificat n est le sujet (`s:`) du certificat n+1**. Le certificat 0 est émis par `GEANT TLS RSA 1`, qui est le sujet du certificat 1. Celui-ci est émis par `HARICA TLS RSA Root CA 2021`, sujet du certificat 2.

### Question 15

> _Quelle partie d'une clé RSA le certificat contient-il ? Quels algorithmes ont été utilisés pour signer le certificat ? Que contient l'attribut CN du sujet ? Quel attribut contient les autres noms de machine ? Quelle est la durée de validité du certificat ? Quelle est l'utilité du lien pointant vers un fichier .crl ?_

**Partie de la clé RSA :** le certificat contient uniquement la **clé publique** du serveur (`Subject Public Key Info`) : le module n de 2048 bits (`Modulus`) et l'exposant public e = 65537 (`Exponent`). La clé privée reste sur le serveur. Un certificat est public et envoyé à chaque client : il ne doit jamais contenir d'élément secret.

**Algorithmes de signature :** `sha256WithRSAEncryption`, c'est-à-dire un haché SHA-256 du certificat, signé avec RSA.

**Attribut CN :** il contient `*.univ-grenoble-alpes.fr`.

**Autres noms de machine :** ils figurent dans l'extension **`X509v3 Subject Alternative Name`** (SAN) :

```text
DNS:*.univ-grenoble-alpes.fr, DNS:univ-grenoble-alpes.fr
```

Le _wildcard_ ne couvre pas `univ-grenoble-alpes.fr` sans préfixe, d'où la seconde entrée. Les navigateurs ne vérifient plus que le SAN.

**Durée de validité :** du **20 octobre 2026** (`Not Before`) au **7 mai 2027** (`Not After`), soit 199 jours, sous la limite de 200 jours imposée aux CA publiques par le CA/Browser Forum.

**Lien vers le fichier .crl :** l'extension `X509v3 CRL Distribution Points` contient l'adresse `http://crl.harica.gr/HARICA-GEANT-TLS-R1.crl`. Une **CRL** (_Certificate Revocation List_) est la liste, signée par la CA, des numéros de série des certificats qu'elle a **révoqués** avant leur date d'expiration, par exemple parce que la clé privée a été volée. Le client vérifie que le numéro de série du certificat n'y figure pas.

Les autres extensions confirment qu'il s'agit d'un certificat de serveur : `CA:FALSE` interdit de l'utiliser pour signer d'autres certificats, `Key Usage` et `Extended Key Usage` limitent son usage à la signature, au chiffrement de clé et à l'authentification TLS.

### Question 16

> _Par qui le certificat de `www.univ-grenoble-alpes.fr` a-t-il été signé ? Soit E l'algorithme de chiffrement RSA, donner la formule utilisée pour calculer la signature présente dans le certificat._

Le certificat a été signé par l'autorité intermédiaire **`GEANT TLS RSA 1`** (champ `Issuer`), avec **sa clé privée**. On peut le vérifier : l'`Authority Key Identifier` du certificat (`86:01:72:3F:...`) doit être égal au `Subject Key Identifier` du certificat de `GEANT TLS RSA 1`.

La signature est calculée sur la partie `Data` du certificat (appelée _TBSCertificate_, _to be signed_), qui contient tous les champs sauf la signature elle-même. En notant $H$ la fonction SHA-256, $E$ le chiffrement RSA et $K_{priv}^{CA} = (n_{CA}, d_{CA})$ la clé privée de GEANT TLS RSA 1 :

```math
\text{Signature} = E_{K_{priv}^{CA}}\big(H(\text{TBSCertificate})\big) = \big(\text{pad}(H(\text{TBSCertificate}))\big)^{d_{CA}} \bmod n_{CA}
```

où `pad` est le remplissage PKCS#1 v1.5, qui complète l'empreinte de 32 octets jusqu'à la taille du module.

Pour **vérifier** la signature, le client recalcule $H(\text{TBSCertificate})$ et le compare au résultat de l'opération inverse, faite avec la clé publique de la CA :

```math
\text{Signature}^{e_{CA}} \bmod n_{CA} \stackrel{?}{=} \text{pad}(H(\text{TBSCertificate}))
```

La taille de la signature confirme qui l'a produite : la valeur affichée sous `Signature Value` fait 384 octets, soit **3072 bits**. C'est la taille de la clé de `GEANT TLS RSA 1` (`a:PKEY: RSA, 3072 (bit)`), et non celle de la clé de 2048 bits du serveur.

À ne pas confondre avec la ligne `Peer signature type: rsa_pss_rsae_sha256` de `s_client` : c'est la signature `CertificateVerify` produite par le serveur pendant la poignée de main (question 4).

### Question 17

> _Afficher le certificat de la CA qui a délivré le certificat de `www.univ-grenoble-alpes.fr`. Relever le sujet de ce certificat. Quelle est la taille de la clé publique présente dans ce certificat ? Par quelle CA ce certificat a-t-il été signé ?_

Le certificat de la CA émettrice est le deuxième de la chaîne envoyée par le serveur, extrait dans `cert1.pem`. Plutôt que d'afficher tout le certificat, nous avons demandé à OpenSSL uniquement les champs utiles :

```console
[etudiant@tls-ca-palancac ~]$ openssl x509 -in cert1.pem -noout -subject -issuer -dates
subject=C=GR, O=Hellenic Academic and Research Institutions CA, CN=GEANT TLS RSA 1
issuer=C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
notBefore=Jan  3 11:15:00 2025 GMT
notAfter=Dec 31 11:14:59 2039 GMT
[etudiant@tls-ca-palancac ~]$ openssl x509 -in cert1.pem -noout -text | grep -E "Public-Key|CA:|Path|Key Usage" -A1
                Public-Key: (3072 bit)
                Modulus:
--
                CA:TRUE, pathlen:0
            X509v3 Authority Key Identifier:
--
            X509v3 Extended Key Usage:
                TLS Web Client Authentication, TLS Web Server Authentication
--
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
```

- **Sujet :** `C=GR, O=Hellenic Academic and Research Institutions CA, CN=GEANT TLS RSA 1`. C'est l'autorité intermédiaire exploitée par HARICA pour le compte de GÉANT.
- **Taille de la clé publique :** **3072 bits**, contre 2048 bits pour le serveur. Une CA utilise une clé plus longue, car elle reste en service beaucoup plus longtemps : ce certificat est valable de 2025 à **2039**, soit près de 15 ans, contre 199 jours pour celui du serveur. Une clé de CA compromise permettrait de fabriquer de faux certificats pour n'importe quel site.
- **Signé par :** `HARICA TLS RSA Root CA 2021` (champ `issuer`), l'autorité racine de HARICA.

Les extensions montrent que ce certificat est bien celui d'une autorité de certification, contrairement à celui du serveur :

| Extension           | Certificat du serveur (`cert0`)       | Certificat de la CA (`cert1`)                   |
| ------------------- | ------------------------------------- | ----------------------------------------------- |
| `Basic Constraints` | `CA:FALSE`                            | `CA:TRUE, pathlen:0`                            |
| `Key Usage`         | `Digital Signature, Key Encipherment` | `Digital Signature, Certificate Sign, CRL Sign` |

`CA:TRUE` et `Certificate Sign` autorisent la CA à signer des certificats, et `CRL Sign` à signer la liste de révocation vue à la question 15. `pathlen:0` signifie qu'aucune autre CA intermédiaire ne peut exister sous elle : elle peut seulement signer des certificats finaux, comme celui de l'université.

### Question 18

> _Pour chaque certificat de niveau n, vérifier rapidement qu'il contient les informations nécessaires pour valider le certificat de niveau n-1. On s'intéresse au certificat de dernier niveau. Quel certificat permet de valider ce certificat ? Où se trouve-t-il ?_

Ici, le certificat de niveau n est celui de l'émetteur, et le certificat de niveau n−1 celui qu'il a signé. Pour que le certificat n puisse valider le certificat n−1, deux conditions doivent être réunies :

1. **Le sujet du certificat n est égal à l'émetteur du certificat n−1.** C'est ce lien qui permet de construire la chaîne.
2. **Le certificat n contient la clé publique qui vérifie la signature du certificat n−1.** Pour la retrouver sans ambiguïté, chaque certificat porte deux identifiants de clé : le _Subject Key Identifier_ (SKI) identifie sa propre clé, et l'_Authority Key Identifier_ (AKI) identifie la clé de l'émetteur. L'AKI du certificat n−1 doit donc être égal au SKI du certificat n.

Nous avons affiché ces quatre champs pour les trois certificats de la chaîne :

```console
[etudiant@tls-ca-palancac ~]$ for i in 0 1 2; do
  echo "== cert$i.pem"
  openssl x509 -in cert$i.pem -noout -subject -issuer -ext subjectKeyIdentifier,authorityKeyIdentifier
done
== cert0.pem
subject=C=FR, ST=Auvergne-Rhône-Alpes, L=Saint-Martin-d'Hères, O=Université Grenoble Alpes, CN=*.univ-grenoble-alpes.fr
issuer=C=GR, O=Hellenic Academic and Research Institutions CA, CN=GEANT TLS RSA 1
X509v3 Authority Key Identifier:
    86:01:72:3F:8C:A9:70:E2:31:06:53:16:CE:01:5F:5B:79:C8:3C:3B
X509v3 Subject Key Identifier:
    97:DD:13:BA:7F:CC:52:79:B5:76:BE:3A:83:EF:90:38:60:C3:AD:CB
== cert1.pem
subject=C=GR, O=Hellenic Academic and Research Institutions CA, CN=GEANT TLS RSA 1
issuer=C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
X509v3 Authority Key Identifier:
    0A:48:23:A6:60:A4:92:0A:33:EA:93:5B:C5:57:EA:25:4D:BD:12:EE
X509v3 Subject Key Identifier:
    86:01:72:3F:8C:A9:70:E2:31:06:53:16:CE:01:5F:5B:79:C8:3C:3B
== cert2.pem
subject=C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
issuer=C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions RootCA 2015
X509v3 Authority Key Identifier:
    71:15:67:C8:C8:C9:BD:75:5D:72:D0:38:18:6A:9D:F3:71:24:54:0B
X509v3 Subject Key Identifier:
    0A:48:23:A6:60:A4:92:0A:33:EA:93:5B:C5:57:EA:25:4D:BD:12:EE
```

Les identifiants s'enchaînent parfaitement :

| Certificat validé (n−1) | AKI du certificat n−1 | Certificat validant (n)    | SKI du certificat n       |
| ----------------------- | --------------------- | -------------------------- | ------------------------- |
| `cert0` (serveur)       | `86:01:72:3F:…:3C:3B` | `cert1` (GEANT TLS RSA 1)  | `86:01:72:3F:…:3C:3B`     |
| `cert1` (GEANT)         | `0A:48:23:A6:…:12:EE` | `cert2` (HARICA Root 2021) | `0A:48:23:A6:…:12:EE`     |
| `cert2` (HARICA 2021)   | `71:15:67:C8:…:54:0B` | Hellenic RootCA 2015       | non envoyé par le serveur |

Les sujets et émetteurs concordent de la même façon. Chaque certificat de la chaîne contient donc bien la clé publique nécessaire pour vérifier la signature du précédent, ainsi que `CA:TRUE` et `Certificate Sign` qui l'autorisent à signer.

**Le certificat de dernier niveau** est `cert2`, `HARICA TLS RSA Root CA 2021`. Il est signé par `Hellenic Academic and Research Institutions RootCA 2015`, dont la clé a pour identifiant `71:15:67:C8:…`. **Ce certificat n'a pas été envoyé par le serveur** : il doit se trouver sur la machine du client, dans son **magasin de certificats de confiance**. C'est ce point de départ, installé à l'avance, qui permet de faire confiance à tout le reste de la chaîne.

#### Recherche de la racine dans le magasin de confiance

La page de manuel de `update-ca-trust` indique que les certificats de confiance sont regroupés dans `/etc/pki/ca-trust/extracted/`, et cite le fichier `openssl/ca-bundle.trust.crt`. Ce fichier n'existe pas sur la version d'Alma Linux utilisée : le dossier `openssl/` ne contient plus qu'un `README`. Nous avons donc utilisé le fichier `pem/tls-ca-bundle.pem`, décrit dans la même page comme contenant les CA de confiance pour l'authentification des serveurs TLS :

```console
[etudiant@tls-ca-palancac ~]$ man update-ca-trust | grep -n -B1 -A4 "extracted/"
[...]
123:       The directory /etc/pki/ca-trust/extracted/openssl/ contains CA certificate bundle files in the extended BEGIN/END TRUSTED CERTIFICATE file format, as
124-       described in the x509(1) manual page. File ca-bundle.trust.crt contains the full set of all trusted or distrusted certificates, including the associated
125-       trust flags.
126-
127:       The directory /etc/pki/ca-trust/extracted/pem/ contains CA certificate bundle files in the simple BEGIN/END CERTIFICATE file format, as described in the
128-       x509(1) manual page. Distrust information cannot be represented in this file format, and distrusted certificates are missing from these files. File
129-       tls-ca-bundle.pem contains CA certificates trusted for TLS server authentication. File email-ca-bundle.pem contains CA certificates trusted for E-Mail
130-       protection. File objsign-ca-bundle.pem contains CA certificates trusted for code signing.
[...]
[etudiant@tls-ca-palancac ~]$ ls -l /etc/pki/ca-trust/extracted/openssl/ /etc/pki/ca-trust/extracted/pem/
/etc/pki/ca-trust/extracted/openssl/:
total 4
-rw-r--r--. 1 root root 787 Oct 29  2024 README

/etc/pki/ca-trust/extracted/pem/:
total 904
-rw-r--r--. 1 root root    898 Oct 29  2024 README
dr-xr-xr-x. 2 root root  16384 Aug 27  2025 directory-hash
-r--r--r--. 1 root root 165521 Aug 27  2025 email-ca-bundle.pem
-r--r--r--. 1 root root 502506 Aug 27  2025 objsign-ca-bundle.pem
-r--r--r--. 1 root root 226489 Aug 27  2025 tls-ca-bundle.pem
```

Ce fichier contient plusieurs centaines de certificats à la suite. Nous l'avons découpé en un fichier par certificat, puis nous avons cherché ceux de HARICA :

```console
[etudiant@tls-ca-palancac ~]$ mkdir -p ~/store && cd ~/store
[etudiant@tls-ca-palancac store]$ awk '/BEGIN CERTIFICATE/{n++; f=sprintf("ca%03d.pem", n)} f{print > f} /END CERTIFICATE/{f=""}' \
  /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
[etudiant@tls-ca-palancac store]$ for f in ca*.pem; do
  s=$(openssl x509 -in $f -noout -subject)
  echo "$s" | grep -qiE "harica|hellenic" && echo "$f : $s"
done
ca076.pem : subject=C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS ECC Root CA 2021
ca077.pem : subject=C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
ca078.pem : subject=C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions ECC RootCA 2015
ca079.pem : subject=C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions RootCA 2015
```

Le certificat qui valide `cert2` est `Hellenic Academic and Research Institutions RootCA 2015`, en version RSA (`ca079.pem`). Il se trouve dans le magasin de confiance du système, `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` (paquet `ca-certificates`).

`HARICA TLS RSA Root CA 2021` est elle-même présente dans le magasin (`ca077.pem`), en version auto-signée : le client n'a pas besoin de remonter jusqu'à la racine de 2015.

```console
[etudiant@tls-ca-palancac ~]$ openssl verify -show_chain -untrusted cert1.pem cert0.pem
cert0.pem: OK
Chain:
depth=0: C=FR, ST=Auvergne-Rhône-Alpes, L=Saint-Martin-d'Hères, O=Université Grenoble Alpes, CN=*.univ-grenoble-alpes.fr (untrusted)
depth=1: C=GR, O=Hellenic Academic and Research Institutions CA, CN=GEANT TLS RSA 1 (untrusted)
depth=2: C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
```

`-untrusted` fournit l'intermédiaire sans lui accorder de confiance. Le niveau 2 n'est pas marqué `(untrusted)` : OpenSSL l'a trouvé dans le magasin, d'où l'arrêt à `depth=2` à la question 12.

Les deux versions de `HARICA TLS RSA Root CA 2021` (croisée et auto-signée) ont le même SKI `0A:48:23:A6:…`, donc la même clé publique :

```console
[etudiant@tls-ca-palancac ~]$ openssl x509 -in ~/store/ca077.pem -noout -subject -issuer -ext subjectKeyIdentifier
subject=C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
issuer=C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
X509v3 Subject Key Identifier:
    0A:48:23:A6:60:A4:92:0A:33:EA:93:5B:C5:57:EA:25:4D:BD:12:EE
```

C'est l'intérêt du certificat croisé : un système récent s'arrête à la racine de 2021, un système ancien remonte jusqu'à celle de 2015 grâce à `cert2`.

#### Extraction du certificat de la CA racine

Nous avons copié le certificat de la racine `Hellenic Academic and Research Institutions RootCA 2015`, trouvé à l'étape précédente, dans le fichier `root-ca1.pem`, puis nous avons affiché son contenu :

```console
[etudiant@tls-ca-palancac ~]$ cp ~/store/ca079.pem root-ca1.pem
[etudiant@tls-ca-palancac ~]$ openssl x509 -in root-ca1.pem -noout -text | head -30
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 0 (0x0)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions RootCA 2015
        Validity
            Not Before: Jul  7 10:11:21 2015 GMT
            Not After : Jun 30 10:11:21 2040 GMT
        Subject: C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions RootCA 2015
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:c2:f8:a9:3f:1b:89:fc:3c:3c:04:5d:3d:90:36:
                    [...]
[etudiant@tls-ca-palancac ~]$ openssl x509 -in root-ca1.pem -noout -subject -issuer -ext subjectKeyIdentifier,authorityKeyIdentifier,basicConstraints,keyUsage
subject=C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions RootCA 2015
issuer=C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions RootCA 2015
X509v3 Basic Constraints: critical
    CA:TRUE
X509v3 Key Usage: critical
    Certificate Sign, CRL Sign
X509v3 Subject Key Identifier:
    71:15:67:C8:C8:C9:BD:75:5D:72:D0:38:18:6A:9D:F3:71:24:54:0B
```

Le SKI de cette racine, `71:15:67:C8:…`, est bien égal à l'AKI de `cert2` relevé à la question 18. Pour le confirmer, nous avons demandé à OpenSSL de vérifier `cert2` en utilisant **uniquement** `root-ca1.pem` comme autorité de confiance. Les options `-no-CApath -no-CAstore` désactivent le magasin du système :

```console
[etudiant@tls-ca-palancac ~]$ openssl verify -no-CApath -no-CAstore -CAfile root-ca1.pem cert2.pem
cert2.pem: OK
[etudiant@tls-ca-palancac ~]$ openssl verify -no-CApath -no-CAstore -CAfile root-ca1.pem root-ca1.pem
root-ca1.pem: OK
```

La première vérification prouve que c'est bien cette racine qui a signé `cert2`. La seconde montre que la racine se valide elle-même : sa signature est vérifiée avec sa propre clé publique.

### Question 19

> _Comparer les champs `subject` et `issuer`. Qu'en déduisez-vous ? Donnez la formule qui a permis de générer la signature de ce certificat. Comment s'appelle ce type de certificat ?_

**Les champs `subject` et `issuer` sont identiques :**

```text
C=GR, L=Athens, O=Hellenic Academic and Research Institutions Cert. Authority, CN=Hellenic Academic and Research Institutions RootCA 2015
```

Le titulaire du certificat et l'autorité qui l'a signé sont donc la même entité : **la CA a signé son propre certificat**, avec sa propre clé privée. Il n'existe aucune autorité au-dessus d'elle : c'est le sommet de la chaîne de confiance.

Plusieurs autres éléments le confirment :

- **L'extension `Authority Key Identifier` est absente.** Elle servirait à désigner la clé de l'émetteur, qui est ici la même que celle du sujet (SKI `71:15:67:C8:…`).
- **`openssl verify` accepte `root-ca1.pem` en se servant de lui-même comme seule autorité** : la signature est vérifiée avec la clé publique contenue dans le certificat.
- **`Basic Constraints` vaut `CA:TRUE` sans `pathlen`** : contrairement à `GEANT TLS RSA 1` (`pathlen:0`), aucune limite n'est imposée au nombre de CA intermédiaires en dessous.
- **`Key Usage` est limité à `Certificate Sign, CRL Sign`.** Une racine ne sert qu'à signer des certificats de CA et des listes de révocation, jamais à authentifier un serveur.
- **La clé fait 4096 bits et le certificat est valable 25 ans**, de 2015 à 2040. C'est la clé la plus longue et la durée de vie la plus longue de toute la chaîne : 2048 bits et 199 jours pour le serveur, 3072 bits et 15 ans pour la CA intermédiaire.

**Formule de la signature :** comme à la question 16, en notant $H$ la fonction SHA-256 et $E$ le chiffrement RSA, mais avec cette fois la **clé privée de la racine elle-même**, $K_{priv}^{root} = (n_{root}, d_{root})$ :

```math
\text{Signature} = E_{K_{priv}^{root}}\big(H(\text{TBSCertificate})\big) = \big(\text{pad}(H(\text{TBSCertificate}))\big)^{d_{root}} \bmod n_{root}
```

La vérification utilise la clé publique $(n_{root}, e_{root})$, qui se trouve dans le même certificat :

```math
\text{Signature}^{e_{root}} \bmod n_{root} \stackrel{?}{=} \text{pad}(H(\text{TBSCertificate}))
```

**Ce type de certificat s'appelle un certificat auto-signé** (_self-signed certificate_), et ici plus précisément un **certificat racine** (_root certificate_).

Cette auto-signature ne prouve rien sur l'identité du titulaire : la confiance vient de **la présence du certificat dans le magasin de confiance** du système ou du navigateur, qui n'y intègrent une CA qu'après audit. C'est pourquoi la racine n'a pas besoin d'être envoyée par le serveur.

### 5.2 Dans un navigateur

J'ai affiché dans Chrome le certificat de `https://www.univ-grenoble-alpes.fr`. L'onglet « Général » du lecteur de certificat donne les informations suivantes :

| Information             | Chrome (« Lecteur du certificat »)                                 | OpenSSL (`cert0.pem`)                                              |
| ----------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| Émis pour (CN)          | `*.univ-grenoble-alpes.fr`                                         | `Subject: … CN=*.univ-grenoble-alpes.fr`                           |
| Émis pour (O)           | `Université Grenoble Alpes`                                        | `Subject: … O=Université Grenoble Alpes`                           |
| Émis par (CN)           | `GEANT TLS RSA 1`                                                  | `Issuer: … CN=GEANT TLS RSA 1`                                     |
| Émis par (O)            | `Hellenic Academic and Research Institutions CA`                   | `Issuer: … O=Hellenic Academic and Research Institutions CA`       |
| Émis le                 | mardi 20 octobre 2026 à 11:03:04                                   | `Not Before: Oct 20 09:03:04 2026 GMT`                             |
| Expire le               | vendredi 7 mai 2027 à 11:03:03                                     | `Not After : May  7 09:03:03 2027 GMT`                             |
| Empreinte du certificat | `5716ad84d1bffda30b99098995d1a064ac19adabfdc19add30e5b3612ac7e342` | `57:16:AD:84:D1:BF:FD:A3:…:2A:C7:E3:42`                            |
| Empreinte de la clé     | `a0a4174f66ef9de3660a18ff161b8aec805ff374b88789bf0b8f4cf8f2feea57` | `a0a4174f66ef9de3660a18ff161b8aec805ff374b88789bf0b8f4cf8f2feea57` |

Les informations sont identiques. Les heures diffèrent de deux heures, car Chrome les affiche dans le fuseau horaire local (heure d'été de Paris, UTC+2), alors qu'OpenSSL les affiche en temps universel (GMT).

Les empreintes SHA-256 permettent de prouver qu'il s'agit **exactement du même certificat**, et pas seulement d'un certificat portant les mêmes noms. Je les ai recalculées avec OpenSSL à partir du fichier `cert0.pem` :

```console
[etudiant@tls-ca-palancac ~]$ openssl x509 -in cert0.pem -noout -fingerprint -sha256
sha256 Fingerprint=57:16:AD:84:D1:BF:FD:A3:0B:99:09:89:95:D1:A0:64:AC:19:AD:AB:FD:C1:9A:DD:30:E5:B3:61:2A:C7:E3:42
[etudiant@tls-ca-palancac ~]$ openssl x509 -in cert0.pem -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256
SHA2-256(stdin)= a0a4174f66ef9de3660a18ff161b8aec805ff374b88789bf0b8f4cf8f2feea57
```

- **L'empreinte du certificat** est le haché SHA-256 du certificat complet, encodé en DER. Changer un seul bit du certificat (une date, un nom, la signature…) changerait totalement cette valeur. Les deux empreintes sont identiques : Chrome et OpenSSL ont reçu le même certificat.
- **L'empreinte de la clé publique** est le haché du seul bloc `Subject Public Key Info`. Elle reste identique si le certificat est renouvelé avec la même clé. C'est pourquoi elle sert notamment à « épingler » une clé (_public key pinning_).

## 6. Mise en place d'une PKI

### 6.1 Présentation de la PKI

```text
Root Lorne                    (CA racine, gérée par l'enseignant)
   └── RA palancac            (notre CA intermédiaire, signée par Root Lorne)
          └── www.palancac.fr (certificat du serveur web, signé par RA palancac)
```

| Niveau           | Distinguished Name                                              | Équivalent à la section 5   |
| ---------------- | --------------------------------------------------------------- | --------------------------- |
| CA racine        | `C=FR, ST=Savoie, L=Chambery, O=TP Sécurité, CN=Root Lorne`     | HARICA TLS RSA Root CA 2021 |
| CA intermédiaire | `C=FR, ST=Savoie, L=Chambery, O=TP Sécurité, CN=RA palancac`    | GEANT TLS RSA 1             |
| Serveur          | `CN=www.palancac.fr`, entreprise « Canut palancac inc. » à Lyon | `*.univ-grenoble-alpes.fr`  |

Bien qu'elle s'appelle « racine », `Root Lorne` n'est présente dans aucun magasin de confiance. Il faudra donc l'ajouter manuellement sur les clients pour qu'ils acceptent les certificats de cette PKI.

### 6.2 Étude de la CA racine (CN=Root Lorne)

La CA racine est installée sur une machine dédiée (`root-ca-tp`, `192.168.170.231`). Nous nous y sommes connectés en SSH depuis `tls-ca-palancac` avec le compte `camanager` fourni dans le sujet :

```bash
ssh camanager@192.168.170.231
```

#### Contenu du dossier de la CA

```console
[camanager@root-ca-tp ca]$ ls -la
total 48
drwxr-xr-x. 7 camanager camanager 4096 Nov 16 10:05 .
drwx------. 6 camanager camanager 4096 Nov 16 10:12 ..
drwxr-xr-x. 2 camanager camanager 4096 Nov 16 09:47 certs
drwxr-xr-x. 2 camanager camanager    6 Nov  1  2025 crl
drwxr-xr-x. 2 camanager camanager 4096 Nov 16 09:46 csr
-rw-r--r--. 1 camanager camanager 3062 Nov 16 09:47 index.txt
-rw-r--r--. 1 camanager camanager   21 Nov 16 09:47 index.txt.attr
-rw-r--r--. 1 camanager camanager   21 Nov 16 09:47 index.txt.attr.old
-rw-r--r--. 1 camanager camanager 3062 Nov 16 09:47 index.txt.old
drwxr-xr-x. 2 camanager camanager 4096 Nov 16 09:47 newcerts
-rw-r--r--. 1 camanager camanager 3728 Nov  2  2025 openssl.cnf
drwx------. 2 camanager camanager   24 Nov 12  2025 private
-rw-r--r--. 1 camanager camanager    5 Nov 16 09:47 serial
-rw-r--r--. 1 camanager camanager    5 Nov 16 09:47 serial.old
[camanager@root-ca-tp ca]$ ls -la */
certs/:
-rw-r--r--. 1 camanager camanager 1216 Nov 10  2025 abranteg.cert.pem
[...]
-rw-r--r--. 1 camanager camanager  818 Nov 12  2025 ca.cert.pem
[...]
csr/:
-rw-r--r--. 1 camanager camanager 1346 Nov 10  2025 abranteg.csr.pem
[...]
newcerts/:
-rw-r--r--. 1 camanager camanager 1216 Nov  2  2025 1000.pem
-rw-r--r--. 1 camanager camanager 1216 Nov 10  2025 1001.pem
[...]
-rw-r--r--. 1 camanager camanager  769 Nov 16 09:47 101F.pem

private/:
-r--------. 1 camanager camanager  314 Nov 12  2025 ca.key.pem
```

Les listes de `certs/`, `csr/` et `newcerts/` ont été raccourcies : elles contiennent les fichiers des autres étudiants.

Chaque élément a un rôle précis dans le fonctionnement de la CA :

| Élément              | Rôle                                                                                                                               |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `openssl.cnf`        | Configuration de la CA : emplacement des fichiers, durées, politiques et extensions                                                |
| `private/ca.key.pem` | Clé privée de la CA. Le dossier est en `700` et le fichier en `400` : seul `camanager` peut le lire                                |
| `certs/`             | Certificats délivrés, dont celui de la CA elle-même (`ca.cert.pem`) et ceux des CA intermédiaires des étudiants (`login.cert.pem`) |
| `csr/`               | Demandes de certificat (_Certificate Signing Request_) déposées par les étudiants                                                  |
| `newcerts/`          | Copie de chaque certificat signé, nommée d'après son numéro de série (`1000.pem` à `101F.pem`, soit 32 certificats délivrés)       |
| `index.txt`          | Base de données de la CA : une ligne par certificat délivré (état valide ou révoqué, date d'expiration, numéro de série, sujet)    |
| `serial`             | Prochain numéro de série à attribuer, en hexadécimal. Chaque certificat doit avoir un numéro unique                                |
| `crl/`               | Listes de révocation (vide : aucune CRL n'a encore été publiée)                                                                    |
| `*.old`              | Sauvegardes automatiques faites par `openssl ca` avant chaque modification de la base                                              |

#### Fichier de configuration `openssl.cnf`

Les concepteurs d'OpenSSL fournissent, avec la commande `openssl ca`, de quoi gérer une « petite » autorité de certification. Ses paramètres sont regroupés dans `openssl.cnf`. Les lignes utiles :

```console
[camanager@root-ca-tp ca]$ grep -nE "^\s*(dir|certificate|private_key|policy)\s*=" openssl.cnf
9:dir = /home/camanager/ca
17:private_key = $dir/private/ca.key.pem
18:certificate = $dir/certs/ca.cert.pem
30:policy = policy_strict
```

La section `[ ca ]` indique que la CA par défaut est `CA_default`. Dans cette section, `dir` contient le répertoire racine de la CA, et les autres chemins sont construits à partir de lui : le certificat de la CA est donc `/home/camanager/ca/certs/ca.cert.pem` et sa clé privée `/home/camanager/ca/private/ca.key.pem`.

Le fichier définit aussi plusieurs jeux d'extensions, appliqués selon le type de certificat à signer :

| Section                  | Utilisée pour              | Extensions principales                                                             |
| ------------------------ | -------------------------- | ---------------------------------------------------------------------------------- |
| `[ v3_ca ]`              | Le certificat de la racine | `CA:true`, `keyCertSign`, `cRLSign`                                                |
| `[ v3_intermediate_ca ]` | Les CA intermédiaires      | `CA:true, pathlen:0`, `keyCertSign`, `cRLSign`                                     |
| `[ server_cert ]`        | Les certificats de serveur | `CA:FALSE`, `digitalSignature`, `keyEncipherment`, `extendedKeyUsage = serverAuth` |
| `[ usr_cert ]`           | Les certificats de client  | `CA:FALSE`, `extendedKeyUsage = clientAuth, emailProtection`                       |

On retrouve exactement les extensions observées sur la chaîne de l'université : `pathlen:0` comme `GEANT TLS RSA 1`, `CA:FALSE` et `serverAuth` comme le certificat du serveur.

#### Certificat de la CA racine

La ligne `certificate` donne l'emplacement du certificat, que l'on affiche avec `openssl x509` :

```console
[camanager@root-ca-tp ca]$ openssl x509 -in certs/ca.cert.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            03:3f:2e:7e:15:1a:53:7a:94:f5:59:85:fe:4b:48:49:c8:88:b2:ee
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=FR, ST=Savoie, L=ChambÃ©ry, O=TP SÃ©curitÃ©, CN=Root Lorne
        Validity
            Not Before: Nov 12 12:43:56 2025 GMT
            Not After : Nov  7 12:43:56 2045 GMT
        Subject: C=FR, ST=Savoie, L=ChambÃ©ry, O=TP SÃ©curitÃ©, CN=Root Lorne
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:23:f4:3f:da:7f:59:3d:b1:a9:b0:8b:94:9b:3a:
                    ee:7f:b9:ac:05:84:fc:32:f1:ee:df:ff:e3:b2:86:
                    a7:14:f1:75:4a:de:d6:05:91:58:56:61:0a:ba:c9:
                    45:c2:15:50:22:d6:f1:3e:bd:6d:9b:ac:11:57:39:
                    64:5f:15:bd:fd
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                85:44:BC:D9:48:94:58:B7:90:E3:B0:65:31:CC:2C:23:2C:8F:5F:80
            X509v3 Authority Key Identifier:
                85:44:BC:D9:48:94:58:B7:90:E3:B0:65:31:CC:2C:23:2C:8F:5F:80
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:22:49:af:ef:00:1f:8f:83:21:45:6c:48:26:c5:
        2b:10:92:ac:36:81:7f:68:8b:c5:40:42:73:08:b3:11:19:ba:
        02:20:05:4e:78:5a:14:85:5d:71:65:93:42:cd:4d:37:db:bb:
        e3:2e:37:08:24:73:9d:43:32:01:78:a5:fd:ce:eb:10
```

### Question 20

> _Quel est le type de clé utilisée ? Quelle est la taille de la clé ? Quelle courbe est utilisée ? Quelle est la durée de validité ? Qu'est-ce qui vous permet de dire qu'il s'agit d'un certificat « racine » ou auto-signé ? Pour quels « X509v3 Key Usage » cette autorité de certification peut-elle être utilisée ?_

**Type de clé :** une clé à **courbe elliptique** (`Public Key Algorithm: id-ecPublicKey`), et non une clé RSA comme dans la chaîne de l'université. Le certificat est d'ailleurs signé en **ECDSA** (`ecdsa-with-SHA256`) : le haché SHA-256 du certificat est signé avec l'algorithme de signature sur courbe elliptique.

**Taille de la clé :** **256 bits**, soit une sécurité d'environ 128 bits, équivalente à RSA 3072. Les clés et signatures EC sont bien plus courtes : 70 octets de signature ici, contre 384 pour la signature RSA de la question 16.

**Courbe utilisée :** `prime256v1`, appelée **P-256** par le NIST (`NIST CURVE: P-256`) et `secp256r1` dans d'autres normes. C'est la courbe la plus utilisée en TLS.

**Durée de validité :** du **12 novembre 2025** au **7 novembre 2045**, soit **20 ans**. Comme vu à la question 19, une racine a une durée de vie très longue, car la remplacer oblige à mettre à jour tous les clients qui lui font confiance.

**Certificat racine auto-signé :** plusieurs éléments le montrent :

- **Le sujet et l'émetteur sont identiques** (`C=FR, ST=Savoie, L=Chambéry, O=TP Sécurité, CN=Root Lorne`) : la CA a signé son propre certificat.
- **Le _Subject Key Identifier_ et l'_Authority Key Identifier_ sont égaux** (`85:44:BC:D9:…:5F:80`) : la clé qui a signé le certificat est celle qu'il contient.
- **`Basic Constraints` vaut `CA:TRUE` sans `pathlen`** : c'est une autorité de certification, sans limite sur le nombre de niveaux en dessous d'elle.

**_Key Usage_ autorisés :** `Digital Signature, Certificate Sign, CRL Sign`. La CA peut donc :

- **`Certificate Sign`** : signer des certificats, ici ceux des CA intermédiaires des étudiants ;
- **`CRL Sign`** : signer des listes de révocation ;
- **`Digital Signature`** : produire des signatures numériques sur d'autres données, par exemple des réponses OCSP.

L'extension est marquée `critical` : un logiciel qui ne la comprend pas doit refuser le certificat plutôt que de l'ignorer.

#### Clé privée de la CA racine

La ligne `private_key` du fichier de configuration localise la clé privée. Comme elle est chiffrée, la passphrase fournie dans le sujet est demandée pour l'afficher avec `openssl ec` :

```console
[camanager@root-ca-tp ca]$ openssl ec -in private/ca.key.pem -noout -text | head -3
read EC key
Enter pass phrase for private/ca.key.pem:
Private-Key: (256 bit)
priv:
    [masqué]
```

La valeur `priv` (256 bits) est masquée : elle permettrait de signer des certificats au nom de `Root Lorne`.

#### Politique de signature

La ligne `policy = policy_strict` désigne la politique appliquée aux demandes de certificat. Le fichier en définit deux :

```console
[camanager@root-ca-tp ca]$ sed -n '/\[ policy_strict \]/,/^$/p;/\[ policy_loose \]/,/^$/p' openssl.cnf
[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName = match
stateOrProvinceName = match
organizationName = match
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
```

| Valeur     | Signification                                            |
| ---------- | -------------------------------------------------------- |
| `match`    | Le champ doit être présent et identique à celui de la CA |
| `supplied` | Le champ doit être présent, avec une valeur quelconque   |
| `optional` | Le champ peut être absent                                |

Avec `policy_strict`, la racine n'accepte de signer que les demandes dont le pays (`C=FR`), la région (`ST=Savoie`) et l'organisation (`O=TP Sécurité`) sont identiques aux siens. C'est logique : les CA intermédiaires doivent appartenir à la même organisation que la racine. La ville (`L`) n'est pas contrôlée, ce qui explique que la racine s'appelle `Chambéry` alors que le sujet impose `Chambery` aux intermédiaires.

La politique `policy_loose`, qui n'impose que le `commonName`, est destinée aux CA intermédiaires : elles doivent pouvoir signer les certificats de serveurs appartenant à d'autres organisations, comme « Canut palancac inc. » à Lyon.

### 6.3 Création d'une autorité de certification intermédiaire

Nous mettons en place sur `tls-ca-palancac` notre CA intermédiaire `RA palancac` en trois étapes : bi-clé, demande de certificat (CSR), signature par `Root Lorne`. Nous avons d'abord téléchargé le `openssl.cnf` préconfiguré fourni par l'enseignant :

```console
[etudiant@tls-ca-palancac ~]$ mkdir -p ~/ca && cd ~/ca
[etudiant@tls-ca-palancac ca]$ curl -fO http://192.168.176.2/etrs713/TP-TLS/openssl.interm.cnf
100  3961  100  3961    0     0  2320k      0 --:--:-- --:--:-- --:--:-- 3868k
[etudiant@tls-ca-palancac ca]$ mv openssl.interm.cnf openssl.cnf
[etudiant@tls-ca-palancac ca]$ grep -nE "^\s*(dir|private_key|certificate|policy)\s*=" openssl.cnf
9:dir = /root/ca/intermediate
17:private_key = $dir/private/intermediate.key.pem
18:certificate = $dir/certs/intermediate.cert.pem
30:policy = policy_loose
```

Le fichier est presque identique à celui de la racine, avec trois différences importantes :

| Paramètre                                      | Racine (`Root Lorne`) | Intermédiaire (`RA palancac`)       | Conséquence                                                                                                            |
| ---------------------------------------------- | --------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `policy`                                       | `policy_strict`       | `policy_loose`                      | Notre CA pourra signer des certificats pour d'autres organisations (`Canut palancac inc.`), seul le CN est obligatoire |
| `copy_extensions`                              | absent                | `copy`                              | Les extensions demandées dans la CSR (notamment le `subjectAltName`) sont recopiées dans le certificat                 |
| `authorityInfoAccess` (dans `[ server_cert ]`) | absent                | `OCSP;URI:http://ocsp2.example.com` | Les certificats de serveur indiqueront une adresse OCSP. C'est une valeur d'exemple : aucun serveur OCSP n'y répond    |

Avec `copy_extensions = copy`, toute extension de la CSR qui n'est pas définie dans la section de signature est recopiée : il faut donc relire une demande avant de la signer.

### Question 21

> _Quelle valeur avez-vous mise dans le paramètre `dir` de la section `CA_default` ? Dans quel dossier et sous quel nom la clé privée de la CA devra-t-elle être stockée ? Dans quel dossier et sous quel nom le certificat de la CA devra-t-il être stocké ?_

Le fichier fourni pointait vers `/root/ca/intermediate`, un dossier qui n'existe pas sur notre machine. Nous avons remplacé cette valeur par **`/home/etudiant/ca`**, le dossier imposé par le sujet :

```console
[etudiant@tls-ca-palancac ca]$ sed -i 's|^dir = /root/ca/intermediate|dir = /home/etudiant/ca|' openssl.cnf
[etudiant@tls-ca-palancac ca]$ grep -n "^dir" openssl.cnf
9:dir = /home/etudiant/ca
```

Les autres chemins étant construits à partir de `$dir` :

- **la clé privée de la CA** doit être stockée dans le dossier **`/home/etudiant/ca/private/`**, sous le nom **`intermediate.key.pem`** (paramètre `private_key`) ;
- **le certificat de la CA** doit être stocké dans le dossier **`/home/etudiant/ca/certs/`**, sous le nom **`intermediate.cert.pem`** (paramètre `certificate`).

Nous avons ensuite créé l'arborescence et les fichiers attendus par `openssl ca` :

```console
[etudiant@tls-ca-palancac ca]$ mkdir certs crl csr newcerts private
[etudiant@tls-ca-palancac ca]$ chmod 700 private
[etudiant@tls-ca-palancac ca]$ touch index.txt
[etudiant@tls-ca-palancac ca]$ echo 1000 > serial
[etudiant@tls-ca-palancac ca]$ echo 1000 > crlnumber
[etudiant@tls-ca-palancac ca]$ ls -la
total 16
drwxr-xr-x. 7 etudiant etudiant  139 Nov 16 10:17 .
drwx------. 5 etudiant etudiant 4096 Nov 16 10:15 ..
drwxr-xr-x. 2 etudiant etudiant    6 Nov 16 10:17 certs
drwxr-xr-x. 2 etudiant etudiant    6 Nov 16 10:17 crl
-rw-r--r--. 1 etudiant etudiant    5 Nov 16 10:17 crlnumber
drwxr-xr-x. 2 etudiant etudiant    6 Nov 16 10:17 csr
-rw-r--r--. 1 etudiant etudiant    0 Nov 16 10:17 index.txt
drwxr-xr-x. 2 etudiant etudiant    6 Nov 16 10:17 newcerts
-rw-r--r--. 1 etudiant etudiant 3957 Nov 16 10:17 openssl.cnf
drwx------. 2 etudiant etudiant    6 Nov 16 10:17 private
-rw-r--r--. 1 etudiant etudiant    5 Nov 16 10:17 serial
```

C'est la même structure que celle de la racine (6.2), avec `private/` accessible à son seul propriétaire.

### Question 22

> _Relever la commande saisie pour créer la clé._

Le sujet laissait le choix entre une clé RSA de 3072 bits et une clé sur courbe elliptique. Nous avons choisi une clé **EC sur la courbe P-256**, la même que celle de `Root Lorne` : elle offre une sécurité équivalente à RSA 3072 (voir la question 20) avec des clés et des signatures bien plus courtes.

```console
[etudiant@tls-ca-palancac ca]$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes128 -out private/intermediate.key.pem
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
[etudiant@tls-ca-palancac ca]$ chmod 400 private/intermediate.key.pem
[etudiant@tls-ca-palancac ca]$ ls -l private/
total 4
-r--------. 1 etudiant etudiant 412 Nov 16 10:17 intermediate.key.pem
[etudiant@tls-ca-palancac ca]$ head -1 private/intermediate.key.pem
-----BEGIN ENCRYPTED PRIVATE KEY-----
```

| Option                              | Rôle                                                                                       |
| ----------------------------------- | ------------------------------------------------------------------------------------------ |
| `genpkey -algorithm EC`             | Génère une bi-clé sur courbe elliptique                                                    |
| `-pkeyopt ec_paramgen_curve:P-256`  | Choisit la courbe P-256 (`prime256v1`)                                                     |
| `-aes128`                           | Chiffre la clé privée en AES 128 bits, avec une clé dérivée de la passphrase (notre login) |
| `-out private/intermediate.key.pem` | Enregistre la clé à l'emplacement attendu par `openssl.cnf` (question 21)                  |

L'en-tête `ENCRYPTED PRIVATE KEY` confirme que la clé est chiffrée, et le `chmod 400` la rend lisible par son seul propriétaire.

### Question 23

> _On constate que la demande de certificat contient déjà une signature. Pourquoi la présence de cette signature peut-elle être qualifiée d'incongrue ? Rechercher l'intérêt de cette signature._

Nous avons généré la demande de certificat avec la commande du sujet. La passphrase est demandée, car la CSR est signée avec la clé privée de la CA intermédiaire :

```console
[etudiant@tls-ca-palancac ca]$ openssl req -config openssl.cnf -new -sha256 -key private/intermediate.key.pem \
  -out csr/intermediate.csr.pem -subj "/C=FR/ST=Savoie/L=Chambery/O=TP Sécurité/CN=RA palancac"
Enter pass phrase for private/intermediate.key.pem:
[etudiant@tls-ca-palancac ca]$ openssl req -in csr/intermediate.csr.pem -noout -text
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C=FR, ST=Savoie, L=Chambery, O=TP SÃ©curitÃ©, CN=RA palancac
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:08:a0:6e:1e:8b:f6:3a:75:f1:5e:6e:02:37:a8:
                    b0:e4:6d:05:f9:07:81:e5:c3:06:1c:72:44:68:36:
                    91:46:2d:36:e4:06:db:08:e7:af:b7:8f:1e:67:8b:
                    bb:a4:ff:28:eb:f9:cd:69:72:fd:72:95:66:cb:bc:
                    73:a5:ce:a2:fe
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:5c:fa:3f:aa:33:93:ea:af:74:b6:71:af:c6:a2:
        3a:97:a6:ce:c6:b9:7a:ef:e5:28:97:ab:a7:c6:cc:e2:62:05:
        02:20:4c:4f:e4:c4:10:13:b4:4f:2b:3b:81:72:30:9c:fb:14:
        7b:87:a2:a2:6d:34:cd:47:6c:7b:2b:e7:6e:4f:27:e9
```

Une CSR (PKCS#10) contient le sujet demandé, la clé publique et d'éventuelles extensions (aucune ici) : les extensions de CA seront ajoutées par la racine à la signature (`[ v3_intermediate_ca ]`).

**Problème d'encodage du champ O.** Le « é » de `TP Sécurité` s'affiche `Ã©`, exactement comme dans le certificat de `Root Lorne`. L'analyse de la structure ASN.1 en donne la raison :

```console
[etudiant@tls-ca-palancac ca]$ openssl asn1parse -in csr/intermediate.csr.pem | grep -A1 organizationName
   65:d=5  hl=2 l=   3 prim: OBJECT            :organizationName
   70:d=5  hl=2 l=  17 prim: UTF8STRING        :TP SÃ©curitÃ©
```

Le champ fait **17 octets** au lieu de 13 : sans `-utf8`, `openssl req` traite chaque octet de « é » (`C3 A9`) comme un caractère et le réencode. C'est en fait nécessaire : `policy_strict` exige un `organizationName` identique octet pour octet à celui de `Root Lorne`, créé de la même façon.

**Pourquoi cette signature est incongrue :** une demande de certificat sert justement à obtenir une signature, celle de l'autorité de certification. Or elle est déjà signée, **par le demandeur lui-même**, avec sa propre clé privée : c'est une signature « auto-signée », que personne n'a de raison de croire, puisque personne ne garantit encore que cette clé appartient à `RA palancac`. De plus, cette signature disparaît : le certificat final ne contiendra que la signature de la racine.

**L'intérêt de cette signature** est double :

- **Prouver la possession de la clé privée :** En vérifiant la signature avec la clé publique contenue dans la CSR, la CA s'assure que le demandeur détient bien la clé privée correspondante. Sans cette preuve, n'importe qui pourrait récupérer la clé publique de quelqu'un d'autre (par exemple celle d'un serveur, qui est publique) et obtenir un certificat associant cette clé à sa propre identité.
- **Garantir l'intégrité de la demande :** Si le sujet ou la clé publique étaient modifiés pendant le transfert de la CSR vers la CA (ici par copier-coller), la signature ne serait plus valide.

OpenSSL permet de vérifier cette signature, comme le fera la racine avant de signer :

```console
[etudiant@tls-ca-palancac ca]$ openssl req -in csr/intermediate.csr.pem -noout -verify
Certificate request self-signature verify OK
```

#### Signature de la demande par la CA racine

Comme le demande le sujet, nous avons affiché la CSR sur `tls-ca-palancac`, puis nous l'avons copiée-collée dans `ca/csr/palancac.csr.pem` sur `root-ca-tp` :

```console
[etudiant@tls-ca-palancac ca]$ cat csr/intermediate.csr.pem
-----BEGIN CERTIFICATE REQUEST-----
MIIBHTCBxQIBADBjMQswCQYDVQQGEwJGUjEPMA0GA1UECAwGU2F2b2llMREwDwYD
VQQHDAhDaGFtYmVyeTEaMBgGA1UECgwRVFAgU8ODwqljdXJpdMODwqkxFDASBgNV
BAMMC1JBIHBhbGFuY2FjMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECKBuHov2
OnXxXm4CN6iw5G0F+QeB5cMGHHJEaDaRRi025AbbCOevt48eZ4u7pP8o6/nNaXL9
cpVmy7xzpc6i/qAAMAoGCCqGSM49BAMCA0cAMEQCIFz6P6ozk+qvdLZxr8aiOpem
zsa5eu/lKJerp8bM4mIFAiBMT+TEEBO0Tys7gXIwnPsUe4eiom00zUdseyvnbk8n
6Q==
-----END CERTIFICATE REQUEST-----
```

La racine a signé la demande avec les extensions `v3_intermediate_ca`, pour 10 ans (`-days 3650`) :

```console
[camanager@root-ca-tp ca]$ openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
  -days 3650 -notext -md sha256 -in csr/palancac.csr.pem \
  -out certs/palancac.cert.pem
Using configuration from openssl.cnf
Enter pass phrase for /home/camanager/ca/private/ca.key.pem:
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number: 4129 (0x1021)
        Validity
            Not Before: Nov 16 09:24:55 2026 GMT
            Not After : Nov 13 09:24:55 2036 GMT
        Subject:
            countryName               = FR
            stateOrProvinceName       = Savoie
            organizationName          = TP S\C3\A9curit\C3\A9
            commonName                = RA palancac
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                EA:22:EA:80:2F:10:18:6B:41:BE:F3:5A:2F:70:CB:47:2C:A6:35:96
            X509v3 Authority Key Identifier:
                85:44:BC:D9:48:94:58:B7:90:E3:B0:65:31:CC:2C:23:2C:8F:5F:80
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
Certificate is to be certified until Nov 13 09:24:55 2036 GMT (3650 days)
Sign the certificate? [y/n]:y


1 out of 1 certificate requests certified, commit? [y/n]y
Write out database with 1 new entries
Database updated
```

Le déroulement de la signature est le suivant :

1. **`Check that the request matches the signature` / `Signature ok`** : la racine vérifie d'abord la signature de la CSR, c'est-à-dire la preuve de possession de la clé privée (question 23).
2. **Application de la politique `policy_strict`** : les champs `C`, `ST` et `O` de la demande sont identiques à ceux de la racine, octet pour octet, ce qui confirme que le choix de ne pas utiliser `-utf8` était le bon. Le champ `L=Chambery` a en revanche **disparu** du sujet : `localityName` ne figure pas dans `policy_strict`, et avec `preserve = no`, `openssl ca` supprime tout champ que la politique ne mentionne pas.
3. **Ajout des extensions `v3_intermediate_ca`** : `CA:TRUE, pathlen:0` et les usages `Certificate Sign` et `CRL Sign`, qui n'étaient pas dans la demande. L'_Authority Key Identifier_ (`85:44:BC:D9:…`) est égal au SKI de `Root Lorne` relevé à la question 20.
4. **Attribution du numéro de série** `0x1021`, lu dans le fichier `serial` de la racine. C'est le 34ᵉ certificat délivré depuis `0x1000`.
5. **Double confirmation** (`Sign the certificate?`, puis `commit?`), puis mise à jour de la base `index.txt`.

#### Vérification du certificat de la CA intermédiaire

```console
[camanager@root-ca-tp ca]$ openssl x509 -in certs/palancac.cert.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4129 (0x1021)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=FR, ST=Savoie, L=ChambÃ©ry, O=TP SÃ©curitÃ©, CN=Root Lorne
        Validity
            Not Before: Nov 16 09:24:55 2026 GMT
            Not After : Nov 13 09:24:55 2036 GMT
        Subject: C=FR, ST=Savoie, O=TP SÃ©curitÃ©, CN=RA palancac
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:08:a0:6e:1e:8b:f6:3a:75:f1:5e:6e:02:37:a8:
                    [...]
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                EA:22:EA:80:2F:10:18:6B:41:BE:F3:5A:2F:70:CB:47:2C:A6:35:96
            X509v3 Authority Key Identifier:
                85:44:BC:D9:48:94:58:B7:90:E3:B0:65:31:CC:2C:23:2C:8F:5F:80
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:e6:0f:09:53:84:44:e0:cf:ab:82:49:0e:8c:
        [...]
```

Le certificat correspond à celui attendu :

| Élément      | Valeur                                               | Remarque                                                                          |
| ------------ | ---------------------------------------------------- | --------------------------------------------------------------------------------- |
| Émetteur     | `CN=Root Lorne`                                      | Signé par la racine, en ECDSA                                                     |
| Sujet        | `C=FR, ST=Savoie, O=TP Sécurité, CN=RA palancac`     | Sans `L`, supprimé par la politique                                               |
| Clé publique | EC P-256, `04:08:a0:6e:…`                            | Identique à celle de la CSR : c'est bien la clé de `private/intermediate.key.pem` |
| Validité     | du 16 novembre 2026 au 13 novembre 2036              | 10 ans, entre les 20 ans de la racine et l'année d'un certificat de serveur       |
| Extensions   | `CA:TRUE, pathlen:0`, `Certificate Sign`, `CRL Sign` | CA autorisée à signer des certificats finaux uniquement                           |

On retrouve la même structure qu'avec `GEANT TLS RSA 1` à la question 17 : une CA intermédiaire avec `pathlen:0`, dont l'AKI pointe vers la racine qui l'a signée.

#### Installation du certificat sur la CA intermédiaire

Nous avons copié-collé le certificat sur `tls-ca-palancac`, à l'emplacement défini par le paramètre `certificate` (question 21) :

```console
[etudiant@tls-ca-palancac ca]$ cat > certs/intermediate.cert.pem <<'EOF'
-----BEGIN CERTIFICATE-----
MIICCzCCAbGgAwIBAgICECEwCgYIKoZIzj0EAwIwZTELMAkGA1UEBhMCRlIxDzAN
[...]
A20h1CAD8/ELcMoYdQIgTUuJSYmXsZb07oSgR6L1mOQcOiEpmPao/ujSWU+9mpo=
-----END CERTIFICATE-----
EOF
[etudiant@tls-ca-palancac ca]$ openssl x509 -in certs/intermediate.cert.pem -noout -subject -issuer -dates
subject=C=FR, ST=Savoie, O=TP SÃ©curitÃ©, CN=RA palancac
issuer=C=FR, ST=Savoie, L=ChambÃ©ry, O=TP SÃ©curitÃ©, CN=Root Lorne
notBefore=Nov 16 09:24:55 2026 GMT
notAfter=Nov 13 09:24:55 2036 GMT
[etudiant@tls-ca-palancac ca]$ openssl x509 -in certs/intermediate.cert.pem -noout -pubkey | diff - <(openssl pkey -in private/intermediate.key.pem -pubout) && echo "clé OK"
Enter pass phrase for private/intermediate.key.pem:
clé OK
```

La dernière commande compare la clé publique du certificat à celle de la clé privée : le certificat correspond bien à la clé de notre CA.

### 6.4 Création du certificat du serveur

La machine `tls-serv-palancac` hébergera le serveur web. Son certificat sera signé par notre CA intermédiaire `RA palancac`. Le sujet fixe les caractéristiques suivantes :

| Élément                  | Valeur                                      |
| ------------------------ | ------------------------------------------- |
| Organisation             | `Canut palancac inc.`                       |
| Localisation             | Lyon (`L=Lyon`), dans le Rhône (`ST=Rhone`) |
| Nom principal du serveur | `www.palancac.fr`                           |
| Noms alternatifs (SAN)   | `www.palancac.fr` et `dev.palancac.fr`      |

La clé privée du serveur n'est pas chiffrée, sinon il faudrait saisir la passphrase à chaque démarrage du serveur web. Elle n'est protégée que par les droits du fichier.

### Question 24

> _Sur quelle machine est-il pertinent de générer la clé de chiffrement asymétrique qui sera utilisée par le serveur ?_

Il faut générer la clé **sur la machine qui l'utilisera, le serveur `tls-serv-palancac`**, et non sur la machine de la CA.

Une clé privée ne doit jamais quitter la machine sur laquelle elle sert. Si elle était générée sur la CA, il faudrait la transférer jusqu'au serveur (par copier-coller, `scp`…), et elle pourrait être interceptée pendant ce transfert ou laisser une copie sur la CA. En la générant directement sur le serveur :

- **seule la CSR circule entre les deux machines.** Elle ne contient que des informations publiques (le sujet et la clé publique), et sa signature protège son intégrité (question 23) ;
- **la CA ne connaît jamais la clé privée du serveur.** Elle n'a pas besoin de la connaître pour signer le certificat. Si la CA était compromise, les clés privées des serveurs ne le seraient pas pour autant, et seul le serveur peut prouver qu'il est bien `www.palancac.fr`.

C'est le même principe que pour la CA intermédiaire en 6.3 : sa clé a été générée sur `tls-ca-palancac`, et seule sa CSR a été envoyée à `Root Lorne`.

#### Génération de la clé et de la demande de certificat (sur `tls-serv-palancac`)

Nous avons généré une bi-clé RSA de 2048 bits, non chiffrée, dans le dossier standard des clés privées du système, puis la demande de certificat :

```bash
sudo openssl genrsa -out /etc/pki/tls/private/serveur_http.pem 2048
sudo openssl req -new -key /etc/pki/tls/private/serveur_http.pem -out serveur_http.csr.pem \
  -subj "/C=FR/ST=Rhone/L=Lyon/O=Canut palancac inc./CN=www.palancac.fr" \
  -addext "subjectAltName = DNS:www.palancac.fr, DNS:dev.palancac.fr"
```

`-addext` ajoute à la demande le `subjectAltName` avec les deux noms du serveur. `sudo` est nécessaire, car `/etc/pki/tls/private/` n'est accessible qu'à `root`.

Nous avons copié-collé la demande sur la CA, dans `/home/etudiant/ca/csr/`, puis nous l'avons vérifiée :

```console
[etudiant@tls-ca-palancac ca]$ cat > csr/serveur_http.csr.pem <<'EOF'
-----BEGIN CERTIFICATE REQUEST-----
MIIC5zCCAc8CAQAwZDELMAkGA1UEBhMCRlIxDjAMBgNVBAgMBVJob25lMQ0wCwYD
[...]
eFwT1GACFwnIea8hEKAmmfP8qjqSegpr3qG7
-----END CERTIFICATE REQUEST-----
EOF
[etudiant@tls-ca-palancac ca]$ openssl req -in csr/serveur_http.csr.pem -noout -verify -subject
Certificate request self-signature verify OK
subject=C=FR, ST=Rhone, L=Lyon, O=Canut palancac inc., CN=www.palancac.fr
```

#### Signature par la CA intermédiaire

Notre CA a signé la demande avec les extensions `server_cert`, pour une durée de 375 jours :

```console
[etudiant@tls-ca-palancac ca]$ openssl ca -config openssl.cnf -extensions server_cert \
  -days 375 -notext -md sha256 -in csr/serveur_http.csr.pem \
  -out certs/serveur_http.cert.pem
Using configuration from openssl.cnf
Enter pass phrase for /home/etudiant/ca/private/intermediate.key.pem:
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number: 4096 (0x1000)
        Validity
            Not Before: Nov 16 09:34:08 2026 GMT
            Not After : Nov 26 09:34:08 2027 GMT
        Subject:
            countryName               = FR
            stateOrProvinceName       = Rhone
            localityName              = Lyon
            organizationName          = Canut palancac inc.
            commonName                = www.palancac.fr
        X509v3 extensions:
            [...]
Certificate is to be certified until Nov 26 09:34:08 2027 GMT (375 days)
Sign the certificate? [y/n]:y


1 out of 1 certificate requests certified, commit? [y/n]y
Write out database with 1 new entries
Database updated
```

Cette fois, la passphrase demandée est celle de **ma** CA intermédiaire (`intermediate.key.pem`), et non celle de `Root Lorne`. C'est le premier certificat délivré par `RA palancac`, d'où le numéro de série `0x1000`, valeur initiale du fichier `serial` créé à la question 21.

Deux différences avec la signature de notre CA par la racine :

- **La politique `policy_loose` a accepté une organisation différente** (`Canut palancac inc.` au lieu de `TP Sécurité`), et a **conservé** le champ `L=Lyon`, car `localityName` y est déclaré `optional`. Avec `policy_strict`, la demande aurait été refusée.
- **Le SAN de la demande a été recopié dans le certificat**, grâce au paramètre `copy_extensions = copy` vu en 6.3.

#### Vérification du certificat du serveur

```console
[etudiant@tls-ca-palancac ca]$ openssl x509 -in certs/serveur_http.cert.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4096 (0x1000)
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=FR, ST=Savoie, O=TP SÃ©curitÃ©, CN=RA palancac
        Validity
            Not Before: Nov 16 09:34:08 2026 GMT
            Not After : Nov 26 09:34:08 2027 GMT
        Subject: C=FR, ST=Rhone, L=Lyon, O=Canut palancac inc., CN=www.palancac.fr
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:de:b2:cf:05:c4:f3:93:8c:9d:d6:07:55:42:5d:
                    [...]
                    61:27
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            Netscape Cert Type:
                SSL Server
            Netscape Comment:
                OpenSSL Generated Server Certificate
            X509v3 Subject Key Identifier:
                9D:3E:D5:3B:85:76:40:6D:89:0B:27:52:97:24:66:00:B4:9E:93:FE
            X509v3 Authority Key Identifier:
                keyid:EA:22:EA:80:2F:10:18:6B:41:BE:F3:5A:2F:70:CB:47:2C:A6:35:96
                DirName:/C=FR/ST=Savoie/L=Chamb\xC3\x83\xC2\xA9ry/O=TP S\xC3\x83\xC2\xA9curit\xC3\x83\xC2\xA9/CN=Root Lorne
                serial:10:21
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            Authority Information Access:
                OCSP - URI:http://ocsp2.example.com
            X509v3 Subject Alternative Name:
                DNS:www.palancac.fr, DNS:dev.palancac.fr
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:71:3e:0a:d0:e7:9b:6d:d9:42:66:d6:1a:9b:23:
        [...]
```

Le certificat correspond à celui attendu :

| Élément                    | Valeur                                                              | Commentaire                                                                                                      |
| -------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Émetteur                   | `CN=RA palancac`                                                    | Signé par notre CA intermédiaire                                                                                 |
| Sujet                      | `C=FR, ST=Rhone, L=Lyon, O=Canut palancac inc., CN=www.palancac.fr` | Conforme à la demande                                                                                            |
| Clé publique               | RSA 2048 bits                                                       | La clé générée sur le serveur                                                                                    |
| Signature                  | `ecdsa-with-SHA256`                                                 | Faite avec la clé EC de notre CA : la clé signée (RSA) et la clé qui signe (EC) peuvent être de types différents |
| Validité                   | du 16 novembre 2026 au 26 novembre 2027                             | 375 jours                                                                                                        |
| `Basic Constraints`        | `CA:FALSE`                                                          | Ce certificat ne peut pas signer d'autres certificats                                                            |
| `Extended Key Usage`       | `TLS Web Server Authentication`                                     | Utilisable uniquement pour authentifier un serveur TLS                                                           |
| `Subject Alternative Name` | `DNS:www.palancac.fr, DNS:dev.palancac.fr`                          | Recopié depuis la CSR                                                                                            |

Quelques extensions à commenter :

- **`Authority Key Identifier`** contient l'identifiant de clé de notre CA (`EA:22:EA:80:…`), mais aussi l'émetteur et le numéro de série de son certificat (`CN=Root Lorne`, `serial:10:21`), car `[ server_cert ]` demande `keyid,issuer:always`.
- **`Authority Information Access`** pointe vers `http://ocsp2.example.com`, une adresse d'exemple où aucun serveur OCSP ne répond.
- **`Netscape Cert Type` / `Netscape Comment`** sont des extensions obsolètes, ignorées par les clients actuels.

La durée de 375 jours dépasse la limite de 200 jours des CA publiques (question 15), qui ne s'applique pas à une PKI privée.

#### Installation du certificat sur le serveur

Nous avons copié-collé le certificat sur `tls-serv-palancac`, dans `/etc/pki/tls/certs/`. Ce dossier appartenant à `root`, nous utilisons `sudo tee` (une redirection `>` s'exécuterait sans les droits de `root`) :

```console
[etudiant@tls-serv-palancac ~]$ sudo tee /etc/pki/tls/certs/serveur_http.cert.pem > /dev/null <<'EOF'
-----BEGIN CERTIFICATE-----
MIIEAjCCA6igAwIBAgICEAAwCgYIKoZIzj0EAwIwUDELMAkGA1UEBhMCRlIxDzAN
[...]
-----END CERTIFICATE-----
EOF
[etudiant@tls-serv-palancac ~]$ openssl x509 -in /etc/pki/tls/certs/serveur_http.cert.pem -noout -subject -issuer -ext subjectAltName
subject=C=FR, ST=Rhone, L=Lyon, O=Canut palancac inc., CN=www.palancac.fr
issuer=C=FR, ST=Savoie, O=TP SÃ©curitÃ©, CN=RA palancac
X509v3 Subject Alternative Name:
    DNS:www.palancac.fr, DNS:dev.palancac.fr
[etudiant@tls-serv-palancac ~]$ sudo ls -l /etc/pki/tls/private/serveur_http.pem /etc/pki/tls/certs/serveur_http.cert.pem
-rw-r--r--. 1 root root 1452 Nov 16 10:36 /etc/pki/tls/certs/serveur_http.cert.pem
-rw-------. 1 root root 1704 Nov 16 10:32 /etc/pki/tls/private/serveur_http.pem
```

Le certificat est lisible par tous (`644`), la clé privée par `root` seul (`600`). Nous vérifions ensuite que le certificat correspond à la clé privée :

```console
[etudiant@tls-serv-palancac ~]$ openssl x509 -in /etc/pki/tls/certs/serveur_http.cert.pem -noout -pubkey | sha256sum
4e48dffed73e9aa953cd39b6a66ad15b33675b4035e477db6261e53a48608918  -
[etudiant@tls-serv-palancac ~]$ sudo openssl pkey -in /etc/pki/tls/private/serveur_http.pem -pubout | sha256sum
4e48dffed73e9aa953cd39b6a66ad15b33675b4035e477db6261e53a48608918  -
```

Les empreintes sont identiques. La chaîne de confiance est complète :

```text
Root Lorne          (EC P-256, auto-signé, valable jusqu'en 2045)
   └── RA palancac      (EC P-256, n° 0x1021, CA:TRUE pathlen:0, valable jusqu'en 2036)
          └── www.palancac.fr  (RSA 2048, n° 0x1000, CA:FALSE serverAuth, valable jusqu'en 2027)
```

## 7. Mise en place d'un reverse proxy

Le certificat et sa clé sont utilisés par un **reverse proxy HTTPS** (Nginx), qui transmet les requêtes à deux serveurs web internes (_backends_). Les trois services tournent dans des conteneurs Docker décrits par un fichier Docker Compose :

```text
                        HTTPS (certificat www.palancac.fr)
   Client  ─────────────────────────────►  reverse proxy (Nginx)
                                              │            │
                                     /        │            │  /admin/
                                              ▼            ▼
                                        web1 (Apache)   web2 (Apache)
```

Seul le proxy est exposé : il établit la connexion TLS et détient la clé privée (**terminaison TLS**), les backends n'ont pas de certificat.

### 7.1 Installation de Docker et Git

Docker n'étant pas fourni par les dépôts d'Alma Linux, nous avons ajouté le dépôt officiel de Docker, puis installé le moteur Docker et ses outils sur `tls-serv-palancac` :

```console
[etudiant@tls-serv-palancac ~]$ sudo dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
Adding repo from: https://download.docker.com/linux/centos/docker-ce.repo
[etudiant@tls-serv-palancac ~]$ sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
[...]
Installing:
 containerd.io                 x86_64   2.4.2-4.el10          docker-ce-stable   35 M
 docker-ce                     x86_64   3:29.9.3-1.el10       docker-ce-stable   26 M
 docker-ce-cli                 x86_64   1:29.9.3-1.el10       docker-ce-stable  8.9 M
 docker-compose-plugin         x86_64   5.7.1-1.el10          docker-ce-stable  8.8 M
[...]
Importing GPG key 0x621E9F35:
 Userid     : "Docker Release (CE rpm) <docker@docker.com>"
 Fingerprint: 060A 61C5 1B55 8A7F 742B 77AA C52F EB6B 621E 9F35
 From       : https://download.docker.com/linux/centos/gpg
Key imported successfully
[...]
Complete!
[etudiant@tls-serv-palancac ~]$ sudo systemctl start docker
[etudiant@tls-serv-palancac ~]$ sudo systemctl enable docker
Created symlink '/etc/systemd/system/multi-user.target.wants/docker.service' → '/usr/lib/systemd/system/docker.service'.
```

| Paquet                  | Rôle                                                                                        |
| ----------------------- | ------------------------------------------------------------------------------------------- |
| `docker-ce`             | Le démon Docker (_Community Edition_), qui gère les images et les conteneurs                |
| `docker-ce-cli`         | La commande `docker`, qui envoie les ordres au démon                                        |
| `containerd.io`         | L'environnement d'exécution qui lance réellement les conteneurs                             |
| `docker-compose-plugin` | La commande `docker compose`, qui démarre plusieurs conteneurs décrits dans un fichier YAML |

`systemctl enable` relance Docker à chaque démarrage de la machine. Test de l'installation :

```console
[etudiant@tls-serv-palancac ~]$ sudo docker run hello-world
Unable to find image 'hello-world:latest' locally
latest: Pulling from library/hello-world
4f55086f7dd0: Pull complete
d5e71e642bf5: Download complete
Digest: sha256:cf1b20a0c89a666b6950fecda7ccbc1b1a86520e7c53f908f3a21e79d0d60458
Status: Downloaded newer image for hello-world:latest

Hello from Docker!
This message shows that your installation appears to be working correctly.
[...]
```

Docker a téléchargé l'image depuis Docker Hub et lancé le conteneur : l'installation fonctionne.

Git a ensuite été installé avec `sudo dnf -y install git`, ainsi que `tree` pour afficher l'arborescence des fichiers.

### 7.2 Mise en place des conteneurs pour l'infrastructure

Avant de mettre en place HTTPS, on teste l'infrastructure en HTTP simple. L'enseignant fournit les fichiers nécessaires dans un dépôt Git :

```console
[etudiant@tls-serv-palancac ~]$ git clone https://github.com/lorne-univ/tls-reverse
[etudiant@tls-serv-palancac ~]$ cd tls-reverse
[etudiant@tls-serv-palancac tls-reverse]$ tree
.
├── README.md
├── compose.yaml
├── httpd-web1
│   └── picture
├── httpd-web2
│   └── styles
└── nginx-reverse
    ├── conf
    │   └── nginx.conf
    └── ssl
```

Le dossier `nginx-reverse/ssl/` est vide : c'est là que seront placés le certificat et la clé du serveur à l'étape 7.3.

#### Le fichier `compose.yaml`

```console
[etudiant@tls-serv-palancac tls-reverse]$ cat compose.yaml
services:
  web1:
    image: "httpd:2.4"
    volumes:
      - ./httpd-web1:/usr/local/apache2/htdocs/

  web2:
    image: "httpd:2.4"
    volumes:
      - ./httpd-web2:/usr/local/apache2/htdocs/

  reverse:
    image: "nginx:1.25"
    volumes:
      - ./nginx-reverse/conf/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx-reverse/ssl:/etc/nginx/ssl
    ports:
      - "443:443"
      - "80:80"
```

Ce fichier décrit trois conteneurs (_services_) :

| Service   | Image        | Volumes montés                                                                                   | Ports publiés |
| --------- | ------------ | ------------------------------------------------------------------------------------------------ | ------------- |
| `web1`    | `httpd:2.4`  | `./httpd-web1` à la place de `htdocs`, la racine du site Apache                                  | aucun         |
| `web2`    | `httpd:2.4`  | `./httpd-web2` à la place de `htdocs`                                                            | aucun         |
| `reverse` | `nginx:1.25` | `nginx.conf` à la place de la configuration de Nginx, et le dossier `ssl/` dans `/etc/nginx/ssl` | 80 et 443     |

- **Les volumes** relient un dossier de la machine hôte à un dossier du conteneur. Les fichiers placés dans `httpd-web1/` sont donc directement servis par Apache dans le conteneur `web1`, sans avoir à reconstruire d'image. De même, `nginx.conf` peut être modifié sur l'hôte, puis pris en compte en redémarrant le conteneur.
- **Seul `reverse` publie des ports** (`"80:80"` signifie : le port 80 de l'hôte est redirigé vers le port 80 du conteneur). `web1` et `web2` ne sont pas joignables depuis l'extérieur : on ne peut y accéder qu'en passant par le reverse proxy.
- Compose crée un **réseau privé** (`tls-reverse_default`) commun aux trois conteneurs, avec un DNS interne : Nginx peut joindre les backends par leur nom de service, `web1` et `web2`.

#### Le fichier `nginx.conf`

```console
[etudiant@tls-serv-palancac tls-reverse]$ cat nginx-reverse/conf/nginx.conf
events {}
http {
  server {
      listen    80;
      server_name    www.votre_login.fr;

     # ssl_certificate /etc/nginx/ssl/serveur_http.cert.pem;
     # ssl_certificate_key /etc/nginx/ssl/serveur_http.pem;

      location / {

          proxy_pass http://web1;
      }

      location /admin/ {

          proxy_pass http://web2/;
      }
  }
}
```

Le bloc `server` écoute sur le port 80, en HTTP. Les deux lignes `ssl_certificate`, encore commentées, serviront à l'étape 7.3. Le `server_name` n'a pas encore été adapté, ce qui n'a pas d'effet ici : comme il n'existe qu'un seul bloc `server`, Nginx l'utilise pour toutes les requêtes.

Les deux blocs `location` répartissent les requêtes. Nginx choisit le préfixe **le plus long** qui correspond à l'URL : `/admin/...` va vers `web2`, et tout le reste vers `web1`. Les deux `proxy_pass` ne s'écrivent pas tout à fait de la même façon, et cette différence change l'URL transmise au backend :

| Directive                  | Forme                    | URL transmise au backend                                                                               |
| -------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------ |
| `proxy_pass http://web1;`  | sans chemin après l'hôte | L'URL d'origine, **inchangée** : `/picture/` reste `/picture/`                                         |
| `proxy_pass http://web2/;` | avec un `/` après l'hôte | Le préfixe de la `location` (`/admin/`) est **remplacé** par `/` : `/admin/styles/` devient `/styles/` |

Grâce à ce remplacement, `web2` n'a pas besoin de savoir qu'il est publié sous `/admin/` : ses fichiers sont à la racine de son site.

#### Création des pages et prévision des résultats

Les dossiers des backends étant vides, nous avons créé une page d'accueil pour chaque serveur et une page dans chaque sous-dossier, avec les commandes du sujet :

```bash
echo "L'URL / et toutes les URL autres que /admin/ sont servies par <b>web1</b>." > httpd-web1/index.html
echo "L'URL /admin/ et les sous URL de /admin/ sont servies par <b>web2<b>." > httpd-web2/index.html
echo "Styles web2" > httpd-web2/styles/index.html
echo "Picture web1" > httpd-web1/picture/index.html
```

La deuxième commande du sujet contient une coquille (`<b>` au lieu de `</b>` après « web2 »), sans incidence sur le proxy.

À partir des deux fichiers de configuration, on peut prévoir ce qu'affichera chaque URL :

| URL demandée                      | `location` choisie | Requête reçue par le backend | Résultat attendu                                        |
| --------------------------------- | ------------------ | ---------------------------- | ------------------------------------------------------- |
| `http://@IP_serveur`              | `/`                | `web1` : `/`                 | Page d'accueil de `web1`                                |
| `http://@IP_serveur/admin/`       | `/admin/`          | `web2` : `/`                 | Page d'accueil de `web2`                                |
| `http://@IP_serveur/picture/`     | `/`                | `web1` : `/picture/`         | « Picture web1 »                                        |
| `http://@IP_serveur/admin/styles` | `/admin/`          | `web2` : `/styles`           | Redirection vers `/admin/styles/`, puis « Styles web2 » |

Le dernier cas est particulier. `/styles`, sans `/` final, désigne un dossier : Apache répond par une redirection (code 301) vers `/styles/`. Il l'exprime avec son propre nom d'hôte, `http://web2/styles/`, une adresse que le client ne peut pas résoudre. Nginx corrige automatiquement l'en-tête `Location` des redirections grâce à sa directive `proxy_redirect`, active par défaut : il y remplace `http://web2/` par le préfixe public `/admin/`.

#### Démarrage des conteneurs

Nginx résout les noms des backends (`web1`, `web2`) au chargement de sa configuration. Nous avons donc ajouté au service `reverse` une directive `depends_on`, pour que Compose démarre `web1` et `web2` avant lui :

```console
[etudiant@tls-serv-palancac tls-reverse]$ sed -i 's|^  reverse:|  reverse:\n    depends_on:\n      - web1\n      - web2|' compose.yaml
[etudiant@tls-serv-palancac tls-reverse]$ sed -n '/reverse:/,$p' compose.yaml
  reverse:
    depends_on:
      - web1
      - web2
    image: "nginx:1.25"
    [...]
[etudiant@tls-serv-palancac tls-reverse]$ sudo docker compose up -d
[...]
[etudiant@tls-serv-palancac tls-reverse]$ sudo docker compose ps
NAME                    IMAGE        COMMAND                  SERVICE   CREATED         STATUS                  PORTS
tls-reverse-reverse-1   nginx:1.25   "/docker-entrypoint.…"   reverse   2 minutes ago   Up Less than a second   0.0.0.0:80->80/tcp, [::]:80->80/tcp, 0.0.0.0:443->443/tcp, [::]:443->443/tcp
tls-reverse-web1-1      httpd:2.4    "httpd-foreground"       web1      2 minutes ago   Up 2 minutes            80/tcp
tls-reverse-web2-1      httpd:2.4    "httpd-foreground"       web2      2 minutes ago   Up 2 minutes            80/tcp
```

L'option `-d` lance les conteneurs en arrière-plan. Seul `reverse` publie des ports sur l'hôte (80 et 443) : `web1` et `web2` ne sont joignables que dans le réseau Docker (`80/tcp`).

#### Tests

```console
[etudiant@tls-serv-palancac tls-reverse]$ curl http://localhost/
L'URL / et toutes les URL autres que /admin/ sont servies par <b>web1</b>.
[etudiant@tls-serv-palancac tls-reverse]$ curl http://localhost/admin/
L'URL /admin/ et les sous URL de /admin/ sont servies par <b>web2<b>.
[etudiant@tls-serv-palancac tls-reverse]$ curl http://localhost/picture/
Picture web1
[etudiant@tls-serv-palancac tls-reverse]$ curl -i http://localhost/admin/styles
HTTP/1.1 301 Moved Permanently
Server: nginx/1.25.5
Date: Mon, 16 Nov 2026 10:36:35 GMT
Content-Type: text/html; charset=iso-8859-1
Content-Length: 267
Location: http://localhost/admin/styles/
Connection: keep-alive

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://web2/styles/">here</a>.</p>
</body></html>
[etudiant@tls-serv-palancac tls-reverse]$ curl -L http://localhost/admin/styles
Styles web2
```

Les quatre résultats correspondent aux prévisions (`-i` affiche les en-têtes, `-L` suit la redirection). Dans la réponse 301, Nginx a réécrit l'en-tête `Location` en `http://localhost/admin/styles/`, mais pas le corps de la page, qui contient toujours `http://web2/styles/`. L'en-tête `Server: nginx/1.25.5` montre que le client ne voit que le proxy, et pas les serveurs Apache derrière lui.

### 7.3 Mise en place de SSL

#### 7.3.1 Configuration de Nginx

Pour activer TLS, Nginx a besoin de deux fichiers : le certificat du serveur (directive `ssl_certificate`) et la clé privée correspondante (`ssl_certificate_key`). Le conteneur ne voit pas le dossier `/etc/pki/tls/` de l'hôte, seulement le volume `./nginx-reverse/ssl`, monté dans `/etc/nginx/ssl`. Nous y avons donc copié les deux fichiers créés à la section 6.4, sous les noms attendus par la configuration fournie :

```console
[etudiant@tls-serv-palancac tls-reverse]$ sudo cp /etc/pki/tls/certs/serveur_http.cert.pem nginx-reverse/ssl/
[etudiant@tls-serv-palancac tls-reverse]$ sudo cp /etc/pki/tls/private/serveur_http.pem nginx-reverse/ssl/
[etudiant@tls-serv-palancac tls-reverse]$ sudo chmod 644 nginx-reverse/ssl/serveur_http.cert.pem
[etudiant@tls-serv-palancac tls-reverse]$ ls -l nginx-reverse/ssl/
total 8
-rw-r--r--. 1 root root 1452 Nov 16 11:38 serveur_http.cert.pem
-rw-------. 1 root root 1704 Nov 16 11:38 serveur_http.pem
```

La clé privée garde des droits `600` : le processus maître de Nginx, lancé en `root` dans le conteneur, peut la lire. Le dossier `ssl/` n'est pas versionné dans le dépôt du compte rendu.

Nous avons ensuite modifié `nginx.conf`, après en avoir conservé une copie (`nginx.conf.orig`). Le bloc existant sur le port 80 est conservé, et un second bloc `server` est ajouté pour HTTPS :

```nginx
events {}
http {
  server {
      listen    80;
      server_name    www.palancac.fr dev.palancac.fr;

      location / {
          proxy_pass http://web1;
      }

      location /admin/ {
          proxy_pass http://web2/;
      }
  }

  server {
      listen    443 ssl;
      server_name    www.palancac.fr dev.palancac.fr;

      ssl_certificate /etc/nginx/ssl/serveur_http.cert.pem;
      ssl_certificate_key /etc/nginx/ssl/serveur_http.pem;
      ssl_protocols TLSv1.2 TLSv1.3;

      location / {
          proxy_pass http://web1;
      }

      location /admin/ {
          proxy_pass http://web2/;
      }
  }
}
```

| Directive                                     | Rôle                                                                                                                                     |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `listen 443 ssl`                              | Écoute sur le port 443 (HTTPS) et établit une session TLS avant de traiter la requête HTTP                                               |
| `server_name www.palancac.fr dev.palancac.fr` | Les noms du serveur, les mêmes que dans le SAN du certificat. `votre_login` a été remplacé par notre login                               |
| `ssl_certificate`                             | Le certificat envoyé au client pendant la poignée de main TLS                                                                            |
| `ssl_certificate_key`                         | La clé privée qui permet de prouver la possession du certificat (signature `CertificateVerify`, question 4)                              |
| `ssl_protocols TLSv1.2 TLSv1.3`               | N'accepte que les versions récentes de TLS. Les versions SSLv3, TLS 1.0 et TLS 1.1, qui présentent des faiblesses connues, sont refusées |

Les blocs `location` sont identiques dans les deux serveurs : le proxy chiffre la connexion avec le client, puis transmet la requête en HTTP aux backends, à l'intérieur du réseau Docker. C'est la terminaison TLS décrite en introduction de cette section.

Avant de redémarrer Nginx, on peut vérifier la syntaxe de la nouvelle configuration dans le conteneur, puis le redémarrer avec les commandes du sujet :

```bash
sudo docker compose exec reverse nginx -t
sudo docker ps
sudo docker restart tls-reverse-reverse-1
```

#### Tests en HTTPS

```console
[etudiant@tls-serv-palancac tls-reverse]$ curl https://192.168.170.119
curl: (60) SSL certificate problem: unable to get local issuer certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the webpage mentioned above.
```

Ce refus est attendu : `curl` ne connaît pas `RA palancac` et ne peut remonter à aucune racine de confiance. L'option `-k` ignore la vérification et permet de tester le serveur :

```console
[etudiant@tls-serv-palancac tls-reverse]$ curl -k https://192.168.170.119
L'URL / et toutes les URL autres que /admin/ sont servies par <b>web1</b>.
[etudiant@tls-serv-palancac tls-reverse]$ curl -k https://192.168.170.119/admin/
L'URL /admin/ et les sous URL de /admin/ sont servies par <b>web2<b>.
```

Le mode verbeux (`-v`) de `curl` détaille la session TLS établie :

```console
[etudiant@tls-serv-palancac tls-reverse]$ curl -kv https://192.168.170.119 2>&1 | grep -E "SSL connection|subject:|issuer:|expire date|SSL certificate verify"
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / x25519 / RSASSA-PSS
*  subject: C=FR; ST=Rhone; L=Lyon; O=Canut palancac inc.; CN=www.palancac.fr
*  expire date: Nov 26 09:34:08 2027 GMT
*  issuer: C=FR; ST=Savoie; O=TP Sécurité; CN=RA palancac
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
```

- **La session utilise TLS 1.3** avec la suite `TLS_AES_256_GCM_SHA384`, la même que celle du site de l'université (section 5.1). La clé de session est échangée avec `x25519` (Diffie-Hellman sur courbe elliptique), et le serveur prouve la possession de sa clé RSA par une signature `RSASSA-PSS`.
- **Le certificat présenté** est bien celui de `www.palancac.fr`, émis par `RA palancac`, et valable jusqu'au 26 novembre 2027.
- **L'erreur de vérification** est l'erreur OpenSSL n° 20, `unable to get local issuer certificate` : le client n'a trouvé localement aucun certificat correspondant à l'émetteur, `RA palancac`. Avec `-k`, `curl` continue malgré tout (`continuing anyway`).

Le mode _insecure_ ne doit servir qu'au diagnostic. La connexion est bien chiffrée, mais le serveur n'est pas authentifié : un attaquant placé entre le client et le serveur pourrait présenter son propre certificat sans que `curl` le refuse.

#### 7.3.2 Mise en place de la chaîne de confiance de certificat

Pour que les clients acceptent le certificat sans l'option `-k`, ils doivent pouvoir le rattacher à un certificat auquel ils font confiance. Le sujet propose trois possibilités :

1. faire confiance au **certificat du serveur** uniquement ;
2. faire confiance au **certificat de la CA intermédiaire** (`RA palancac`) : les clients valideront alors tous les certificats qu'elle délivre ;
3. faire confiance au **certificat de la CA racine** (`Root Lorne`).

### Question 25

> _Justifier que la 3ᵉ solution est la plus pertinente._

Faire confiance à la CA racine est la solution la plus pertinente, pour plusieurs raisons :

| Critère                            | 1. Certificat du serveur                          | 2. CA intermédiaire                            | 3. CA racine                                                        |
| ---------------------------------- | ------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------- |
| Certificats acceptés               | Un seul serveur                                   | Les serveurs d'une seule CA intermédiaire      | Tous les serveurs de toutes les CA intermédiaires de l'organisation |
| Nombre d'imports sur chaque client | Un par serveur                                    | Un par CA intermédiaire (une par étudiant ici) | **Un seul**                                                         |
| Durée avant de devoir recommencer  | 375 jours : à chaque renouvellement du certificat | 10 ans                                         | 20 ans (jusqu'en 2045)                                              |
| Ajout d'un nouveau serveur         | Nouvel import sur tous les clients                | Aucun import s'il dépend de la même CA         | **Aucun import**                                                    |

- **Elle préserve la souplesse de la hiérarchie.** La racine peut créer de nouvelles CA intermédiaires, ou en révoquer une, sans modifier les clients : c'est l'intérêt d'une PKI à plusieurs niveaux.
- **C'est le modèle utilisé sur Internet.** Les navigateurs et les systèmes ne contiennent que des certificats racines (question 19). Les certificats intermédiaires et ceux des serveurs sont envoyés par le serveur pendant la poignée de main TLS.

En contrepartie, la clé privée de la racine devient critique : dans une vraie PKI, elle est conservée hors ligne, ce qui n'est pas le cas dans ce TP.

#### Constat de départ

Avant toute modification, `curl` et `openssl s_client` refusent tous les deux le certificat :

```console
[etudiant@tls-serv-palancac tls-reverse]$ curl https://127.0.0.1
curl: (60) SSL certificate problem: unable to get local issuer certificate
[...]
[etudiant@tls-serv-palancac tls-reverse]$ openssl s_client -connect 127.0.0.1:443 </dev/null 2>&1 | head -12
Connecting to 127.0.0.1
Can't use SSL_get_servername
depth=0 C=FR, ST=Rhone, L=Lyon, O=Canut palancac inc., CN=www.palancac.fr
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C=FR, ST=Rhone, L=Lyon, O=Canut palancac inc., CN=www.palancac.fr
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 C=FR, ST=Rhone, L=Lyon, O=Canut palancac inc., CN=www.palancac.fr
verify return:1
CONNECTED(00000003)
---
```

`s_client` ne voit qu'un seul niveau (`depth=0`) : le serveur n'envoie que son propre certificat. L'erreur 20 indique que l'émetteur de ce certificat (`RA palancac`) est introuvable, et l'erreur 21 que la vérification n'a donc pas pu aller plus loin que le premier certificat. Comme on n'a pas utilisé l'option `-verify_return_error`, `s_client` affiche les erreurs mais poursuit la connexion (`verify return:1`).

La ligne `Can't use SSL_get_servername` signifie que le client n'a pas envoyé de nom de serveur (extension SNI, question 4) : on s'est connecté avec une adresse IP, et non avec un nom.

#### Ajout de Root Lorne au magasin de confiance

Nous avons récupéré le certificat de `Root Lorne` par copier-coller depuis `root-ca-tp` (`cat ~/ca/certs/ca.cert.pem`), puis nous l'avons enregistré sur le serveur dans `root-ca-lorne.pem`. Son empreinte permet de vérifier qu'il n'a pas été altéré pendant la copie :

```console
[etudiant@tls-serv-palancac ~]$ cat > ~/root-ca-lorne.pem <<'EOF'
-----BEGIN CERTIFICATE-----
MIICLjCCAdWgAwIBAgIUAz8ufhUaU3qU9VmF/ktISciIsu4wCgYIKoZIzj0EAwIw
[...]
AiAFTnhaFIVdcWWTQs1NN9u74y43CCRznUMyAXil/c7rEA==
-----END CERTIFICATE-----
EOF
[etudiant@tls-serv-palancac ~]$ openssl x509 -in ~/root-ca-lorne.pem -noout -subject -fingerprint -sha256
subject=C=FR, ST=Savoie, L=ChambÃ©ry, O=TP SÃ©curitÃ©, CN=Root Lorne
sha256 Fingerprint=00:20:04:F1:27:14:F7:53:B7:8B:B7:E3:FC:44:75:B4:8D:FC:BF:EB:12:00:80:C7:11:46:38:B6:D2:86:54:B7
```

Dans une situation réelle, cette empreinte devrait être comparée à celle communiquée par l'administrateur de la CA, par un autre canal. C'est la seule façon de s'assurer que le certificat racine installé est bien le bon, puisqu'un certificat auto-signé ne prouve rien par lui-même (question 19).

La page de manuel de `update-ca-trust` explique comment ajouter une autorité de confiance sous Red Hat :

```console
[etudiant@tls-serv-palancac ~]$ man update-ca-trust | grep -n -A3 "source/anchors"
56:       •   add it as a new file to directory /etc/pki/ca-trust/source/anchors/
57-
58-       •   run update-ca-trust extract
[...]
89:       In the anchors subdirectories /usr/share/pki/ca-trust-source/anchors/ or /etc/pki/ca-trust/source/anchors/ you may install one or multiple certificates in
90-       either the DER file format or in the PEM (BEGIN/END CERTIFICATE) file format. Each certificate will be treated as trusted for all purposes.
```

Il faut donc copier le certificat dans le dossier des **ancres de confiance** (_trust anchors_), `/etc/pki/ca-trust/source/anchors/`, puis lancer `update-ca-trust extract`. Cette commande régénère les fichiers de `/etc/pki/ca-trust/extracted/`, dont le `tls-ca-bundle.pem` étudié à la question 18, utilisé par OpenSSL, `curl` et la plupart des applications du système :

```console
[etudiant@tls-serv-palancac ~]$ sudo cp ~/root-ca-lorne.pem /etc/pki/ca-trust/source/anchors/
[etudiant@tls-serv-palancac ~]$ sudo update-ca-trust extract
[etudiant@tls-serv-palancac ~]$ trust list | grep -B2 -A3 "Root Lorne"
pkcs11:id=%85%44%BC%D9%48%94%58%B7%90%E3%B0%65%31%CC%2C%23%2C%8F%5F%80;type=cert
    type: certificate
    label: Root Lorne
    trust: anchor
    category: authority
```

La commande `trust list` liste les certificats connus du système. `Root Lorne` y figure désormais comme ancre de confiance (`trust: anchor`) et comme autorité (`category: authority`). L'identifiant `85:44:BC:D9:…` est le _Subject Key Identifier_ de `Root Lorne`, relevé à la question 20.

#### Le certificat n'est toujours pas validé

```console
[etudiant@tls-serv-palancac ~]$ curl https://127.0.0.1
curl: (60) SSL certificate problem: unable to get local issuer certificate
[...]
[etudiant@tls-serv-palancac ~]$ openssl s_client -connect 127.0.0.1:443 </dev/null 2>&1 | head -12
[...]
depth=0 C=FR, ST=Rhone, L=Lyon, O=Canut palancac inc., CN=www.palancac.fr
verify error:num=20:unable to get local issuer certificate
[...]
depth=0 C=FR, ST=Rhone, L=Lyon, O=Canut palancac inc., CN=www.palancac.fr
verify error:num=21:unable to verify the first certificate
[...]
```

Le résultat est identique, et c'est normal : le certificat du serveur n'a pas été signé par `Root Lorne`, mais par `RA palancac`. Le client sait maintenant faire confiance à la racine, mais il lui manque le maillon intermédiaire pour relier les deux :

```text
Root Lorne        ← dans le magasin de confiance du client
   └── RA palancac       ← inconnu du client : la chaîne est rompue
          └── www.palancac.fr  ← envoyé par le serveur
```

C'est exactement la situation de la question 18 : le serveur de l'université envoyait le certificat de `GEANT TLS RSA 1` en plus du sien, pour que le client puisse reconstituer la chaîne.

#### Envoi de la chaîne de certificats par le serveur

La solution la plus simple est que le serveur fournisse au client le certificat de la CA intermédiaire en même temps que le sien. Nginx envoie tous les certificats contenus dans le fichier indiqué par `ssl_certificate` : il suffit donc de concaténer les deux certificats dans `serveur_http.cert.pem`.

Nous avons d'abord récupéré le certificat de `RA palancac` sur le serveur, toujours par copier-coller, et vérifié qu'il est bien signé par `Root Lorne` :

```console
[etudiant@tls-serv-palancac tls-reverse]$ cat > ~/intermediate.cert.pem <<'EOF'
-----BEGIN CERTIFICATE-----
MIICCzCCAbGgAwIBAgICECEwCgYIKoZIzj0EAwIwZTELMAkGA1UEBhMCRlIxDzAN
[...]
A20h1CAD8/ELcMoYdQIgTUuJSYmXsZb07oSgR6L1mOQcOiEpmPao/ujSWU+9mpo=
-----END CERTIFICATE-----
EOF
[etudiant@tls-serv-palancac tls-reverse]$ openssl verify -CAfile ~/root-ca-lorne.pem ~/intermediate.cert.pem
/home/etudiant/intermediate.cert.pem: OK
```

Nous avons ensuite concaténé les deux certificats, après avoir conservé une copie du certificat seul :

```console
[etudiant@tls-serv-palancac tls-reverse]$ sudo cp nginx-reverse/ssl/serveur_http.cert.pem nginx-reverse/ssl/serveur_http.cert.pem.seul
[etudiant@tls-serv-palancac tls-reverse]$ cat nginx-reverse/ssl/serveur_http.cert.pem.seul ~/intermediate.cert.pem | sudo tee nginx-reverse/ssl/serveur_http.cert.pem > /dev/null
[etudiant@tls-serv-palancac tls-reverse]$ grep -c "BEGIN CERTIFICATE" nginx-reverse/ssl/serveur_http.cert.pem
2
[etudiant@tls-serv-palancac tls-reverse]$ sudo docker restart tls-reverse-reverse-1
tls-reverse-reverse-1
```

**L'ordre des certificats est important** : le certificat du serveur doit venir en premier, suivi de celui de l'autorité qui l'a signé. Nginx associe la clé privée (`ssl_certificate_key`) au premier certificat du fichier, et refuse de démarrer si elle ne correspond pas. Le certificat racine n'a pas besoin d'être ajouté : le client doit déjà le posséder, et c'est justement lui qui fonde la confiance.

La vérification réussit désormais :

```console
[etudiant@tls-serv-palancac tls-reverse]$ openssl s_client -connect 127.0.0.1:443 </dev/null 2>&1 | head -12
Connecting to 127.0.0.1
Can't use SSL_get_servername
depth=2 C=FR, ST=Savoie, L=ChambÃ©ry, O=TP SÃ©curitÃ©, CN=Root Lorne
verify return:1
depth=1 C=FR, ST=Savoie, O=TP SÃ©curitÃ©, CN=RA palancac
verify return:1
depth=0 C=FR, ST=Rhone, L=Lyon, O=Canut palancac inc., CN=www.palancac.fr
verify return:1
CONNECTED(00000003)
---
Certificate chain
 0 s:C=FR, ST=Rhone, L=Lyon, O=Canut palancac inc., CN=www.palancac.fr
```

La chaîne complète est maintenant reconstituée, sur trois niveaux, et chaque niveau est valide (`verify return:1`, sans erreur) :

| Niveau    | Certificat        | Provenance                                                             |
| --------- | ----------------- | ---------------------------------------------------------------------- |
| `depth=0` | `www.palancac.fr` | Envoyé par le serveur (1ᵉʳ certificat du fichier)                      |
| `depth=1` | `RA palancac`     | Envoyé par le serveur (2ᵉ certificat du fichier)                       |
| `depth=2` | `Root Lorne`      | Trouvé dans le magasin de confiance local, ajouté à l'étape précédente |

C'est la même structure que celle observée pour le site de l'université à la question 12.

#### Vérification du nom du serveur

`curl`, en revanche, refuse toujours la connexion, mais pour une autre raison :

```console
[etudiant@tls-serv-palancac tls-reverse]$ curl https://127.0.0.1
curl: (60) SSL: no alternative certificate subject name matches target ipv4 address '127.0.0.1'
More details here: https://curl.se/docs/sslcerts.html
[...]
```

La chaîne de confiance est désormais valide, mais le certificat a été délivré pour `www.palancac.fr` et `dev.palancac.fr`, et non pour l'adresse `127.0.0.1`. `curl` compare l'adresse qu'on lui a demandée aux noms du _Subject Alternative Name_, et ne trouve aucune correspondance. `openssl s_client` n'effectue pas cette vérification par défaut, d'où la différence entre les deux outils.

Cette vérification est indispensable : sans elle, n'importe quel serveur possédant un certificat valide, émis par une CA de confiance pour **un autre nom**, pourrait se faire passer pour `www.palancac.fr`.

Pour joindre le serveur par son nom, il faudrait un serveur DNS. Faute d'en avoir un, on utilise le fichier `/etc/hosts`, qui associe localement des noms à des adresses IP et qui est consulté avant le DNS.

### Question 26

> _Quelle modification (ligne modifiée ou ajoutée) avez-vous effectuée dans le fichier hosts ?_

Nous avons **ajouté** à la fin du fichier `/etc/hosts` la ligne suivante :

```text
192.168.170.119 www.palancac.fr dev.palancac.fr
```

Elle associe les deux noms présents dans le certificat (`www.palancac.fr` et `dev.palancac.fr`) à l'adresse IP du serveur, `192.168.170.119`. Nous avons choisi l'adresse réelle du serveur plutôt que `127.0.0.1` : c'est la même ligne qu'il faudrait ajouter sur une autre machine de la salle, et les requêtes passent par l'interface réseau, comme pour un vrai client.

```console
[etudiant@tls-serv-palancac tls-reverse]$ echo "192.168.170.119 www.palancac.fr dev.palancac.fr" | sudo tee -a /etc/hosts
192.168.170.119 www.palancac.fr dev.palancac.fr
[etudiant@tls-serv-palancac tls-reverse]$ cat /etc/hosts
# Loopback entries; do not change.
# For historical reasons, localhost precedes localhost.localdomain:
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
# See hosts(5) for proper format and other examples:
# 192.168.1.10 foo.example.org foo
# 192.168.1.13 bar.example.org bar
192.168.170.119 www.palancac.fr dev.palancac.fr
```

L'option `-a` de `tee` ajoute la ligne à la fin du fichier au lieu de l'écraser. `sudo` est nécessaire, car `/etc/hosts` appartient à `root`.

#### Tests finaux

```console
[etudiant@tls-serv-palancac tls-reverse]$ curl https://www.palancac.fr
L'URL / et toutes les URL autres que /admin/ sont servies par <b>web1</b>.
[etudiant@tls-serv-palancac tls-reverse]$ curl https://www.palancac.fr/admin/
L'URL /admin/ et les sous URL de /admin/ sont servies par <b>web2<b>.
[etudiant@tls-serv-palancac tls-reverse]$ curl https://dev.palancac.fr/picture/
Picture web1
[etudiant@tls-serv-palancac tls-reverse]$ curl -L https://www.palancac.fr/admin/styles
Styles web2
```

Toutes les URL testées en HTTP à la section 7.2 sont accessibles en HTTPS, **sans l'option `-k`**, avec les deux noms du certificat. Le détail de la connexion confirme que le serveur est entièrement authentifié :

```console
[etudiant@tls-serv-palancac tls-reverse]$ curl -v https://www.palancac.fr 2>&1 | grep -E "SSL connection|subject:|issuer:|subjectAltName|SSL certificate verify"
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / x25519 / RSASSA-PSS
*  subject: C=FR; ST=Rhone; L=Lyon; O=Canut palancac inc.; CN=www.palancac.fr
*  subjectAltName: host "www.palancac.fr" matched cert's "www.palancac.fr"
*  issuer: C=FR; ST=Savoie; O=TP Sécurité; CN=RA palancac
*  SSL certificate verify ok.
```

Les deux vérifications de l'authentification du serveur réussissent :

- **la chaîne de confiance** est valide jusqu'à `Root Lorne` (`SSL certificate verify ok`) ;
- **le nom demandé** figure dans le SAN du certificat (`host "www.palancac.fr" matched cert's "www.palancac.fr"`).

Depuis une autre machine, le certificat est refusé tant que `Root Lorne` n'est pas dans son magasin de confiance. Je l'ai vérifié depuis mon poste, avec l'option `--resolve` de `curl` à la place du fichier `hosts` :

```console
$ curl --resolve www.palancac.fr:443:192.168.170.119 https://www.palancac.fr/
curl: (60) SSL certificate problem: unable to get local issuer certificate
More details here: https://curl.se/docs/sslcerts.html
$ curl -k --resolve www.palancac.fr:443:192.168.170.119 https://www.palancac.fr/admin/
L'URL /admin/ et les sous URL de /admin/ sont servies par <b>web2<b>.
```

Le site est accessible depuis le réseau, mais sans `-k` mon poste ne peut pas terminer la chaîne. Pour que tous les postes acceptent le site, il suffit d'y déployer `Root Lorne` (question 25).

## 8. Développement d'un client Web

Nous avons écrit en Python un client HTTPS, [`client/client_tls.py`](client/client_tls.py), qui n'utilise que la bibliothèque standard (`socket`, `ssl`). Il lance chaque test, compare le résultat obtenu au résultat attendu et affiche le détail de la session TLS ou la raison du refus.

Le client utilise `ssl.create_default_context()`, qui reproduit le comportement d'un vrai client :

- il charge le magasin de confiance du système, qui contient `Root Lorne` depuis la section 7.3.2 ;
- il vérifie la chaîne de certificats (`verify_mode = CERT_REQUIRED`) ;
- il vérifie que le nom demandé figure dans le SAN (`check_hostname = True`). Ce nom est passé dans `server_hostname`, qui sert aussi d'extension SNI.

Le client se connecte toujours à l'adresse IP du serveur, et le nom demandé est fourni séparément. Nous pouvons ainsi tester un nom absent du certificat sans toucher au fichier `hosts`.

### Question 27

> _Rédiger un scénario de tests (objectif du test, résultat attendu) pour valider que l'authentification du serveur est menée à bien complètement. Mettre en œuvre les tests et relever les résultats obtenus. Vérifier également que la communication est chiffrée entre le client et le serveur._

#### Scénario de tests

Chaque test vise une des vérifications de l'authentification décrites à la question 4 :

| #  | Objectif du test                                            | Mise en place                                                                   | Résultat attendu                                   |
| -- | ----------------------------------------------------------- | ------------------------------------------------------------------------------- | -------------------------------------------------- |
| T1 | Cas nominal : chaîne et nom valides                         | `www.palancac.fr:443` (Nginx)                                                   | Connexion acceptée, page reçue                     |
| T2 | Refus d'une chaîne qui ne mène à aucune racine de confiance | Même serveur, client sans aucune CA de confiance                                | Refus : `unable to get local issuer certificate`   |
| T3 | Refus d'une chaîne incomplète                               | `openssl s_server` sur le port 8443, qui n'envoie que le certificat du serveur  | Refus : `unable to get local issuer certificate`   |
| T4 | Vérification du nom                                         | Nginx, avec le nom demandé `palancac.fr`, absent du SAN                         | Refus : `Hostname mismatch`                        |
| T5 | Refus d'un imposteur avec un certificat auto-signé          | `s_server` sur le port 8444, certificat auto-signé `CN=www.palancac.fr`         | Refus : `self-signed certificate`                  |
| T6 | Vérification de la période de validité                      | `s_server` sur le port 8445, certificat signé par `RA palancac` mais expiré     | Refus : `certificate has expired`                  |
| T7 | Vérification de l'usage du certificat                       | `s_server` sur le port 8446, certificat signé par `RA palancac` avec `usr_cert` | Refus : `unsuitable certificate purpose`           |
| T8 | Contre-exemple : un client qui ne vérifie rien              | Serveur de T5, client avec `CERT_NONE` et `check_hostname = False`              | Connexion acceptée : l'imposteur n'est pas détecté |
| T9 | Chiffrement des échanges                                    | Capture `tcpdump` pendant T1                                                    | Contenu HTTP illisible sur le port 443             |

Les tests T3 et T5 à T7 utilisent des serveurs temporaires lancés avec `openssl s_server`, sur d'autres ports, sans modifier le Nginx en place. Les certificats de T6 et T7 sont signés par notre CA `RA palancac`. Ils ne diffèrent du certificat valide que par le point testé : les dates pour T6, l'extension `usr_cert` (`extendedKeyUsage = clientAuth`) pour T7.

#### Préparation des serveurs de test

Sur `tls-serv-palancac`, nous avons généré une clé de test, deux demandes de certificat et le certificat auto-signé de l'imposteur. Le champ `OU` distingue les deux demandes du certificat déjà délivré : `openssl ca` refuse de signer deux certificats valides de même sujet.

```bash
mkdir -p ~/tests && cd ~/tests
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test.key
openssl req -new -key test.key -out expire.csr.pem \
  -subj "/C=FR/ST=Rhone/L=Lyon/O=Canut palancac inc./OU=Test expire/CN=www.palancac.fr" \
  -addext "subjectAltName = DNS:www.palancac.fr, DNS:dev.palancac.fr"
openssl req -new -key test.key -out client.csr.pem \
  -subj "/C=FR/ST=Rhone/L=Lyon/O=Canut palancac inc./OU=Test client/CN=www.palancac.fr" \
  -addext "subjectAltName = DNS:www.palancac.fr, DNS:dev.palancac.fr"
openssl req -x509 -newkey rsa:2048 -nodes -keyout imposteur.key -out imposteur.cert.pem -days 30 \
  -subj "/C=FR/ST=Rhone/L=Lyon/O=Canut palancac inc./CN=www.palancac.fr" \
  -addext "subjectAltName = DNS:www.palancac.fr, DNS:dev.palancac.fr"
```

Les deux demandes ont été copiées-collées sur la CA, puis signées par `RA palancac`. Pour T6, `-startdate` et `-enddate` remplacent `-days` et fixent une période déjà écoulée. Pour T7, la section `usr_cert` remplace `server_cert` :

```console
[etudiant@tls-ca-palancac ca]$ openssl ca -config openssl.cnf -extensions server_cert -startdate 250101000000Z -enddate 250201000000Z \
  -notext -md sha256 -in csr/expire.csr.pem -out certs/expire.cert.pem
[...]
        Serial Number: 4097 (0x1001)
        Validity
            Not Before: Jan  1 00:00:00 2025 GMT
            Not After : Feb  1 00:00:00 2025 GMT
[...]
Certificate is to be certified until Feb  1 00:00:00 2025 GMT (-654 days)
[...]
[etudiant@tls-ca-palancac ca]$ openssl ca -config openssl.cnf -extensions usr_cert -days 30 \
  -notext -md sha256 -in csr/client.csr.pem -out certs/client.cert.pem
[...]
        Serial Number: 4098 (0x1002)
[...]
            X509v3 Extended Key Usage:
                TLS Web Client Authentication, E-mail Protection
            X509v3 Subject Alternative Name:
                DNS:www.palancac.fr, DNS:dev.palancac.fr
[...]
```

Les signatures de ces deux certificats sont valides : seule la date (T6) ou l'usage (T7) les rend inutilisables pour un serveur. Une fois les certificats copiés sur le serveur, nous avons lancé les quatre serveurs de test en arrière-plan. Celui de T3 utilise le vrai certificat du serveur, mais sans l'intermédiaire (fichier `.seul`). Ceux de T6 et T7 envoient la chaîne complète (`-cert_chain`), pour que seul le point testé soit en défaut :

```console
[etudiant@tls-serv-palancac tests]$ S=~/tls-reverse/nginx-reverse/ssl
[etudiant@tls-serv-palancac tests]$ sudo openssl s_server -accept 8443 -www -cert $S/serveur_http.cert.pem.seul -key $S/serveur_http.pem >/dev/null 2>&1 &
[etudiant@tls-serv-palancac tests]$ openssl s_server -accept 8444 -www -cert imposteur.cert.pem -key imposteur.key >/dev/null 2>&1 &
[etudiant@tls-serv-palancac tests]$ openssl s_server -accept 8445 -www -cert expire.cert.pem -key test.key -cert_chain ~/intermediate.cert.pem >/dev/null 2>&1 &
[etudiant@tls-serv-palancac tests]$ openssl s_server -accept 8446 -www -cert client.cert.pem -key test.key -cert_chain ~/intermediate.cert.pem >/dev/null 2>&1 &
[etudiant@tls-serv-palancac tests]$ ss -ltn | grep -E ':(443|844[3-6]) '
LISTEN 0      4096         0.0.0.0:443       0.0.0.0:*
LISTEN 0      4096               *:8443            *:*
LISTEN 0      4096               *:8446            *:*
LISTEN 0      4096               *:8445            *:*
LISTEN 0      4096               *:8444            *:*
LISTEN 0      4096            [::]:443          [::]:*
```

#### Résultats des tests T1 à T8

Le client a été copié sur `tls-serv-palancac` (Python 3.12.9), dont le magasin de confiance contient `Root Lorne` :

```console
[etudiant@tls-serv-palancac tests]$ python3 ~/tests/client_tls.py
[T1] Cas nominal : chaîne et nom valides  (www.palancac.fr -> 192.168.170.119:443, contexte systeme)
     attendu : acceptée | obtenu : acceptée -> CONFORME
     TLSv1.3 TLS_AES_256_GCM_SHA384 | sujet CN=www.palancac.fr | émetteur CN=RA palancac | SAN www.palancac.fr, dev.palancac.fr
     réponse : HTTP/1.1 200 OK

[T2] CA racine inconnue (magasin vide)  (www.palancac.fr -> 192.168.170.119:443, contexte vide)
     attendu : refusée | obtenu : refusée -> CONFORME
     refus : unable to get local issuer certificate (code 20)

[T3] Chaîne incomplète (intermédiaire non envoyé)  (www.palancac.fr -> 192.168.170.119:8443, contexte systeme)
     attendu : refusée | obtenu : refusée -> CONFORME
     refus : unable to get local issuer certificate (code 20)

[T4] Nom demandé absent du SAN  (palancac.fr -> 192.168.170.119:443, contexte systeme)
     attendu : refusée | obtenu : refusée -> CONFORME
     refus : Hostname mismatch, certificate is not valid for 'palancac.fr'. (code 62)

[T5] Certificat auto-signé (imposteur)  (www.palancac.fr -> 192.168.170.119:8444, contexte systeme)
     attendu : refusée | obtenu : refusée -> CONFORME
     refus : self-signed certificate (code 18)

[T6] Certificat expiré  (www.palancac.fr -> 192.168.170.119:8445, contexte systeme)
     attendu : refusée | obtenu : refusée -> CONFORME
     refus : certificate has expired (code 10)

[T7] Certificat non prévu pour un serveur  (www.palancac.fr -> 192.168.170.119:8446, contexte systeme)
     attendu : refusée | obtenu : refusée -> CONFORME
     refus : unsuitable certificate purpose (code 26)

[T8] Client qui ne vérifie rien, face à T5  (www.palancac.fr -> 192.168.170.119:8444, contexte aucune_verif)
     attendu : acceptée | obtenu : acceptée -> CONFORME
     TLSv1.3 TLS_AES_256_GCM_SHA384 | certificat reçu mais non vérifié
     réponse : HTTP/1.0 200 ok

Bilan : 8/8 tests conformes
```

| #  | Vérification testée               | Résultat obtenu                                 | Conforme |
| -- | --------------------------------- | ----------------------------------------------- | -------- |
| T1 | Authentification complète         | Acceptée, TLS 1.3, page `200 OK`                | Oui      |
| T2 | Racine de confiance               | Refus, code 20                                  | Oui      |
| T3 | Construction de la chaîne         | Refus, code 20                                  | Oui      |
| T4 | Nom du serveur (SAN)              | Refus, code 62 `Hostname mismatch`              | Oui      |
| T5 | Signature par une CA de confiance | Refus, code 18 `self-signed certificate`        | Oui      |
| T6 | Période de validité               | Refus, code 10 `certificate has expired`        | Oui      |
| T7 | Usage du certificat (EKU)         | Refus, code 26 `unsuitable certificate purpose` | Oui      |
| T8 | Contre-exemple sans vérification  | Acceptée : l'imposteur n'est pas détecté        | Oui      |

Le client effectue donc bien chacune des vérifications de la question 4 :

- **T2 et T3** donnent la même erreur (code 20) pour deux causes différentes : en T2 le client ne connaît aucune racine, en T3 il connaît `Root Lorne` mais ne peut pas l'atteindre sans `RA palancac`. C'est la situation de la section 7.3.2 avant la concaténation de la chaîne.
- **T4** montre qu'une chaîne valide ne suffit pas : le certificat doit aussi correspondre au nom demandé.
- **T5** est l'attaque la plus réaliste : l'imposteur présente un certificat au bon nom (`CN=www.palancac.fr`, même SAN), mais signé par lui-même.
- **T6 et T7** utilisent des certificats émis par notre propre CA, avec une chaîne complète : ils sont refusés uniquement à cause de leur date ou de leur usage (`clientAuth` au lieu de `serverAuth`).
- **T8** montre que la connexion est chiffrée (TLS 1.3) même avec l'imposteur : le chiffrement seul ne garantit rien si le client n'authentifie pas le serveur. C'est le même danger que l'option `-k` de `curl` (section 7.3.1).

#### T9 : vérification du chiffrement

Nous avons capturé avec `tcpdump` le trafic des ports 443 et 80 pendant l'exécution de T1, puis cherché dans la capture des chaînes connues en clair : le texte de la page servie par `web1` (« servies par ») et l'organisation du certificat (« Canut »).

```console
[etudiant@tls-serv-palancac tests]$ sudo tcpdump -i any -U -s0 -w capture.pcap 'tcp port 443 or tcp port 80' >/dev/null 2>&1 &
[etudiant@tls-serv-palancac tests]$ python3 client_tls.py T1; sudo pkill tcpdump
[...]
Bilan : 1/1 tests conformes
[etudiant@tls-serv-palancac tests]$ sudo tcpdump -r capture.pcap -nn 'tcp port 443' 2>/dev/null | head -3
14:06:51.482835 br-4141f9c1ce7a Out IP 192.168.170.119.52622 > 172.18.0.3.443: Flags [S], seq 2978217756, [...]
14:06:51.482845 veth5a84e36 Out IP 192.168.170.119.52622 > 172.18.0.3.443: Flags [S], seq 2978217756, [...]
14:06:51.482872 veth5a84e36 P   IP 172.18.0.3.443 > 192.168.170.119.52622: Flags [S.], seq 835385169, [...]
[etudiant@tls-serv-palancac tests]$ sudo tcpdump -r capture.pcap -A 'tcp port 443' 2>/dev/null | grep -c "servies par"
0
[etudiant@tls-serv-palancac tests]$ sudo tcpdump -r capture.pcap -A 'tcp port 443' 2>/dev/null | grep -c "Canut"
0
[etudiant@tls-serv-palancac tests]$ sudo tcpdump -r capture.pcap -A 'tcp port 80' 2>/dev/null | grep -E "GET /|servies par"
14:06:51.486547 veth5a84e36 P   IP 172.18.0.3.33624 > 172.18.0.4.http: Flags [P.], seq 1:50, [...] length 49: HTTP: GET / HTTP/1.0
.GET / HTTP/1.0
[...]
L'URL / et toutes les URL autres que /admin/ sont servies par <b>web1</b>.
```

- **Sur le port 443, entre le client et Nginx, le contenu est chiffré.** Le texte de la page n'apparaît dans aucun paquet. Les paquets passent par le pont Docker (`br-…`, `172.18.0.3` est le conteneur `reverse`), car Docker redirige le port 443 de l'hôte vers le conteneur.
- **Le nom du site, en revanche, circule en clair.** En relançant la recherche avec `-nn` (sans `-nn`, tcpdump remplace l'adresse `192.168.170.119` par `www.palancac.fr` grâce à `/etc/hosts`, ce qui fausse le comptage), on le trouve dans le premier paquet de données envoyé par le client, le `ClientHello` (`seq 1:1546`) :

  ```console
  [etudiant@tls-serv-palancac tests]$ sudo tcpdump -r capture.pcap -nn -A 'tcp port 443' 2>/dev/null | grep -c "www.palancac.fr"
  2
  [etudiant@tls-serv-palancac tests]$ sudo tcpdump -r capture.pcap -nn -A 'tcp port 443' 2>/dev/null | grep -B3 "www.palancac.fr" | head -4
  14:06:51.483512 br-4141f9c1ce7a Out IP 192.168.170.119.52622 > 172.18.0.3.443: Flags [P.], seq 1:1546, ack 1, [...] length 1545
  [...]
  ...     .............k.g.9.3..................www.palancac.fr.........
  ```

  Les deux occurrences correspondent au même paquet, vu sur deux interfaces (le pont Docker et l'interface `veth` du conteneur). C'est l'extension **SNI** (question 4) : le client indique en clair le nom du site demandé, pour que le serveur choisisse le bon certificat. Un observateur du réseau sait donc à quel site le client se connecte, sans voir le contenu échangé.
- **Le certificat lui-même n'est pas lisible.** « Canut », présent dans le sujet du certificat, n'apparaît pas. En TLS 1.3, le message `Certificate` est envoyé après l'échange de clés, et il est donc chiffré. En TLS 1.2, il passait en clair.
- **Sur le port 80, le trafic est en clair.** On lit la requête `GET / HTTP/1.0` envoyée par Nginx (`172.18.0.3`) à `web1` (`172.18.0.4`), puis la page. C'est la **terminaison TLS** : la connexion n'est chiffrée qu'entre le client et le proxy, et les échanges avec les backends restent en HTTP dans le réseau Docker. Ce n'est acceptable que parce que ce réseau est interne à la machine.

Le test T9 est donc conforme : les échanges entre le client et le serveur sont chiffrés.

---

## Conclusion

Ce TP nous a permis de mettre en œuvre, de bout en bout, les mécanismes qui permettent à un client de faire confiance à un serveur HTTPS.

- **Chiffrement asymétrique :** l'échange de messages avec Kylian a montré que RSA garantit la confidentialité, mais pas l'origine d'un message. Il n'y a aucune garantie que la clé publique reçue appartient bien à son propriétaire. Les certificats répondent à ce problème.
- **Certificats X.509 :** l'analyse de la chaîne de l'université (section 5) puis la création de notre propre PKI (section 6) nous ont montré la même structure : une racine auto-signée, présente dans le magasin de confiance, une CA intermédiaire (`pathlen:0`) et un certificat de serveur (`CA:FALSE`, `serverAuth`, SAN). La confiance ne vient pas de la signature de la racine, mais de sa présence dans le magasin de confiance du client.
- **Déploiement :** le reverse proxy Nginx assure la terminaison TLS. Un seul import, celui de `Root Lorne`, suffit pour que les clients acceptent le serveur, à condition que celui-ci envoie aussi le certificat de `RA palancac`, et que le nom demandé figure dans le SAN.
- **Validation par le client :** les tests de la section 8 confirment que l'authentification repose sur plusieurs vérifications indépendantes : chaîne jusqu'à une racine de confiance, nom, période de validité et usage du certificat. Chacune peut faire échouer la connexion. Le test T8 montre qu'un client qui désactive ces vérifications reste chiffré, mais parle sans le savoir à un imposteur.

Quelques limites de cette PKI de TP restent à noter :
- la clé de la racine et le compte `camanager` sont partagés entre tous les étudiants ;
- aucune CRL ni aucun serveur OCSP ne permet de révoquer un certificat (l'adresse `ocsp2.example.com` est fictive) ;
- le nom du site reste visible en clair dans le SNI ;
- le trafic entre le proxy et les backends n'est pas chiffré.
