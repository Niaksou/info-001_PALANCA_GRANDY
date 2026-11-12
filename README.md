# Compte rendu TP1 INFO 001 : Cryptographie appliquée, TLS/SSL et PKI

**Binôme :** Clément PALANCA · Kylian GRANDY

---

## Sommaire

- [Contexte et objectifs](#contexte-et-objectifs)
- [2. Questions préliminaires](#2-questions-préliminaires)
  - [Question 1: Chiffrement et déchiffrement RSA](#question-1-chiffrement-et-déchiffrement-rsa)
  - [Question 2: Rôle de Diffie-Hellman](#question-2-rôle-de-diffie-hellman)
  - [Question 3: Informations contenues dans un certificat](#question-3-informations-contenues-dans-un-certificat)
  - [Question 4: Authentification du site d’Alice par Bob](#question-4-authentification-du-site-dalice-par-bob)
- [3. Accès aux machines virtuelles](#3-accès-aux-machines-virtuelles)
- [4. Étude du chiffrement RSA](#4-étude-du-chiffrement-rsa)
- [5. Analyse du contenu d'un certificat](#5-analyse-du-contenu-dun-certificat)
- [6. Mise en place d'une PKI](#6-mise-en-place-dune-pki)
- [7. Mise en place d'un reverse proxy](#7-mise-en-place-dun-reverse-proxy)
- [8. Développement d'un client Web](#8-développement-dun-client-web)
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

Les champs `privateExponent`, `prime1`, `prime2`, `exponent1`, `exponent2` et `coefficient` ont été volontairement masqués : ils constituent la clé privée (d, p et q permettent de déchiffrer et de signer à notre place) et n'ont pas leur place dans un dépôt public. Seuls `modulus` (n) et `publicExponent` (e) sont publics.

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

OpenSSL relit la bi-clé (`-in`), la chiffre avec une clé AES dérivée de la passphrase (`-aes128`) et écrit le résultat dans un nouveau fichier (`-out`). La passphrase est saisie de façon interactive plutôt qu'avec l'option `-passout pass:...`, pour qu'elle n'apparaisse pas en clair dans l'historique du shell.

On vérifie que le fichier est bien chiffré en comparant les en-têtes :

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

Le fichier est bien plus court que la bi-clé : il ne contient que n et e. Contrairement à la clé privée, il peut être publié sans risque.

### Question 7

> _Quel est l'encodage utilisé pour la clé ? Quel est l'avantage de cet encodage ?_

La clé est au format **PEM** (_Privacy-Enhanced Mail_). La structure de la clé est d'abord décrite en ASN.1 puis sérialisée en binaire (format **DER**). Ce binaire est ensuite encodé en **Base64**, découpé en lignes de 64 caractères et encadré par les balises `-----BEGIN PUBLIC KEY-----` et `-----END PUBLIC KEY-----`.

Cet encodage a deux avantages :

- **Le fichier est du texte ASCII pur.** On peut le copier-coller, l'envoyer par mail ou le publier sur un serveur web sans risque de corruption, ce qui n'est pas garanti pour un fichier binaire.
- **Les balises indiquent la nature du contenu** (clé publique, clé privée chiffrée, certificat…). On peut aussi mettre plusieurs objets à la suite dans un même fichier, par exemple une chaîne de certificats.

L'inconvénient est une taille environ 33 % plus grande que le DER binaire, à cause du Base64.

### Lecture de la clé publique interprétée

Pour lire le contenu du fichier PEM de façon lisible, on demande à OpenSSL de le décoder. L'option `-pubin` indique que le fichier d'entrée contient une clé publique seule. Aucune passphrase n'est demandée, car ce fichier n'est pas chiffré.

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

Le fichier a ensuite été renommé avec notre login, pour qu'il ne se confonde pas avec celui de notre voisin lors de l'échange :

```bash
mv pub.pem pub.palancac.pem
```

### 4.2 Chiffrement asymétrique

Le couple de clés généré précédemment va maintenant servir à échanger des messages chiffrés avec un voisin.

### Question 9

> _Quelle clé doit-on utiliser pour chiffrer un message RSA lorsqu'on veut l'envoyer de manière confidentielle ?_

Pour envoyer un message confidentiel, on le chiffre avec la **clé publique du destinataire**. Seul le destinataire possède la clé privée correspondante, il est donc le seul à pouvoir déchiffrer le message.

Dans notre cas, pour écrire à Kylian, nous devons récupérer sa clé publique (`pub.kgrandy.pem`). Lui utilisera la nôtre (`pub.palancac.pem`) pour nous répondre. C'est pour cela que la première étape consiste à s'échanger les clés publiques.

À l'inverse, chiffrer avec sa propre clé privée ne protège pas la confidentialité : n'importe qui pourrait déchiffrer avec la clé publique. Ce mécanisme sert à la **signature**, qui prouve l'origine du message, et non à le garder secret.

#### 4.2.1 Partage de la clé publique avec un voisin (installation de httpd)

Pour échanger nos clés publiques de façon réaliste, nous avons installé le serveur web Apache (`httpd`) sur la machine `tls-ca-palancac` et y avons publié notre clé :

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

L'installation d'Apache 2.4.63 a ajouté 12 paquets (httpd et ses dépendances). Les deux `success` confirment l'ouverture du port 80, et les commandes `systemctl` et `cp` n'affichent rien lorsqu'elles réussissent.

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

Nous avons ensuite récupéré la clé publique depuis le poste de Kylian (`kgrandy`, machine `192.168.170.219`) à partir de l'adresse IP et du nom de fichier :

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

L'option `-O` enregistre le fichier sous son nom d'origine, et `-f` fait échouer `curl` en cas d'erreur HTTP. Sans elle, une page « 404 Not Found » aurait été enregistrée à la place de la clé, comme cela nous est arrivé lors d'un premier essai avec une mauvaise adresse IP.

L'échange a été testé depuis les deux postes. Kylian a récupéré de la même façon notre clé publique depuis sa machine :

```console
[etudiant@tls-ca-kgrandy ~]$ curl -fO http://192.168.170.85/pub.palancac.pem
100   272  100   272    0     0  53872      0 --:--:-- --:--:-- --:--:-- 54400
```

Chacun dispose ainsi de la clé publique de l'autre, et le fichier reçu est identique à celui publié (272 octets, même contenu).

Publier une clé publique sur un serveur web ne pose aucun problème de sécurité, puisqu'elle est faite pour être diffusée. En revanche, rien ne garantit ici que la clé récupérée appartient bien au voisin : c'est précisément le rôle des certificats, étudiés dans la suite du TP.

## 5. Analyse du contenu d'un certificat

## 6. Mise en place d'une PKI

## 7. Mise en place d'un reverse proxy

## 8. Développement d'un client Web

---

## Conclusion
