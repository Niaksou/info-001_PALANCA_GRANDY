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

OpenSSL n'étant pas présent sur l'image, je l'ai d'abord installé :

```bash
sudo dnf install -y openssl
```

La page de manuel (`man openssl-genpkey`) indique que la sous-commande `genpkey` génère une bi-clé, et que la taille d'une clé RSA se règle avec l'option `-pkeyopt rsa_keygen_bits:<taille>`. La commande du sujet demandait 512 bits. Je l'ai corrigée pour générer une clé de 1024 bits :

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

Les champs `privateExponent`, `prime1`, `prime2`, `exponent1`, `exponent2` et `coefficient` ont été volontairement masqués : ils constituent la clé privée (d, p et q permettent de déchiffrer et de signer à ma place) et n'ont pas leur place dans un dépôt public. Seuls `modulus` (n) et `publicExponent` (e) sont publics.

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

Le fichier `rsa_keys.pem` contient la clé privée en clair : toute personne qui y accède peut l'utiliser. Pour le protéger, je l'ai chiffré avec l'algorithme symétrique AES 128 bits, en utilisant mon login comme passphrase. La commande du sujet se terminait par un point, que j'ai retiré pour que le fichier s'appelle bien `rsa_keys_cyphered.pem` :

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

Le fichier en clair n'étant plus utile, je l'ai supprimé avec `rm rsa_keys.pem`. Toutes les commandes suivantes utilisent la version chiffrée et redemandent la passphrase.

### Question 6

> _Y a-t-il un intérêt à chiffrer une clé publique ? À chiffrer une clé privée ?_

Chiffrer une clé publique n'a aucun intérêt : elle est faite pour être diffusée, et la connaître ne permet ni de déchiffrer ni de signer à la place de son propriétaire.

Chiffrer une clé privée est au contraire essentiel. Si le fichier est volé (accès au disque, sauvegarde, dépôt Git…), l'attaquant ne peut pas s'en servir sans la passphrase. Ici, le fichier contient la bi-clé complète, et c'est la partie privée qu'on protège.

### Extraction de la clé publique

Pour pouvoir diffuser ma clé publique sans exposer la clé privée, je l'ai extraite dans un fichier séparé. L'option `-pubout` demande à OpenSSL de n'écrire que la partie publique. Comme la bi-clé est chiffrée, la passphrase est demandée pour la lire.

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
- **C'est ce dont ont besoin mes correspondants** : chiffrer un message qu'ils me destinent, ou vérifier une signature que j'ai produite. C'est aussi ce qu'une CA place dans un certificat.

Le fichier a ensuite été renommé avec mon login, pour qu'il ne se confonde pas avec celui de mon voisin lors de l'échange :

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

L'option `-O` enregistre le fichier sous son nom d'origine, et `-f` fait échouer `curl` en cas d'erreur HTTP. Sans elle, une page « 404 Not Found » aurait été enregistrée à la place de la clé, comme cela m'est arrivé lors d'un premier essai avec une mauvaise adresse IP.

L'échange a été testé depuis les deux postes. Kylian a récupéré de la même façon ma clé publique depuis sa machine :

```console
[etudiant@tls-ca-kgrandy ~]$ curl -fO http://192.168.170.85/pub.palancac.pem
100   272  100   272    0     0  53872      0 --:--:-- --:--:-- --:--:-- 54400
```

Chacun dispose ainsi de la clé publique de l'autre, et le fichier reçu est identique à celui publié (272 octets, même contenu).

Publier une clé publique sur un serveur web ne pose aucun problème de sécurité, puisqu'elle est faite pour être diffusée. En revanche, rien ne garantit ici que la clé récupérée appartient bien au voisin : c'est précisément le rôle des certificats, étudiés dans la suite du TP.

#### 4.2.2 Chiffrement avec la clé publique

Maintenant que je dispose de la clé publique de Kylian, je peux lui envoyer un message que lui seul pourra lire.

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

Le fichier obtenu est binaire et ne peut pas être affiché avec `cat`. On le visualise donc avec `hexdump`. L'option `-C` affiche en plus, à droite, la traduction ASCII de chaque octet :

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

**Le contenu est illisible.** Aucun fragment du message d'origine (« Bonjour », « PALANCA »…) n'apparaît dans la colonne ASCII : les octets semblent aléatoires.

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

**C'est normal, et c'est même voulu.** Avant d'appliquer le calcul $C = M^e \bmod n$, OpenSSL ne chiffre pas le message brut : il le complète avec un **remplissage** (_padding_) qui contient des octets aléatoires. Le bloc réellement chiffré a la forme suivante :

```text
00 | 02 | PS (au moins 8 octets aléatoires non nuls) | 00 | message
```

PS est tiré au hasard à chaque chiffrement : le nombre M réellement chiffré change donc à chaque fois, et le chiffré C aussi. Au déchiffrement, Kylian retrouve ce bloc complet, retire le remplissage et récupère le message d'origine.

Sans cet aléa, RSA serait **déterministe** : un même message donnerait toujours le même chiffré, ce qui poserait deux problèmes :

- **Un attaquant pourrait reconnaître les messages répétés** en comparant simplement les chiffrés qui circulent sur le réseau.
- **Il pourrait deviner le contenu d'un message.** La clé publique étant connue de tous, il lui suffirait de chiffrer les messages probables (« oui », « non », « Bonjour de … ») et de comparer le résultat au chiffré intercepté.

#### Échange et déchiffrement des messages

J'ai publié mon chiffré sur le serveur web, sous un nom contenant mon login pour qu'il ne se confonde pas avec celui de Kylian :

```bash
sudo cp cipher.bin /var/www/html/cipher.palancac.bin
```

Kylian l'a téléchargé depuis sa machine. Avec sa propre bi-clé chiffrée, le déchiffrement fonctionne. La passphrase est demandée, puisque la clé privée est protégée par AES :

```console
[etudiant@tls-ca-kgrandy ~]$ openssl pkeyutl -decrypt -inkey rsa_keys_cyphered.pem -in cipher.palancac.bin -out dechiffre.txt
Enter pass phrase for rsa_keys_cyphered.pem:
[etudiant@tls-ca-kgrandy ~]$ cat dechiffre.txt
Bonjour de Clément PALANCA
```

De mon côté, j'ai récupéré le chiffré de Kylian et l'ai déchiffré de la même façon, avec ma clé privée :

```console
[etudiant@tls-ca-palancac ~]$ curl -fO http://192.168.170.219/cipher.kgrandy.bin
100   128  100   128    0     0  33648      0 --:--:-- --:--:-- --:--:-- 42666
[etudiant@tls-ca-palancac ~]$ openssl pkeyutl -decrypt -inkey rsa_keys_cyphered.pem -in cipher.kgrandy.bin -out dechiffre.txt
Enter pass phrase for rsa_keys_cyphered.pem:
[etudiant@tls-ca-palancac ~]$ cat dechiffre.txt
Bonjour de GRANDY Kylian
```

Les options de déchiffrement reprennent celles du chiffrement :

| Option                         | Rôle                                                                           |
| ------------------------------ | ------------------------------------------------------------------------------ |
| `-decrypt`                     | Déchiffre les données d'entrée avec une clé privée                             |
| `-inkey rsa_keys_cyphered.pem` | Ma bi-clé. Pas besoin de `-pubin`, car le fichier contient bien une clé privée |
| `-in cipher.kgrandy.bin`       | Le message chiffré reçu                                                        |
| `-out dechiffre.txt`           | Le fichier où est écrit le message déchiffré                                   |

Les deux messages ont été retrouvés à l'identique, accents compris : l'échange confidentiel fonctionne dans les deux sens. Chaque chiffré a été transmis en clair sur le réseau, via HTTP, sans que cela compromette le message : sans la clé privée du destinataire, ces 128 octets sont inexploitables.

Une limite subsiste toutefois : rien ne prouve que le message vient bien de la personne qui prétend l'avoir envoyé. N'importe qui disposant de la clé publique de Kylian aurait pu lui écrire « Bonjour de Clément PALANCA ». Pour garantir l'origine d'un message, il faudrait le signer avec sa clé privée.

## 5. Analyse du contenu d'un certificat

Cette partie étudie les informations contenues dans un certificat réel et la façon dont sa validité est vérifiée. Les manipulations sont faites depuis la machine `tls-ca-palancac`.

### 5.1 En ligne de commande avec `openssl s_client`

La sous-commande `s_client` d'OpenSSL se comporte comme un client TLS minimal : elle ouvre une connexion TLS vers un serveur et affiche tout ce qui se passe pendant la poignée de main.

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

Les blocs Base64 des certificats et les deux _tickets_ de session envoyés après la poignée de main ont été coupés (`[...]`), car ils ne sont pas lisibles et n'apportent rien à l'analyse.

La fin de la sortie résume la connexion : la chaîne a été vérifiée avec succès (`Verification: OK`, `Verify return code: 0 (ok)`). La session utilise TLS 1.3 avec la suite `TLS_AES_256_GCM_SHA384` (chiffrement symétrique AES 256 bits en mode GCM). La clé de session a été échangée avec `X25519`, une variante de Diffie-Hellman sur courbe elliptique : c'est le mécanisme décrit à la question 2.

### Question 12

> _Lire dans la page de manuel de `s_client` le rôle de l'option `-showcerts`. Expliquer le rôle de cette option. Après avoir parcouru le résultat de la commande, indiquer le nombre de certificats envoyés par le serveur._

D'après `man openssl-s_client`, l'option `-showcerts` affiche **toute la chaîne de certificats envoyée par le serveur**, chacun au format PEM. Sans cette option, `s_client` n'affiche que le certificat du serveur lui-même. Elle permet donc de récupérer les certificats des autorités intermédiaires, que l'on ne possède pas forcément localement.

Le serveur a envoyé **3 certificats**, numérotés de 0 à 2 dans la section `Certificate chain` :

| N°  | Sujet (CN)                    | Rôle                                                                            | Clé      |
| --- | ----------------------------- | ------------------------------------------------------------------------------- | -------- |
| 0   | `*.univ-grenoble-alpes.fr`    | Certificat du serveur                                                           | RSA 2048 |
| 1   | `GEANT TLS RSA 1`             | CA intermédiaire, qui a signé le certificat 0                                   | RSA 3072 |
| 2   | `HARICA TLS RSA Root CA 2021` | CA racine, ici sous forme de certificat signé par l'ancienne racine HARICA 2015 | RSA 4096 |

Le serveur envoie donc son certificat, mais aussi ceux des autorités qui permettent de remonter jusqu'à une racine de confiance. Le certificat 2 est particulier : `HARICA TLS RSA Root CA 2021` est une racine, mais la version envoyée par le serveur n'est pas auto-signée. Elle est signée par l'ancienne racine `Hellenic Academic and Research Institutions RootCA 2015`. On parle de **certificat croisé** (_cross-certificate_) : il permet aux clients plus anciens, qui ne connaissent que la racine de 2015, de valider quand même la chaîne.

Le début de la sortie (`depth=2`, `depth=1`, `depth=0`) montre l'ordre dans lequel OpenSSL a vérifié la chaîne, de la racine jusqu'au serveur. `verify return:1` indique que chaque niveau est valide. La vérification s'arrête à `depth=2` et ne remonte pas jusqu'à la racine de 2015, car `HARICA TLS RSA Root CA 2021` est déjà présente dans le magasin de confiance de la machine.

#### Extraction et lecture du certificat du serveur

Plutôt que de copier-coller le bloc PEM à la main, j'ai extrait chaque certificat de la chaîne dans un fichier séparé (`cert0.pem` pour le serveur, `cert1.pem` et `cert2.pem` pour les CA) :

```bash
openssl s_client -showcerts -connect www.univ-grenoble-alpes.fr:443 </dev/null > uga.txt 2>&1
awk '/BEGIN CERTIFICATE/{n++; f="cert" n-1 ".pem"} f{print > f} /END CERTIFICATE/{f=""}' uga.txt
```

`</dev/null` ferme immédiatement l'entrée de `s_client`, qui sinon reste connecté en attendant une saisie. Le script `awk` ouvre un nouveau fichier à chaque ligne `BEGIN CERTIFICATE` et y écrit les lignes jusqu'à `END CERTIFICATE`.

On affiche ensuite le certificat du serveur dans un format lisible :

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

Le module et la signature ont été raccourcis, et seule la première des trois preuves SCT est affichée.

L'extension `CT Precertificate SCTs` est liée à la **_Certificate Transparency_** : avant de délivrer le certificat, la CA l'a déclaré dans trois journaux publics, gérés par des organismes indépendants. Chaque journal a renvoyé un _Signed Certificate Timestamp_ (SCT), une preuve signée (ici en ECDSA) que le certificat y a été enregistré le 20 octobre 2026. Ces journaux sont publics : le propriétaire d'un domaine peut y repérer un certificat émis à son nom sans son accord. Les navigateurs comme Chrome et Safari refusent d'ailleurs un certificat qui ne contient pas assez de SCT.

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

**Algorithmes de signature :** `sha256WithRSAEncryption`. La CA a combiné deux algorithmes :

**Attribut CN :** il contient `*.univ-grenoble-alpes.fr`.

**Autres noms de machine :** ils figurent dans l'extension **`X509v3 Subject Alternative Name`** (SAN) :

```text
DNS:*.univ-grenoble-alpes.fr, DNS:univ-grenoble-alpes.fr
```

Le SAN est nécessaire ici, car le _wildcard_ `*` remplace exactement un niveau : `*.univ-grenoble-alpes.fr` ne couvre pas `univ-grenoble-alpes.fr` sans préfixe. Ce nom est donc ajouté explicitement. Les navigateurs actuels ne regardent d'ailleurs plus que le SAN pour vérifier le nom du site, le CN n'étant conservé que par compatibilité.

**Durée de validité :** du **20 octobre 2026** (`Not Before`) au **7 mai 2027** (`Not After`).

**Lien vers le fichier .crl :** l'extension `X509v3 CRL Distribution Points` contient l'adresse `http://crl.harica.gr/HARICA-GEANT-TLS-R1.crl`. Une **CRL** (_Certificate Revocation List_) est la liste, signée par la CA, des numéros de série des certificats qu'elle a **révoqués** avant leur date d'expiration, par exemple parce que la clé privée a été volée. Le client peut télécharger cette liste et vérifier que le numéro de série du certificat (`0b:38:0b:15:...`) n'y figure pas. Sans ce mécanisme, un certificat compromis resterait accepté jusqu'à sa date de fin.

Les autres extensions confirment qu'il s'agit d'un certificat de serveur : `CA:FALSE` interdit de l'utiliser pour signer d'autres certificats, `Key Usage` et `Extended Key Usage` limitent son usage à la signature, au chiffrement de clé et à l'authentification TLS.

### Question 16

> _Par qui le certificat de `www.univ-grenoble-alpes.fr` a-t-il été signé ? Soit E l'algorithme de chiffrement RSA, donner la formule utilisée pour calculer la signature présente dans le certificat._

Le certificat a été signé par l'autorité intermédiaire **`GEANT TLS RSA 1`** (champ `Issuer`), avec **sa clé privée**. On peut le vérifier : l'`Authority Key Identifier` du certificat (`86:01:72:3F:...`) doit être égal au `Subject Key Identifier` du certificat de `GEANT TLS RSA 1`.

La signature est calculée sur la partie `Data` du certificat (appelée _TBSCertificate_, _to be signed_), qui contient tous les champs sauf la signature elle-même. En notant $H$ la fonction SHA-256, $E$ le chiffrement RSA et $K_{priv}^{CA} = (n_{CA}, d_{CA})$ la clé privée de GEANT TLS RSA 1 :

```math
\text{Signature} = E_{K_{priv}^{CA}}\big(H(\text{TBSCertificate})\big) = \big(\text{pad}(H(\text{TBSCertificate}))\big)^{d_{CA}} \bmod n_{CA}
```

où `pad` est le remplissage , qui complète l'empreinte de 32 octets jusqu'à la taille du module.

Pour **vérifier** la signature, le client recalcule $H(\text{TBSCertificate})$ et le compare au résultat de l'opération inverse, faite avec la clé publique de la CA :

```math
\text{Signature}^{e_{CA}} \bmod n_{CA} \stackrel{?}{=} \text{pad}(H(\text{TBSCertificate}))
```

La taille de la signature confirme qui l'a produite : la valeur affichée sous `Signature Value` fait 384 octets, soit **3072 bits**. C'est la taille de la clé de `GEANT TLS RSA 1` (`a:PKEY: RSA, 3072 (bit)`), et non celle de la clé de 2048 bits du serveur.

Il ne faut pas confondre cette signature avec la ligne `Peer signature type: rsa_pss_rsae_sha256` de la sortie de `s_client`. Celle-ci est une signature produite **par le serveur**, avec sa propre clé privée, pendant la poignée de main TLS (message `CertificateVerify`). Elle prouve qu'il possède bien la clé privée correspondant au certificat, comme vu à l'étape 6 de la question 4.

### Question 17

> _Afficher le certificat de la CA qui a délivré le certificat de `www.univ-grenoble-alpes.fr`. Relever le sujet de ce certificat. Quelle est la taille de la clé publique présente dans ce certificat ? Par quelle CA ce certificat a-t-il été signé ?_

Le certificat de la CA émettrice est le deuxième de la chaîne envoyée par le serveur, extrait dans `cert1.pem`. Plutôt que d'afficher tout le certificat, j'ai demandé à OpenSSL uniquement les champs utiles :

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

J'ai affiché ces quatre champs pour les trois certificats de la chaîne :

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

La page de manuel de `update-ca-trust` indique que les certificats de confiance sont regroupés dans `/etc/pki/ca-trust/extracted/`, et cite le fichier `openssl/ca-bundle.trust.crt`. Ce fichier n'existe pas sur la version d'Alma Linux utilisée : le dossier `openssl/` ne contient plus qu'un `README`. J'ai donc utilisé le fichier `pem/tls-ca-bundle.pem`, décrit dans la même page comme contenant les CA de confiance pour l'authentification des serveurs TLS :

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

Ce fichier contient plusieurs centaines de certificats à la suite. Je l'ai découpé en un fichier par certificat, puis j'ai cherché ceux de HARICA :

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

Le certificat qui valide `cert2` est `Hellenic Academic and Research Institutions RootCA 2015`, en version RSA (`ca079.pem`). Il se trouve dans le magasin de confiance du système, `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, installé avec le paquet `ca-certificates`. Les variantes ECC (`ca076`, `ca078`) correspondent à d'autres racines HARICA, à base de courbes elliptiques.

On constate aussi que **`HARICA TLS RSA Root CA 2021` est elle-même présente dans le magasin** (`ca077.pem`), cette fois sous forme de certificat auto-signé. Le client n'a donc même pas besoin de remonter jusqu'à la racine de 2015, comme le montre la vérification de la chaîne :

```console
[etudiant@tls-ca-palancac ~]$ openssl verify -show_chain -untrusted cert1.pem cert0.pem
cert0.pem: OK
Chain:
depth=0: C=FR, ST=Auvergne-Rhône-Alpes, L=Saint-Martin-d'Hères, O=Université Grenoble Alpes, CN=*.univ-grenoble-alpes.fr (untrusted)
depth=1: C=GR, O=Hellenic Academic and Research Institutions CA, CN=GEANT TLS RSA 1 (untrusted)
depth=2: C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
```

L'option `-untrusted cert1.pem` fournit le certificat intermédiaire sans lui accorder de confiance : il sert seulement à construire la chaîne. Les niveaux 0 et 1 sont marqués `(untrusted)`, car ils viennent de fichiers fournis par l'utilisateur. Le niveau 2 ne l'est pas : OpenSSL l'a trouvé dans le magasin de confiance, où il s'arrête. C'est pour cela que `s_client` s'arrêtait déjà à `depth=2` à la question 12.

Les deux versions de `HARICA TLS RSA Root CA 2021` (celle signée par la racine de 2015, envoyée par le serveur, et la version auto-signée du magasin) contiennent la **même clé publique**. Elles ont le même SKI, `0A:48:23:A6:…`, qui correspond aussi à l'AKI de `cert1` :

```console
[etudiant@tls-ca-palancac ~]$ openssl x509 -in ~/store/ca077.pem -noout -subject -issuer -ext subjectKeyIdentifier
subject=C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
issuer=C=GR, O=Hellenic Academic and Research Institutions CA, CN=HARICA TLS RSA Root CA 2021
X509v3 Subject Key Identifier:
    0A:48:23:A6:60:A4:92:0A:33:EA:93:5B:C5:57:EA:25:4D:BD:12:EE
```

N'importe laquelle des deux peut donc valider la signature de `GEANT TLS RSA 1`. C'est tout l'intérêt du certificat croisé : un système récent fait confiance directement à la racine de 2021, et un système plus ancien, qui ne connaît que la racine de 2015, peut quand même valider la chaîne grâce à `cert2`.

#### Extraction du certificat de la CA racine

J'ai copié le certificat de la racine `Hellenic Academic and Research Institutions RootCA 2015`, trouvé à l'étape précédente, dans le fichier `root-ca1.pem`, puis j'ai affiché son contenu :

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

Le SKI de cette racine, `71:15:67:C8:…`, est bien égal à l'AKI de `cert2` relevé à la question 18. Pour le confirmer, j'ai demandé à OpenSSL de vérifier `cert2` en utilisant **uniquement** `root-ca1.pem` comme autorité de confiance. Les options `-no-CApath -no-CAstore` désactivent le magasin du système :

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

Cette auto-signature ne prouve rien sur l'identité du titulaire : n'importe qui peut créer un certificat auto-signé au nom de HARICA. Elle prouve seulement l'intégrité du certificat et la possession de la clé privée. La confiance dans une racine ne vient donc pas de sa signature, mais de **sa présence dans le magasin de confiance**. Ce magasin est fourni par le système d'exploitation (ici le paquet `ca-certificates` d'Alma Linux) ou par le navigateur, qui n'y intègrent une CA qu'après des audits de sécurité. C'est pour cela que la racine n'a pas besoin d'être envoyée par le serveur pendant la poignée de main TLS : elle doit déjà se trouver chez le client.

### 5.2 Dans un navigateur

L'onglet « Général » du lecteur affiche les informations suivantes, que je compare à celles obtenues avec OpenSSL :

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

Les informations sont identiques. Les heures diffèrent de deux heures, car Chrome les affiche dans le fuseau horaire local (heure d'été de Paris, UTC+2), alors qu'OpenSSL les affiche en temps universel (GMT). La ligne « Unité d'organisation (OU) : &lt;Ne fait pas partie du certificat&gt; » correspond à l'absence d'attribut `OU` dans le sujet et l'émetteur, que l'on avait déjà constatée à la question 13.

Les empreintes SHA-256 permettent de prouver qu'il s'agit **exactement du même certificat**, et pas seulement d'un certificat portant les mêmes noms. Je les ai recalculées avec OpenSSL à partir du fichier `cert0.pem` :

```console
[etudiant@tls-ca-palancac ~]$ openssl x509 -in cert0.pem -noout -fingerprint -sha256
sha256 Fingerprint=57:16:AD:84:D1:BF:FD:A3:0B:99:09:89:95:D1:A0:64:AC:19:AD:AB:FD:C1:9A:DD:30:E5:B3:61:2A:C7:E3:42
[etudiant@tls-ca-palancac ~]$ openssl x509 -in cert0.pem -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256
SHA2-256(stdin)= a0a4174f66ef9de3660a18ff161b8aec805ff374b88789bf0b8f4cf8f2feea57
```

- **L'empreinte du certificat** est le haché SHA-256 du certificat complet, encodé en DER. Changer un seul bit du certificat (une date, un nom, la signature…) changerait totalement cette valeur. Les deux empreintes sont identiques : Chrome et OpenSSL ont reçu le même certificat.
- **L'empreinte de la clé publique** est le haché du seul bloc `Subject Public Key Info`. Elle reste identique si le certificat est renouvelé avec la même clé. C'est pourquoi elle sert notamment à « épingler » une clé (_public key pinning_).

Le navigateur et OpenSSL donnent donc la même vision du certificat. Le navigateur est plus pratique pour une vérification rapide, alors qu'OpenSSL permet d'extraire les certificats, de les manipuler et d'automatiser les vérifications.

## 6. Mise en place d'une PKI

## 7. Mise en place d'un reverse proxy

## 8. Développement d'un client Web

---

## Conclusion
