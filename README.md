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
2. Calculer le module $n = p \times q$ et l'indicatrice d'Euler $\varphi(n) = (p-1)(q-1)$
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
| **Clé publique du sujet**                         | Algorithme (RSA, ECDSA…), taille et valeur de la clé                                          | Sert à vérifier les signatures du serveur ou à échanger la clé de session |
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

## 5. Analyse du contenu d'un certificat

## 6. Mise en place d'une PKI

## 7. Mise en place d'un reverse proxy

## 8. Développement d'un client Web

---

## Conclusion
