#!/usr/bin/env python3
"""Client HTTPS de test : vérifie que l'authentification du serveur est complète.

Usage : python3 client_tls.py          (tous les tests)
        python3 client_tls.py T1 T5    (tests choisis)
"""
import socket
import ssl
import sys

IP = "192.168.170.119"      # adresse de tls-serv-palancac
NOM = "www.palancac.fr"     # nom attendu dans le SAN du certificat

# (id, objectif, port, nom demandé, contexte TLS, connexion attendue ?)
TESTS = [
    ("T1", "Cas nominal : chaîne et nom valides",          443,  NOM,           "systeme",      True),
    ("T2", "CA racine inconnue (magasin vide)",            443,  NOM,           "vide",         False),
    ("T3", "Chaîne incomplète (intermédiaire non envoyé)", 8443, NOM,           "systeme",      False),
    ("T4", "Nom demandé absent du SAN",                    443,  "palancac.fr", "systeme",      False),
    ("T5", "Certificat auto-signé (imposteur)",            8444, NOM,           "systeme",      False),
    ("T6", "Certificat expiré",                            8445, NOM,           "systeme",      False),
    ("T7", "Certificat non prévu pour un serveur",         8446, NOM,           "systeme",      False),
    ("T8", "Client qui ne vérifie rien, face à T5",        8444, NOM,           "aucune_verif", True),
]


def contexte(mode):
    """Construit le contexte TLS du client."""
    if mode == "systeme":
        # Magasin de confiance du système (contient Root Lorne), vérification
        # de la chaîne et du nom activées, comme dans un vrai client.
        return ssl.create_default_context()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # vérifications actives, aucune CA chargée
    if mode == "aucune_verif":
        # Client mal écrit : désactive les deux vérifications.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def cn(champ):
    """Extrait le CN d'un sujet ou d'un émetteur renvoyé par getpeercert()."""
    for rdn in champ:
        for cle, valeur in rdn:
            if cle == "commonName":
                return valeur
    return "?"


def requete(port, nom, mode):
    """Ouvre la connexion TLS, envoie un GET / et renvoie les informations de session."""
    ctx = contexte(mode)
    with socket.create_connection((IP, port), timeout=5) as sock:
        # server_hostname sert à la fois pour le SNI et pour la vérification du nom.
        with ctx.wrap_socket(sock, server_hostname=nom) as tls:
            tls.sendall(f"GET / HTTP/1.1\r\nHost: {nom}\r\nConnection: close\r\n\r\n".encode())
            reponse = b""
            try:
                while bloc := tls.recv(4096):
                    reponse += bloc
            except (ssl.SSLEOFError, ConnectionResetError):
                pass  # openssl s_server ferme la connexion sans close_notify
            cert = tls.getpeercert()
            info = f"{tls.version()} {tls.cipher()[0]}"
            if cert:
                san = ", ".join(v for _, v in cert.get("subjectAltName", ()))
                info += f" | sujet CN={cn(cert['subject'])} | émetteur CN={cn(cert['issuer'])} | SAN {san}"
            else:
                info += " | certificat reçu mais non vérifié"
            premiere_ligne = reponse.split(b"\r\n", 1)[0].decode(errors="replace")
            return info, premiere_ligne


def main():
    choix = [t.upper() for t in sys.argv[1:]]
    conformes = total = 0
    for tid, objectif, port, nom, mode, attendu in TESTS:
        if choix and tid not in choix:
            continue
        total += 1
        print(f"[{tid}] {objectif}  ({nom} -> {IP}:{port}, contexte {mode})")
        try:
            info, ligne = requete(port, nom, mode)
            obtenu, detail = True, f"{info}\n     réponse : {ligne}"
        except ssl.SSLCertVerificationError as e:
            obtenu, detail = False, f"refus : {e.verify_message} (code {e.verify_code})"
        except (OSError, ssl.SSLError) as e:
            print(f"     ERREUR inattendue : {type(e).__name__}: {e}\n")
            continue
        ok = obtenu == attendu
        conformes += ok
        txt = {True: "acceptée", False: "refusée"}
        print(f"     attendu : {txt[attendu]} | obtenu : {txt[obtenu]} -> {'CONFORME' if ok else 'NON CONFORME'}")
        print(f"     {detail}\n")
    print(f"Bilan : {conformes}/{total} tests conformes")


if __name__ == "__main__":
    main()
