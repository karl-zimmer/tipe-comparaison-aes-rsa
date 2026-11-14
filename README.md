# Comparaison de la cryptographie symétrique (AES) et asymétrique (RSA)

TIPE, CPGE MPI (2024-2025). C, OpenSSL

## Objectif

Comparer les temps de chiffrement et de déchiffrement d'AES-128 (symétrique) et de RSA-2048 (asymétrique), ainsi que leur utilisation du processeur et leur consommation électrique, et en déduire l'intérêt d'un chiffrement hybride.

## Contenu du dépôt

| Fichier | Rôle |
|---|---|
| `TIPE_AES.c` | Chiffrement et déchiffrement AES-128 en mode CBC, avec mesure des temps |
| `TIPE_RSA.c` | Génération d'une clé RSA-2048, chiffrement et déchiffrement RSA-OAEP par blocs, avec mesure des temps |

## Méthode

- **Données de test** : chaîne de caractères aléatoires générée avec `RAND_bytes` (taille commune)
- **AES** : AES-128 en mode CBC, vecteur d'initialisation (IV) aléatoire. La clé est une clé de test fixe dans le code, à ne jamais réutiliser.
- **RSA** : clé de 2048 bits générée à chaque exécution, padding OAEP. Le message est découpé en blocs de 214 octets (taille maximale en OAEP avec une clé de 2048 bits), soit 234 blocs pour 50 000 caractères.
- **Mesure du temps** : temps réel avec `clock_gettime(CLOCK_MONOTONIC)` pour la génération de clé (RSA), le chiffrement, le déchiffrement et le total.
- **Utilisation du processeur** : taux d'utilisation du CPU (en %) relevé avec le logiciel de monitoring HWMonitor pendant l'exécution, en dehors du code.
- **Consommation électrique** : relevé du courant au niveau de la prise d'alimentation de la machine pendant l'exécution, en dehors du code.
- **Vérification** : chaque programme compare le texte déchiffré au message d'origine et affiche « Déchiffrement correct ».

## Ouverture

Chiffrement hybride : RSA pour échanger une clé de session, AES pour chiffrer les données. Cette approche n'est pas implémentée dans ces fichiers.

## Limites

- Les résultats dépendent de la machine (notamment des instructions matérielles dédiées à AES, que RSA n'exploite pas de la même façon).
- Chiffrement et déchiffrement RSA ont des coûts différents (clé publique contre clé privée) : un rapport avec AES doit être donné par opération.
- Chaque programme effectue une seule mesure par exécution.
- Le taux d'utilisation du CPU (en %) dépend du logiciel de monitoring.
- La mesure à la prise inclut la consommation de toute la machine, pas seulement celle du processeur, et sa précision dépend de l'appareil utilisé.
- AES en mode CBC sans authentification : adapté à la mesure de performance, pas à un usage réel
- La clé AES est fixe dans le code : elle n'a qu'un usage de test.

## Compilation et exécution

Prérequis : un compilateur C et les en-têtes d'OpenSSL (`sudo apt install build-essential libssl-dev` sous Debian/Ubuntu ; sous Windows, passer par WSL).

```bash
gcc -O2 -Wall -o aes_bench TIPE_AES.c -lcrypto
gcc -O2 -Wall -o rsa_bench TIPE_RSA.c -lcrypto
./aes_bench
./rsa_bench
```
