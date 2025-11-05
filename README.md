# anonYmyMD.py — Chiffrement récursif AES-GCM des fichiers et répertoires

**anonYmyMD** est un utilitaire Python conçu pour chiffrer et déchiffrer récursivement des fichiers ainsi que, de manière optionnelle, les **noms de fichiers et de répertoires**.
Le script repose sur l’algorithme **AES-GCM**, garantissant la **confidentialité** et l’**intégrité** des données, tout en assurant une écriture atomique et des sauvegardes facultatives.

Ce projet est compatible avec **Windows**, **Linux** et **macOS**.

---

## Fonctionnalités principales

* **Chiffrement AES-GCM (authentifié)** avec nonce unique par élément.
* **Détection automatique** des fichiers à traiter selon leur extension.
* **Écriture atomique** et création optionnelle de fichiers de sauvegarde `.bak`.
* **Renommage chiffré/déchiffré** des fichiers et répertoires (Base64 URL-safe sans padding).
* **Mode simulation (`--dry-run`)** sans modification réelle du disque.
* **Journalisation détaillée** (`--verbose`) pour le suivi des opérations.
* **Exclusion automatique** de répertoires techniques (`.venv`, `.git`, `node_modules`, `__pycache__`).

---

## Pré-requis techniques

* **Python 3.9+**
* **pip** (installé avec Python)
* **PyCryptodome** pour le chiffrement AES

---

## Installation et initialisation de l’environnement virtuel

Il est **fortement recommandé** d’exécuter anonYmyMD dans un environnement virtuel afin d’isoler les dépendances.

### Étapes d’installation

1. **Cloner ou copier le projet :**

   ```bash
   git clone https://github.com/<ton-utilisateur>/anonYmyMD.git
   cd anonYmyMD
   ```

2. **Créer un environnement virtuel :**

   ```bash
   python -m venv .venv
   ```

3. **Activer l’environnement virtuel :**

   * **Windows (PowerShell)**

     ```powershell
     .venv\Scripts\Activate.ps1
     ```
   * **macOS / Linux**

     ```bash
     source .venv/bin/activate
     ```

4. **Installer les dépendances :**

   ```bash
   pip install -r requirements.txt
   ```

---

## Configuration de la clé de chiffrement

anonYmyMD lit la clé AES à partir de la variable d’environnement **`AES_KEY_HEX`**.
Si elle n’est pas définie, une clé de démonstration est utilisée (non sécurisée).

* La clé doit être une chaîne hexadécimale de **16**, **24** ou **32 octets** (128, 192 ou 256 bits).
* Pour une sécurité maximale, privilégiez **AES-256** (64 caractères hexadécimaux).

### Définition de la clé

**Windows PowerShell**

```powershell
$env:AES_KEY_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

**Windows cmd**

```cmd
set AES_KEY_HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

**macOS / Linux**

```bash
export AES_KEY_HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

---

## Utilisation

### Syntaxe générale

```bash
python anonYmyMD.py encrypt <chemin_du_dossier> [options]
python anonYmyMD.py decrypt <chemin_du_dossier> [options]
```

### Options disponibles

| Option                      | Description                                                                   |
| :-------------------------- | :---------------------------------------------------------------------------- |
| `--ext .md .png .jpg .jpeg` | Extensions ciblées (par défaut : `.md`, `.png`, `.jpg`, `.jpeg`)              |
| `--names` (directory only !)| Active le chiffrement ou le déchiffrement des noms de fichiers et répertoires |
| `--backup`                  | Crée un fichier `.bak` avant d’écraser un contenu                             |
| `--dry-run`                 | Simulation sans écriture sur le disque                                        |
| `--verbose`                 | Active un mode de journalisation détaillée                                    |

---

### Exemples

Chiffrer un dossier complet avec contenu et noms :

```bash
python anonYmyMD.py encrypt ./Documents --names --verbose
```

Déchiffrer proprement (ordre inverse : noms puis contenu) :

```bash
python anonYmyMD.py decrypt ./Documents --names --verbose
```

Simulation sans modification :

```bash
python anonYmyMD.py encrypt ./vault --names --dry-run
```

Sauvegarde automatique avant écrasement :

```bash
python anonYmyMD.py decrypt ./images --backup
```

---

## Notes techniques

### Format des fichiers chiffrés

Chaque fichier suit la structure :

```
MAGIC "AGM1" | nonce(12 octets aléatoires) | tag(16 octets) | ciphertext
```

Le **nonce** est aléatoire et unique par fichier.
Le **tag** garantit l’authenticité et l’intégrité du contenu.

### Ordre des opérations

* **Chiffrement** : contenu → noms
* **Déchiffrement** : **noms → contenu**

Cet ordre est obligatoire pour éviter la perte d’extensions et garantir un déchiffrement correct.

### Compatibilité Windows

* Les chemins très longs peuvent nécessiter l’activation du paramètre `LongPathsEnabled`.
* Les noms encodés en Base64 URL-safe sont compatibles avec NTFS (aucun caractère interdit).
* Certains antivirus peuvent bloquer temporairement les opérations d’écriture atomique (`os.replace`).

---

## Sécurité

* Utilisez une **clé unique par projet ou client**.
* Sauvegardez vos clés dans un gestionnaire de secrets sécurisé.
* En cas de perte de la clé, le déchiffrement est impossible.
* Le mode AES-GCM assure la **confidentialité** et **l’intégrité** des données.

---