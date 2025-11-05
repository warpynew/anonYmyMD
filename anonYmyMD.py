#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Chiffrement/déchiffrement récursif de fichiers et, optionnellement, de NOMS de fichiers/répertoires.
- AES-GCM (authentifié) avec nonce aléatoire par élément.
- Écriture atomique, logs propres, filtrage d'extensions, répertoires ignorés.
- Renommage "sûr" avec Base64 urlsafe + préfixe __enc__ pour détecter les noms chiffrés.

Usage:
    python anonYmyMD.py encrypt /chemin/du/dossier --names
    python anonYmyMD.py decrypt /chemin/du/dossier --names
Options:
    --ext .md .png .jpg .jpeg    # extensions ciblées (par défaut: .md .png .jpg .jpeg)
    --dry-run                    # n'écrit rien, montre ce qui serait fait
    --backup                     # crée un .bak avant d'écraser (contenu)
    --names                      # active le chiffrement/déchiffrement des NOMS
    --verbose                    # logs détaillés
Clé:
    - Par défaut, une clé de démo est utilisée (à CHANGER).
    - Recommandé: export AES_KEY_HEX="<64 hex chars>" (clé 256-bit)
"""

from __future__ import annotations
import argparse
import base64
import binascii
import logging
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterable

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# =========================
# Configuration & constantes
# =========================

MAGIC = b"AGM1"       # Entête pour formats de fichier: b"AGM1" + nonce(12) + tag(16) + ciphertext
NAME_PREFIX = "__enc__"  # Préfixe pour marquer les noms chiffrés
NONCE_SIZE = 12
TAG_SIZE = 16

DEFAULT_IGNORE_DIRS = {".venv", ".git", "node_modules", "__pycache__"}

DEFAULT_EXTS = {".md", ".png", ".jpg", ".jpeg", ".canvas", ".base"}

# Clé par défaut (DEMO). Remplace par AES_KEY_HEX env var (64 hex chars) ou modifie ci-dessous.
DEFAULT_KEY = b"change_me_use_env_var_for_real_32_bytes!!"[:32]  # 32 bytes (AES-256)


def load_key() -> bytes:
    """Charge la clé depuis AES_KEY_HEX si dispo, sinon DEFAULT_KEY."""
    env_hex = os.environ.get("AES_KEY_HEX")
    if env_hex:
        try:
            key = binascii.unhexlify(env_hex)
            if len(key) not in (16, 24, 32):
                raise ValueError("Mauvaise taille de clé (attendu 16/24/32 bytes).")
            return key
        except Exception as e:
            logging.warning("AES_KEY_HEX invalide (%s). Utilisation de la clé par défaut NON SÉCURISÉE.", e)
    # Fallback de démo
    if len(DEFAULT_KEY) not in (16, 24, 32):
        raise ValueError("DEFAULT_KEY doit faire 16/24/32 octets.")
    return DEFAULT_KEY


# =========================
# Utilitaires encodage noms
# =========================

def b64u_encode(b: bytes) -> str:
    """Base64 urlsafe sans padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    """Decode Base64 urlsafe en restaurant le padding."""
    s_bytes = s.encode("ascii")
    pad_len = (-len(s_bytes)) % 4
    s_bytes += b"=" * pad_len
    return base64.urlsafe_b64decode(s_bytes)


# =========================
# Crypto AES-GCM contenu
# =========================

def encrypt_bytes(key: bytes, plaintext: bytes) -> bytes:
    """Retourne: MAGIC | nonce(12) | tag(16) | ciphertext"""
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return MAGIC + nonce + tag + ciphertext


def decrypt_bytes(key: bytes, blob: bytes) -> bytes:
    """Attend: MAGIC | nonce | tag | ciphertext. Lève ValueError en cas d'échec."""
    if not blob.startswith(MAGIC):
        raise ValueError("Format non reconnu (MAGIC manquant).")
    blob = blob[len(MAGIC):]
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Blob trop court.")
    nonce = blob[:NONCE_SIZE]
    tag = blob[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = blob[NONCE_SIZE + TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# =========================
# Crypto AES-GCM noms
# =========================

def encrypt_name(key: bytes, name: str) -> str:
    raw = name.encode("utf-8", errors="surrogatepass")
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(raw)
    token = b64u_encode(nonce + tag + ct)
    return NAME_PREFIX + token


def is_encrypted_name(name: str) -> bool:
    return name.startswith(NAME_PREFIX)


def decrypt_name(key: bytes, enc_name: str) -> str:
    if not is_encrypted_name(enc_name):
        raise ValueError("Nom non chiffré.")
    token = enc_name[len(NAME_PREFIX):]
    data = b64u_decode(token)
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Token de nom invalide.")
    nonce = data[:NONCE_SIZE]
    tag = data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ct = data[NONCE_SIZE + TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plain = cipher.decrypt_and_verify(ct, tag)
    return plain.decode("utf-8", errors="surrogatepass")


# =========================
# Fichiers: écriture atomique
# =========================

def atomic_write(path: Path, data: bytes) -> None:
    """Écriture atomique dans le même répertoire."""
    with NamedTemporaryFile(dir=str(path.parent), delete=False) as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        temp_name = tmp.name
    os.replace(temp_name, path)


# =========================
# Parcours et traitement
# =========================

def iter_targets(root: Path, exts: Iterable[str]) -> Iterable[Path]:
    exts = {e.lower() for e in exts}
    for p in root.rglob("*"):
        # Ignore certains répertoires
        if any(part in DEFAULT_IGNORE_DIRS for part in p.parts):
            continue
        if p.is_file() and p.suffix.lower() in exts:
            yield p


def process_file_encrypt(key: bytes, path: Path, dry: bool, backup: bool) -> None:
    try:
        raw = path.read_bytes()
    except Exception as e:
        logging.warning("Lecture échouée: %s (%s)", path, e)
        return
    try:
        blob = encrypt_bytes(key, raw)
    except Exception as e:
        logging.error("Chiffrement échoué: %s (%s)", path, e)
        return
    logging.info("Encrypt: %s", path)
    if dry:
        return
    if backup:
        try:
            path.with_suffix(path.suffix + ".bak").write_bytes(raw)
        except Exception as e:
            logging.warning("Backup échoué: %s (%s)", path, e)
    try:
        atomic_write(path, blob)
    except Exception as e:
        logging.error("Écriture échouée: %s (%s)", path, e)


def process_file_decrypt(key: bytes, path: Path, dry: bool, backup: bool) -> None:
    try:
        blob = path.read_bytes()
    except Exception as e:
        logging.warning("Lecture échouée: %s (%s)", path, e)
        return
    try:
        plain = decrypt_bytes(key, blob)
    except Exception as e:
        logging.error("Déchiffrement échoué: %s (%s)", path, e)
        return
    logging.info("Decrypt: %s", path)
    if dry:
        return
    if backup:
        try:
            path.with_suffix(path.suffix + ".bak").write_bytes(blob)
        except Exception as e:
            logging.warning("Backup échoué: %s (%s)", path, e)
    try:
        atomic_write(path, plain)
    except Exception as e:
        logging.error("Écriture échouée: %s (%s)", path, e)


def process_names_encrypt(key: bytes, root: Path, dry: bool) -> None:
    # Post-ordre: renommer d'abord l'intérieur pour éviter de perdre la navigation
    for path in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if any(part in DEFAULT_IGNORE_DIRS for part in path.parts):
            continue
        try:
            new_name = encrypt_name(key, path.name)
        except Exception as e:
            logging.error("Chiffrement nom échoué: %s (%s)", path, e)
            continue
        new_path = path.with_name(new_name)
        if path == new_path:
            continue
        logging.info("Rename +: %s -> %s", path, new_path)
        if dry:
            continue
        try:
            path.rename(new_path)
        except Exception as e:
            logging.error("Rename échoué: %s -> %s (%s)", path, new_path, e)


def process_names_decrypt(key: bytes, root: Path, dry: bool) -> None:
    # Pré-ordre inverse: renommer du plus profond au plus haut
    for path in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if any(part in DEFAULT_IGNORE_DIRS for part in path.parts):
            continue
        if not is_encrypted_name(path.name):
            continue
        try:
            clear_name = decrypt_name(key, path.name)
        except Exception as e:
            logging.error("Déchiffrement nom échoué: %s (%s)", path, e)
            continue
        new_path = path.with_name(clear_name)
        if path == new_path:
            continue
        logging.info("Rename -: %s -> %s", path, new_path)
        if dry:
            continue
        try:
            path.rename(new_path)
        except Exception as e:
            logging.error("Rename échoué: %s -> %s (%s)", path, new_path, e)


# =========================
# CLI
# =========================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Chiffrement/déchiffrement récursif AES-GCM.")
    p.add_argument("action", choices={"encrypt", "decrypt"}, help="Action à effectuer.")
    p.add_argument("path", type=Path, help="Chemin racine du coffre/dossier.")
    p.add_argument("--ext", nargs="+", default=list(DEFAULT_EXTS), help="Extensions ciblées (avec point).")
    p.add_argument("--names", action="store_true", help="Chiffrer/Déchiffrer aussi les noms des fichiers/dossiers.")
    p.add_argument("--backup", action="store_true", help="Créer un .bak avant écrasement (contenu).")
    p.add_argument("--dry-run", action="store_true", help="Simulation, aucun changement écrit.")
    p.add_argument("--verbose", action="store_true", help="Logs détaillés.")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    root: Path = args.path
    if not root.exists():
        logging.error("Chemin inexistant: %s", root)
        raise SystemExit(1)

    key = load_key()
    exts = {e if e.startswith(".") else "." + e for e in args.ext}

    if not root.is_dir():
        #logging.error("Chemin n'est pas un répertoire: %s", root)
        #raise SystemExit(1)
        if args.action == "encrypt":
            if args.names:
                process_names_encrypt(load_key(), root.parent, args.dry_run)
                logging.error("Chemin n'est pas un répertoire l'argument --names n'est pas valable: %s", root)
                raise SystemExit(1)
            else:
                process_file_encrypt(load_key(), root, args.dry_run, args.backup)
                exit(0)
        else:
            if args.names:
                process_names_decrypt(load_key(), root.parent, args.dry_run)
                logging.error("Chemin n'est pas un répertoire l'argument --names n'est pas valable: %s", root)
                raise SystemExit(1)
            else:
                process_file_decrypt(load_key(), root, args.dry_run, args.backup)
                exit(0)

    logging.info("Racine: %s", root.resolve())
    logging.info("Extensions: %s", ", ".join(sorted(exts)))
    logging.info("Noms: %s | Dry-run: %s | Backup: %s", args.names, args.dry_run, args.backup)

    if args.action == "encrypt":
        # 1) chiffrer contenu, 2) chiffrer noms (optionnel)
        for f in iter_targets(root, exts):
            process_file_encrypt(key, f, args.dry_run, args.backup)
        if args.names:
            process_names_encrypt(key, root, args.dry_run)
    else:
        # 1) déchiffrer noms (optionnel), 2) déchiffrer contenu
        if args.names:
            process_names_decrypt(key, root, args.dry_run)
        for f in iter_targets(root, exts):
            process_file_decrypt(key, f, args.dry_run, args.backup)



if __name__ == "__main__":
    main()
