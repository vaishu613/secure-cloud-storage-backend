
from pathlib import Path
import json
import os
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BLOCKS_DIR = Path("encrypted_blocks")
KEY_FILE = Path("encryption.key")
MANIFEST_FILE = Path("block_manifest.json")

def encrypt_blocks():
    # Stop if the blocks have not been created
    block_files = sorted(
        BLOCKS_DIR.glob("block_*.bin"),
        key=lambda path: int(path.stem.split("_")[1])
    )

    if len(block_files) != 4:
        raise ValueError(
            f"Expected 4 blocks, found {len(block_files)}. "
            "Run split_file.py first."
        )

    # Generate a 256-bit key if one doesn't exist yet
    if KEY_FILE.exists():
        key = KEY_FILE.read_bytes()
        if len(key) != 32:
            raise ValueError("encryption.key must contain a 32-byte key.")
        print("Using existing encryption key.")
    else:
        key = AESGCM.generate_key(bit_length=256)
        KEY_FILE.write_bytes(key)
        print("Generated encryption.key.")

    aesgcm = AESGCM(key)
    manifest = []

    for block_path in block_files:
        plaintext = block_path.read_bytes()

        # A fresh, random 96-bit nonce for each block
        nonce = os.urandom(12)

        # Encrypt and authenticate the block
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        encrypted_path = BLOCKS_DIR / f"{block_path.stem}.enc"
        encrypted_path.write_bytes(ciphertext)

        manifest.append({
            "block": block_path.stem,
            "encrypted_file": encrypted_path.name,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "sha256_plaintext": hashlib.sha256(plaintext).hexdigest(),
            "size_bytes": len(plaintext)
        })

        print(f"Encrypted {block_path.name} -> {encrypted_path.name}")

    MANIFEST_FILE.write_text(
        json.dumps(manifest, indent=4),
        encoding="utf-8"
    )

    print("\nEncryption complete. Total blocks encrypted:", len(manifest))
    print("Keep encryption.key private and backed up securely.")

if __name__ == "__main__":
    encrypt_blocks()
