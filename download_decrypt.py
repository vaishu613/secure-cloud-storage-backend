
from pathlib import Path
import json
import base64
import hashlib

import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BUCKET_NAME = "secure-cloud-storage-p2-2026"
REGION = "ap-south-1"

KEY_FILE = Path("encryption.key")
DOWNLOAD_DIR = Path("downloaded_blocks")
OUTPUT_DIR = Path("output")
MANIFEST_PATH = DOWNLOAD_DIR / "block_manifest.json"


def main():
    if not KEY_FILE.is_file():
        raise FileNotFoundError(
            "encryption.key is missing. You need the original key to decrypt."
        )

    key = KEY_FILE.read_bytes()
    if len(key) != 32:
        raise ValueError("Invalid AES-256 key: expected 32 bytes.")

    DOWNLOAD_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)

    s3 = boto3.client("s3", region_name=REGION)

    # Download manifest from S3
    s3.download_file(
        BUCKET_NAME,
        "metadata/block_manifest.json",
        str(MANIFEST_PATH)
    )

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if len(manifest) != 4:
        raise ValueError("Expected exactly 4 blocks in the manifest.")

    aesgcm = AESGCM(key)
    decrypted_blocks = []

    for item in sorted(
        manifest,
        key=lambda entry: int(entry["block"].split("_")[1])
    ):
        encrypted_name = item["encrypted_file"]
        local_encrypted = DOWNLOAD_DIR / encrypted_name

        # Download encrypted block from S3
        s3.download_file(
            BUCKET_NAME,
            f"encrypted_blocks/{encrypted_name}",
            str(local_encrypted)
        )

        nonce = base64.b64decode(item["nonce"], validate=True)
        ciphertext = local_encrypted.read_bytes()

        # AES-GCM verifies authenticity while decrypting
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        # Verify the decrypted block matches the manifest
        digest = hashlib.sha256(plaintext).hexdigest()
        if digest != item["sha256_plaintext"]:
            raise ValueError(f"Checksum mismatch: {encrypted_name}")

        decrypted_blocks.append(plaintext)
        print(f"Downloaded, decrypted and verified: {encrypted_name}")

    # Reconstruct the PDF in the original block order
    output_path = OUTPUT_DIR / "recovered_file.pdf"
    with output_path.open("wb") as output_file:
        for block in decrypted_blocks:
            output_file.write(block)

    print("\nSUCCESS: Reconstructed PDF.")
    print(f"Output: {output_path.resolve()}")
    print(f"Recovered size: {output_path.stat().st_size} bytes")


if __name__ == "__main__":
    main()
