
import os
import json
import uuid
import base64
import hashlib
import logging

from pathlib import Path
from io import BytesIO
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse


# ==================================================
# CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent

INPUT_DIR = BASE_DIR / "uploads"
BLOCKS_DIR = BASE_DIR / "blocks"
MANIFEST_DIR = BASE_DIR / "manifests"
KEY_FILE = BASE_DIR / "encryption.key"

for directory in (INPUT_DIR, BLOCKS_DIR, MANIFEST_DIR):
    directory.mkdir(parents=True, exist_ok=True)

BUCKET_NAME = "secure-cloud-storage-p2-2026"
AWS_REGION = "ap-south-1"

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
BLOCK_COUNT = 4

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==================================================
# FASTAPI APPLICATION
# Define app BEFORE configuring middleware.
# ==================================================

app = FastAPI(
    title="Secure Cloud File Storage API",
    version="1.3.0",
    description="Secure file storage using AES-256-GCM and Amazon S3",
)


# ==================================================
# CORS CONFIGURATION
# ==================================================

FRONTEND_ORIGINS = [
    "https://d2fqq2prjertec.cloudfront.net",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5501",
    "http://127.0.0.1:5501",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ==================================================
# AWS S3 CLIENT
# Credentials are read from the environment or
# the configured AWS credentials provider.
# ==================================================

s3 = boto3.client(
    "s3",
    region_name=AWS_REGION,
)


# ==================================================
# ENCRYPTION KEY
# IMPORTANT:
# Keep the same key to decrypt previously stored files.
# Configure ENCRYPTION_KEY_B64 in Render.
# ==================================================

def get_encryption_key():
    encoded_key = os.environ.get("ENCRYPTION_KEY_B64")

    if encoded_key:
        try:
            key = base64.b64decode(
                encoded_key,
                validate=True,
            )
        except Exception as exc:
            raise RuntimeError(
                "ENCRYPTION_KEY_B64 must be valid Base64."
            ) from exc

        if len(key) != 32:
            raise RuntimeError(
                "The encryption key must be exactly 32 bytes."
            )

        return key

    # Local development fallback: use the existing key.
    if KEY_FILE.exists():
        key = KEY_FILE.read_bytes()

        if len(key) != 32:
            raise RuntimeError(
                "encryption.key must contain exactly 32 bytes."
            )

        return key

    # Do not silently generate a replacement key.
    raise RuntimeError(
        "Encryption key is missing. Configure ENCRYPTION_KEY_B64 "
        "in Render or restore the original encryption.key file."
    )


# ==================================================
# HELPER FUNCTIONS
# ==================================================

def is_valid_file_id(file_id: str) -> bool:
    try:
        return str(uuid.UUID(file_id)) == file_id
    except (ValueError, TypeError, AttributeError):
        return False


def get_s3_json(key: str):
    response = s3.get_object(
        Bucket=BUCKET_NAME,
        Key=key,
    )

    return json.loads(
        response["Body"].read().decode("utf-8")
    )


def save_manifest(file_id: str, manifest: dict):
    manifest_path = MANIFEST_DIR / f"{file_id}.json"

    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=f"metadata/{file_id}.json",
        Body=json.dumps(manifest).encode("utf-8"),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )


def load_manifest(file_id: str):
    try:
        return get_s3_json(
            f"metadata/{file_id}.json"
        )

    except ClientError as exc:
        code = exc.response.get(
            "Error", {}
        ).get("Code", "")

        if code in ("NoSuchKey", "404", "NotFound"):
            raise HTTPException(
                status_code=404,
                detail="File not found in cloud storage.",
            ) from exc

        logger.exception("Could not retrieve file metadata")

        raise HTTPException(
            status_code=502,
            detail="Could not retrieve file metadata from S3.",
        ) from exc


# ==================================================
# HOME AND HEALTH CHECK
# ==================================================

@app.get("/")
def root():
    return {
        "message": "Secure Cloud File Storage API is running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "Secure Cloud File Storage API",
        "storage": "Amazon S3",
        "region": AWS_REGION,
    }


# ==================================================
# UPLOAD, SPLIT, ENCRYPT AND STORE
# ==================================================

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    original_name = Path(
        file.filename or "uploaded_file"
    ).name

    if original_name in ("", ".", ".."):
        raise HTTPException(
            status_code=400,
            detail="A valid filename is required.",
        )

    data = await file.read(MAX_FILE_SIZE + 1)

    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="Maximum file size is 25 MB.",
        )

    if not data:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file is empty.",
        )

    file_id = str(uuid.uuid4())

    try:
        key = get_encryption_key()
        aes = AESGCM(key)

        # Split the original data into up to four blocks.
        number_of_blocks = min(
            BLOCK_COUNT,
            len(data),
        )

        block_size = (
            len(data) + number_of_blocks - 1
        ) // number_of_blocks

        block_entries = []

        for index, start in enumerate(
            range(0, len(data), block_size)
        ):
            plaintext = data[start:start + block_size]
            nonce = os.urandom(12)

            # AES-GCM encrypts and authenticates each block.
            encrypted = aes.encrypt(
                nonce,
                plaintext,
                None,
            )

            s3_key = (
                f"encrypted_blocks/{file_id}/"
                f"block_{index}.bin"
            )

            # Upload encrypted data to S3.
            s3.put_object(
                Bucket=BUCKET_NAME,
                Key=s3_key,
                Body=encrypted,
                ContentType="application/octet-stream",
                ServerSideEncryption="AES256",
                Metadata={
                    "file-id": file_id,
                    "block-index": str(index),
                },
            )

            # Record the information needed to decrypt the block.
            block_entries.append({
                "index": index,
                "s3_key": s3_key,
                "nonce": nonce.hex(),
                "size": len(plaintext),
                "sha256": hashlib.sha256(
                    plaintext
                ).hexdigest(),
            })

        manifest = {
            "file_id": file_id,
            "filename": original_name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "created_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "encryption": "AES-256-GCM",
            "block_count": len(block_entries),
            "blocks": block_entries,
        }

        # Save file metadata in S3.
        save_manifest(file_id, manifest)

        # Save local copies for development only.
        local_original = (
            INPUT_DIR / f"{file_id}_{original_name}"
        )
        local_original.write_bytes(data)

        for entry in block_entries:
            response = s3.get_object(
                Bucket=BUCKET_NAME,
                Key=entry["s3_key"],
            )

            encrypted_block = response["Body"].read()

            local_block = (
                BLOCKS_DIR
                / file_id
                / f"block_{entry['index']}.bin"
            )

            local_block.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            local_block.write_bytes(encrypted_block)

        return {
            "message": "File encrypted and uploaded successfully.",
            "file_id": file_id,
            "filename": original_name,
            "size": len(data),
            "block_count": len(block_entries),
            "encryption": "AES-256-GCM",
        }

    except HTTPException:
        raise

    except Exception as exc:
        logger.exception(
            "Upload failed for file_id=%s",
            file_id,
        )

        raise HTTPException(
            status_code=500,
            detail="Upload failed. Check the backend logs.",
        ) from exc

    finally:
        await file.close()


# ==================================================
# LIST STORED FILES
# ==================================================

@app.get("/files")
def list_files():
    files = []

    try:
        paginator = s3.get_paginator(
            "list_objects_v2"
        )

        for page in paginator.paginate(
            Bucket=BUCKET_NAME,
            Prefix="metadata/",
        ):
            for item in page.get("Contents", []):
                object_key = item["Key"]
                filename = object_key.rsplit(
                    "/", 1
                )[-1]

                if not filename.endswith(".json"):
                    continue

                file_id = filename[:-5]

                if not is_valid_file_id(file_id):
                    continue

                try:
                    manifest = get_s3_json(object_key)

                    files.append({
                        "file_id": file_id,
                        "filename": manifest.get(
                            "filename", "download"
                        ),
                        "size": manifest.get("size", 0),
                        "last_modified": item[
                            "LastModified"
                        ].isoformat(),
                        "encryption": manifest.get(
                            "encryption", "AES-256-GCM"
                        ),
                    })

                except Exception:
                    logger.exception(
                        "Could not read metadata: %s",
                        object_key,
                    )

        files.sort(
            key=lambda item: item["last_modified"],
            reverse=True,
        )

        return {
            "count": len(files),
            "files": files,
        }

    except ClientError as exc:
        logger.exception("S3 file listing failed")

        raise HTTPException(
            status_code=502,
            detail="Could not list files from S3.",
        ) from exc


# ==================================================
# DOWNLOAD, DECRYPT AND VERIFY
# ==================================================

@app.get("/download/{file_id}")
def download_file(file_id: str):
    if not is_valid_file_id(file_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid file ID.",
        )

    manifest = load_manifest(file_id)

    if manifest.get("file_id") != file_id:
        raise HTTPException(
            status_code=422,
            detail="File metadata does not match the requested ID.",
        )

    try:
        aes = AESGCM(get_encryption_key())
        plaintext_blocks = []

        blocks = sorted(
            manifest.get("blocks", []),
            key=lambda block: block["index"],
        )

        if not blocks or len(blocks) > BLOCK_COUNT:
            raise HTTPException(
                status_code=422,
                detail="Invalid block information in file metadata.",
            )

        for block in blocks:
            s3_key = block.get("s3_key", "")
            expected_prefix = (
                f"encrypted_blocks/{file_id}/"
            )

            if not s3_key.startswith(expected_prefix):
                raise HTTPException(
                    status_code=422,
                    detail="Invalid block storage path.",
                )

            response = s3.get_object(
                Bucket=BUCKET_NAME,
                Key=s3_key,
            )

            encrypted = response["Body"].read()
            nonce = bytes.fromhex(block["nonce"])

            if len(nonce) != 12:
                raise HTTPException(
                    status_code=422,
                    detail="Invalid encryption nonce.",
                )

            # Decrypt and authenticate the block.
            plaintext = aes.decrypt(
                nonce,
                encrypted,
                None,
            )

            actual_hash = hashlib.sha256(
                plaintext
            ).hexdigest()

            if actual_hash != block.get("sha256"):
                raise HTTPException(
                    status_code=422,
                    detail="File block integrity check failed.",
                )

            if len(plaintext) != block.get("size"):
                raise HTTPException(
                    status_code=422,
                    detail="File block size verification failed.",
                )

            plaintext_blocks.append(plaintext)

        # Reconstruct the original file in block order.
        original_data = b"".join(plaintext_blocks)

        if len(original_data) != manifest.get("size"):
            raise HTTPException(
                status_code=422,
                detail="Reconstructed file size does not match.",
            )

        overall_hash = manifest.get("sha256")

        if overall_hash:
            actual_hash = hashlib.sha256(
                original_data
            ).hexdigest()

            if actual_hash != overall_hash:
                raise HTTPException(
                    status_code=422,
                    detail="Complete file integrity check failed.",
                )

        filename = Path(
            manifest.get("filename", "download")
        ).name

        return StreamingResponse(
            BytesIO(original_data),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition":
                    f'attachment; filename="{filename}"',
                "Content-Length": str(len(original_data)),
                "Cache-Control": "no-store",
            },
        )

    except HTTPException:
        raise

    except InvalidTag as exc:
        logger.exception(
            "AES-GCM authentication failed for %s",
            file_id,
        )

        raise HTTPException(
            status_code=422,
            detail=(
                "Decryption failed. The encryption key or "
                "encrypted data may not match."
            ),
        ) from exc

    except ClientError as exc:
        logger.exception(
            "S3 download failed for %s",
            file_id,
        )

        raise HTTPException(
            status_code=502,
            detail="Could not retrieve the encrypted file from S3.",
        ) from exc

    except Exception as exc:
        logger.exception(
            "Download or decryption failed for %s",
            file_id,
        )

        raise HTTPException(
            status_code=500,
            detail="Download failed. Check the backend logs.",
        ) from exc
