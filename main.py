import os
import json
import uuid
import base64
import hashlib
import logging
from pathlib import Path
from io import BytesIO
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from dotenv import load_dotenv
load_dotenv()

import boto3
from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

import database
from auth import auth_router, get_current_user

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

BUCKET_NAME = os.environ.get("BUCKET_NAME", "secure-cloud-storage-p2-2026")
AWS_REGION = os.environ.get("AWS_REGION", "ap-south-1")

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
BLOCK_COUNT = 4

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==================================================
# FASTAPI APPLICATION
# ==================================================

app = FastAPI(
    title="Secure Cloud File Storage API",
    version="2.0.0",
    description=(
        "Secure cloud file storage featuring email/password authentication, "
        "user-specific file isolation, AES-256-GCM block encryption, "
        "and strict ownership-based access control with private Amazon S3 storage."
    ),
)

# Include Authentication Router
app.include_router(auth_router)


# ==================================================
# CORS CONFIGURATION
# ==================================================

FRONTEND_ORIGINS = [
    "https://d2fqq2prjertec.cloudfront.net",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:5501",
    "http://127.0.0.1:5501",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# ==================================================
# AWS S3 CLIENT
# Uses boto3 with credentials from environment or AWS config.
# Direct public access to the bucket is prohibited.
# ==================================================

s3 = boto3.client(
    "s3",
    region_name=AWS_REGION,
)


# ==================================================
# ENCRYPTION KEY MANAGEMENT
# ==================================================

def get_encryption_key() -> bytes:
    """
    Retrieves the 32-byte AES-256 key.
    Prioritizes ENCRYPTION_KEY_B64 environment variable (for cloud hosting),
    then falls back to encryption.key on the local filesystem.
    """
    encoded_key = os.environ.get("ENCRYPTION_KEY_B64")

    if encoded_key:
        try:
            key = base64.b64decode(encoded_key, validate=True)
        except Exception as exc:
            raise RuntimeError("ENCRYPTION_KEY_B64 must be valid Base64.") from exc

        if len(key) != 32:
            raise RuntimeError("The encryption key must be exactly 32 bytes.")

        return key

    # Local development fallback: use existing key file
    if KEY_FILE.exists():
        key = KEY_FILE.read_bytes()
        if len(key) != 32:
            raise RuntimeError("encryption.key must contain exactly 32 bytes.")
        return key

    # Generate a new 256-bit key if none exists
    new_key = AESGCM.generate_key(bit_length=256)
    try:
        KEY_FILE.write_bytes(new_key)
        logger.info("Generated a new 32-byte AES-256 encryption key at %s", KEY_FILE)
        return new_key
    except Exception as exc:
        raise RuntimeError("Failed to generate or persist encryption key.") from exc


# ==================================================
# HELPER FUNCTIONS
# ==================================================

def is_valid_file_id(file_id: str) -> bool:
    try:
        return str(uuid.UUID(file_id)) == file_id
    except (ValueError, TypeError, AttributeError):
        return False


def get_s3_json(key: str) -> dict:
    response = s3.get_object(
        Bucket=BUCKET_NAME,
        Key=key,
    )
    return json.loads(response["Body"].read().decode("utf-8"))


def save_manifest(file_id: str, manifest: dict):
    # Save local development copy
    manifest_path = MANIFEST_DIR / f"{file_id}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # Upload manifest to private S3 bucket with server-side encryption
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=f"metadata/{file_id}.json",
        Body=json.dumps(manifest).encode("utf-8"),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )


def load_manifest(file_id: str) -> dict:
    try:
        return get_s3_json(f"metadata/{file_id}.json")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404", "NotFound"):
            raise HTTPException(
                status_code=404,
                detail="File not found in cloud storage.",
            ) from exc

        logger.exception("Could not retrieve file metadata from S3")
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
        "version": "2.0.0",
        "docs": "/docs",
        "web_ui": {
            "login": "/login",
            "signup": "/signup",
            "dashboard": "/dashboard"
        },
        "auth": {
            "signup": "/auth/signup",
            "login": "/auth/login",
            "me": "/auth/me"
        }
    }


STATIC_DIR = BASE_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/login")
def login_page():
    return RedirectResponse(url="/static/login.html")


@app.get("/signup")
def signup_page():
    return RedirectResponse(url="/static/signup.html")


@app.get("/dashboard")
def dashboard_page():
    return RedirectResponse(url="/static/dashboard.html")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "Secure Cloud File Storage API",
        "storage": "Amazon S3 (Private)",
        "region": AWS_REGION,
        "bucket": BUCKET_NAME,
        "encryption": "AES-256-GCM (Per-Block)",
        "access_control": "User-Specific / JWT"
    }


# ==================================================
# 1 & 2. UPLOAD, SPLIT, ENCRYPT, AND STORE WITH OWNER ID
# ==================================================

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    1. Authenticates logged-in user.
    2. Splits uploaded file into blocks.
    3. Encrypts each block individually using AES-256-GCM.
    4. Uploads blocks to private S3 with server-side encryption.
    5. Saves manifest containing owner_id, filename, and S3 object keys.
    6. Stores owner relationship in the database.
    """
    original_name = Path(file.filename or "uploaded_file").name
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
    owner_id = current_user["id"]
    owner_email = current_user["email"]

    try:
        key = get_encryption_key()
        aes = AESGCM(key)

        # Split data into up to 4 blocks
        number_of_blocks = min(BLOCK_COUNT, len(data))
        block_size = (len(data) + number_of_blocks - 1) // number_of_blocks

        block_entries = []

        for index, start in enumerate(range(0, len(data), block_size)):
            plaintext = data[start:start + block_size]
            nonce = os.urandom(12)  # Unique 96-bit nonce for each block

            # AES-GCM encrypts and authenticates each block
            encrypted = aes.encrypt(nonce, plaintext, None)

            s3_key = f"encrypted_blocks/{file_id}/block_{index}.bin"

            # Upload encrypted block to private S3 bucket
            s3.put_object(
                Bucket=BUCKET_NAME,
                Key=s3_key,
                Body=encrypted,
                ContentType="application/octet-stream",
                ServerSideEncryption="AES256",
                Metadata={
                    "file-id": file_id,
                    "block-index": str(index),
                    "owner-id": owner_id,
                },
            )

            block_entries.append({
                "index": index,
                "s3_key": s3_key,
                "nonce": nonce.hex(),
                "size": len(plaintext),
                "sha256": hashlib.sha256(plaintext).hexdigest(),
            })

        manifest = {
            "file_id": file_id,
            "owner_id": owner_id,
            "owner_email": owner_email,
            "filename": original_name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "encryption": "AES-256-GCM",
            "block_count": len(block_entries),
            "blocks": block_entries,
        }

        # Save manifest to private S3 and local cache
        save_manifest(file_id, manifest)

        # Register file ownership in database
        database.register_user_file(
            file_id=file_id,
            owner_id=owner_id,
            filename=original_name,
            size=len(data),
            block_count=len(block_entries),
            s3_metadata_key=f"metadata/{file_id}.json",
            created_at=manifest["created_at"],
        )

        return {
            "message": "File encrypted and uploaded successfully.",
            "file_id": file_id,
            "owner_id": owner_id,
            "filename": original_name,
            "size": len(data),
            "block_count": len(block_entries),
            "encryption": "AES-256-GCM",
            "s3_keys": [entry["s3_key"] for entry in block_entries],
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Upload failed for file_id=%s", file_id)
        raise HTTPException(
            status_code=500,
            detail="Upload failed. Check backend logs for details.",
        ) from exc
    finally:
        await file.close()


# ==================================================
# 2. USER-SPECIFIC FILE LISTING
# ==================================================

@app.get("/files")
def list_user_files(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns the file list for the authenticated user only.
    Each file entry contains the owner ID, filename, size, and S3 object keys.
    """
    user_id = current_user["id"]

    try:
        # Retrieve all files owned by current user from the database
        owned_files = database.get_files_by_owner(user_id)
        result = []

        for record in owned_files:
            file_id = record["file_id"]
            block_count = record.get("block_count", BLOCK_COUNT)

            s3_keys = [
                f"encrypted_blocks/{file_id}/block_{i}.bin"
                for i in range(block_count)
            ]

            result.append({
                "file_id": file_id,
                "owner_id": record["owner_id"],
                "filename": record["filename"],
                "size": record["size"],
                "block_count": block_count,
                "s3_metadata_key": record["s3_metadata_key"],
                "s3_keys": s3_keys,
                "created_at": record["created_at"],
                "encryption": "AES-256-GCM",
            })

        return {
            "count": len(result),
            "owner_id": user_id,
            "files": result,
        }

    except Exception as exc:
        logger.exception("Failed to retrieve user file list for user_id=%s", user_id)
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve user file list.",
        ) from exc


# ==================================================
# 4. ACCESS CONTROL & FILE DOWNLOAD
# ==================================================

@app.get("/download/{file_id}")
def download_file(
    file_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Access Control:
    1. Verifies the user is authenticated.
    2. Loads file manifest and checks if current_user['id'] == manifest['owner_id'].
    3. Rejects unauthorized access with 403 Forbidden.
    4. Downloads encrypted blocks from private S3.
    5. Decrypts and authenticates each block with AES-256-GCM.
    6. Verifies block and complete file integrity (SHA-256).
    7. Streams the verified plaintext file back to the owner.
    """
    if not is_valid_file_id(file_id):
        raise HTTPException(status_code=400, detail="Invalid file ID.")

    manifest = load_manifest(file_id)

    # ACCESS CONTROL CHECK
    owner_id = manifest.get("owner_id")
    if owner_id and owner_id != current_user["id"]:
        logger.warning(
            "Access denied: User %s attempted to download file %s owned by %s",
            current_user["id"], file_id, owner_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not own this file.",
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
                detail="Invalid block configuration in file metadata.",
            )

        for block in blocks:
            s3_key = block.get("s3_key", "")
            expected_prefix = f"encrypted_blocks/{file_id}/"

            if not s3_key.startswith(expected_prefix):
                raise HTTPException(
                    status_code=422,
                    detail="Invalid block storage path.",
                )

            # Download encrypted block from private S3
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

            # Decrypt and authenticate block using AES-256-GCM
            plaintext = aes.decrypt(nonce, encrypted, None)

            # Check individual block integrity
            actual_hash = hashlib.sha256(plaintext).hexdigest()
            if actual_hash != block.get("sha256"):
                raise HTTPException(
                    status_code=422,
                    detail="File block integrity verification failed.",
                )

            if len(plaintext) != block.get("size"):
                raise HTTPException(
                    status_code=422,
                    detail="File block size verification failed.",
                )

            plaintext_blocks.append(plaintext)

        # Reconstruct file in block order
        original_data = b"".join(plaintext_blocks)

        if len(original_data) != manifest.get("size"):
            raise HTTPException(
                status_code=422,
                detail="Reconstructed file size does not match metadata.",
            )

        overall_hash = manifest.get("sha256")
        if overall_hash:
            actual_hash = hashlib.sha256(original_data).hexdigest()
            if actual_hash != overall_hash:
                raise HTTPException(
                    status_code=422,
                    detail="Complete file integrity check failed.",
                )

        filename = Path(manifest.get("filename", "download")).name

        return StreamingResponse(
            BytesIO(original_data),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(original_data)),
                "Cache-Control": "no-store",
            },
        )

    except HTTPException:
        raise
    except InvalidTag as exc:
        logger.exception("AES-GCM authentication failed for file_id=%s", file_id)
        raise HTTPException(
            status_code=422,
            detail="Decryption failed. The encryption key or encrypted data may have been altered.",
        ) from exc
    except ClientError as exc:
        logger.exception("S3 download failed for file_id=%s", file_id)
        raise HTTPException(
            status_code=502,
            detail="Could not retrieve encrypted file blocks from S3.",
        ) from exc
    except Exception as exc:
        logger.exception("Download or decryption failed for file_id=%s", file_id)
        raise HTTPException(
            status_code=500,
            detail="Download failed. Check the backend logs.",
        ) from exc


# ==================================================
# ACCESS CONTROL & FILE DELETION
# ==================================================

@app.delete("/files/{file_id}")
def delete_file(
    file_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Access Control:
    Verifies that the logged-in user owns the file before deleting it from S3 and the database.
    """
    if not is_valid_file_id(file_id):
        raise HTTPException(status_code=400, detail="Invalid file ID.")

    manifest = load_manifest(file_id)

    # ACCESS CONTROL CHECK
    owner_id = manifest.get("owner_id")
    if owner_id and owner_id != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not own this file.",
        )

    try:
        # Delete encrypted blocks from private S3
        for block in manifest.get("blocks", []):
            s3_key = block.get("s3_key")
            if s3_key:
                try:
                    s3.delete_object(Bucket=BUCKET_NAME, Key=s3_key)
                except Exception:
                    pass

        # Delete metadata from private S3
        try:
            s3.delete_object(Bucket=BUCKET_NAME, Key=f"metadata/{file_id}.json")
        except Exception:
            pass

        # Remove from local database
        database.delete_file_record(file_id, current_user["id"])

        return {
            "message": "File deleted successfully.",
            "file_id": file_id
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to delete file_id=%s", file_id)
        raise HTTPException(
            status_code=500,
            detail="Failed to delete file from storage.",
        ) from exc


# ==================================================
# FILE METADATA INSPECTION (OWNER ONLY)
# ==================================================

@app.get("/files/{file_id}/metadata")
def get_file_metadata(
    file_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns file metadata and block keys to the verified file owner.
    """
    if not is_valid_file_id(file_id):
        raise HTTPException(status_code=400, detail="Invalid file ID.")

    manifest = load_manifest(file_id)

    owner_id = manifest.get("owner_id")
    if owner_id and owner_id != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You do not own this file.",
        )

    return manifest
