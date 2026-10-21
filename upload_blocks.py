
import boto3
from pathlib import Path
from botocore.exceptions import ClientError

BUCKET_NAME = "secure-cloud-storage-p2-2026"
REGION = "ap-south-1"

BLOCKS_DIR = Path("encrypted_blocks")
MANIFEST_FILE = Path("block_manifest.json")

s3 = boto3.client("s3", region_name=REGION)


def upload_file(local_path, s3_key):
    try:
        s3.upload_file(str(local_path), BUCKET_NAME, s3_key)
        print(f"Uploaded: {local_path} -> s3://{BUCKET_NAME}/{s3_key}")
    except ClientError as error:
        print(f"Upload failed for {local_path}: {error}")
        raise


def main():
    encrypted_files = sorted(BLOCKS_DIR.glob("block_*.enc"))

    if len(encrypted_files) != 4:
        raise ValueError(
            f"Expected 4 encrypted blocks, found {len(encrypted_files)}. "
            "Run encrypt_blocks.py first."
        )

    if not MANIFEST_FILE.is_file():
        raise FileNotFoundError(
            "block_manifest.json not found. Run encrypt_blocks.py first."
        )

    for path in encrypted_files:
        upload_file(path, f"encrypted_blocks/{path.name}")

    upload_file(MANIFEST_FILE, "metadata/block_manifest.json")

    print("\nSUCCESS: All encrypted blocks and manifest uploaded!")


if __name__ == "__main__":
    main()
