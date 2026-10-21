
import boto3
from botocore.exceptions import ClientError

BUCKET_NAME = "secure-cloud-storage-p2-2026"
REGION = "ap-south-1"

s3 = boto3.client("s3", region_name=REGION)

try:
    s3.head_bucket(Bucket=BUCKET_NAME)
    print("SUCCESS: Python connected to AWS S3!")
    print("Bucket:", BUCKET_NAME)
    print("Region:", REGION)

except ClientError as error:
    print("S3 connection failed:")
    print(error)
      