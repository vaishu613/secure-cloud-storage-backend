import io
import json
import os
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import main
import database

# In-memory S3 simulation dictionary for hermetic unit testing
s3_storage = {}

def mock_put_object(**kwargs):
    bucket = kwargs["Bucket"]
    key = kwargs["Key"]
    body = kwargs["Body"]
    if hasattr(body, "read"):
        body = body.read()
    s3_storage[key] = {
        "Body": body,
        "ContentType": kwargs.get("ContentType"),
        "Metadata": kwargs.get("Metadata", {}),
    }
    return {"ResponseMetadata": {"HTTPStatusCode": 200}}

def mock_get_object(**kwargs):
    key = kwargs["Key"]
    if key not in s3_storage:
        from botocore.exceptions import ClientError
        raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "The specified key does not exist."}}, "GetObject")
    
    body_data = s3_storage[key]["Body"]
    return {
        "Body": io.BytesIO(body_data),
        "Metadata": s3_storage[key].get("Metadata", {}),
    }

def mock_delete_object(**kwargs):
    key = kwargs["Key"]
    s3_storage.pop(key, None)
    return {"ResponseMetadata": {"HTTPStatusCode": 204}}


class TestSecureCloudStorage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Patch S3 client methods
        cls.s3_put_patch = patch.object(main.s3, "put_object", side_effect=mock_put_object)
        cls.s3_get_patch = patch.object(main.s3, "get_object", side_effect=mock_get_object)
        cls.s3_del_patch = patch.object(main.s3, "delete_object", side_effect=mock_delete_object)
        cls.s3_put_patch.start()
        cls.s3_get_patch.start()
        cls.s3_del_patch.start()

        cls.client = TestClient(main.app)

    @classmethod
    def tearDownClass(cls):
        cls.s3_put_patch.stop()
        cls.s3_get_patch.stop()
        cls.s3_del_patch.stop()

    def setUp(self):
        s3_storage.clear()

    def test_01_signup_and_login(self):
        """Requirement 1: Email and password authentication."""
        # 1. Register User A
        reg_resp = self.client.post("/auth/register", json={
            "email": "alice@example.com",
            "password": "Password123",
            "full_name": "Alice Smith"
        })
        self.assertIn(reg_resp.status_code, (200, 409))
        if reg_resp.status_code == 200:
            data = reg_resp.json()
            self.assertIn("access_token", data)
            self.assertEqual(data["user"]["email"], "alice@example.com")

        # 2. Login User A
        login_resp = self.client.post("/auth/login", json={
            "email": "alice@example.com",
            "password": "Password123"
        })
        self.assertEqual(login_resp.status_code, 200)
        login_data = login_resp.json()
        self.assertIn("access_token", login_data)
        token = login_data["access_token"]

        # 3. Verify /auth/me
        me_resp = self.client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_resp.status_code, 200)
        self.assertEqual(me_resp.json()["user"]["email"], "alice@example.com")

        # 4. Reject invalid password
        bad_login = self.client.post("/auth/login", json={
            "email": "alice@example.com",
            "password": "WrongPassword999"
        })
        self.assertEqual(bad_login.status_code, 401)

    def test_02_user_specific_file_list_and_private_s3(self):
        """Requirements 2, 3, 5: User-specific file list, private S3, per-block encryption."""
        # Setup two distinct users
        self.client.post("/auth/register", json={"email": "bob@example.com", "password": "Password123", "full_name": "Bob"})
        bob_token = self.client.post("/auth/login", json={"email": "bob@example.com", "password": "Password123"}).json()["access_token"]
        bob_id = self.client.get("/auth/me", headers={"Authorization": f"Bearer {bob_token}"}).json()["user"]["id"]

        self.client.post("/auth/register", json={"email": "charlie@example.com", "password": "Password123", "full_name": "Charlie"})
        charlie_token = self.client.post("/auth/login", json={"email": "charlie@example.com", "password": "Password123"}).json()["access_token"]

        # Bob uploads a test file
        test_content = b"Confidential company report with secret data! " * 100
        upload_resp = self.client.post(
            "/upload",
            headers={"Authorization": f"Bearer {bob_token}"},
            files={"file": ("bob_report.txt", test_content, "text/plain")}
        )
        self.assertEqual(upload_resp.status_code, 200)
        upload_data = upload_resp.json()
        file_id = upload_data["file_id"]

        # Verify owner ID and S3 keys are recorded
        self.assertEqual(upload_data["owner_id"], bob_id)
        self.assertEqual(upload_data["encryption"], "AES-256-GCM")
        self.assertEqual(upload_data["block_count"], 4)
        self.assertTrue(len(upload_data["s3_keys"]) == 4)

        # Requirement 2: Bob lists files -> sees his file
        bob_files_resp = self.client.get("/files", headers={"Authorization": f"Bearer {bob_token}"})
        self.assertEqual(bob_files_resp.status_code, 200)
        bob_files = bob_files_resp.json()["files"]
        bob_file_ids = [f["file_id"] for f in bob_files]
        self.assertIn(file_id, bob_file_ids)
        self.assertEqual(bob_files[0]["owner_id"], bob_id)
        self.assertIn("s3_keys", bob_files[0])

        # Requirement 2: Charlie lists files -> does NOT see Bob's file
        charlie_files_resp = self.client.get("/files", headers={"Authorization": f"Bearer {charlie_token}"})
        self.assertEqual(charlie_files_resp.status_code, 200)
        charlie_file_ids = [f["file_id"] for f in charlie_files_resp.json()["files"]]
        self.assertNotIn(file_id, charlie_file_ids)

    def test_03_access_control_and_download(self):
        """Requirement 4: Verify logged-in user's identity and ownership before allowing downloads."""
        # Log in Bob and Charlie
        bob_token = self.client.post("/auth/login", json={"email": "bob@example.com", "password": "Password123"}).json()["access_token"]
        charlie_token = self.client.post("/auth/login", json={"email": "charlie@example.com", "password": "Password123"}).json()["access_token"]

        # Upload a file as Bob
        original_bytes = b"Access Control Verification Secret Document."
        upload_resp = self.client.post(
            "/upload",
            headers={"Authorization": f"Bearer {bob_token}"},
            files={"file": ("secret.txt", original_bytes, "text/plain")}
        )
        file_id = upload_resp.json()["file_id"]

        # 1. Unauthenticated download attempt -> 401 Unauthorized
        anon_resp = self.client.get(f"/download/{file_id}")
        self.assertEqual(anon_resp.status_code, 401)

        # 2. Charlie attempts to download Bob's file -> 403 Forbidden!
        unauth_resp = self.client.get(
            f"/download/{file_id}",
            headers={"Authorization": f"Bearer {charlie_token}"}
        )
        self.assertEqual(unauth_resp.status_code, 403)
        self.assertIn("Access denied", unauth_resp.json()["detail"])

        # 3. Bob downloads his own file -> 200 OK and data matches perfectly!
        auth_resp = self.client.get(
            f"/download/{file_id}",
            headers={"Authorization": f"Bearer {bob_token}"}
        )
        self.assertEqual(auth_resp.status_code, 200)
        self.assertEqual(auth_resp.content, original_bytes)

        # 4. Charlie attempts to delete Bob's file -> 403 Forbidden!
        bad_delete = self.client.delete(
            f"/files/{file_id}",
            headers={"Authorization": f"Bearer {charlie_token}"}
        )
        self.assertEqual(bad_delete.status_code, 403)

        # 5. Bob deletes his file -> 200 OK
        good_delete = self.client.delete(
            f"/files/{file_id}",
            headers={"Authorization": f"Bearer {bob_token}"}
        )
        self.assertEqual(good_delete.status_code, 200)


if __name__ == "__main__":
    unittest.main()
