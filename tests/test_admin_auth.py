import tempfile
import unittest
from contextlib import closing
from pathlib import Path

import app as backend
from werkzeug.security import generate_password_hash


class AdminAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        backend.DATABASE = Path(self.temp_directory.name) / "test.sqlite3"
        backend.initialize_database()
        with closing(backend.connect_database()) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO admin_account (id, email, password_hash) VALUES (1, ?, ?)",
                    (
                        "admin@example.test",
                        generate_password_hash("test-only-password-123"),
                    ),
                )
        self.client = backend.app.test_client()
        self.csrf_token = self.client.get("/api/auth").json["csrfToken"]
        self.product = {
            "name": "Test Cleanser",
            "category": "cleansers",
            "description": "A test product",
            "price": 12.5,
            "size": "100 ml",
            "image": "",
        }

    def tearDown(self):
        self.temp_directory.cleanup()

    def test_guest_can_list_products_but_cannot_add(self):
        self.assertEqual(self.client.get("/api/products").status_code, 200)
        response = self.client.post(
            "/api/products",
            json=self.product,
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(response.status_code, 401)

    def test_admin_login_requires_csrf_and_valid_credentials(self):
        payload = {"email": "admin@example.test", "password": "test-only-password-123"}
        self.assertEqual(
            self.client.post("/api/login", json=payload).status_code,
            403,
        )
        response = self.client.post(
            "/api/login",
            json=payload,
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["authenticated"])
        self.assertNotEqual(response.json["csrfToken"], self.csrf_token)

    def test_product_creation_requires_admin_and_valid_csrf(self):
        login = self.client.post(
            "/api/login",
            json={"email": "admin@example.test", "password": "test-only-password-123"},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        token = login.json["csrfToken"]
        self.assertEqual(
            self.client.post(
                "/api/products",
                json=self.product,
                headers={"X-CSRF-Token": "invalid"},
            ).status_code,
            403,
        )
        created = self.client.post(
            "/api/products",
            json=self.product,
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(self.client.get("/api/products").json[0]["name"], self.product["name"])

    def test_logout_removes_admin_access(self):
        login = self.client.post(
            "/api/login",
            json={"email": "admin@example.test", "password": "test-only-password-123"},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        logout = self.client.post(
            "/api/logout",
            headers={"X-CSRF-Token": login.json["csrfToken"]},
        )
        self.assertEqual(logout.status_code, 200)
        response = self.client.post(
            "/api/products",
            json=self.product,
            headers={"X-CSRF-Token": logout.json["csrfToken"]},
        )
        self.assertEqual(response.status_code, 401)

    def test_login_is_rate_limited(self):
        client = backend.app.test_client()
        client.environ_base["REMOTE_ADDR"] = "192.0.2.55"
        token = client.get("/api/auth").json["csrfToken"]
        responses = [
            client.post(
                "/api/login",
                json={"email": "admin@example.test", "password": "incorrect"},
                headers={"X-CSRF-Token": token},
            )
            for _ in range(6)
        ]
        self.assertEqual([response.status_code for response in responses[:5]], [401] * 5)
        self.assertEqual(responses[5].status_code, 429)

    def test_live_server_origin_gets_credentialed_cors_but_unknown_origin_does_not(self):
        allowed = self.client.get(
            "/api/auth",
            headers={"Origin": "http://127.0.0.1:5500"},
        )
        self.assertEqual(
            allowed.headers.get("Access-Control-Allow-Origin"),
            "http://127.0.0.1:5500",
        )
        self.assertEqual(allowed.headers.get("Access-Control-Allow-Credentials"), "true")

        preflight = self.client.options(
            "/api/login",
            headers={
                "Origin": "http://localhost:5500",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,x-csrf-token",
            },
        )
        self.assertEqual(preflight.headers.get("Access-Control-Allow-Origin"), "http://localhost:5500")
        self.assertIn("X-CSRF-Token", preflight.headers.get("Access-Control-Allow-Headers", ""))

        rejected = self.client.get(
            "/api/auth",
            headers={"Origin": "https://untrusted.example"},
        )
        self.assertIsNone(rejected.headers.get("Access-Control-Allow-Origin"))


if __name__ == "__main__":
    unittest.main()
