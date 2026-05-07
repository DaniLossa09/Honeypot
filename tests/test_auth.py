import unittest

from backend.auth import AuthError, create_token, hash_password, verify_password, verify_token


class AuthTest(unittest.TestCase):
    def test_password_hash_verification(self):
        stored = hash_password("secret-password")

        self.assertTrue(verify_password("secret-password", stored))
        self.assertFalse(verify_password("wrong-password", stored))

    def test_token_verification_rejects_tampering(self):
        config = {
            "username": "admin",
            "password_hash": hash_password("secret-password"),
            "token_secret": "test-secret",
            "token_ttl_seconds": 60,
        }
        token = create_token("admin", config)

        self.assertEqual(verify_token(token, config)["sub"], "admin")
        with self.assertRaises(AuthError):
            verify_token(token + "x", config)


if __name__ == "__main__":
    unittest.main()
