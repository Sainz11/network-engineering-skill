import unittest
from scripts.redact import redact_sensitive_data

class TestRedaction(unittest.TestCase):
    def test_redact_passwords(self):
        text = 'password="MySecretPassword123" and auth-password: supersecret'
        redacted = redact_sensitive_data(text)
        self.assertNotIn("MySecretPassword123", redacted)
        self.assertNotIn("supersecret", redacted)
        self.assertIn("***REDACTED***", redacted)

    def test_redact_snmp_community(self):
        text = 'snmp-server community publicRO 10.0.0.1'
        redacted = redact_sensitive_data(text)
        self.assertNotIn("publicRO", redacted)
        self.assertIn("***REDACTED***", redacted)

    def test_redact_bearer_token(self):
        text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
        redacted = redact_sensitive_data(text)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", redacted)
        self.assertIn("***REDACTED***", redacted)

    def test_redact_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Yq...\n-----END RSA PRIVATE KEY-----"
        redacted = redact_sensitive_data(text)
        self.assertNotIn("MIIEowIBAAKCAQEA0Yq...", redacted)
        self.assertIn("***REDACTED PRIVATE KEY***", redacted)

if __name__ == '__main__':
    unittest.main()
