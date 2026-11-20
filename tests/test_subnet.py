import ipaddress
import unittest

class SubnetTests(unittest.TestCase):
    def test_network(self):
        self.assertEqual(str(ipaddress.ip_interface("192.168.1.10/24").network), "192.168.1.0/24")
    def test_host_count(self):
        self.assertEqual(ipaddress.ip_network("10.0.0.0/24").num_addresses - 2, 254)
    def test_invalid(self):
        with self.assertRaises(ValueError):
            ipaddress.ip_interface("not-a-cidr")

if __name__ == "__main__":
    unittest.main()
