import unittest
from scanner.headers_scanner import scan_security_headers

class TestHeadersScanner(unittest.TestCase):
    def test_scan_security_headers_returns_list(self):
        result = scan_security_headers("http://testphp.vulnweb.com")
        self.assertIsInstance(result, list)

if __name__ == "__main__":
    unittest.main()