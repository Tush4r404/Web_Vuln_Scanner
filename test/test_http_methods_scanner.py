import unittest
from scanner.http_methods_scanner import scan_http_methods

class TestHTTPMethodsScanner(unittest.TestCase):
    def test_scan_http_methods_returns_list(self):
        result = scan_http_methods("http://testphp.vulnweb.com")
        self.assertIsInstance(result, list)

if __name__ == "__main__":
    unittest.main()