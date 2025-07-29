import unittest
from scanner.xss_scanner import scan_url_for_xss

class TestXSSScanner(unittest.TestCase):
    def test_scan_url_for_xss_returns_list(self):
        result = scan_url_for_xss("http://testphp.vulnweb.com")
        self.assertIsInstance(result, list)

if __name__ == "__main__":
    unittest.main()