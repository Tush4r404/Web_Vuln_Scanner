import unittest
from scanner.cookie_scanner import scan_insecure_cookies

class TestCookieScanner(unittest.TestCase):
    def test_scan_insecure_cookies_returns_list(self):
        result = scan_insecure_cookies("http://testphp.vulnweb.com")
        self.assertIsInstance(result, list)

if __name__ == "__main__":
    unittest.main()