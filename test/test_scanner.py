import unittest
from scanner.scanner import scan_forms_for_sqli

class TestSQLiScanner(unittest.TestCase):
    def test_scan_forms_for_sqli_returns_list(self):
        forms = [{"action": "/search", "method": "get", "inputs": [{"name": "q", "type": "text"}]}]
        result = scan_forms_for_sqli(forms, "http://testphp.vulnweb.com")
        self.assertIsInstance(result, list)

if __name__ == "__main__":
    unittest.main()