import unittest
from scanner.csrf_scanner import scan_forms_for_csrf

class TestCSRFScanner(unittest.TestCase):
    def test_csrf_returns_list(self):
        forms = [{"action": "/submit", "method": "post", "inputs": [{"name": "name", "type": "text"}]}]
        result = scan_forms_for_csrf(forms)
        self.assertIsInstance(result, list)

if __name__ == "__main__":
    unittest.main()