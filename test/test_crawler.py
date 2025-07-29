import unittest
from scanner.crawler import crawl

class TestCrawler(unittest.TestCase):
    def test_crawl_returns_pages_and_forms(self):
        pages, forms = crawl("http://testphp.vulnweb.com")
        self.assertIsInstance(pages, list)
        self.assertIsInstance(forms, list)
        self.assertGreater(len(pages), 0)

if __name__ == "__main__":
    unittest.main()