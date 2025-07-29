# 🔍 CLI Web Application Vulnerability Scanner

This project is a **Command-Line Interface (CLI)-based Web Application Vulnerability Scanner** designed to identify common vulnerabilities such as **XSS, SQL Injection, CSRF**, and **security misconfigurations**. It aims to be fast, modular, and easily extensible, built using Python with modern practices.

## 🚀 Features

- URL crawling and form discovery
- Detection of:
  - Cross-Site Scripting (XSS)
  - SQL Injection (SQLi)
  - CSRF token absence
  - Insecure cookies and headers
  - Admin exposure, outdated JS, open redirects
  - Directory listing & brute-force login
- Summary by severity (High, Medium, Info)
- HTML report generation and MongoDB storage support

## 🛠️ Tools & Libraries Used

- `requests`, `BeautifulSoup`, `concurrent.futures`
- `argparse`, `colorama`, `json`, `threading`
- MongoDB for result storage (optional)
- Python 3.8+

## 📦 Project Structure

```
vuln_scanner/
│
├── scanner/                   # All scanning modules
├── database/db.py             # MongoDB interaction
├── utils/html_report.py       # HTML report generation
├── cli_test_scanner.py        # Main CLI entry point
├── requirements.txt
└── README.md
```

## ⚙️ How to Use

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the scanner:**
   ```bash
   python cli_test_scanner.py http://example.com --verbose --html-report=report.html
   ```

## ✅ Run Tests (Optional)

To ensure the code is working as expected:
```bash
python -m unittest discover test
```

## 🏆 Why This Project Stands Out

- Modular, readable codebase
- Real-time logging with severity color coding
- Highly extensible with OWASP Top 10 coverage

## 🌐 GitHub

[GitHub Repository](https://github.com/Tush4r404/Web_Vuln_Scanner)

## 📃 License

MIT License
