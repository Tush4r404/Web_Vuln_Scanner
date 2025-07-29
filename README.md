# 🔍 Web Vulnerability Scanner - CLI Edition

This is a powerful command-line-based web vulnerability scanner designed to detect common OWASP Top 10 vulnerabilities.

## 🛠️ Features

- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- CSRF
- Open Redirects
- Directory Listing
- Insecure Cookies
- Missing Security Headers
- Outdated JavaScript Libraries
- Cryptographic Misconfigurations
- Weak Login Forms
- HTTP Method Tampering
- Exposed Admin Panels

## ⚖️ Ethical Use Warning

> ⚠️ **This tool is strictly intended for educational purposes and authorized penetration testing only.**
>
> **Do not scan or attack websites without proper permission.**  
> Unauthorized use of this scanner on live websites may be illegal and unethical.  
> Always follow legal guidelines and obtain consent from asset owners before using this tool.

---

## 🧰 Tools & Libraries Used

- `requests`, `BeautifulSoup`, `argparse`, `colorama`, `json`, `lxml`, `threading`, `concurrent.futures`
- MongoDB for result storage *(optional)*
- Python 3.8+

---

## 📁 Project Structure

```
web_vuln_scanner/
├── cli_test_scanner.py          # Main CLI scanner entry point
├── scanner/                     # Core scanning modules
│   ├── crawler.py
│   ├── xss_scanner.py
│   ├── csrf_scanner.py
│   ├── scanner.py
│   └── ...
├── database/
│   └── db.py                    # MongoDB saving logic
├── utils/
│   └── html_report.py          # HTML report generator
├── test/                        # Unit tests
│   ├── __init__.py
│   ├── test_crawler.py
│   └── test_xss_scanner.py
├── requirements.txt
└── README.md
```

---

## ⚙️ How to Use

### 1. Clone the Repository

```bash
git clone https://github.com/Tush4r404/Web_Vuln_Scanner.git
cd Web_Vuln_Scanner
```

### 2. Create a Virtual Environment (Optional)

```bash
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Linux/macOS
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Scanner

```bash
python cli_test_scanner.py http://testphp.vulnweb.com --verbose --html-report report.html
```

### 5. Run Tests (Optional)

```bash
python -m unittest discover test
```

### 6. Output Files

- `scan_log.json` – JSON formatted scan results
- `report.html` – Optional HTML report if `--html-report` is used

---

## 👨‍💻 Author

**Tushar**  
[GitHub Repo](https://github.com/Tush4r404/Web_Vuln_Scanner)

---

## 📄 License

This project is licensed under the MIT License.
