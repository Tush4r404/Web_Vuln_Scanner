# Cyber Threat Intelligence (CTI) Dashboard

A Flask-based web dashboard to analyze and visualize IP and domain threat intelligence data using VirusTotal, AbuseIPDB, IPInfo, and other APIs.

---

## Features

- IP and domain reputation lookup  
- GeoIP location and visualization  
- JSON API response viewer  
- Light/dark mode toggle  
- PDF and HTML report export  
- Local logging of scan results  
- Modular Flask backend  
- Responsive UI with Bootstrap or Tailwind CSS  

---

## Technology Stack

- Python, Flask (Backend)  
- HTML, CSS (Bootstrap/Tailwind) (Frontend)  
- VirusTotal, AbuseIPDB, IPInfo APIs  
- WeasyPrint (PDF generation)  
- geoip2 (GeoIP lookup)  
- python-dotenv (Environment config)  

---

## Project Structure

- Project2_CTI_Dashboard/
  - app.py
  - geo.py
  - templates/      (HTML templates)
  - static/         (CSS, JavaScript, images)
  - utils/          (Helper scripts)
  - results/        (Scan results and reports)
  - .env.example    (Sample environment config)
  - .gitignore      (Git ignore file)
  - requirements.txt (Python dependencies)
  - README.md       (This file)

---

## Setup Instructions

1. Clone the repository:

       git clone https://github.com/Tush4r404/Web_Vuln_Scanner.git
       cd Web_Vuln_Scanner/Project2_CTI_Dashboard

2. Create and activate virtual environment:

       python -m venv venv

   - On Windows:

         venv\Scripts\activate

   - On macOS/Linux:

         source venv/bin/activate

3. Install dependencies:

       pip install -r requirements.txt

4. Configure environment variables:

       cp .env.example .env

   Edit `.env` and add your API keys:

       VIRUSTOTAL_API_KEY=your_virustotal_api_key
       ABUSEIPDB_API_KEY=your_abuseipdb_api_key
       IPINFO_TOKEN=your_ipinfo_token

5. Run the application:

       python app.py

6. Open your browser at:

       http://127.0.0.1:5000

---

## License

MIT License

---

## Contributions

Issues and pull requests are welcome. Please open an issue to discuss changes.
