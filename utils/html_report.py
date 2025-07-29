# utils/html_report.py

import os
from datetime import datetime

def generate_html_report(results, output_path="report.html", target=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity_colors = {
        "High": "#ff4d4d",
        "Medium": "#ffa500",
        "Info": "#5bc0de",
        "Uncategorized": "#ccc"
    }

    rows = ""
    for issue in results:
        sev = issue.get("severity", "Uncategorized")
        color = severity_colors.get(sev, "#ccc")
        rows += f"""
        <tr style="background-color:{color};">
            <td>{issue.get("type", "N/A")}</td>
            <td>{issue.get("url", "N/A")}</td>
            <td>{issue.get("evidence", "N/A")}</td>
            <td>{sev}</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerability Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; }}
            th {{ background-color: #333; color: white; }}
            tr:hover {{ background-color: #f1f1f1; }}
        </style>
    </head>
    <body>
        <h1>🛡️ Vulnerability Scan Report</h1>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Date:</strong> {timestamp}</p>
        <table>
            <tr>
                <th>Type</th>
                <th>URL</th>
                <th>Evidence</th>
                <th>Severity</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
