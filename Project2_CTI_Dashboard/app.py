from flask import Flask, render_template, request, jsonify, make_response
from utils.virustotal import lookup_virustotal
from utils.abuseipdb import lookup_abuseipdb
from utils.geo import lookup_geo_info
from utils.threat_score import calculate_threat_score
from datetime import datetime
import csv
from io import StringIO

app = Flask(__name__)
latest_results = {}

@app.route("/", methods=["GET", "POST"])
def index():
    global latest_results
    results = {}
    selected_sources = []
    selected_ioc = ""
    error = None

    if request.method == "POST":
        ioc = request.form.get("ioc", "").strip()
        selected_sources = request.form.getlist("source")
        selected_ioc = ioc

        if not selected_sources:
            error = "Please select at least one source."
        else:
            vt_data = abuse_data = geo_data = None

            if "vt" in selected_sources:
                vt_data = lookup_virustotal(ioc)
                results["virustotal"] = vt_data

            if "abuseipdb" in selected_sources:
                abuse_data = lookup_abuseipdb(ioc)
                results["abuseipdb"] = abuse_data

            if "geo" in selected_sources:
                geo_data = lookup_geo_info(ioc)
                results["geo"] = geo_data

            score = calculate_threat_score(vt_data, abuse_data)
            results.update({
                "score": score,
                "id": ioc,
                "type": "ip" if ioc.replace(".", "").isdigit() else "domain",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

            latest_results = results

    return render_template(
        "index.html",
        results=results or None,
        selected_sources=selected_sources,
        selected_ioc=selected_ioc,
        error=error
    )

@app.route("/export/json")
def export_json():
    if not latest_results:
        return "No results to export", 400
    response = make_response(jsonify(latest_results))
    response.headers["Content-Disposition"] = (
        f"attachment; filename=cti_report_{timestamp_suffix()}.json"
    )
    return response

@app.route("/export/csv")
def export_csv():
    if not latest_results:
        return "No results to export", 400

    csv_output = StringIO()
    writer = csv.writer(csv_output)
    writer.writerow([
        "IOC", "Type", "Score",
        "VT Malicious", "Abuse Score",
        "Country", "City", "ISP",
        "Timestamp"
    ])
    writer.writerow([
        latest_results.get("id", ""),
        latest_results.get("type", ""),
        latest_results.get("score", ""),
        latest_results.get("virustotal", {}).get("last_analysis_stats", {}).get("malicious", ""),
        latest_results.get("abuseipdb", {}).get("abuseConfidenceScore", ""),
        latest_results.get("geo", {}).get("country", ""),
        latest_results.get("geo", {}).get("city", ""),
        latest_results.get("geo", {}).get("isp", ""),
        latest_results.get("timestamp", "")
    ])

    response = make_response(csv_output.getvalue())
    response.headers["Content-Disposition"] = (
        f"attachment; filename=cti_report_{timestamp_suffix()}.csv"
    )
    response.headers["Content-Type"] = "text/csv"
    return response

def timestamp_suffix():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

if __name__ == "__main__":
    app.run(debug=True)
