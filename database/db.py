from pymongo import MongoClient
from datetime import datetime

client = MongoClient("mongodb://localhost:27017/")
db = client.vulnscanner

def save_scan_results(target_url, results):
    if not results:
        return

    entry = {
        "target": target_url,
        "timestamp": datetime.utcnow(),
        "vulnerabilities": results
    }
    db.scans.insert_one(entry)

def get_all_scans():
    return list(db.scans.find({}, {"_id": 0}))
