from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

client = MongoClient(os.getenv("MONGO_URI"))
db = client.cti_db

def save_to_mongo(ioc, data):
    db.iocs.insert_one({
        "ioc": ioc,
        "virustotal": data.get("virustotal"),
        "abuseipdb": data.get("abuseipdb"),
        "tags": data.get("tags", []),
        "score": data.get("score"),
        "timestamp": datetime.utcnow()
    })

def get_all_iocs():
    return list(db.iocs.find({}, {'_id': 0}))

def get_filtered_iocs(search, score, tag):
    query = {}
    if search:
        query["ioc"] = {"$regex": search, "$options": "i"}
    if score:
        query["score"] = score
    if tag:
        query["tags"] = tag
    return list(db.iocs.find(query, {'_id': 0}))

def get_score_stats():
    return list(db.iocs.aggregate([
        {"$group": {"_id": "$score", "count": {"$sum": 1}}}
    ]))

def get_summary_stats():
    total = db.iocs.count_documents({})
    malicious = db.iocs.count_documents({"score": "High"})
    safe = db.iocs.count_documents({"score": "Low"})
    return {"total": total, "malicious": malicious, "safe": safe}

def get_tag_stats():
    return list(db.iocs.aggregate([
        {"$unwind": "$tags"},
        {"$group": {"_id": "$tags", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]))
