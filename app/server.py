import os
import uuid
import threading
from flask import Flask, request, jsonify, send_file
from iplookup import IPLookup
from utils import process_file, validate_ips
from pathlib import Path

app = Flask(__name__)
STORAGE_DIR = Path("storage")
STORAGE_DIR.mkdir(exist_ok=True)
jobs = {}  # {job_id: {"status": str, "progress": int, "total": int, "output_file": str}}

@app.route("/submit", methods=["POST"])
def submit_job():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]
    job_id = str(uuid.uuid4())
    input_path = STORAGE_DIR / f"{job_id}_input.txt"
    output_path = STORAGE_DIR / f"{job_id}_output.txt"
    
    try:
        file.save(input_path)
        ips = process_file(input_path)
        if not validate_ips(ips):
            return jsonify({"error": "Invalid IPs in file"}), 400
        if len(ips) > 15000:
            return jsonify({"error": "Exceeds 15,000 IP limit"}), 400
        
        jobs[job_id] = {"status": "queued", "progress": 0, "total": len(ips), "output_file": str(output_path)}
        
        def run_job():
            try:
                iplookup = IPLookup()
                jobs[job_id]["status"] = "running"
                iplookup.run(ips, str(output_path))
                jobs[job_id]["status"] = "completed"
            except Exception as e:
                jobs[job_id]["status"] = "failed"
                jobs[job_id]["error"] = str(e)
        
        threading.Thread(target=run_job, daemon=True).start()
        return jsonify({"job_id": job_id, "status": "queued"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/status/<job_id>", methods=["GET"])
def check_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Invalid job ID"}), 404
    return jsonify(job)

@app.route("/result/<job_id>", methods=["GET"])
def get_result(job_id):
    job = jobs.get(job_id)
    if not job or job["status"] != "completed":
        return jsonify({"error": "Job not completed or invalid"}), 400
    output_file = job["output_file"]
    if not Path(output_file).exists():
        return jsonify({"error": "Output file not found"}), 500
    return send_file(output_file, as_attachment=True)

@app.route("/delete/<job_id>", methods=["DELETE"])
def delete_job(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Invalid job ID"}), 404
    try:
        input_file = STORAGE_DIR / f"{job_id}_input.txt"
        output_file = job["output_file"]
        if input_file.exists():
            input_file.unlink()
        if Path(output_file).exists():
            Path(output_file).unlink()
        del jobs[job_id]
        return jsonify({"message": "Job deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)