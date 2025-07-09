import os
import uuid
import threading
from flask import Flask, request, jsonify, send_file
from iplookup import IPLookup
from utils import process_file, validate_ips
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
STORAGE_DIR = Path("storage")
STORAGE_DIR.mkdir(exist_ok=True)
jobs = {}  # {job_id: {"status": str, "progress": int, "total": int, "output_file": str}}
jobs_lock = threading.Lock()  # For thread-safe updates

@app.route("/submit", methods=["POST"])
def submit_job():
    logger.debug("Received submit request")
    if "file" not in request.files:
        logger.error("No file provided")
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]
    job_id = str(uuid.uuid4())
    input_path = STORAGE_DIR / f"{job_id}_input.txt"
    output_path = STORAGE_DIR / f"{job_id}_output.txt"
    
    try:
        file.save(input_path)
        ips = process_file(input_path)
        if not validate_ips(ips):
            logger.error("Invalid IPs in file")
            return jsonify({"error": "Invalid IPs in file"}), 400
        if len(ips) > 15000:
            logger.error("Exceeds 15,000 IP limit")
            return jsonify({"error": "Exceeds 15,000 IP limit"}), 400
        
        with jobs_lock:
            jobs[job_id] = {"status": "queued", "progress": 0, "total": len(ips), "output_file": str(output_path)}
        
        logger.info(f"Job {job_id} queued with {len(ips)} IPs")
        
        def run_job():
            try:
                iplookup = IPLookup()
                with jobs_lock:
                    jobs[job_id]["status"] = "running"
                logger.debug(f"Job {job_id} started")
                iplookup.run(ips, str(output_path), job_id=job_id)
                with jobs_lock:
                    jobs[job_id]["status"] = "completed"
                logger.info(f"Job {job_id} completed")
            except Exception as e:
                with jobs_lock:
                    jobs[job_id]["status"] = "failed"
                    jobs[job_id]["error"] = str(e)
                logger.error(f"Job {job_id} failed: {str(e)}")
        
        threading.Thread(target=run_job, daemon=True).start()
        return jsonify({"job_id": job_id, "status": "queued"})
    except Exception as e:
        logger.error(f"Submit error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/status/<job_id>", methods=["GET"])
def check_status(job_id):
    logger.debug(f"Checking status for job {job_id}")
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        logger.error(f"Invalid job ID: {job_id}")
        return jsonify({"error": "Invalid job ID"}), 404
    logger.info(f"Returning status for job {job_id}: {job['status']}, progress: {job['progress']}/{job['total']}")
    return jsonify(job)

@app.route("/result/<job_id>", methods=["GET"])
def get_result(job_id):
    logger.debug(f"Fetching result for job {job_id}")
    with jobs_lock:
        job = jobs.get(job_id)
    if not job or job["status"] != "completed":
        logger.error(f"Job not completed or invalid: {job_id}")
        return jsonify({"error": "Job not completed or invalid"}), 400
    output_file = job["output_file"]
    if not Path(output_file).exists():
        logger.error(f"Output file not found: {output_file}")
        return jsonify({"error": "Output file not found"}), 500
    logger.info(f"Sending result file for job {job_id}")
    return send_file(output_file, as_attachment=True)

@app.route("/delete/<job_id>", methods=["DELETE"])
def delete_job(job_id):
    logger.debug(f"Deleting job {job_id}")
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        logger.error(f"Invalid job ID: {job_id}")
        return jsonify({"error": "Invalid job ID"}), 404
    try:
        input_file = STORAGE_DIR / f"{job_id}_input.txt"
        output_file = job["output_file"]
        if input_file.exists():
            input_file.unlink()
        if Path(output_file).exists():
            Path(output_file).unlink()
        with jobs_lock:
            del jobs[job_id]
        logger.info(f"Job {job_id} deleted")
        return jsonify({"message": "Job deleted"})
    except Exception as e:
        logger.error(f"Delete error: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    logger.info(f"Starting server on port {port}")
    app.run(host="0.0.0.0", port=port)