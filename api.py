from flask import Flask, render_template, request
import requests
import os

app = Flask(__name__)

# Get API Key from environment variable
API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
headers = {"x-apikey": API_KEY}

def check_ip(ip):
    """
    Checks IP reputation via VirusTotal API.
    Returns a dictionary with 'status' and 'message'.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            if stats["malicious"] > 0:
                return {"status": "malicious", "message": "Malicious IP detected"}
            else:
                return {"status": "safe", "message": "IP is safe"}
        else:
            return {"status": "error", "message": f"IP not found or error ({response.status_code})"}
    except Exception as e:
        return {"status": "error", "message": f"Exception: {e}"}

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    ip = None
    if request.method == "POST":
        ip = request.form["ip"]
        result = check_ip(ip)
    return render_template("index.html", result=result, ip=ip)

if __name__ == "__main__":
    app.run(debug=True)
