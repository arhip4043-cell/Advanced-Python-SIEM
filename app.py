from flask import Flask, render_template
import json
import os

app=Flask(__name__)
ALERTS_FILE="alerts.json"

def get_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    with open(ALERTS_FILE, "r") as f:
        try:
            alerts=json.load(f)
            return alerts[::-1]
        except json.JSONDecodeError:
            return []

@app.route("/")
def index():
    alerts=get_alerts()
    return render_template("index.html", alerts=alerts)

if __name__=="__main__":
    print("Web Server avviato su http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
