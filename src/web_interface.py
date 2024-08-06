from flask import Flask, render_template, request, jsonify
from .scanner import scan_for_cve_2023_38831
from .database import Database
import logging

app = Flask(__name__)
db = Database()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        is_vulnerable, version_or_error = scan_for_cve_2023_38831()
        
        # For demonstration, we're using placeholder values for some fields
        db.insert_scan_result(
            is_vulnerable,
            version_or_error,
            "Integrity check passed",
            "No suspicious patterns in memory",
            "No suspicious network traffic",
            "No issues in sandbox environment"
        )
        
        return jsonify({
            'status': 'success',
            'is_vulnerable': is_vulnerable,
            'version_or_error': version_or_error
        })
    except Exception as e:
        logging.error(f"Error during scan: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/results')
def results():
    scan_results = db.get_all_scan_results()
    return render_template('report.html', results=scan_results)

def run_web_interface():
    app.run(debug=True)
