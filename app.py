from flask import Flask, request, jsonify, render_template
import subprocess
import os
import tempfile
from werkzeug.utils import secure_filename

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('tester.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'pcapFile' not in request.files:
        return 'No file part', 400
    file = request.files['pcapFile']
    is_tor = request.form['isTor']  
    if file.filename == '':
        return 'No selected file', 400

    temp_dir = tempfile.gettempdir()
    filename = secure_filename(file.filename)
    filepath = os.path.join(temp_dir, filename)
    file.save(filepath)
    

    try:
        process_result = subprocess.run(['py', 'process_pcap.py', filepath, str(is_tor)], capture_output=True, text=True, check=True)
        if process_result.returncode != 0:
            process_result("Error running process_pcap.py:")
            process_result(process_result.stderr)
        csv_file_path = process_result.stdout.strip()

        evaluate_result = subprocess.run(['py', 'evaluate_model.py', 'rf_model.joblib', 'rf_scaler.joblib', csv_file_path], capture_output=True, text=True, check=True)
        
        accuracy = evaluate_result.stdout.strip()

        
    except subprocess.CalledProcessError as e:
        print(f"Subprocess error: {e}")
        return jsonify({'error': 'Processing failed'}), 500
    
    finally:
        if os.path.exists(filepath):
            print(filepath)
            os.remove(filepath)
        if csv_file_path and os.path.exists(csv_file_path):
            os.remove(csv_file_path)

    return jsonify({'accuracy': accuracy})

if __name__ == '__main__':
    app.run(debug=True)
