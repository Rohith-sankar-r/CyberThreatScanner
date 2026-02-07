from flask import Flask, render_template, request
import os
from scanner.file_scanner import scan_file, load_malicious_hashes

UPLOAD_FOLDER = "uploads"

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        file = request.files["file"]

        if file:
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(file_path)

            hashes = load_malicious_hashes()
            result = scan_file(file_path, hashes)

            os.remove(file_path)  # cleanup after scan

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
