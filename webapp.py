from flask import Flask, render_template, request
from hash_utils import generate_hash, detect_hash, analyze_strength, generate_secure_password
from cracker import dictionary_attack

app = Flask(__name__)

@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    result = {}
    
    if request.method == "POST":

        # HASH GENERATOR
        if "generate_hash" in request.form:
            password = request.form["password"]
            algorithm = request.form["algorithm"]
            result["generated_hash"] = generate_hash(password, algorithm)

        # PASSWORD STRENGTH
        if "analyze_strength" in request.form:
            password = request.form["strength_password"]
            result["strength"] = analyze_strength(password)

        # SECURE PASSWORD GENERATOR
        if "generate_secure" in request.form:
            result["secure_password"] = generate_secure_password()

        # HASH CRACKER
        if "crack_hash" in request.form:
            hash_value = request.form["hash_value"]
            hash_type = detect_hash(hash_value)
            password, attempts, time_taken = dictionary_attack(hash_value, hash_type)

            result["hash_type"] = hash_type
            result["cracked_password"] = password
            result["attempts"] = attempts
            result["time_taken"] = time_taken

    return render_template("dashboard.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)