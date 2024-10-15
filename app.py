from flask import Flask, render_template, request
from Attack1 import birthday_attack, pollard_rho, hash_message

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run_attack', methods=['POST'])
def run_attack():
    algorithm = request.form['algorithm']
    attack_type = request.form['attack_type']
    hash_length = int(request.form.get('hash_length', 6))
    attempts = int(request.form.get('attempts', 4096))
    max_iterations = int(request.form.get('max_iterations', 1000000))

    if attack_type == 'birthday':
        result = birthday_attack(hash_message, hash_length, attempts, algorithm)
    elif attack_type == 'pollard':
        result = pollard_rho(hash_message, algorithm, max_iterations)
    else:
        result = "Invalid attack type selected."

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
