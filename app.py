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
    char_type = request.form['char_type']
    attempts_exponent = int(request.form.get('attempts_exponent', 12))
    attempts = 2 ** attempts_exponent  # 根据用户输入的次方计算尝试的次数

    # 确保用户输入的 char_type 合法
    char_type_options = ['int', 'string', 'both']
    if char_type not in char_type_options:
        return render_template('index.html', result=f"Invalid character type. Please choose from {char_type_options}.")

    # 确保用户输入的攻击类型合法
    attack_type_options = ['birthday', 'pollard_rho']
    if attack_type not in attack_type_options:
        return render_template('index.html', result=f"Invalid attack type. Please choose from {attack_type_options}.")

    # 确保用户输入的哈希算法合法
    hash_algorithm_options = ['MD5', 'SHA1', 'SHA256']
    if algorithm not in hash_algorithm_options:
        return render_template('index.html', result=f"Invalid hash algorithm. Please choose from {hash_algorithm_options}.")

    # 根据用户选择的攻击类型执行相应的攻击
    if attack_type == 'birthday':
        result = birthday_attack(hash_message, attempts, algorithm, char_type)
    elif attack_type == 'pollard_rho':
        result = pollard_rho(hash_message, algorithm, char_type=char_type)
    else:
        result = "Invalid attack type selected."

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)