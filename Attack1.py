import hashlib
import random
import string

# 从用户输入获取哈希算法
hash_algorithm_options = ['MD5', 'SHA1', 'SHA256']
print(f"Choose hash algorithm from {hash_algorithm_options}:")
hash_algorithm = input().strip().upper()

# 确保用户输入的哈希算法合法
if hash_algorithm not in hash_algorithm_options:
    raise ValueError(f"Invalid hash algorithm. Please choose from {hash_algorithm_options}.")

# 从用户输入获取 char_type
char_type_options = ['int', 'string', 'both']
print(f"Choose character type from {char_type_options}:")
char_type = input().strip().lower()

# 确保用户输入的 char_type 合法
if char_type not in char_type_options:
    raise ValueError(f"Invalid character type. Please choose from {char_type_options}.")

# 从用户输入获取攻击类型
attack_type_options = ['birthday', 'pollard_rho', 'second_preimage']
print(f"Choose attack type from {attack_type_options}:")
attack_type = input().strip().lower()

# 确保用户输入的攻击类型合法
if attack_type not in attack_type_options:
    raise ValueError(f"Invalid attack type. Please choose from {attack_type_options}.")

# 从用户输入获取 attempts 的次方
attempts_exponent = int(input("Enter the exponent for the number of attempts (e.g., for 2^12, enter 12): ").strip())
attackAttempts = 2 ** attempts_exponent  # 根据用户输入的次方计算尝试的次数


for algo in ['MD5', 'SHA1', 'SHA256']:
    if algo == 'MD5':
        hash_length = 32  # 完整的MD5哈希长度
    elif algo == 'SHA1':
        hash_length = 40  # 完整的SHA-1哈希长度
    elif algo == 'SHA256':
        hash_length = 64  # 完整的SHA-256哈希长度

# 生成随机字符串
def random_string(length: int, type: str) -> str:
    if type == 'int':
        chars = string.digits
    elif type == 'string':
        chars = string.ascii_lowercase
    else:
        chars = string.ascii_lowercase + string.digits
    
    result = ''.join(random.choice(chars) for i in range(length))
    print(f"Generated string: {result}")
    return result

# 哈希函数封装器
def hash_message(message: str, algorithm: str) -> str:
    if algorithm == 'MD5':
        return hashlib.md5(message.encode('utf-8')).hexdigest()
    elif algorithm == 'SHA1':
        return hashlib.sha1(message.encode('utf-8')).hexdigest()
    elif algorithm == 'SHA256':
        return hashlib.sha256(message.encode('utf-8')).hexdigest()
    else:
        raise ValueError("Unsupported algorithm")

# 生日攻击函数
def birthday_attack(hash_func, hash_length: int, attackAttempts: int, algorithm: str, type: str):
    hash_dict = {}

    for _ in range(attackAttempts):
        # 生成随机消息
        message = random_string(8, type)
        hashed_value = hash_func(message, algorithm)[:hash_length]  # 只考虑部分哈希值

        # 检查是否有碰撞
        if hashed_value in hash_dict and hash_dict[hashed_value] != message:
            print(f"Collision found for {algorithm}!")
            print(f"Message 1: {hash_dict[hashed_value]}, Message 2: {message}")
            print(f"Hash Value: {hashed_value}")
            return True
        else:
            hash_dict[hashed_value] = message

    print(f"No collision found for {algorithm} after {attackAttempts} attempts")
    return False



# Pollard ρ 碰撞查找
def pollard_rho(type: str, hash_func, algorithm: str, compare_length: int, attackAttempts):
    def f(x):
      hash_value = hash_func(x, algorithm)
      return hash_value

    # x = random_string(8)  # 初始值
    x = random_string(8, type)
    y = x  
    print(f"The original input is {x}")

    for i in range(attackAttempts):
        
        x_hash = f(x)
        y_hash2 = f(f(y))

        # 检查是否有碰撞
        if x_hash[:compare_length] == y_hash2[:compare_length]:
            print(f"Collision found for {algorithm} after {i+1} iterations!")
            print(f"Message 1: {x}, Message 2: {y}")
            print(f"M1 Hash Value: {x_hash}")
            print(f"M2 Hash Value: {y_hash2}")
            return True
        else: 
          x = x_hash
          y = y_hash2

    print(f"No collision found for {algorithm} after {attackAttempts} iterations")
    return False


#second_preimage attack
def second_preimage_attack(hash_func, target_hash, char_type, max_length, attempts: int, algorithm: str, type: str, compare_length=int):
    # 只取目标哈希的前 compare_length 位
    target_hash_prefix = target_hash[:t_compare_length]

    for _ in range(attempts):
        candidate_str = random_string(max_length, char_type)
        hash_value = hash_func(candidate_str, algorithm)
        
        # Now, use t_compare_length for slicing
        if hash_value[:t_compare_length] == target_hash_prefix: 
            print(f"second_Preimage found: {candidate_str} hashes to {hash_value} (first {t_compare_length} chars match target hash {target_hash})")

            return candidate_str
    
    print("No second_preimage found within the given constraints.")
    return None



# 根据用户选择的攻击类型执行相应的攻击
if attack_type == 'birthday':
    hash_length = int(input("Enter the number of hash characters to compare (e.g., 8, 16): ").strip())
    print(f"Attempting birthday attack on {hash_algorithm}...")
    birthday_attack(hash_message, hash_length, attackAttempts=attackAttempts, algorithm=hash_algorithm, type=char_type)  # 使用用户输入的参数
elif attack_type == 'pollard_rho':
    compare_length = int(input("Enter the number of hash characters to compare (e.g., 8, 16): ").strip())
    print(f"Attempting Pollard's rho attack on {hash_algorithm}...")
    pollard_rho(char_type, hash_message, algorithm=hash_algorithm, compare_length=compare_length, attackAttempts=attackAttempts)  # 使用用户输入的参数
elif attack_type == 'second_preimage':
    max_length = int(input("Enter the maximum length for the random string: ").strip())
    t_compare_length = int(input("Enter the number of hash characters to compare (e.g., 8, 16): ").strip())
    # 随机生成一个目标字符串，并生成其哈希值作为目标哈希
    target_string = random_string(max_length, char_type)
    target_hash = hash_message(target_string, hash_algorithm)
    print(f"Target string: {target_string}, Target hash: {target_hash}")
    print(f"Attempting second_preimage attack on {hash_algorithm} with target hash {target_hash}...")
    second_preimage_attack(hash_message, target_hash, char_type, max_length, attackAttempts, hash_algorithm, type=char_type)