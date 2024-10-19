import hashlib
import random
import string

# 生成随机字符串
def random_string(length: int) -> str:
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

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





def birthday_attack(hash_func, hash_length: int, attempts: int, algorithm: str):
    hash_dict = {}

    for _ in range(attempts):
        # 生成随机消息
        message = random_string(8)
        hashed_value = hash_func(message, algorithm)[:hash_length]  # 只考虑部分哈希值

        # 检查是否有碰撞
        if hashed_value in hash_dict and hash_dict[hashed_value] != message:
            print(f"Collision found for {algorithm}!")
            print(f"Message 1: {hash_dict[hashed_value]}, Message 2: {message}")
            print(f"Hash Value: {hashed_value}")
            return True
        else:
            hash_dict[hashed_value] = message

    print(f"No collision found for {algorithm} after {attempts} attempts")
    return False

# 运行生日攻击
for algo in ['MD5', 'SHA1', 'SHA256']:
    if algo == 'MD5':
        hash_length = 8  # 完整的MD5哈希长度
    elif algo == 'SHA1':
        hash_length = 8  # 完整的SHA-1哈希长度
    elif algo == 'SHA256':
        hash_length = 8  # 完整的SHA-256哈希长度

attempts = 2**20  # 尝试的次数

for algo in ['MD5', 'SHA1', 'SHA256']:
    print(f"Attempting birthday attack on {algo}...")
    birthday_attack(hash_message, hash_length, attempts, algo)





# Pollard ρ 碰撞查找
def pollard_rho(hash_func, algorithm: str, compare_length: int, max_iterations=2**16):
    def f(x):
      hash_value = hash_func(x, algorithm)
      return hash_value

    x = random_string(8)  # 初始值
    y = x  
    print(f"The original input is {x}")

    for i in range(max_iterations):
        
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

    print(f"No collision found for {algorithm} after {max_iterations} iterations")
    return False

# 运行 Pollard ρ 方法
for algo in ['MD5', 'SHA1', 'SHA256']:
    print(f"Attempting Pollard's rho attack on {algo}...")
    pollard_rho(hash_message, algo, compare_length=2)




