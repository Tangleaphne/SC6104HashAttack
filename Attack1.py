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





# 生日攻击函数
def birthday_attack(hash_func, hash_length: int, attempts: int, algorithm: str):
    hash_dict = {}
    
    for _ in range(attempts):
        # 生成随机消息
        message = random_string(8)
        hashed_value = hash_func(message, algorithm)[:hash_length]  # 只考虑部分哈希值

        # 检查是否有碰撞
        if hashed_value in hash_dict:
            print(f"Collision found for {algorithm}!")
            print(f"Message 1: {message}, Message 2: {hash_dict[hashed_value]}")
            print(f"Hash Value: {hashed_value}")
            return True
        else:
            hash_dict[hashed_value] = message
    
    print(f"No collision found for {algorithm} after {attempts} attempts")
    return False

# 运行生日攻击
# hash_length = 32  # 比较前 6 位的哈希值，简化实验
for algo in ['MD5', 'SHA1', 'SHA256']:
    if algo == 'MD5':
        hash_length = 32  # 完整的MD5哈希长度
    elif algo == 'SHA1':
        hash_length = 40  # 完整的SHA-1哈希长度
    elif algo == 'SHA256':
        hash_length = 64  # 完整的SHA-256哈希长度
attempts = 2**20  # 尝试的次数

for algo in ['MD5', 'SHA1', 'SHA256']:
    print(f"Attempting birthday attack on {algo} (first {hash_length} hex digits)...")
    birthday_attack(hash_message, hash_length, attempts, algo)





# Pollard ρ 碰撞查找
def pollard_rho(hash_func, algorithm: str, max_iterations=2**64):
    def f(x):
        return hash_func(x, algorithm)  # 使用哈希函数
    
    x = random_string(8)  # 初始值
    y = f(x)  # f(x)
    
    for i in range(max_iterations):
        # 快速前进2步
        x = f(x)
        y = f(f(y))
        
        # 检查是否有碰撞
        if x == y:
            print(f"Collision found for {algorithm} after {i+1} iterations!")
            print(f"Message 1: {x}, Message 2: {y}")
            print(f"Hash Value: {hash_func(x, algorithm)}")
            return True

    print(f"No collision found for {algorithm} after {max_iterations} iterations")
    return False

# 运行 Pollard ρ 方法
for algo in ['MD5', 'SHA1', 'SHA256']:
    print(f"Attempting Pollard's rho attack on {algo}...")
    pollard_rho(hash_message, algo)



