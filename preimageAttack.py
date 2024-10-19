import hashlib
import string
import itertools
import random

# 生成随机字符串
def random_string(length: int) -> str:
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


# 定义要破解的哈希值
target_hash0 = hashlib.sha256(b"hello111").hexdigest()

# 简单的字符集
charset = string.ascii_lowercase + string.digits

# 暴力破解函数
def brute_force_hash(hash_func, target_hash, max_len):
    """
    对给定的哈希值进行暴力破解以寻找原象
    :param hash_func: 哈希函数
    :param target_hash: 目标哈希值
    :param max_len: 最大尝试长度
    :return: 找到的原象
    """
    # 尝试不同长度的组合
    for length in range(1, max_len + 1):
        # 使用itertools生成所有可能的字符组合
        for guess in itertools.product(charset, repeat=length):
            # 将字符组合转换为字符串
            guess_str = ''.join(guess)
            # 计算猜测字符串的哈希值
            guess_hash = hash_func(guess_str.encode()).hexdigest()
            # 如果哈希值匹配，则返回原象
            if guess_hash == target_hash:
                return guess_str
    return None

# 调用破解函数，使用SHA-256哈希
result = brute_force_hash(hashlib.sha256, target_hash0, max_len=5)

if result:
    print(f"找到原象: {result}")
else:
    print("未找到原象")
