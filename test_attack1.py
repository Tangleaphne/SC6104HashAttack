from Attack1 import birthday_attack, hash_message

def test_birthday_attack():
    print("Starting the test...")
    
    # Prompt the user for the character type
    char_type = input("Enter character type (int, string, both): ").strip().lower()
    print(f"Character type entered: {char_type}")
    
    # Prompt the user for the hash length and number of attempts
    hash_length = int(input("Enter the hash length: ").strip())
    attempts = int(input("Enter the number of attempts: ").strip())

    # Run the birthday attack using the specified parameters
    for algo in ['MD5', 'SHA1', 'SHA256']:
        print(f"Attempting birthday attack on {algo} (first {hash_length} hex digits)...")
        birthday_attack(hash_message, hash_length, attempts, algo, char_type)

if __name__ == "__main__":
    test_birthday_attack()