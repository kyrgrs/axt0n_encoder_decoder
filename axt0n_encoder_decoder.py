import os
from art import text2art

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def generate_vigenere_table():
    table = []
    for i in range(26):
        row = [(chr((i + j) % 26 + 65)) for j in range(26)]
        table.append(row)
    return table

def extend_key(message, key):
    key = list(key)
    if len(message) == len(key):
        return key
    else:
        for i in range(len(message) - len(key)):
            key.append(key[i % len(key)])
    return "".join(key)

def vigenere_encrypt(message, key):
    table = generate_vigenere_table()
    key = extend_key(message, key)
    cipher_text = []
    for i in range(len(message)):
        if message[i].isalpha():
            row = ord(key[i]) - 65
            col = ord(message[i]) - 65
            cipher_text.append(table[row][col])
        else:
            cipher_text.append(message[i])
    return "".join(cipher_text)

def vigenere_decrypt(cipher_text, key):
    table = generate_vigenere_table()
    key = extend_key(cipher_text, key)
    original_text = []
    for i in range(len(cipher_text)):
        if cipher_text[i].isalpha():
            row = ord(key[i]) - 65
            col = table[row].index(cipher_text[i])
            original_text.append(chr(col + 65))
        else:
            original_text.append(cipher_text[i])
    return "".join(original_text)

def caesar_encrypt(message, shift):
    cipher_text = []
    for char in message:
        if char.isalpha():
            shift_amount = shift % 26
            new_char = chr((ord(char) - 65 + shift_amount) % 26 + 65)
            cipher_text.append(new_char)
        else:
            cipher_text.append(char)
    return "".join(cipher_text)

def caesar_decrypt(cipher_text, shift):
    original_text = []
    for char in cipher_text:
        if char.isalpha():
            shift_amount = shift % 26
            new_char = chr((ord(char) - 65 - shift_amount) % 26 + 65)
            original_text.append(new_char)
        else:
            original_text.append(char)
    return "".join(original_text)

def gronsfeld_encrypt(message, key):
    cipher_text = []
    key = [int(digit) for digit in key]  # Convert key to list of integers
    for i in range(len(message)):
        if message[i].isalpha():
            shift_amount = key[i % len(key)]
            new_char = chr((ord(message[i]) - 65 + shift_amount) % 26 + 65)
            cipher_text.append(new_char)
        else:
            cipher_text.append(message[i])
    return "".join(cipher_text)

def gronsfeld_decrypt(cipher_text, key):
    original_text = []
    key = [int(digit) for digit in key]  # Convert key to list of integers
    for i in range(len(cipher_text)):
        if cipher_text[i].isalpha():
            shift_amount = key[i % len(key)]
            new_char = chr((ord(cipher_text[i]) - 65 - shift_amount) % 26 + 65)
            original_text.append(new_char)
        else:
            original_text.append(cipher_text[i])
    return "".join(original_text)

def main():
    while True:
        clear_screen()
        print(text2art("Axton Encoder/Decoder", font="slant", chr_ignore=True))
        print("\033[1;35;40m1. Vigenere Cipher")
        print("\033[1;35;40m2. Caesar Cipher")
        print("\033[1;35;40m3. Gronsfeld Cipher")
        print("\033[1;32;40m4. Exit")
        choice = input("\033[1;34;40mChoose a cipher (1/2/3/4): ")

        if choice == "1":
            clear_screen()
            print(text2art("Vigenere Cipher", font="slant", chr_ignore=True))
            print("\033[1;35;40m1. Encode")
            print("\033[1;35;40m2. Decode")
            action = input("\033[1;34;40mChoose an action (1/2): ")
            if action == "1":
                message = input("\033[1;34;40mEnter the message to encode: ").upper()
                key = input("\033[1;34;40mEnter the key: ").upper()
                encrypted_message = vigenere_encrypt(message, key)
                print("\033[1;32;40mEncoded Message: ", encrypted_message)
            elif action == "2":
                cipher_text = input("\033[1;34;40mEnter the message to decode: ").upper()
                key = input("\033[1;34;40mEnter the key: ").upper()
                decrypted_message = vigenere_decrypt(cipher_text, key)
                print("\033[1;32;40mDecoded Message: ", decrypted_message)
            else:
                print("\033[1;31;40mInvalid choice. Please try again.")
            input("\033[1;34;40mPress Enter to continue...")

        elif choice == "2":
            clear_screen()
            print(text2art("Caesar Cipher", font="slant", chr_ignore=True))
            print("\033[1;35;40m1. Encode")
            print("\033[1;35;40m2. Decode")
            action = input("\033[1;34;40mChoose an action (1/2): ")
            if action == "1":
                message = input("\033[1;34;40mEnter the message to encode: ").upper()
                shift = int(input("\033[1;34;40mEnter the shift value: "))
                encrypted_message = caesar_encrypt(message, shift)
                print("\033[1;32;40mEncoded Message: ", encrypted_message)
            elif action == "2":
                cipher_text = input("\033[1;34;40mEnter the message to decode: ").upper()
                shift = int(input("\033[1;34;40mEnter the shift value: "))
                decrypted_message = caesar_decrypt(cipher_text, shift)
                print("\033[1;32;40mDecoded Message: ", decrypted_message)
            else:
                print("\033[1;31;40mInvalid choice. Please try again.")
            input("\033[1;34;40mPress Enter to continue...")

        elif choice == "3":
            clear_screen()
            print(text2art("Gronsfeld Cipher", font="slant", chr_ignore=True))
            print("\033[1;35;40m1. Encode")
            print("\033[1;35;40m2. Decode")
            action = input("\033[1;34;40mChoose an action (1/2): ")
            if action == "1":
                message = input("\033[1;34;40mEnter the message to encode: ").upper()
                key = input("\033[1;34;40mEnter the key (digits): ")
                encrypted_message = gronsfeld_encrypt(message, key)
                print("\033[1;32;40mEncoded Message: ", encrypted_message)
            elif action == "2":
                cipher_text = input("\033[1;34;40mEnter the message to decode: ").upper()
                key = input("\033[1;34;40mEnter the key (digits): ")
                decrypted_message = gronsfeld_decrypt(cipher_text, key)
                print("\033[1;32;40mDecoded Message: ", decrypted_message)
            else:
                print("\033[1;31;40mInvalid choice. Please try again.")
            input("\033[1;34;40mPress Enter to continue...")

        elif choice == "4":
            break

if __name__ == "__main__":
    main()
