def caesar_cipher_encrypt(plaintext, shift):
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                ciphertext += chr(((ord(char) - 97 + shift_amount) % 26) + 97)
            else:
                ciphertext += chr(((ord(char) - 65 + shift_amount) % 26) + 65)
        else:
            ciphertext += char
    return ciphertext

def vigenere_cipher_encrypt(plaintext, key):
    ciphertext = ''
    key_length = len(key)
    for i in range(len(plaintext)):
        char = plaintext[i]
        if char.isalpha():
            key_char = key[i % key_length]
            shift = ord(key_char) - ord('A')
            ciphertext += caesar_cipher_encrypt(char, shift)
        else:
            ciphertext += char
    return ciphertext

def vigenere_caesar_encrypt(plaintext, vigenere_key, caesar_shift):
    # Langkah pertama: Enkripsi dengan Caesar Cipher
    caesar_ciphertext = caesar_cipher_encrypt(plaintext, caesar_shift)
    
    # Langkah kedua: Enkripsi hasil Caesar Cipher dengan Vigenère Cipher
    final_ciphertext = vigenere_cipher_encrypt(caesar_ciphertext, vigenere_key)
    
    return final_ciphertext

def caesar_cipher_decrypt(ciphertext, shift):
    return caesar_cipher_encrypt(ciphertext, -shift)

def vigenere_cipher_decrypt(ciphertext, key):
    plaintext = ''
    key_length = len(key)
    for i in range(len(ciphertext)):
        char = ciphertext[i]
        if char.isalpha():
            key_char = key[i % key_length]
            shift = ord(key_char) - ord('A')
            plaintext += caesar_cipher_decrypt(char, shift)
        else:
            plaintext += char
    return plaintext

def vigenere_caesar_decrypt(ciphertext, vigenere_key, caesar_shift):
    # Langkah pertama: Dekripsi dengan Vigenère Cipher
    vigenere_plaintext = vigenere_cipher_decrypt(ciphertext, vigenere_key)
    
    # Langkah kedua: Dekripsi hasil Vigenère Cipher dengan Caesar Cipher
    final_plaintext = caesar_cipher_decrypt(vigenere_plaintext, caesar_shift)
    
    return final_plaintext

# Teks yang akan dienkripsi
plaintext = "Success is not final, failure is not fatal, it is the courage to continue that counts"
vigenere_key = "RATRI"
caesar_shift = 1

# Enkripsi pesan
ciphertext = vigenere_caesar_encrypt(plaintext, vigenere_key, caesar_shift)
print("Teks terenkripsi:", ciphertext)

# Dekripsi pesan
decrypted_message = vigenere_caesar_decrypt(ciphertext, vigenere_key, caesar_shift)
print("Teks terdekripsi:", decrypted_message)
