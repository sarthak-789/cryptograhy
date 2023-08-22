import os
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives import padding
from PIL import Image

if __name__ == "__main__":
    # Plain Text
    user_input = input("Enter the text: ")

    # Converting the input to bytes
    plainText = user_input.encode('utf-8')
    print(f"PlainText: {plainText}")

    # 256-bit AES key
    key = os.urandom(256 // 8)
    print(f"Key : {key}")
    # Create AES ECB Cipher
    aes_ecb_cipher = Cipher(AES(key), ECB())

    # Encrypt
    cipherText = aes_ecb_cipher.encryptor().update(plainText)
    print(f"Cipher Text : {cipherText}")

    # Decrypt
    recovered_text = aes_ecb_cipher.decryptor().update(cipherText)
    print(f"Recovered Text: {recovered_text}")

    # pad the text in order to be multiple of 128bits
    pkcs7_padder = padding.PKCS7(AES.block_size).padder()
    padded_text = pkcs7_padder.update(plainText) + pkcs7_padder.finalize()
    print(f"Padded Plain Text: {padded_text}")

    # Encrypt padded text
    padded_cipher_text = aes_ecb_cipher.encryptor().update(padded_text)
    print(f"Padded Cipher Text: {padded_cipher_text}")

    # Decrypt Padded text
    padded_recovered_text = aes_ecb_cipher.decryptor().update(padded_cipher_text)
    print(f"Padded Recovered Text: {padded_recovered_text}")

    # Remove the padding
    pkcs7_unpadded = padding.PKCS7(AES.block_size).unpadder()
    original_text = pkcs7_unpadded.update(padded_recovered_text) + pkcs7_unpadded.finalize()
    print(f"Original Text: {original_text}")

    assert(original_text == plainText)

    # Encrypt & Decrypt Image

    # Read the Image into memory
    file_path = input("Enter the File Path:")
    destination_file_path = input("Enter The Destination File Path:")
    image = Image.open(file_path)
    #width, height = image.size
    header_size = image.fp.tell()
    #print(width)
    #print(height)
    print(header_size)
    with open(file_path, 'rb') as image:
        image_file = image.read()
        image_bytes = bytearray(image_file)    
        
    # Keep the header
    image_header = image_bytes[:header_size]    
    image_body = image_bytes[header_size:]

    # Pad the image body
    pkcs7_padder = padding.PKCS7(AES.block_size).padder()
    padder_image_body = pkcs7_padder.update(image_body) + pkcs7_padder.finalize()

    # Encrypt the Image Body
    encrypted_image_body = aes_ecb_cipher.encryptor().update(padder_image_body)

    # Assemble Encrypted Image
    encrypted_image = image_header + encrypted_image_body[:len(image_body)]

    # Crate and save the encrypted image body
    with open(destination_file_path, 'wb') as image_encrypted:
        image_encrypted.write(encrypted_image)

    # Decrypt Image
    image = Image.open(destination_file_path)
    #width, height = image.size
    header_size = image.fp.tell()
    #print(width)
    #print(height)
    print(header_size)
    with open(destination_file_path, 'rb') as image:
        image_file = image.read()
        image_bytes = bytearray(image_file)    
        
    # Keep the header
    image_header = image_bytes[:header_size]    
    image_body = image_bytes[header_size:]

    # Decrypt Padded text
    recovered_image = aes_ecb_cipher.decryptor().update(image_body)
    print(f"Padded Recovered Text: {recovered_image}")

    # Assemble Decrypted Image
    encrypted_image = image_header + recovered_image[:len(image_body)]

    original_file_path = input("Enter The File Path for Decrypted Image:")
    # Create and save the decrypted image body
    with open(original_file_path, 'wb') as image_decrypted:
        image_decrypted.write(encrypted_image)