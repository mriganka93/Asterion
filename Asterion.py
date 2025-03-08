import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, PngImagePlugin
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from bitarray import bitarray

# Function to Encrypt PDF with Password and return IV, Salt, Padding, and Encrypted Data
def encrypt_pdf_with_password(pdf_path, password):
    salt = os.urandom(16)  # Generate a random salt
    iterations = 100000  # Set iterations for PBKDF2HMAC

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES 256-bit key
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive the key using the password

    # Print the encryption key (in hex format)
    print(f"Encryption key: {key.hex()}")  # Prints the key in a human-readable hex format

    with open(pdf_path, 'rb') as f:
        pdf_data = f.read()  # Read the PDF data

    # Print size of the original PDF data
    print(f"Original PDF data size: {len(pdf_data)} bytes")

    # Apply PKCS7 padding to make the data length a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(pdf_data) + padder.finalize()

    # Print size of the padded data
    print(f"Padded data size: {len(padded_data)} bytes")

    iv = os.urandom(16)  # Generate a random Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Print size of the encrypted data
    print(f"Encrypted data size: {len(encrypted_data)} bytes")

    return iv, salt, iterations, encrypted_data, padded_data

def embed_pdf_in_image(image_path, encrypted_pdf_data, output_image_path):
    data_bits = bitarray()
    data_bits.frombytes(encrypted_pdf_data)

    img = Image.open(image_path)
    pixels = img.load()

    width, height = img.size
    total_pixels = width * height
    if len(data_bits) > total_pixels * 3:
        raise ValueError("Image is too small to embed the PDF data.")

    bit_index = 0
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            r = (r & 0xFE) | (data_bits[bit_index] if bit_index < len(data_bits) else 0)
            g = (g & 0xFE) | (data_bits[bit_index + 1] if bit_index + 1 < len(data_bits) else 0)
            b = (b & 0xFE) | (data_bits[bit_index + 2] if bit_index + 2 < len(data_bits) else 0)

            pixels[x, y] = (r, g, b)
            bit_index += 3

    img.save(output_image_path)

def select_image_file():
    return filedialog.askopenfilename(title="Select Image File", filetypes=[("All Files", "*.*")])

def select_pdf_file():
    return filedialog.askopenfilename(title="Select Your File", filetypes=[("All Files", "*.*")])

def encrypt_and_embed():
    password = password_entry.get()

    if not password:
        messagebox.showwarning("Input Error", "Please enter a password!")
        return

    image_path = image_file_label.cget("text")
    pdf_path = pdf_file_label.cget("text")

    if image_path == "No image selected" or pdf_path == "No File selected":
        messagebox.showwarning("Input Error", "Please select both image and File!")
        return

    try:
        iv, salt, iterations, encrypted_pdf_data, padded_data = encrypt_pdf_with_password(pdf_path, password)

        # Create metadata with IV, Salt, Iterations, and Encrypted Data Size
        img_info = PngImagePlugin.PngInfo()
        img_info.add_text("IV", iv.hex())
        img_info.add_text("Salt", salt.hex())
        img_info.add_text("Iterations", str(iterations))
        img_info.add_text("EncryptedDataSize", str(len(encrypted_pdf_data)))  # Add the size of the encrypted data

        # Embed the encrypted PDF data into the image
        output_image_path = "output_image_with_pdf.png"
        embed_pdf_in_image(image_path, encrypted_pdf_data, output_image_path)

        # Save the image with metadata
        img = Image.open(output_image_path)
        img.save(output_image_path, "PNG", pnginfo=img_info)

        messagebox.showinfo("Success", f"File successfully embedded in image. Saved as {output_image_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def update_image_file_label():
    image_path = select_image_file()
    if image_path:
        image_file_label.config(text=image_path)

def update_pdf_file_label():
    pdf_path = select_pdf_file()
    if pdf_path:
        pdf_file_label.config(text=pdf_path)

root = tk.Tk()
root.title(" Encryptor and Image Embedder")
root.geometry("400x300")

password_label = tk.Label(root, text="Enter Password:")
password_label.pack(pady=10)

password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack(pady=5)

image_file_label = tk.Label(root, text="No image selected", relief="solid", width=40, height=2)
image_file_label.pack(pady=10)

select_image_button = tk.Button(root, text="Select Image File", command=update_image_file_label)
select_image_button.pack(pady=5)

pdf_file_label = tk.Label(root, text="No File selected", relief="solid", width=40, height=2)
pdf_file_label.pack(pady=10)

select_pdf_button = tk.Button(root, text="Select PDF File", command=update_pdf_file_label)
select_pdf_button.pack(pady=5)

encrypt_button = tk.Button(root, text="Encrypt and Embed", command=encrypt_and_embed)
encrypt_button.pack(pady=20)

root.mainloop()
