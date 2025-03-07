import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, PngImagePlugin
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from bitarray import bitarray
import os

# Function to Extract Metadata (IV, Salt, Iterations) from Image
def extract_metadata_from_image(image_path):
    img = Image.open(image_path)
    metadata = img.text  # Extract metadata from the image

    iv = bytes.fromhex(metadata.get("IV", ""))  # Extract IV (Initialization Vector)
    salt = bytes.fromhex(metadata.get("Salt", ""))  # Extract Salt
    iterations = int(metadata.get("Iterations", "100000"))  # Extract Iterations
    data_size = int(metadata.get("EncryptedDataSize",""))

    return iv, salt, iterations, data_size

# Function to Decrypt PDF using Password and Return the Original PDF Data
def decrypt_pdf_with_password(encrypted_pdf_data, password, iv, salt, iterations):
    # Derive the key using PBKDF2HMAC with the password, salt, and iterations
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit AES key
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive the key

    # Print the decryption key (in hex format)
    print(f"Decryption key: {key.hex()}")  # Prints the key in a human-readable hex format

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  # Create AES cipher in CBC mode
    decryptor = cipher.decryptor()  # Create a decryptor

    try:
        decrypted_data = decryptor.update(encrypted_pdf_data) + decryptor.finalize()  # Decrypt the data
    except ValueError as e:
        raise ValueError("Decryption failed. Ensure the correct password and valid data.") from e

    # Remove PKCS7 Padding (Make sure the data was padded during encryption)
    unpadder = padding.PKCS7(128).unpadder()
    try:
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    except ValueError as e:
        raise ValueError("Padding error. Ensure the data was correctly padded during encryption.") from e

    return unpadded_data

# Function to Extract Encrypted PDF from Image
def extract_pdf_from_image(image_path, data_size):
    img = Image.open(image_path)
    pixels = img.load()

    width, height = img.size
    total_pixels = width * height
    data_bits = bitarray()  # Initialize bitarray for storing extracted data
    expected_bits = data_size * 8

    bit_index = 0
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]  # Get RGB values from pixel
            data_bits.append(r & 0x01)  # Extract LSB of red component
            data_bits.append(g & 0x01)  # Extract LSB of green component
            data_bits.append(b & 0x01)  # Extract LSB of blue component
            bit_index += 3
            if (bit_index >= expected_bits):
                break
    data_bytes = data_bits[:expected_bits]

    # Convert bitarray to bytes
    encrypted_pdf_data = data_bytes.tobytes()
    return encrypted_pdf_data

# Function to Decrypt and Save the PDF
def decrypt_and_save_pdf():
    password = password_entry.get()  # Get the password from the UI

    if not password:
        messagebox.showwarning("Input Error", "Please enter a password!")  # Check if password is provided
        return

    image_path = image_file_label.cget("text")  # Get image path from the UI

    if image_path == "No image selected":
        messagebox.showwarning("Input Error", "Please select an image file!")  # Ensure image is selected
        return

    try:
        # Extract encrypted PDF data from the image


        # Extract metadata (IV, Salt, Iterations) from the image
        iv, salt, iterations,data_size = extract_metadata_from_image(image_path)

        encrypted_pdf_data = extract_pdf_from_image(image_path, data_size)

        # Debugging: Check the length of encrypted PDF data
        print(f"Length of encrypted data: {len(encrypted_pdf_data)}")

        # Decrypt the PDF data using the password, IV, salt, and iterations
        decrypted_pdf_data = decrypt_pdf_with_password(encrypted_pdf_data, password, iv, salt, iterations)

        # Save the decrypted PDF to a file
        output_pdf_path = "decrypted_pdf.pdf"
        with open(output_pdf_path, 'wb') as f:
            f.write(decrypted_pdf_data)

        messagebox.showinfo("Success", f"PDF decrypted and saved as {output_pdf_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Update Label Text After File Selection (for image file)
def update_image_file_label():
    image_path = filedialog.askopenfilename(title="Select Image File", filetypes=[("PNG Files", "*.png")])
    if image_path:
        image_file_label.config(text=image_path)

# Create the main application window for Tkinter
root = tk.Tk()
root.title("PDF Decryptor and Extractor")

# Set the size of the window
root.geometry("400x300")

# Add a password input field
password_label = tk.Label(root, text="Enter Password:")
password_label.pack(pady=10)

password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack(pady=5)

# Add a file selection for image
image_file_label = tk.Label(root, text="No image selected", relief="solid", width=40, height=2)
image_file_label.pack(pady=10)

select_image_button = tk.Button(root, text="Select Image File", command=update_image_file_label)
select_image_button.pack(pady=5)

# Add the "Decrypt" button
decrypt_button = tk.Button(root, text="Decrypt and Save PDF", command=decrypt_and_save_pdf)
decrypt_button.pack(pady=20)

# Run the application
root.mainloop()