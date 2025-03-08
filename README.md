Asterion: Encrypt and Embed PDF in Image
Overview

Asterion is a Python-based tool that helps you protect private PDF files by encrypting them using AES-256 encryption and embedding the encrypted data into an image file using steganography. The image appears to be normal visually, while it secretly holds the encrypted PDF data.
Features

    Encrypts PDF Files using AES-256 encryption with a password.
    Embeds Encrypted PDF into an image using steganography (modifying the least significant bits of the image's pixels).
    Saves Image as a PNG file with metadata containing the encryption details such as the IV (Initialization Vector), salt, and iterations.
    Password-based Protection: Only the correct password can decrypt the image and retrieve the original PDF.

Requirements

    Python 3.x
    tkinter for the graphical user interface (GUI)
    Pillow for image manipulation
    cryptography for encryption
    bitarray for handling binary data

Install the dependencies with:

pip install -r requirements.txt

The requirements.txt should contain:

tkinter
Pillow
cryptography
bitarray

Usage

    Launch the Application: Run the Asterion.py script, and the GUI will appear.

python Asterion.py

    Select PDF File: Click Select PDF File to choose the PDF that you want to encrypt.

    Select Image File: Click Select Image File to select an image in which the encrypted PDF will be embedded.

    Enter Password: Enter a strong password for encryption.

    Encrypt and Embed: After entering the password and selecting the files, click Encrypt and Embed. The script will:
        Encrypt the PDF using AES-256.
        Embed the encrypted data into the image's MSBs.
        Save the image with encryption metadata (IV, salt, iterations) in PNG format.
        Display a success message with the output image path.

GUI Interface

    Password: Enter a strong password that will be used for encryption.
    Select Image File: Select the image where the encrypted data will be embedded.
    Select PDF File: Choose the PDF you want to encrypt and embed.
    Encrypt and Embed: Click this button to start the encryption and embedding process.

Example Workflow

    Encrypt PDF and Embed:
        Select a PDF file and an image file.
        Enter a password for encryption.
        Click Encrypt and Embed to generate the encrypted image.

    Result: The image is saved as output_image_with_pdf.png with the encrypted PDF data embedded. You can now securely share this image.

Code Walkthrough
Main Functions:

    encrypt_pdf_with_password(pdf_path, password):
        Encrypts the PDF using AES with the provided password.
        Generates a salt and IV (Initialization Vector).
        Returns the IV, salt, iterations, encrypted data, and padded data.

    embed_pdf_in_image(image_path, encrypted_pdf_data, output_image_path):
        Embeds the encrypted PDF data into the selected image by modifying the MSBs of each pixel.
        Saves the modified image as a PNG file.

    GUI Workflow:
        The user selects the PDF and image files, enters a password, and clicks Encrypt and Embed to start the encryption process.
        The encrypted PDF is then embedded into the image and saved as a new PNG image file.

Example Output

    The encrypted image is saved as output_image_with_pdf.png containing the metadata with the IV, salt, and encryption details.

Error Handling

    The program handles various errors such as invalid password, missing files, or image size issues (if the image is too small to embed the data).

Security Considerations

    Encryption Security: The strength of the encryption depends on the password you choose. Make sure to use a strong password for AES-256 encryption.
    Backup the Password: You will need the password to decrypt the image later. Without it, you cannot recover the original PDF.

License

This project is licensed under the MIT License - see the LICENSE file for details.
