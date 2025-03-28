import tkinter as tk
from tkinter import ttk, filedialog, simpledialog
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import getpass
import psutil
import os
import base64
import hashlib
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, createStringObject

def derive_key_from_pin(pin):
    """Generuje klucz AES-256 na podstawie PIN-u."""
    return hashlib.sha256(pin.encode()).digest()


def decrypt_private_key(encrypted_data, pin):
    """Deszyfruje klucz prywatny AES-256 za pomocą podanego PIN-u."""
    key = derive_key_from_pin(pin)
    encrypted_key = encrypted_data
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        return RSA.import_key(unpad(cipher.decrypt(encrypted_key), AES.block_size))
    except (ValueError, KeyError):
        return None


def find_usb_private_key():
    """Szuka zaszyfrowanego pliku klucza na pendrive."""
    for partition in psutil.disk_partitions():
        if 'removable' in partition.opts:
            usb_path = partition.mountpoint
            key_path = os.path.join(usb_path, "private_encrypted.pem")
            if os.path.exists(key_path):
                return key_path
    return None


def check_usb_status():
    """Sprawdza, czy pendrive jest podłączony."""
    for partition in psutil.disk_partitions():
        if 'removable' in partition.opts:
            return f"Pendrive wykryty: {partition.mountpoint}"
    return "Brak wykrytego pendrive."


def update_usb_status():
    """Aktualizuje status pendrive'a w GUI."""
    usb_status_label.config(text=check_usb_status())
    root.after(2000, update_usb_status)  # Odświeżanie co 2 sekundy


def calculateSHA256(file_path):
    # with open(file_path, 'rb') as file:
        # file_data = file.read()
    ## open with pdf reader and than save it
    reader = PdfReader(file_path)
    writer = PdfWriter()

    ## save the file
    for page in reader.pages:
        writer.add_page(page)
    writer.write("temp_sign.pdf")
    with open("temp_sign.pdf", 'rb') as file:
        file_data = file.read()

    sha256_hash = SHA256.new(file_data)
    return sha256_hash


def createSignature(private_key, file_hash):
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(file_hash)
    return signature


def embedSignatureInPDF(pdf_path, signature):
    reader = PdfReader(pdf_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    metadata = reader.metadata or {}

    # Create a PdfObject for the metadata key
    metadata[NameObject("/Signature")] = createStringObject(base64.b64encode(signature).decode())

    writer.add_metadata(metadata)

    signed_pdf_path = pdf_path.replace(".pdf", "_signed.pdf")

    with open(signed_pdf_path, "wb") as signed_pdf:
        writer.write(signed_pdf)

    return signed_pdf_path


def signFile(file_path):
    key_path = find_usb_private_key()
    if not key_path:
        result_label.config(text="Nie znaleziono zaszyfrowanego klucza prywatnego na pendrive.")
        return

    pin = simpledialog.askstring("PIN", "Wprowadź PIN do deszyfrowania klucza:", show='*')
    if not pin:
        result_label.config(text="Podpis anulowany - brak PIN-u.")
        return

    with open(key_path, "rb") as key_file:
        encrypted_key = key_file.read()

    private_key = decrypt_private_key(encrypted_key, pin)
    if private_key is None:
        result_label.config(text="Niepoprawny PIN - nie można odszyfrować klucza.")
        return

    file_hash = calculateSHA256(file_path)
    signature = createSignature(private_key, file_hash)
    signed_pdf_path = embedSignatureInPDF(file_path, signature)
    result_label.config(text=f"Plik został podpisany: {signed_pdf_path}")


def verifyFile():
    selected_file_path = filedialog.askopenfilename(title="Wybierz plik do weryfikacji")
    public_key_path = filedialog.askopenfilename(title="Wybierz plik klucza publicznego")

    if not selected_file_path or not public_key_path:
        result_label.config(text="Weryfikacja anulowana - nie wybrano wszystkich plików.")
        return

    verifySignature(selected_file_path, public_key_path)


def verifySignature(selected_file_path, public_key_path):
    try:
        # Wczytanie pliku PDF
        reader = PdfReader(selected_file_path)
        metadata = reader.metadata or {}

        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        # Odczytanie podpisu z metadanych
        signature_b64 = metadata.get("/Signature", None)
        if not signature_b64:
            result_label.config(text="Brak podpisu w pliku PDF.")
            return False

        signature = base64.b64decode(signature_b64)

        writer.metadata = metadata
        writer.write("temp.pdf")

        # Obliczenie hash'a pliku
        file_hash = calculateSHA256("temp.pdf")

        # Zaimportowanie klucza publicznego
        public_key = RSA.import_key(open(public_key_path).read())
        verifier = pkcs1_15.new(public_key)

        # Weryfikacja podpisu
        try:
            verifier.verify(file_hash, signature)
            result_label.config(text="Podpis jest prawidłowy.")
            return True
        except (ValueError, TypeError):
            result_label.config(text="Podpis jest nieprawidłowy.")
            return False

    except Exception as e:
        result_label.config(text=f"Błąd weryfikacji: {str(e)}")
        return False


# GUI
root = tk.Tk()
root.title("Security of Computer Systems")
root.geometry("1200x600")

style = ttk.Style()
style.configure('TFrame', background='gray')
style.configure('TLabel', background='gray')

mainframe = ttk.Frame(root, padding="40")
mainframe.pack(expand=True, fill="both")

mode_label = ttk.Label(mainframe, text="Wybierz akcję:")
mode_label.pack(expand=True, fill="x")

usb_status_label = ttk.Label(mainframe, text=check_usb_status())
usb_status_label.pack(expand=True, fill="x")

sign_mode_button = ttk.Button(mainframe, text="Podpisz plik", command=lambda: signFile(filedialog.askopenfilename()))
sign_mode_button.pack(expand=True, fill="x")

verify_mode_button = ttk.Button(mainframe, text="Zweryfikuj podpis", command=verifyFile)
verify_mode_button.pack(expand=True, fill="x")

result_label = ttk.Label(mainframe, text="")
result_label.pack(expand=True, fill="x")

update_usb_status()  # Uruchomienie cyklicznego sprawdzania pendrive'a

root.mainloop()
