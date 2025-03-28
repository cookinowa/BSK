from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import tkinter
from usbmonitor import USBMonitor
import time
from Crypto.Util.Padding import pad
from tkinter import simpledialog, messagebox
tk = tkinter.Tk()

tk.withdraw()

def generate_rsa_key_pair():
    keys = RSA.generate(4096)
    return keys


def encrypt_private_key(private_key, pin):
    pin = SHA256.new(str(pin).encode()).digest()
    aes = AES.new(pin, AES.MODE_ECB)
    private_key = pad(private_key, AES.block_size)
    cipher_text = aes.encrypt(private_key)
    return cipher_text
    

def on_usb_connected(device_id, device_info):
    print(f"Podłączono urządzenie USB: {device_id} - {device_info}")


def save_key_to_file(key, file_path):
    with open(file_path, 'wb') as f:
        f.write(key)


def show_popup(message):
    popup = tkinter.Toplevel()
    popup.title("Generowanie kluczy RSA")
    label = tkinter.Label(popup, text=message)
    label.pack()
    popup.update()
    return popup


monitor = USBMonitor()

monitor.start_monitoring(on_connect=on_usb_connected)




print("Generowanie kluczy RSA")
popup = show_popup("Generowanie kluczy RSA")
keys = generate_rsa_key_pair()
popup.destroy()

pin = simpledialog.askstring("Podaj PIN", "Podaj PIN", show='*')
if not pin:
    messagebox.showerror("error", "nie podano PINu")
    exit()

encrypted_key = encrypt_private_key(keys.export_key(), pin)
print(encrypted_key)
save_key_to_file(encrypted_key, "private_encrypted.pem")
monitor.stop_monitoring()
