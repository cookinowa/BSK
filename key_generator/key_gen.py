# @file key_gen.py
## Skrypt do generowania par kluczy RSA, szyfrowania kluczy prywatnych i zapisywania ich do plików lub urządzeń USB.
# @details Skrypt wykorzystuje bibliotekę PyCryptodome do operacji kryptograficznych oraz Tkinter do interakcji z użytkownikiem. Zawiera funkcjonalność monitorowania urządzeń USB i zapisywania na nich zaszyfrowanych kluczy.

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import tkinter
from usbmonitor import USBMonitor
import time
from Crypto.Util.Padding import pad
from tkinter import simpledialog, messagebox, filedialog
import psutil
import os

tk = tkinter.Tk()
tk.withdraw()


## Generuje parę kluczy RSA.
# @return Obiekt klucza RSA zawierający klucze prywatny i publiczny.
def generate_rsa_key_pair():
    keys = RSA.generate(4096)
    return keys


## Szyfruje klucz prywatny za pomocą PIN-u.
# @param private_key Klucz prywatny do zaszyfrowania.
# @param pin PIN używany do szyfrowania.
# @return Zaszyfrowany klucz prywatny w postaci bajtów.
def encrypt_private_key(private_key, pin):
    pin = SHA256.new(str(pin).encode()).digest()
    aes = AES.new(pin, AES.MODE_ECB)
    private_key = pad(private_key, AES.block_size)
    cipher_text = aes.encrypt(private_key)
    return cipher_text


## Funkcja wywoływana po podłączeniu urządzenia USB.
# @param device_id ID podłączonego urządzenia USB.
# @param device_info Informacje o podłączonym urządzeniu USB.
def on_usb_connected(device_id, device_info):
    print(f"Podłączono urządzenie USB: {device_id} - {device_info}")


## Zapisuje klucz do określonego pliku.
# @param key Klucz do zapisania.
# @param file_path Ścieżka do pliku, w którym klucz zostanie zapisany.
def save_key_to_file(key, file_path):
    with open(file_path, 'wb') as f:
        f.write(key)


## Pobiera listę podłączonych urządzeń USB.
# @return Lista ścieżek do podłączonych urządzeń USB.
def get_usb_devices():
    devices = []
    if os.name == 'nt':  # Windows
        for partition in psutil.disk_partitions():
            if 'removable' in partition.opts:
                usb_path = partition.mountpoint
                devices.append(usb_path)
    else:  # Linux
        media_path = "/run/media/" + os.getlogin()
        if os.path.exists(media_path):
            devices = [os.path.join(media_path, d) for d in os.listdir(media_path) if
                       os.path.isdir(os.path.join(media_path, d))]
    return devices


## Zapisuje klucz na podłączonym urządzeniu USB.
# @param key Klucz do zapisania.
def save_key_to_usb(key):
    devices = get_usb_devices()
    if not devices:
        messagebox.showerror("error", "Nie znaleziono podłączonego pendrive'a.")
        return
    for device in devices:
        key_path = os.path.join(device, "private_encrypted.pem")
        with open(key_path, 'wb') as f:
            f.write(key)
        print(f"Zapisano klucz na {device}")


## Zapisuje klucz na urządzeniu USB wybranym za pomocą interfejsu użytkownika.
# @param key Klucz do zapisania.
def save_key_to_usb_with_ui(key):
    devices = get_usb_devices()
    if not devices:
        messagebox.showerror("Błąd", "Nie znaleziono podłączonego pendrive'a.")
        return
    device = filedialog.askdirectory(title="Wybierz urządzenie USB", initialdir=devices[0])
    if not device:
        messagebox.showerror("Błąd", "Nie wybrano urządzenia USB.")
        return
    filename = "klucz_prywatny_zaszyfrowany.pem"
    key_path = os.path.join(device, filename)
    with open(key_path, 'wb') as f:
        f.write(key)
    messagebox.showinfo("Sukces", f"Zapisano klucz na {key_path}")


## Funkcja pomocniczas do odszyfrowania klucza prywatnego.
#@param encrypted_key_location Ścieżka do pliku z zaszyfrowanym kluczem.
#@param pin PIN używany do odszyfrowania.
#@return Odszyfrowany klucz prywatny.
def decrypt_private_key(encrypted_key_location, pin):
    with open(encrypted_key_location, 'rb') as f:
        encrypted_key = f.read()
    pin = SHA256.new(str(pin).encode()).digest()
    aes = AES.new(pin, AES.MODE_ECB)
    decrypted_key = aes.decrypt(encrypted_key)
    return decrypted_key


## Wyświetla okno popup z wiadomością.
# @param message Wiadomość do wyświetlenia w oknie popup.
# @return Obiekt okna popup.
def show_popup(message):
    popup = tkinter.Toplevel()
    popup.title("Generowanie kluczy RSA")
    label = tkinter.Label(popup, text=message)
    label.pack()
    popup.update()
    return popup


monitor = USBMonitor()

monitor.start_monitoring(on_connect=on_usb_connected)

# print(decrypt_private_key("private_encrypted.pem", "2137"))

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
save_key_to_file(keys.publickey().export_key(), "public.pem")

save_to_usb = messagebox.askyesno("Zapisz na USB", "Czy chcesz zapisać zaszyfrowany klucz na urządzeniu USB?")
if save_to_usb:
    save_key_to_usb_with_ui(encrypted_key)

monitor.stop_monitoring()
