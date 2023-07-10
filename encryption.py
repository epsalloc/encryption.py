import tkinter as tk
from tkinter import filedialog
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
import base64

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_file_aes(file_path, key):
    cipher = AES.new(key, AES.MODE_EAX) #encrypt-then-authenticate-then-translate
    with open(file_path, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag

def decrypt_file_aes(file_path, key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(file_path, 'wb') as f:
        f.write(data)

def encrypt_key_rsa(public_key, key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(key)
    return encrypted_key

def decrypt_key_rsa(private_key, encrypted_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    key = cipher_rsa.decrypt(encrypted_key)
    return key

def browse_file():
    file_path = filedialog.askopenfilename()
    return file_path

def browse_folder():
    folder_path = filedialog.askdirectory()
    return folder_path

def encrypt():
    file_path = browse_file()
    private_key, public_key = generate_key_pair()
    key = get_random_bytes(32)
    nonce, ciphertext, tag = encrypt_file_aes(file_path, key)
    encrypted_key = encrypt_key_rsa(public_key, key)

    # şifreli veriyi ve anahatları kaydet
    with open(file_path + '.enc', 'wb') as f:
        f.write(base64.b64encode(nonce))
        f.write(b'\n')
        f.write(base64.b64encode(ciphertext))
        f.write(b'\n')
        f.write(base64.b64encode(tag))

    with open('private_key.pem', 'wb') as f:
        f.write(private_key)

    with open('public_key.pem', 'wb') as f:
        f.write(public_key)

    with open('encrypted_key.bin', 'wb') as f:
        f.write(encrypted_key)

def decrypt():
    file_path = browse_file()
    with open('private_key.pem', 'rb') as f:
        private_key = f.read()

    with open('encrypted_key.bin', 'rb') as f:
        encrypted_key = f.read()

    key = decrypt_key_rsa(private_key, encrypted_key)

    with open(file_path, 'rb') as f:
        nonce = base64.b64decode(f.readline().strip())
        ciphertext = base64.b64decode(f.readline().strip())
        tag = base64.b64decode(f.readline().strip())

    decrypt_file_aes(file_path[:-4], key, nonce, ciphertext, tag)

def encrypt_text():
    text = text_box.get("1.0", "end-1c")
    private_key, public_key = generate_key_pair()
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    nonce = cipher.nonce
    encrypted_key = encrypt_key_rsa(public_key, key)

    folder_path = browse_folder()

    # Save encrypted data and keys
    with open(folder_path + '/encrypted_text.enc', 'wb') as f:
        f.write(base64.b64encode(nonce))
        f.write(b'\n')
        f.write(base64.b64encode(ciphertext))
        f.write(b'\n')
        f.write(base64.b64encode(tag))

    with open(folder_path + '/private_key.pem', 'wb') as f:
        f.write(private_key)

    with open(folder_path + '/public_key.pem', 'wb') as f:
        f.write(public_key)

    with open(folder_path + '/encrypted_key.bin', 'wb') as f:
        f.write(encrypted_key)

def decrypt_text():
    file_path = browse_file()
    with open('private_key.pem', 'rb') as f:
        private_key = f.read()

    with open('encrypted_key.bin', 'rb') as f:
        encrypted_key = f.read()

    key = decrypt_key_rsa(private_key, encrypted_key)

    with open(file_path, 'rb') as f:
        nonce = base64.b64decode(f.readline().strip())
        ciphertext = base64.b64decode(f.readline().strip())
        tag = base64.b64decode(f.readline().strip())

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    text_box.delete("1.0", "end")
    text_box.insert("1.0", data.decode())

def save_text():
    text = text_box.get("1.0", "end-1c")
    file_path = browse_file()
    with open(file_path, 'w') as f:
        f.write(text)

def toggle():
    if var.get() == 1: #Dosya şifrele
        app.geometry("400x100")
        encrypt_button.pack(pady=5)
        decrypt_button.pack(pady=5)
        text_box.pack_forget()
        encrypt_text_button.pack_forget()
        decrypt_text_button.pack_forget()
    else: # Metin şifrele
        app.geometry("400x280")
        encrypt_button.pack_forget()
        decrypt_button.pack_forget()
        text_box.pack(padx=10,pady=5)
        encrypt_text_button.pack(pady=5)
        decrypt_text_button.pack(pady=5)
        

app = tk.Tk()
app.title("Dosya Şifreleme ve Şifre Çözme")
app.geometry("400x280")

var = tk.IntVar()
checkbox = tk.Checkbutton(app, text="Dosya Şifrele", variable=var, command=toggle)
checkbox.pack()

encrypt_button = tk.Button(app, text="Dosya Şifrele", command=encrypt,width=20)
#encrypt_button.pack(pady=5)

decrypt_button = tk.Button(app, text="Dosya Şifre Çöz", command=decrypt,width=20)
#decrypt_button.pack(pady=5)

text_box = tk.Text(app, height=10, width=45)
text_box.pack(padx=10,pady=5)

encrypt_text_button = tk.Button(app, text="Metin Şifrele", command=encrypt_text,width=20)
encrypt_text_button.pack(pady=5)

decrypt_text_button = tk.Button(app, text="Metin Şifresini Çöz", command=decrypt_text,width=20)
decrypt_text_button.pack(pady=5)

save_text_button = tk.Button(app, text="Çıktıyı Kaydet", command=save_text,width=20)
#save_text_button.pack(pady=5)

app.mainloop()
