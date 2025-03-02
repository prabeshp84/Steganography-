import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import numpy as np
import cv2
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import mysql.connector
import bcrypt
import re

# UI Constants
PRIMARY_COLOR = "#1E2A44"    # Dark blue
ACCENT_COLOR = "#00D4FF"     # Cyan
TEXT_COLOR = "#FFFFFF"       # White
BUTTON_COLOR = "#2ECC71"     # Green
HOVER_COLOR = "#27AE60"      # Darker Green
FONT = ("Helvetica", 12)
TITLE_FONT = ("Helvetica", 16, "bold")
WINDOW_SIZE = "900x650"

# Database Configuration
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "stegano_users"
}

# Database Functions
def connect_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        messagebox.showerror("Error", f"Unable to connect to MySQL: {err}")
        exit()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(stored_password, entered_password):
    return bcrypt.checkpw(entered_password.encode(), stored_password.encode())

def init_db():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        first_name VARCHAR(50) NOT NULL,
                        last_name VARCHAR(50) NOT NULL,
                        gmail VARCHAR(100) UNIQUE NOT NULL,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL
                    )''')
    conn.commit()
    conn.close()

# Validation Functions
def validate_name(name):
    return bool(re.fullmatch(r"[A-Z][a-z]{1,19}", name))

def validate_gmail(email):
    return bool(re.fullmatch(r"[a-zA-Z0-9._%+-]{4,}@gmail\.com", email))

def validate_username(username):
    return bool(re.fullmatch(r"^(?=.*[\d])(?=.*[\W_])[a-zA-Z\d\W_]{6,25}$", username))

def validate_password(password):
    return bool(re.fullmatch(r"^(?=.*[A-Z])(?=.*[\d])(?=.*[\W_])[A-Za-z\d\W_]{8,30}$", password))

# UI Utility Functions
def create_styled_frame(parent):
    frame = tk.Frame(parent, bg=PRIMARY_COLOR)
    frame.pack(fill="both", expand=True, padx=20, pady=20)
    return frame

def create_styled_label(parent, text, is_title=False):
    font = TITLE_FONT if is_title else FONT
    label = tk.Label(parent, text=text, font=font, fg=TEXT_COLOR, bg=PRIMARY_COLOR)
    label.pack(pady=15 if is_title else 5)
    return label

def create_styled_entry(parent, var, show=None):
    entry = tk.Entry(parent, textvariable=var, font=FONT, bg="#2C3A57", fg=TEXT_COLOR,
                    insertbackground=ACCENT_COLOR, bd=0, relief="flat", width=30)
    entry.pack(pady=10, ipady=5)
    return entry

def create_styled_button(parent, text, command):
    def on_enter(e):
        button['background'] = HOVER_COLOR
    def on_leave(e):
        button['background'] = BUTTON_COLOR
    
    button = tk.Button(parent, text=text, font=FONT, bg=BUTTON_COLOR, fg=TEXT_COLOR,
                      bd=0, relief="flat", command=command, width=20, pady=5)
    button.pack(pady=15)
    button.bind("<Enter>", on_enter)
    button.bind("<Leave>", on_leave)
    return button

# Sign-up Window
def sign_up():
    signup_window = tk.Toplevel()
    signup_window.title("Sign Up - Steganography Suite")
    signup_window.geometry(WINDOW_SIZE)
    signup_window.configure(bg=PRIMARY_COLOR)

    def submit_signup():
        first_name = first_name_var.get().strip()
        last_name = last_name_var.get().strip()
        gmail = gmail_var.get().strip()
        username = username_var.get().strip()
        password = password_var.get().strip()
        confirm_password = confirm_password_var.get().strip()

        if not validate_name(first_name):
            messagebox.showerror("Error", "First Name must be capitalized and contain only letters (1-20 characters).")
            return
        if not validate_name(last_name):
            messagebox.showerror("Error", "Last Name must be capitalized and contain only letters (1-20 characters).")
            return
        if not validate_gmail(gmail):
            messagebox.showerror("Error", "Invalid Gmail! It must include '@gmail.com'.")
            return
        if not validate_username(username):
            messagebox.showerror("Error", "Username must be 6-25 characters long, contain at least one number and one special character.")
            return
        if not validate_password(password):
            messagebox.showerror("Error", "Password must be 8-30 characters long, contain at least one uppercase letter, one number, and one special character.")
            return
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        hashed_pw = hash_password(password)
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE gmail = %s", (gmail,))
        if cursor.fetchone()[0] > 0:
            messagebox.showerror("Error", "Gmail is already registered!")
            conn.close()
            return
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
        if cursor.fetchone()[0] > 0:
            messagebox.showerror("Error", "Username already exists!")
            conn.close()
            return

        cursor.execute("INSERT INTO users (first_name, last_name, gmail, username, password) VALUES (%s, %s, %s, %s, %s)",
                       (first_name, last_name, gmail, username, hashed_pw))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Sign up successful! You can now log in.")
        signup_window.destroy()

    frame = create_styled_frame(signup_window)
    create_styled_label(frame, "Create Your Account", True)

    first_name_var = tk.StringVar()
    last_name_var = tk.StringVar()
    gmail_var = tk.StringVar()
    username_var = tk.StringVar()
    password_var = tk.StringVar()
    confirm_password_var = tk.StringVar()

    for label, var, show in [
        ("First Name:", first_name_var, None),
        ("Last Name:", last_name_var, None),
        ("Gmail:", gmail_var, None),
        ("Username:", username_var, None),
        ("Password:", password_var, "*"),
        ("Confirm Password:", confirm_password_var, "*")
    ]:
        create_styled_label(frame, label)
        create_styled_entry(frame, var, show)

    create_styled_button(frame, "Sign Up", submit_signup)

# Login Window
def login():
    login_window = tk.Toplevel()
    login_window.title("Login - Steganography Suite")
    login_window.geometry(WINDOW_SIZE)
    login_window.configure(bg=PRIMARY_COLOR)

    def submit_login():
        username = username_var.get().strip()
        password = password_var.get().strip()

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and verify_password(user[0], password):
            messagebox.showinfo("Success", "Login successful! Access granted.")
            login_window.destroy()
            img_steg()
        else:
            messagebox.showerror("Error", "Invalid username or password!")
        conn.close()

    frame = create_styled_frame(login_window)
    create_styled_label(frame, "Welcome Back", True)

    username_var = tk.StringVar()
    password_var = tk.StringVar()

    create_styled_label(frame, "Username:")
    create_styled_entry(frame, username_var)
    create_styled_label(frame, "Password:")
    create_styled_entry(frame, password_var, "*")

    create_styled_button(frame, "Login", submit_login)

# Forgot Password Window
def forgot_password():
    forgot_window = tk.Toplevel()
    forgot_window.title("Reset Password - Steganography Suite")
    forgot_window.geometry(WINDOW_SIZE)
    forgot_window.configure(bg=PRIMARY_COLOR)

    def submit_forgot_password():
        username = username_var.get().strip()
        gmail = gmail_var.get().strip()
        new_password = new_password_var.get().strip()
        confirm_password = confirm_password_var.get().strip()

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = %s AND gmail = %s", (username, gmail))
        user = cursor.fetchone()

        if not user:
            messagebox.showerror("Error", "Username or Gmail is incorrect!")
            conn.close()
            return

        old_hashed_password = user[0]

        if not validate_password(new_password):
            messagebox.showerror("Error", "New password must be 8-30 characters long, contain at least one uppercase letter, one number, and one special character.")
            conn.close()
            return
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            conn.close()
            return
        if verify_password(old_hashed_password, new_password):
            messagebox.showerror("Error", "New password cannot be the same as the previous password.")
            conn.close()
            return

        hashed_pw = hash_password(new_password)
        cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_pw, username))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Password reset successful! You can now log in with your new password.")
        forgot_window.destroy()

    frame = create_styled_frame(forgot_window)
    create_styled_label(frame, "Reset Your Password", True)

    username_var = tk.StringVar()
    gmail_var = tk.StringVar()
    new_password_var = tk.StringVar()
    confirm_password_var = tk.StringVar()

    for label, var, show in [
        ("Username:", username_var, None),
        ("Gmail:", gmail_var, None),
        ("New Password:", new_password_var, "*"),
        ("Confirm Password:", confirm_password_var, "*")
    ]:
        create_styled_label(frame, label)
        create_styled_entry(frame, var, show)

    create_styled_button(frame, "Submit", submit_forgot_password)

# Authentication Window
def authentication():
    init_db()
    main_window = tk.Tk()
    main_window.title("Steganography Suite")
    main_window.geometry(WINDOW_SIZE)
    main_window.configure(bg=PRIMARY_COLOR)

    frame = create_styled_frame(main_window)
    create_styled_label(frame, "Steganography Suite", True)
    create_styled_label(frame, "Secure your secrets in images")

    create_styled_button(frame, "Sign Up", sign_up)
    create_styled_button(frame, "Login", login)
    create_styled_button(frame, "Forgot Password", forgot_password)

    main_window.mainloop()

# Steganography Window
def img_steg():
    steg_window = tk.Tk()
    steg_window.title("Image Steganography - Steganography Suite")
    steg_window.geometry(WINDOW_SIZE)
    steg_window.configure(bg=PRIMARY_COLOR)

    frame = create_styled_frame(steg_window)
    create_styled_label(frame, "Image Steganography Tools", True)
    create_styled_label(frame, "Hide and reveal secret messages in images")

    def check_image():
        file_path = filedialog.askopenfilename(title="Select Image to Check")
        if not file_path:
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found.")
            return
        _, ext = os.path.splitext(file_path)
        img_format = ext.lower().strip('.')
        size_bytes = os.path.getsize(file_path)
        size_mb = size_bytes / (1024 * 1024)
        img = cv2.imread(file_path)
        if img is None:
            messagebox.showerror("Error", "Invalid image format or unable to load image.")
            return
        height, width = img.shape[:2]
        channels = 1 if len(img.shape) == 2 else img.shape[2]
        messagebox.showinfo("Image Info", f"Format: {img_format.upper()}\nSize: {size_mb:.2f} MB\nDimensions: {width}x{height} pixels\nChannels: {channels}")

    def convert_to_png():
        file_path = filedialog.askopenfilename(title="Select Image to Convert")
        if not file_path:
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found.")
            return
        _, ext = os.path.splitext(file_path)
        if ext.lower() == '.png':
            messagebox.showerror("Error", "Image is already in PNG format. Conversion not required.")
            return
        img = cv2.imread(file_path)
        if img is None:
            messagebox.showerror("Error", "Invalid image format or unable to load image.")
            return
        new_file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")], title="Save Converted Image As")
        if not new_file_path:
            return
        try:
            compression_level = 6
            cv2.imwrite(new_file_path, img, [cv2.IMWRITE_PNG_COMPRESSION, compression_level])
            messagebox.showinfo("Success", f"Image successfully converted to PNG format as {new_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error during conversion: {e}")

    def encode_message_in_image():
        file_path = filedialog.askopenfilename(title="Select Image to Encode")
        if not file_path:
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found.")
            return
        img = cv2.imread(file_path)
        if img is None:
            messagebox.showerror("Error", "Invalid image format or unable to load image.")
            return
        key = simpledialog.askstring("Input", "Enter a 16-character encryption key:")
        if not key or len(key) != 16:
            messagebox.showerror("Error", "Key must be exactly 16 characters long.")
            return
        data = simpledialog.askstring("Input", "Enter the data to be encoded in the image:")
        if not data:
            messagebox.showerror("Error", "No data entered.")
            return
        try:
            cipher = AES.new(key.encode(), AES.MODE_CBC)
            encrypted_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
            encrypted_data = base64.b64encode(cipher.iv + encrypted_bytes).decode()
            header = format(len(encrypted_data), '032b')
            encrypted_data_bin = ''.join(format(ord(char), '08b') for char in encrypted_data)
            full_message_bin = header + encrypted_data_bin
            flat_img = img.flatten()
            bits = np.array(list(full_message_bin), dtype=np.uint8) - ord('0')
            flat_img[:len(bits)] = (flat_img[:len(bits)] & np.uint8(254)) | bits
            stego_img = flat_img.reshape(img.shape)
            output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")], title="Save Stego Image As")
            if not output_path:
                return
            cv2.imwrite(output_path, stego_img)
            messagebox.showinfo("Success", f"Data successfully encoded into {output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error during encoding: {e}")

    def decode_message_from_image():
        file_path = filedialog.askopenfilename(title="Select Image to Decode")
        if not file_path:
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found.")
            return
        img = cv2.imread(file_path)
        if img is None:
            messagebox.showerror("Error", "Invalid image format or unable to load image.")
            return
        key = simpledialog.askstring("Input", "Enter the 16-character decryption key:")
        if not key or len(key) != 16:
            messagebox.showerror("Error", "Key must be exactly 16 characters long.")
            return
        try:
            flat_img = img.flatten()
            bits = flat_img & 1
            header_bits = bits[:32]
            header_str = ''.join(str(b) for b in header_bits)
            encrypted_length = int(header_str, 2)
            required_bits = 32 + encrypted_length * 8
            encrypted_bits = bits[32:required_bits]
            encrypted_bin_str = ''.join(str(b) for b in encrypted_bits)
            encrypted_message = ''.join(chr(int(encrypted_bin_str[i:i+8], 2)) for i in range(0, len(encrypted_bin_str), 8))
            raw = base64.b64decode(encrypted_message)
            iv = raw[:AES.block_size]
            cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
            decrypted_message = unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode()
            messagebox.showinfo("Decoded Message", f"Decoded message: {decrypted_message}")
        except Exception as e:
            messagebox.showerror("Error", "Error: Incorrect decryption key or corrupted data.")

    for text, command in [
        ("Check Image Details", check_image),
        ("Convert to PNG", convert_to_png),
        ("Encode Message", encode_message_in_image),
        ("Decode Message", decode_message_from_image),
        ("Exit", steg_window.destroy)
    ]:
        create_styled_button(frame, text, command)

    steg_window.mainloop()

if __name__ == "__main__":
    authentication()
