import tkinter as tk
from tkinter import messagebox, ttk
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
WINDOW_SIZE = "600x500"

# Database Configuration (unchanged)
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "stegano_users"
}

# Database Functions (unchanged)
def connect_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        print(f"❌ Error: Unable to connect to MySQL: {err}")
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

# Validation Functions (unchanged)
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
    signup_window.title("Sign Up")
    signup_window.geometry(WINDOW_SIZE)
    signup_window.configure(bg=PRIMARY_COLOR)

    def submit_signup():
        # Validation logic remains unchanged
        first_name = first_name_var.get().strip()
        last_name = last_name_var.get().strip()
        gmail = gmail_var.get().strip()
        username = username_var.get().strip()
        password = password_var.get().strip()
        confirm_password = confirm_password_var.get().strip()

        if not validate_name(first_name):
            messagebox.showerror("Error", "First Name must be capitalized and contain only letters (1-20 characters).")
            return
        # ... (rest of validation unchanged)

        hashed_pw = hash_password(password)
        conn = connect_db()
        cursor = conn.cursor()
        # ... (rest of database operations unchanged)
        messagebox.showinfo("Success", "Sign up successful! You can now log in.")
        signup_window.destroy()

    frame = create_styled_frame(signup_window)
    create_styled_label(frame, "Create Account", True)

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
    login_window.title("Login")
    login_window.geometry(WINDOW_SIZE)
    login_window.configure(bg=PRIMARY_COLOR)

    def submit_login():
        # Logic remains unchanged
        username = username_var.get().strip()
        password = password_var.get().strip()
        # ... (rest of login logic unchanged)

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
    forgot_window.title("Reset Password")
    forgot_window.geometry(WINDOW_SIZE)
    forgot_window.configure(bg=PRIMARY_COLOR)

    def submit_forgot_password():
        # Logic remains unchanged
        username = username_var.get().strip()
        # ... (rest of forgot password logic unchanged)

    frame = create_styled_frame(forgot_window)
    create_styled_label(frame, "Reset Password", True)

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

# Main Authentication Window
def authentication():
    init_db()
    main_window = tk.Tk()
    main_window.title("Authentication System")
    main_window.geometry(WINDOW_SIZE)
    main_window.configure(bg=PRIMARY_COLOR)

    frame = create_styled_frame(main_window)
    create_styled_label(frame, "Authentication System", True)
    create_styled_label(frame, "Please select an option")

    create_styled_button(frame, "Sign Up", sign_up)
    create_styled_button(frame, "Login", login)
    create_styled_button(frame, "Forgot Password", forgot_password)

    main_window.mainloop()

if __name__ == "__main__":
    authentication()
