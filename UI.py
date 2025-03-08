import tkinter as tk
from tkinter import messagebox, scrolledtext
from firewall import Firewall
import hashlib
import logging
import time
import json

# Configure logging
logging.basicConfig(filename="security.log", level=logging.INFO, format='%(asctime)s - %(message)s')

# Initialize Firewall instance
firewall = Firewall()

# Load firewall rules from file
RULES_FILE = "firewall_rules.json"
def load_rules():
    try:
        with open(RULES_FILE, "r") as file:
            rules = json.load(file)
            for rule in rules:
                firewall.add_rule(rule)
    except FileNotFoundError:
        pass

def save_rules():
    with open(RULES_FILE, "w") as file:
        json.dump(firewall.get_rules(), file)

load_rules()

# Placeholder user data with role-based access control
users = {
    "admin": {"password": hashlib.sha256("password".encode()).hexdigest(), "role": "admin"},
    "user": {"password": hashlib.sha256("userpass".encode()).hexdigest(), "role": "user"}
}

current_user = None
last_activity_time = time.time()

def reset_activity_timer():
    global last_activity_time
    last_activity_time = time.time()
    update_status_bar()

def check_session_timeout():
    if time.time() - last_activity_time > 300:
        messagebox.showwarning("Session Timeout", "Session expired due to inactivity.")
        root.quit()
    root.after(60000, check_session_timeout)

def toggle_dark_mode():
    bg_color = "black" if root.cget("bg") == "white" else "white"
    fg_color = "white" if bg_color == "black" else "black"
    
    root.configure(bg=bg_color)
    for widget in root.winfo_children():
        try:
            widget.configure(bg=bg_color, fg=fg_color)
        except:
            pass

def login():
    global current_user
    username = entry_username.get()
    password = hashlib.sha256(entry_password.get().encode()).hexdigest()
    
    if username in users and users[username]["password"] == password:
        current_user = username
        messagebox.showinfo("Login Success", f"Welcome {username} to Poseidon's Trident Security Dashboard!")
        logging.info(f"User {username} logged in.")
        reset_activity_timer()
        show_dashboard()
    else:
        messagebox.showerror("Login Failed", "Invalid credentials")
        logging.warning(f"Failed login attempt: {username}")

def is_admin():
    return users.get(current_user, {}).get("role") == "admin"

def show_dashboard():
    login_frame.pack_forget()
    dashboard_frame.pack(pady=20)
    update_status_bar()

def open_firewall_management():
    if not is_admin():
        messagebox.showerror("Access Denied", "Only admins can access Firewall Management.")
        return
    
    firewall_window = tk.Toplevel(root)
    firewall_window.title("Firewall Management")
    firewall_window.geometry("500x400")
    
    tk.Label(firewall_window, text="Firewall Management", font=("Arial", 14)).pack()
    rule_entry = tk.Entry(firewall_window)
    rule_entry.pack()
    
    log_area = scrolledtext.ScrolledText(firewall_window, width=50, height=10)
    log_area.pack()
    
    def update_log():
        log_area.delete(1.0, tk.END)
        log_area.insert(tk.END, "\n".join(firewall.get_rules()))
        log_area.yview(tk.END)
    
    def add_rule():
        rule = rule_entry.get()
        if rule:
            firewall.add_rule(rule)
            save_rules()
            logging.info(f"Firewall rule added: {rule}")
            messagebox.showinfo("Firewall", f"Rule '{rule}' added!")
            rule_entry.delete(0, tk.END)
            update_log()
    
    def remove_rule():
        rule = rule_entry.get()
        if rule in firewall.get_rules():
            firewall.remove_rule(rule)
            save_rules()
            logging.info(f"Firewall rule removed: {rule}")
            messagebox.showinfo("Firewall", f"Rule '{rule}' removed!")
            rule_entry.delete(0, tk.END)
            update_log()
    
    tk.Button(firewall_window, text="Add Rule", command=add_rule).pack()
    tk.Button(firewall_window, text="Remove Rule", command=remove_rule).pack()
    tk.Button(firewall_window, text="Refresh", command=update_log).pack()
    tk.Button(firewall_window, text="Apply Firewall", command=lambda: firewall.apply_rules()).pack()
    update_log()

def open_intrusion_detection():
    intrusion_window = tk.Toplevel(root)
    intrusion_window.title("Intrusion Detection")
    intrusion_window.geometry("500x300")
    
    tk.Label(intrusion_window, text="Intrusion Detection System", font=("Arial", 14)).pack()
    
    log_text = scrolledtext.ScrolledText(intrusion_window, height=10, width=50)
    log_text.pack()
    
    def detect_intrusion():
        intrusion_message = "Suspicious activity detected from IP: 192.168.1.10"
        log_text.insert(tk.END, intrusion_message + "\n")
        logging.warning("Intrusion detected: " + intrusion_message)
        messagebox.showwarning("Intrusion Alert", intrusion_message)
    
    tk.Button(intrusion_window, text="Simulate Intrusion", command=detect_intrusion).pack()

def logout():
    global current_user
    current_user = None
    dashboard_frame.pack_forget()
    login_frame.pack()
    entry_username.delete(0, tk.END)  # Clear username field
    entry_password.delete(0, tk.END)  # Clear password field
    update_status_bar()

def real_time_logs():
    logs_window = tk.Toplevel(root)
    logs_window.title("Real-Time Security Logs")
    logs_window.geometry("500x300")
    
    log_text = scrolledtext.ScrolledText(logs_window, height=10, width=50)
    log_text.pack()
    
    def update_logs():
        with open("security.log", "r") as log_file:
            log_text.delete(1.0, tk.END)
            log_text.insert(tk.END, log_file.read())
        log_text.yview(tk.END)
        logs_window.after(5000, update_logs)
    
    update_logs()

def toggle_password():
    current_state = entry_password.cget("show")
    entry_password.config(show="" if current_state == "*" else "*")

def update_status_bar():
    if current_user:
        status_text.set(f"Logged in as: {current_user} | Session Active")
    else:
        status_text.set("Not logged in")

def start_ui():
    global root, login_frame, dashboard_frame, entry_username, entry_password, status_text
    root = tk.Tk()
    root.title("Poseidon's Trident - Security Dashboard")
    root.geometry("500x400")

    # Login Frame
    login_frame = tk.Frame(root)
    login_frame.pack(pady=50)
    
    tk.Label(login_frame, text="Username:").pack()
    entry_username = tk.Entry(login_frame)
    entry_username.pack()
    
    tk.Label(login_frame, text="Password:").pack()
    password_frame = tk.Frame(login_frame)
    entry_password = tk.Entry(password_frame, show="*")
    entry_password.pack(side=tk.LEFT)
    tk.Button(password_frame, text="👁", command=toggle_password).pack(side=tk.LEFT)
    password_frame.pack()
    
    tk.Button(login_frame, text="Login", command=login).pack(pady=5)
    tk.Button(login_frame, text="Toggle Dark Mode", command=toggle_dark_mode).pack()

    # Dashboard Frame
    dashboard_frame = tk.Frame(root)
    tk.Button(dashboard_frame, text="Firewall Management", command=open_firewall_management).pack()
    tk.Button(dashboard_frame, text="Intrusion Detection", command=open_intrusion_detection).pack()
    tk.Button(dashboard_frame, text="Real-Time Logs", command=real_time_logs).pack()
    tk.Button(dashboard_frame, text="Logout", command=logout).pack()
    tk.Button(dashboard_frame, text="Toggle Dark Mode", command=toggle_dark_mode).pack()

    # Status Bar
    status_text = tk.StringVar()
    status_label = tk.Label(root, textvariable=status_text, bd=1, relief=tk.SUNKEN, anchor="w")
    status_label.pack(side=tk.BOTTOM, fill=tk.X)
    update_status_bar()

    root.after(60000, check_session_timeout)
    root.mainloop()

start_ui()
