import tkinter as tk
from tkinter import messagebox, scrolledtext
from firewall import Firewall
import hashlib
import logging
import time
import json
import os
import psutil

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
permissions = {
    "admin": ["firewall", "intrusion", "network", "all"],
    "user": ["network"]
}
def reset_activity_timer():
    global last_activity_time
    last_activity_time = time.time()
    update_status_bar()

def check_session_timeout():
    if time.time() - last_activity_time > 300:  # 5 minutes inactivity timeout
        messagebox.showwarning("Session Timeout", "Session expired due to inactivity.")
        root.quit()
    root.after(60000, check_session_timeout)

def on_entry_click(event, entry, default_text):
    """Clears the placeholder text when clicking on an entry field."""
    if entry.get() == default_text:
        entry.delete(0, tk.END)
        entry.config(fg="black", show="*" if "Password" in default_text else "")

def on_focus_out(event, entry, default_text):
    """Restores the placeholder text if the field is left empty."""
    if entry.get() == "":
        entry.insert(0, default_text)
        entry.config(fg="grey", show="")

def toggle_password_visibility(entry):
    """Toggles password visibility."""
    current_state = entry.cget("show")
    entry.config(show="" if current_state == "*" else "*")

def toggle_dark_mode():
    """Toggles dark mode."""
    bg_color = "#D1F6FF" if root.cget("bg") == "#0A1F44" else "#0A1F44"
    fg_color = "#bde0fe" if bg_color == "#FFFFFF" else "#FFFFFF"
    
    root.configure(bg=bg_color)
    for widget in root.winfo_children():
        try:
            widget.configure(bg=bg_color, fg=fg_color)
        except:
            pass

def is_admin():
    return users.get(current_user, {}).get("role") == "admin"

def login():
    global current_user
    username = entry_username.get()
    password = hashlib.sha256(entry_password.get().encode()).hexdigest()
    
    if username in users and users[username]["password"] == password:
        current_user = username
        messagebox.showinfo("Login Success", f"Welcome {username}")
        logging.info(f"User {username} logged in.")
        reset_activity_timer()
        show_dashboard()
    else:
        messagebox.showerror("Login Failed", "Invalid credentials")
        logging.warning(f"Failed login attempt: {username}")

def monitor_network():
    """Displays active network connections."""
    network_window = tk.Toplevel(root)
    network_window.title("Real-Time Network Monitoring")
    network_window.geometry("600x400")
    
    text_area = scrolledtext.ScrolledText(network_window, width=70, height=15)
    text_area.pack(pady=10)

    def update_network_log():
        text_area.delete(1.0, tk.END)
        connections = psutil.net_connections()
        for conn in connections[:10]:  # Show first 10 connections
            text_area.insert(tk.END, f"IP: {conn.laddr.ip} Port: {conn.laddr.port} Status: {conn.status}\n")
        network_window.after(5000, update_network_log)  # Refresh every 5 sec

    update_network_log()

def logout():
    global current_user
    logging.info(f"User {current_user} logged out.")
    current_user = None
    dashboard_frame.pack_forget()
    login_frame.pack()
    entry_username.delete(0, tk.END)
    entry_password.delete(0, tk.END)
    entry_username.insert(0, "Username")
    entry_password.insert(0, "Password")
    entry_username.config(fg="grey")
    entry_password.config(fg="grey", show="")

def show_dashboard():
    login_frame.pack_forget()
    dashboard_frame.pack(expand=True, fill=tk.BOTH)
    if is_admin():
        btn_firewall.pack(pady=5)
        btn_intrusion.pack(pady=5)
    else:
        btn_firewall.pack_forget()
        btn_intrusion.pack_forget()
    update_status_bar()
        
def open_firewall_management():
    if not is_admin():
        messagebox.showerror("Access Denied", "Only admins can access Firewall Management.")
        return
    
    firewall_window = tk.Toplevel(root)
    firewall_window.title("Firewall Management")
    firewall_window.geometry("500x400")
    firewall_window.configure(bg=root.cget("bg"))
    
    tk.Label(firewall_window, text="Firewall Management", font=("Arial", 14), bg=root.cget("bg"), fg=root.cget("fg")).pack(pady=10)
    rule_entry = tk.Entry(firewall_window, width=40)
    rule_entry.pack(pady=10)
    
    log_area = scrolledtext.ScrolledText(firewall_window, width=50, height=10)
    log_area.pack(pady=10)
    
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
    
    def enable_firewall():
        logging.info("Firewall enabled")
        messagebox.showinfo("Firewall", "Firewall enabled!")
    
    def disable_firewall():
        logging.info("Firewall disabled")
        messagebox.showinfo("Firewall", "Firewall disabled!")
    
    tk.Button(firewall_window, text="Add Rule", command=add_rule, bg="#1E90FF", fg="white").pack(side=tk.LEFT, padx=10)
    tk.Button(firewall_window, text="Remove Rule", command=remove_rule, bg="#FF4500", fg="white").pack(side=tk.LEFT, padx=10)
    tk.Button(firewall_window, text="Refresh", command=update_log, bg="#228B22", fg="white").pack(side=tk.LEFT, padx=10)
    tk.Button(firewall_window, text="Enable Firewall", command=enable_firewall, bg="#32CD32", fg="white").pack(side=tk.LEFT, padx=10)
    tk.Button(firewall_window, text="Disable Firewall", command=disable_firewall, bg="#FF6347", fg="white").pack(side=tk.LEFT, padx=10)
    update_log()

def open_intrusion_detection():
    intrusion_window = tk.Toplevel(root)
    intrusion_window.title("Intrusion Detection")
    intrusion_window.geometry("500x300")
    intrusion_window.configure(bg=root.cget("bg"))
    
    tk.Label(intrusion_window, text="Intrusion Detection System", font=("Arial", 14), bg=root.cget("bg"), fg=root.cget("fg")).pack(pady=10)
    
    log_text = scrolledtext.ScrolledText(intrusion_window, height=10, width=50)
    log_text.pack(pady=10)
    
    def detect_intrusion():
        intrusion_message = "Suspicious activity detected from IP: 192.168.1.10"
        log_text.insert(tk.END, intrusion_message + "\n")
        logging.warning("Intrusion detected: " + intrusion_message)
        messagebox.showwarning("Intrusion Alert", intrusion_message)
    
    tk.Button(intrusion_window, text="Simulate Intrusion", command=detect_intrusion, bg="#FF4500", fg="white").pack()

def open_network_monitoring():
    monitoring_window = tk.Toplevel(root)
    monitoring_window.title("Network Monitoring")
    monitoring_window.geometry("500x300")
    monitoring_window.configure(bg=root.cget("bg"))
    
    tk.Label(monitoring_window, text="Network Monitoring", font=("Arial", 14), bg=root.cget("bg"), fg=root.cget("fg")).pack(pady=10)
    
    log_text = scrolledtext.ScrolledText(monitoring_window, height=10, width=50)
    log_text.pack(pady=10)
    
    def monitor_network():
        network_message = "Monitoring traffic on port 80..."
        log_text.insert(tk.END, network_message + "\n")
        logging.info("Network Monitoring: " + network_message)
        messagebox.showinfo("Network Monitoring", network_message)
    
    tk.Button(monitoring_window, text="Start Monitoring", command=monitor_network, bg="#228B22", fg="white").pack()

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
    global root, login_frame, dashboard_frame, entry_username, entry_password, btn_firewall, btn_intrusion, status_text
    root = tk.Tk()
    root.title("Poseidon's Trident - Security Dashboard")
    root.geometry("400x500")
    root.configure(bg="#0A1F44")  # Deep ocean blue theme

    # Login Frame (Minimal and Rounded)
    login_frame = tk.Frame(root, bg="#102A66", padx=20, pady=20, relief="flat", bd=0)
    login_frame.place(relx=0.5, rely=0.5, anchor="center")

    tk.Label(login_frame, text="Poseidon's Trident 🔱", font=("Georgia", 18, "bold"), bg="#102A66", fg="#FFD700").pack(pady=10)
    tk.Label(login_frame, text="Guarding the Digital Seas", font=("Arial", 12), fg="#A9A9A9", bg="#102A66").pack()

    # Username Field
    entry_username = tk.Entry(login_frame, width=30, relief="flat", bd=2, fg="grey")
    entry_username.insert(0, "Username")
    entry_username.bind("<FocusIn>", lambda event: on_entry_click(event, entry_username, "Username"))
    entry_username.bind("<FocusOut>", lambda event: on_focus_out(event, entry_username, "Username"))
    entry_username.pack(pady=5, ipady=5)

    # Password Field
    entry_password = tk.Entry(login_frame, width=30, relief="flat", bd=2, fg="grey")
    entry_password.insert(0, "Password")
    entry_password.bind("<FocusIn>", lambda event: on_entry_click(event, entry_password, "Password"))
    entry_password.bind("<FocusOut>", lambda event: on_focus_out(event, entry_password, "Password"))
    entry_password.pack(pady=5, ipady=5)

    # Eye Icon for Password Visibility
    eye_icon_frame = tk.Frame(login_frame, bg="#102A66")
    eye_icon_frame.pack()
    tk.Button(eye_icon_frame, text="👁", command=lambda: toggle_password_visibility(entry_password), bg="#102A66", fg="white", relief="flat", bd=0).pack(side=tk.RIGHT)

    # Login Button
    tk.Button(login_frame, text="Login", command=login, bg="#1E90FF", fg="white", font=("Arial", 12, "bold"), width=15, relief="flat", bd=0).pack(pady=10)

    # Dark Mode Toggle
    tk.Button(login_frame, text="Toggle Dark Mode", command=toggle_dark_mode, bg="#1E90FF", fg="white", relief="flat", bd=0).pack(pady=5)

    # Dashboard Frame
    dashboard_frame = tk.Frame(root, bg="#0A1F44")
    tk.Label(dashboard_frame, text="🌊 Welcome to Poseidon's Dashboard 🌊", font=("Georgia", 14, "bold"), bg="#0A1F44", fg="#FFD700").pack(pady=10)
    btn_firewall = tk.Button(dashboard_frame, text="Firewall Management", command=open_firewall_management, bg="#1E90FF", fg="white", relief="flat", bd=0)
    btn_firewall.pack(pady=5)
    btn_intrusion = tk.Button(dashboard_frame, text="Intrusion Detection", command=open_intrusion_detection, bg="#FF4500", fg="white", relief="flat", bd=0)
    btn_intrusion.pack(pady=5)
    tk.Button(dashboard_frame, text="Network Monitoring", command=open_network_monitoring, bg="#228B22", fg="white", relief="flat", bd=0).pack(pady=5)
    tk.Button(dashboard_frame, text="Real-Time Logs", command=real_time_logs, bg="#228B22", fg="white", relief="flat", bd=0).pack(pady=5)
    tk.Button(dashboard_frame, text="Logout", command=logout, bg="#FF4500", fg="white", relief="flat", bd=0).pack(pady=5)

    # Status Bar
    status_text = tk.StringVar()
    status_label = tk.Label(root, textvariable=status_text, bd=1, relief=tk.SUNKEN, anchor="w")
    status_label.pack(side=tk.BOTTOM, fill=tk.X)
    update_status_bar()

    # Pack the login frame initially
    login_frame.pack()

    root.after(60000, check_session_timeout)
    root.mainloop()

start_ui()