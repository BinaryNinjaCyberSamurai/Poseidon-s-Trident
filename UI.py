import tkinter as tk
from tkinter import messagebox, scrolledtext, PhotoImage
from firewall import Firewall
import hashlib
import logging
import time
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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

def send_email(subject, body, to_email):
    from_email = "your_email@example.com"
    password = "your_email_password"
    
    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    
    msg.attach(MIMEText(body, "plain"))
    
    try:
        server = smtplib.SMTP("smtp.example.com", 587)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

def register():
    def create_account():
        username = entry_new_username.get()
        password = hashlib.sha256(entry_new_password.get().encode()).hexdigest()
        
        if username in users:
            messagebox.showerror("Error", "Username already exists.")
        else:
            users[username] = {"password": password, "role": "user"}
            messagebox.showinfo("Success", "Account created successfully!")
            logging.info(f"New user registered: {username}")
            register_window.destroy()
    
    register_window = tk.Toplevel(root)
    register_window.title("Register")
    register_window.geometry("300x200")
    
    tk.Label(register_window, text="Username:").pack()
    entry_new_username = tk.Entry(register_window)
    entry_new_username.pack()
    
    tk.Label(register_window, text="Password:").pack()
    entry_new_password = tk.Entry(register_window, show="*")
    entry_new_password.pack()
    
    tk.Button(register_window, text="Create Account", command=create_account).pack(pady=10)

def two_factor_auth():
    def verify_code():
        code = entry_code.get()
        if code == "123456":  # This should be replaced with a real 2FA code generation and verification
            messagebox.showinfo("Success", "Two-Factor Authentication successful!")
            logging.info(f"User {current_user} passed 2FA.")
            two_factor_window.destroy()
            show_dashboard()
        else:
            messagebox.showerror("Error", "Invalid code.")
    
    two_factor_window = tk.Toplevel(root)
    two_factor_window.title("Two-Factor Authentication")
    two_factor_window.geometry("300x200")
    
    tk.Label(two_factor_window, text="Enter the 2FA code sent to your email:").pack()
    entry_code = tk.Entry(two_factor_window)
    entry_code.pack()
    
    tk.Button(two_factor_window, text="Verify", command=verify_code).pack(pady=10)

def login():
    global current_user
    username = entry_username.get()
    password = hashlib.sha256(entry_password.get().encode()).hexdigest()
    
    if username in users and users[username]["password"] == password:
        current_user = username
        messagebox.showinfo("Login Success", f"Welcome {username} to Poseidon's Trident Security Dashboard!")
        logging.info(f"User {username} logged in.")
        reset_activity_timer()
        send_email("Login Alert", f"User {username} logged in.", "user_email@example.com")
        
        if is_admin():
            show_dashboard()  # Skip 2FA for admin users
        else:
            two_factor_auth()
    else:
        messagebox.showerror("Login Failed", "Invalid credentials")
        logging.warning(f"Failed login attempt: {username}")

def is_admin():
    return users.get(current_user, {}).get("role") == "admin"

def show_dashboard():
    login_frame.pack_forget()
    dashboard_frame.pack(pady=20)
    update_status_bar()

    if is_admin():
        view_firewall_button = tk.Button(dashboard_frame, text="View Firewall Rules", command=view_firewall_rules, bg="#001f3f", fg="#7FDBFF")
        view_firewall_button.pack()
        apply_interactive_effects(view_firewall_button)
        make_pill_button(view_firewall_button)

def log_user_activity(activity):
    with open("user_activity.log", "a") as log_file:
        log_file.write(f"{time.asctime()} - {current_user}: {activity}\n")

def open_firewall_management():
    if not is_admin():
        messagebox.showerror("Access Denied", "Only admins can access Firewall Management.")
        return
    
    log_user_activity("Accessed Firewall Management")
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
    log_user_activity("Accessed Intrusion Detection")
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
    log_user_activity("Logged out")
    current_user = None
    dashboard_frame.pack_forget()
    login_frame.pack()
    entry_username.delete(0, tk.END)  # Clear username field
    entry_password.delete(0, tk.END)  # Clear password field
    update_status_bar()

def real_time_logs():
    log_user_activity("Accessed Real-Time Logs")
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

def change_password():
    log_user_activity("Changed Password")
    def update_password():
        old_password = hashlib.sha256(entry_old_password.get().encode()).hexdigest()
        new_password = hashlib.sha256(entry_new_password.get().encode()).hexdigest()
        
        if users[current_user]["password"] == old_password:
            users[current_user]["password"] = new_password
            messagebox.showinfo("Success", "Password changed successfully!")
            logging.info(f"User {current_user} changed their password.")
            change_password_window.destroy()
        else:
            messagebox.showerror("Error", "Old password is incorrect.")
    
    change_password_window = tk.Toplevel(root)
    change_password_window.title("Change Password")
    change_password_window.geometry("300x200")
    
    tk.Label(change_password_window, text="Old Password:").pack()
    entry_old_password = tk.Entry(change_password_window, show="*")
    entry_old_password.pack()
    
    tk.Label(change_password_window, text="New Password:").pack()
    entry_new_password = tk.Entry(change_password_window, show="*")
    entry_new_password.pack()
    
    tk.Button(change_password_window, text="Update Password", command=update_password).pack(pady=10)

def view_firewall_rules():
    rules_window = tk.Toplevel(root)
    rules_window.title("Current Firewall Rules")
    rules_window.geometry("400x300")
    
    rules_text = scrolledtext.ScrolledText(rules_window, height=15, width=50)
    rules_text.pack()
    
    rules_text.insert(tk.END, "\n".join(firewall.get_rules()))
    rules_text.config(state=tk.DISABLED)

def recover_password():
    def send_recovery_email():
        username = entry_recovery_username.get()
        if username in users:
            recovery_code = "123456"  # This should be replaced with a real recovery code generation
            send_email("Password Recovery", f"Your recovery code is: {recovery_code}", "user_email@example.com")
            messagebox.showinfo("Success", "Recovery email sent!")
            logging.info(f"Password recovery email sent to {username}.")
            recovery_window.destroy()
        else:
            messagebox.showerror("Error", "Username not found.")
    
    recovery_window = tk.Toplevel(root)
    recovery_window.title("Recover Password")
    recovery_window.geometry("300x200")
    
    tk.Label(recovery_window, text="Username:").pack()
    entry_recovery_username = tk.Entry(recovery_window)
    entry_recovery_username.pack()
    
    tk.Button(recovery_window, text="Send Recovery Email", command=send_recovery_email).pack(pady=10)

def manage_roles():
    if not is_admin():
        messagebox.showerror("Access Denied", "Only admins can manage user roles.")
        return
    
    def update_role():
        username = entry_role_username.get()
        role = entry_role.get()
        if username in users:
            users[username]["role"] = role
            messagebox.showinfo("Success", f"Role of {username} updated to {role}.")
            logging.info(f"User {username} role updated to {role}.")
            manage_roles_window.destroy()
        else:
            messagebox.showerror("Error", "Username not found.")
    
    manage_roles_window = tk.Toplevel(root)
    manage_roles_window.title("Manage User Roles")
    manage_roles_window.geometry("300x200")
    
    tk.Label(manage_roles_window, text="Username:").pack()
    entry_role_username = tk.Entry(manage_roles_window)
    entry_role_username.pack()
    
    tk.Label(manage_roles_window, text="Role:").pack()
    entry_role = tk.Entry(manage_roles_window)
    entry_role.pack()
    
    tk.Button(manage_roles_window, text="Update Role", command=update_role).pack(pady=10)

def show_activity_dashboard():
    dashboard_window = tk.Toplevel(root)
    dashboard_window.title("Activity Dashboard")
    dashboard_window.geometry("500x400")
    
    activity_text = scrolledtext.ScrolledText(dashboard_window, height=20, width=60)
    activity_text.pack()
    
    with open("user_activity.log", "r") as log_file:
        activity_text.insert(tk.END, log_file.read())
    activity_text.config(state=tk.DISABLED)

def system_health_check():
    health_window = tk.Toplevel(root)
    health_window.title("System Health Check")
    health_window.geometry("300x200")
    
    tk.Label(health_window, text="System Health Status", font=("Arial", 14)).pack()
    
    # Placeholder for actual health check logic
    health_status = "All systems are operational."
    
    tk.Label(health_window, text=health_status).pack(pady=10)

def apply_gradient(widget, color1, color2):
    width = widget.winfo_width()
    height = widget.winfo_height()
    gradient = tk.PhotoImage(width=width, height=height)
    for y in range(height):
        r = int(color1[1:3], 16) + (int(color2[1:3], 16) - int(color1[1:3], 16)) * y // height
        g = int(color1[3:5], 16) + (int(color2[3:5], 16) - int(color1[3:5], 16)) * y // height
        b = int(color1[5:7], 16) + (int(color2[5:7], 16) - int(color1[5:7], 16)) * y // height
        color = f'#{r:02x}{g:02x}{b:02x}'
        gradient.put(color, to=(0, y, width, y+1))
    widget.configure(image=gradient)
    widget.image = gradient

def apply_glow_effect(widget, color):
    widget.configure(highlightbackground=color, highlightthickness=2)

def animate_widget(widget, start_color, end_color, duration=1000):
    start_r = int(start_color[1:3], 16)
    start_g = int(start_color[3:5], 16)
    start_b = int(start_color[5:7], 16)
    end_r = int(end_color[1:3], 16)
    end_g = int(end_color[3:5], 16)
    end_b = int(end_color[5:7], 16)
    
    steps = duration // 10
    delta_r = (end_r - start_r) / steps
    delta_g = (end_g - start_g) / steps
    delta_b = (end_b - start_b) / steps
    
    def update_color(step):
        if step > steps:
            return
        new_r = int(start_r + delta_r * step)
        new_g = int(start_g + delta_g * step)
        new_b = int(start_b + delta_b * step)
        new_color = f'#{new_r:02x}{new_g:02x}{new_b:02x}'
        widget.configure(bg=new_color)
        widget.after(10, update_color, step + 1)
    
    update_color(0)

def on_enter(event):
    event.widget.config(bg="#0074D9", fg="#FFFFFF")

def on_leave(event):
    event.widget.config(bg="#FFD700", fg="#000000")  # Change back to gold and black

def apply_interactive_effects(widget):
    widget.bind("<Enter>", on_enter)
    widget.bind("<Leave>", on_leave)

def make_rounded_button(button):
    button.config(borderwidth=0, highlightthickness=0, relief=tk.FLAT)
    button.config(compound=tk.CENTER, padx=10, pady=5)
    button.config(font=("Arial", 10, "bold"))

def make_3d_solid_button(button):
    button.config(borderwidth=2, relief=tk.RAISED, bg="#FFD700", fg="#000000")
    button.config(compound=tk.CENTER, padx=10, pady=5)
    button.config(font=("Arial", 10, "bold"))

def make_rounded_icon_button(button):
    button.config(borderwidth=0, highlightthickness=0, relief=tk.FLAT, bg="#FFD700", fg="#000000")
    button.config(compound=tk.CENTER, padx=10, pady=5)
    button.config(font=("Arial", 10, "bold"))
    button.config(width=2, height=1, highlightbackground="#FFD700", highlightcolor="#FFD700", highlightthickness=2)
    button.config(borderwidth=2, relief=tk.RAISED)

def make_pill_button(button):
    button.config(borderwidth=2, relief=tk.RAISED, bg="#FFD700", fg="#000000")
    button.config(compound=tk.CENTER, padx=10, pady=5)
    button.config(font=("Arial", 10, "bold"))
    button.config(highlightbackground="#FFD700", highlightcolor="#FFD700", highlightthickness=2)
    button.config(width=15, height=1, borderwidth=2, relief=tk.RAISED)

def make_pill_icon_button(button):
    button.config(borderwidth=0, highlightthickness=0, relief=tk.FLAT, bg="#FFD700", fg="#000000")
    button.config(compound=tk.CENTER, padx=5, pady=2)
    button.config(font=("Arial", 10, "bold"))
    button.config(width=2, height=1, highlightbackground="#FFD700", highlightcolor="#FFD700", highlightthickness=2)
    button.config(borderwidth=2, relief=tk.RAISED)

def apply_deep_ocean_theme():
    bg_color = "#001f3f"  # Dark blue
    fg_color = "#7FDBFF"  # Light blue
    
    root.configure(bg=bg_color)
    for widget in root.winfo_children():
        try:
            widget.configure(bg=bg_color, fg=fg_color)
            apply_gradient(widget, "#001f3f", "#0074D9")
            apply_glow_effect(widget, "#7FDBFF")
            animate_widget(widget, "#001f3f", "#0074D9")
            apply_interactive_effects(widget)
            if isinstance(widget, tk.Button):
                make_pill_button(widget)
        except:
            pass

def on_entry_click(event, entry, placeholder, show=""):
    if entry.get() == placeholder:
        entry.delete(0, "end")
        entry.config(fg="#7FDBFF", show=show)

def on_focusout(event, entry, placeholder, show=""):
    if entry.get() == "":
        entry.insert(0, placeholder)
        entry.config(fg="grey", show=show)

def start_ui():
    global root, login_frame, dashboard_frame, entry_username, entry_password, status_text, dark_mode_var
    root = tk.Tk()
    root.title("Poseidon's Trident - Security Dashboard")
    root.geometry("500x400")

    apply_deep_ocean_theme()  # Apply the deep ocean theme

    # Load and resize Trident logo
    trident_logo = PhotoImage(file="trident.png")
    trident_logo = trident_logo.subsample(6, 6)  # Reduce size to one-sixth

    # Login Frame
    login_frame = tk.Frame(root, bg="#001f3f")
    login_frame.pack(pady=50)
    
    logo_label = tk.Label(login_frame, image=trident_logo, bg="#001f3f")
    logo_label.image = trident_logo  # Keep a reference to avoid garbage collection
    logo_label.pack(pady=10)
    
    login_heading = tk.Label(login_frame, text="Welcome to Poseidon's Trident", font=("Arial", 20, "bold"), bg="#001f3f", fg="#7FDBFF")
    login_heading.pack(pady=10)
    
    entry_username = tk.Entry(login_frame, bg="#001f3f", fg="grey", insertbackground="#7FDBFF", justify='center')
    entry_username.insert(0, "Username")
    entry_username.bind("<FocusIn>", lambda event: on_entry_click(event, entry_username, "Username"))
    entry_username.bind("<FocusOut>", lambda event: on_focusout(event, entry_username, "Username"))
    entry_username.pack(pady=5)
    
    password_frame = tk.Frame(login_frame, bg="#001f3f")
    entry_password = tk.Entry(password_frame, bg="#001f3f", fg="grey", insertbackground="#7FDBFF", justify='center')
    entry_password.insert(0, "Password")
    entry_password.bind("<FocusIn>", lambda event: on_entry_click(event, entry_password, "Password", show="*"))
    entry_password.bind("<FocusOut>", lambda event: on_focusout(event, entry_password, "Password"))
    entry_password.pack(side=tk.LEFT, pady=5)
    
    eye_label = tk.Label(password_frame, text="👁️", bg="#001f3f", fg="#7FDBFF", cursor="hand2", font=("Arial", 12))
    eye_label.pack(side=tk.LEFT, padx=1)
    eye_label.bind("<Button-1>", lambda e: toggle_password())
    apply_interactive_effects(eye_label)
    
    password_frame.pack()
    
    login_button = tk.Button(login_frame, text="Login", command=login, bg="#001f3f", fg="#7FDBFF")
    login_button.pack(pady=5)
    apply_interactive_effects(login_button)
    make_pill_button(login_button)
    
    register_link = tk.Label(login_frame, text="Register", fg="#7FDBFF", bg="#001f3f", cursor="hand2", font=("Arial", 10, "underline"))
    register_link.pack(pady=5)
    register_link.bind("<Button-1>", lambda e: register())
    
    recover_link = tk.Label(login_frame, text="Recover Password", fg="#7FDBFF", bg="#001f3f", cursor="hand2", font=("Arial", 10, "underline"))
    recover_link.pack(pady=5)
    recover_link.bind("<Button-1>", lambda e: recover_password())
    
    dark_mode_var = tk.IntVar()
    dark_mode_toggle = tk.Checkbutton(login_frame, text="Dark Mode", variable=dark_mode_var, command=toggle_dark_mode, bg="#001f3f", fg="#7FDBFF", selectcolor="#001f3f")
    dark_mode_toggle.pack(pady=5)
    apply_interactive_effects(dark_mode_toggle)

    # Dashboard Frame
    dashboard_frame = tk.Frame(root, bg="#001f3f")
    firewall_button = tk.Button(dashboard_frame, text="Firewall Management", command=open_firewall_management, bg="#001f3f", fg="#7FDBFF")
    firewall_button.pack(pady=5)
    apply_interactive_effects(firewall_button)
    make_pill_button(firewall_button)
    
    intrusion_button = tk.Button(dashboard_frame, text="Intrusion Detection", command=open_intrusion_detection, bg="#001f3f", fg="#7FDBFF")
    intrusion_button.pack(pady=5)
    apply_interactive_effects(intrusion_button)
    make_pill_button(intrusion_button)
    
    logs_button = tk.Button(dashboard_frame, text="Real-Time Logs", command=real_time_logs, bg="#001f3f", fg="#7FDBFF")
    logs_button.pack(pady=5)
    apply_interactive_effects(logs_button)
    make_pill_button(logs_button)
    
    change_password_button = tk.Button(dashboard_frame, text="Change Password", command=change_password, bg="#001f3f", fg="#7FDBFF")
    change_password_button.pack(pady=5)
    apply_interactive_effects(change_password_button)
    make_pill_button(change_password_button)
    
    manage_roles_button = tk.Button(dashboard_frame, text="Manage User Roles", command=manage_roles, bg="#001f3f", fg="#7FDBFF")
    manage_roles_button.pack(pady=5)
    apply_interactive_effects(manage_roles_button)
    make_pill_button(manage_roles_button)
    
    activity_dashboard_button = tk.Button(dashboard_frame, text="Activity Dashboard", command=show_activity_dashboard, bg="#001f3f", fg="#7FDBFF")
    activity_dashboard_button.pack(pady=5)
    apply_interactive_effects(activity_dashboard_button)
    make_pill_button(activity_dashboard_button)
    
    health_check_button = tk.Button(dashboard_frame, text="System Health Check", command=system_health_check, bg="#001f3f", fg="#7FDBFF")
    health_check_button.pack(pady=5)
    apply_interactive_effects(health_check_button)
    make_pill_button(health_check_button)
    
    logout_button = tk.Button(dashboard_frame, text="Logout", command=logout, bg="#001f3f", fg="#7FDBFF")
    logout_button.pack(pady=5)
    apply_interactive_effects(logout_button)
    make_pill_button(logout_button)
    
    dark_mode_dashboard_button = tk.Button(dashboard_frame, text="Toggle Dark Mode", command=toggle_dark_mode, bg="#001f3f", fg="#7FDBFF")
    dark_mode_dashboard_button.pack(pady=5)
    apply_interactive_effects(dark_mode_dashboard_button)
    make_pill_button(dark_mode_dashboard_button)

    # Status Bar
    status_text = tk.StringVar()
    status_label = tk.Label(root, textvariable=status_text, bd=1, relief=tk.SUNKEN, anchor="w", bg="#001f3f", fg="#7FDBFF")
    status_label.pack(side=tk.BOTTOM, fill=tk.X)
    update_status_bar()

    root.after(60000, check_session_timeout)
    root.mainloop()

start_ui()
