import re
import math
import requests
import hashlib
import csv
import tkinter as tk
from tkinter import filedialog, messagebox

# ---------------------------
# Password Strength Functions
# ---------------------------

def calculate_entropy(password):
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'[0-9]', password):
        pool += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        pool += 32
    if pool == 0:
        return 0
    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)

def check_strength(password):
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Use at least 12 characters.")

    if re.search(r'[a-z]', password): score += 1
    else: feedback.append("Add lowercase letters.")

    if re.search(r'[A-Z]', password): score += 1
    else: feedback.append("Add uppercase letters.")

    if re.search(r'[0-9]', password): score += 1
    else: feedback.append("Add numbers.")

    if re.search(r'[^a-zA-Z0-9]', password): score += 1
    else: feedback.append("Add special characters.")

    if not any(word in password.lower() for word in ["password", "123", "qwerty"]):
        score += 1
    else:
        feedback.append("Avoid common patterns like '123', 'password', 'qwerty'.")

    return score, feedback

def check_pwned(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    if response.status_code != 200:
        return -1  # API error
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0

# ---------------------------
# GUI Implementation
# ---------------------------

def analyze_password():
    password = entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password!")
        return

    score, feedback = check_strength(password)
    entropy = calculate_entropy(password)
    breaches = check_pwned(password)

    result_text = f"Score: {score}/6\nEntropy: {entropy} bits\n"

    if breaches > 0:
        result_text += f"⚠️ Found in {breaches} breaches!\n"
    elif breaches == 0:
        result_text += "✅ Not found in breaches.\n"
    else:
        result_text += "⚠️ Breach check unavailable.\n"

    if score >= 5:
        result_text += "\nStrength: ✅ Strong"
    elif score >= 3:
        result_text += "\nStrength: ⚠️ Moderate"
    else:
        result_text += "\nStrength: ❌ Weak"

    if feedback:
        result_text += "\n\nSuggestions:\n" + "\n".join(f"- {f}" for f in feedback)

    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, result_text)

    # Save to CSV log
    with open("password_log.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([password, score, entropy, breaches])

def analyze_file():
    filepath = filedialog.askopenfilename(title="Select Password File", filetypes=[("Text Files", "*.txt")])
    if not filepath:
        return

    report = []
    with open(filepath, "r") as file:
        for line in file:
            pw = line.strip()
            if not pw:
                continue
            score, feedback = check_strength(pw)
            entropy = calculate_entropy(pw)
            breaches = check_pwned(pw)
            report.append([pw, score, entropy, breaches])

    # Save corporate report
    with open("corporate_password_report.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Password", "Score", "Entropy", "Breaches"])
        writer.writerows(report)

    messagebox.showinfo("Report Generated", "Corporate password report saved as corporate_password_report.csv")

# ---------------------------
# Tkinter GUI
# ---------------------------

root = tk.Tk()
root.title("Advanced Password Strength Checker")
root.geometry("600x400")

tk.Label(root, text="Enter a password:", font=("Arial", 12)).pack(pady=5)
entry = tk.Entry(root, show="*", width=40, font=("Arial", 12))
entry.pack(pady=5)

tk.Button(root, text="Check Password", command=analyze_password, bg="lightblue").pack(pady=5)
tk.Button(root, text="Check from File (Corporate)", command=analyze_file, bg="lightgreen").pack(pady=5)

output_box = tk.Text(root, height=12, width=70, font=("Courier", 10))
output_box.pack(pady=10)

root.mainloop()
