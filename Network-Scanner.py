import socket
import os
import time
from datetime import datetime

def show_banner():
    print("     NETWORK SECURITY SCANNER")
    print()

def log_message(message):
    """Simple logging function"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")
    
    # Write to log file
    with open("scan_log.txt", "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def check_port(target, port):
    """Check if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        
        if result == 0:
            return True
        else:
            return False
    except:
        return False

def simple_port_scan():
    """Basic port scanner"""
    print("\n--- PORT SCANNER ---")
    target = input("Enter target IP or website (like google.com): ")
    
    # Common ports to check
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 3389]
    
    log_message(f"Starting port scan on {target}")
    print(f"Scanning common ports on {target}...")
    
    open_ports = []
    
    for port in common_ports:
        if check_port(target, port):
            open_ports.append(port)
            print(f"Port {port} is OPEN")
        else:
            print(f"Port {port} is closed")
        
    
    if open_ports:
        log_message(f"Found open ports: {open_ports}")
        print(f"\nFound {len(open_ports)} open ports!")
    else:
        print("\nNo open ports found.")
    
    return open_ports

def check_website_security():
    """Basic website security checker"""
    print("\n--- WEBSITE SECURITY CHECKER ---")
    website = input("Enter website URL (without http://): ")
    
    print(f"\nChecking {website}...")
    
    # Checks common ports
    web_ports = [80, 443, 8080]
    security_issues = []
    
    for port in web_ports:
        if check_port(website, port):
            if port == 80:
                security_issues.append("HTTP (port 80) is open - not secure!")
            elif port == 443:
                print("HTTPS (port 443) is open - good!")
            else:
                security_issues.append(f"Port {port} is open")
    
    # Simple security assessment
    if security_issues:
        print("\nSECURITY ISSUES FOUND:")
        for issue in security_issues:
            print(f"{issue}")
        log_message(f"Security issues for {website}: {security_issues}")
    else:
        print("\n no major security issues found!")
        log_message(f"{website} looks secure")

def password_strength_check():
    """Basic password strength checker"""
    print("\n--- PASSWORD STRENGTH CHECKER ---")
    password = input("Enter password to check: ")
    
    score = 0
    feedback = []
    
    # Check length
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters")
    
    # Check for numbers
    if any(char.isdigit() for char in password):
        score += 1
    else:
        feedback.append("Add numbers to password")
    
    # Check for uppercase
    if any(char.isupper() for char in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
    
    # Check for lowercase
    if any(char.islower() for char in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
    
    # Check for special characters
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if any(char in special_chars for char in password):
        score += 1
    else:
        feedback.append("Add special characters")
    
    # Give rating
    if score == 5:
        print("Excellent password!")
    elif score >= 3:
        print("Good password, but could be better")
    else:
        print("Weak password!")
    
    if feedback:
        print("\nSuggestions:")
        for suggestion in feedback:
            print(f"- {suggestion}")
    
    log_message(f"Password checked - Score: {score}/5")

def show_menu():
    """Display main menu"""
    print("\nWhat do you want to do?")
    print("1. Scan for open ports")
    print("2. Check website security")
    print("3. Check password strength")
    print("4. View scan log")
    print("5. Exit")
    
    choice = input("\nEnter your choice (1-5): ")
    return choice

def view_log():
    """Show the scan log"""
    print("\n--- SCAN LOG ---")
    try:
        with open("scan_log.txt", "r") as f:
            log_content = f.read()
            if log_content:
                print(log_content)
            else:
                print("Log file is empty")
    except FileNotFoundError:
        print("No log file found yet")

def main():
    """Main program"""
    show_banner()
    
    print("Welcome to Simple Network Security Scanner!")
    print("This tool helps check basic security things.")
    
    while True:
        choice = show_menu()
        
        if choice == "1":
            simple_port_scan()
        elif choice == "2":
            check_website_security()
        elif choice == "3":
            password_strength_check()
        elif choice == "4":
            view_log()
        elif choice == "5":
            print("\nThanks for using the scanner!")
            print("Check 'scan_log.txt' for your results.")
            break
        else:
            print("Please enter 1, 2, 3, 4, or 5")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
