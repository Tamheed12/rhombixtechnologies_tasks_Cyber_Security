import os

# Flaw 1 : Hardocoded sensitive data

db_password = "admin_password_123"

def login():
    #Flaw 2 : Using insecure input function
    user_input = input("Enter your command: ")

    #Flaw 3 : dangerous use of eval() which can excute arbitrary code
    result = eval(user_input)

    # Flaw 4 : Using os.system which is prone to commad injection
    os.system("echo",+user_input)

if __name__ == "__main__":
    login()
    