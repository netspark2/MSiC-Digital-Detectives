def check_password(password):
    if len(password) == 6 and password[0] == "m":
        new = password[::-1]
        if new[0] == "y" and new[1] == "e":
            if password[1:4].upper() == "ONK":
                if new.lower() == new:
                    return "The password is correct!"
        
    return "Invalid password"

while True:
    password = input("Please enter your password: ")
    result = check_password(password)
    print result
    print
    if result == "The password is correct!":
        break
