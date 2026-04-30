# Proiect: AuthX - Break the Login (DASS)

DEMO: https://www.youtube.com/watch?v=RE_03znNX6s

Acest repository conține proiectul pentru materia **Dezvoltarea Aplicațiilor Software Securizate** (Facultatea de Matematică și Informatică, Universitatea din București). 

Aplicația **AuthX** este un portal intern de ticketing dezvoltat urmărind conceptul de *Vulnerable by Design* (Construit pentru a fi atacat și apoi securizat).

## Structura Explicațiilor din Cod
**Notă importantă pentru evaluare:** Pentru a păstra codul curat, lizibil și apropiat de mediul de producție real, nu am inclus comentarii printre liniile de cod. În schimb, **fiecare fișier din acest proiect conține la începutul său un bloc amplu de comentarii**. 
Acolo am explicat în detaliu (ca student) arhitectura gândită, vulnerabilitățile lăsate intenționat în prima fază și soluțiile tehnice de securitate implementate ulterior.

## Structura Repository-ului (Branch-uri)
Acest proiect este împărțit în două branch-uri clare pentru a evidenția procesul de audit și securizare:

1. **Branch-ul `main` (Versiunea V1 - Vulnerabilă)**
   - Conține MVP-ul funcțional, dar complet expus atacurilor.
   - Demonstrează vulnerabilități critice: Parole stocate în MD5, Insecure Direct Object Reference (IDOR), User Enumeration, lipsa Rate Limiting (Brute Force) și Session Hijacking.
   - *Include scriptul `hacker.py` (Proof of Concept) folosit pentru spargerea parolelor.*

2. **Branch-ul `fix-security` (Versiunea V2 - Securizată)**
   - Conține aplicația finală, remediată în urma auditului.
   - Vulnerabilitățile au fost reparate folosind metode moderne (Secure by Design): `flask-bcrypt` pentru parole, Session Hardening (semnături HMAC, HttpOnly), Account Lockout la 3 încercări greșite, Autorizare Server-Side împotriva IDOR și Search parametrizat prin ORM.

## Tehnologii Folosite
* **Backend:** Python 3, Flask
* **Bază de date:** SQLite, SQLAlchemy (ORM)
* **Securitate:** Flask-Bcrypt, ItsDangerous (pentru token-uri sigure)
* **Frontend:** HTML, Jinja2, Bootstrap 5

## Cum se rulează proiectul local (Linux/Ubuntu VM)

```bash
# 1. Clonarea repository-ului
git clone https://github.com/JubyJubson/AuthX_Project.git
cd AuthX_Project

# (Opțional) Pentru a rula versiunea securizată, schimbați branch-ul:
# git checkout fix-security

# 2. Crearea și activarea mediului virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalarea dependențelor
pip install -r requirements.txt

# 4. Rularea serverului Flask
python3 app.py
