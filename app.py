"""
Fisierul principal al aplicatiei Flask. Aici am facut toata logica de rute si autentificare.
Am lasat intentionat vulnerabilitatile pentru faza MVP a proiectului ca sa le pot demonstra la audit.
De exemplu, hash-ul pentru parole este MD5 (foarte slab), iar la login dau erori diferite daca utilizatorul exista sau nu.
Sesiunea este tinuta printr-un cookie simplu in browser unde stochez direct ID-ul utilizatorului, ceea ce e super usor de modificat.
La partea de tichete nu am pus verificare pe backend la stergere, deci teoretic oricine poate sterge tichetul oricui din greseala sau intentionat.
Token-ul de resetare parola e format doar dintr-un string concatenat cu emailul ca sa nu ma complic cu librarii de criptare acum.
"""

from flask import Flask, request, render_template, redirect, url_for, make_response
from models import baza_date, Utilizator, LogAudit, Tichet
import hashlib

aplicatie = Flask(__name__)
aplicatie.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///authx.db'
aplicatie.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

baza_date.init_app(aplicatie)

with aplicatie.app_context():
    baza_date.create_all()


def generare_hash_simplu(text_parola):
    rezultat_hash = hashlib.md5(text_parola.encode()).hexdigest()
    return rezultat_hash


@aplicatie.route('/')
def pagina_principala():
    cookie_sesiune = request.cookies.get('user_session')

    if cookie_sesiune:
        utilizator_logat = baza_date.session.get(Utilizator, int(cookie_sesiune))
        if utilizator_logat:
            lista_toate_tichetele = Tichet.query.all()
            return render_template('dashboard.html', user=utilizator_logat, tickets=lista_toate_tichetele)

    return redirect(url_for('pagina_login'))


@aplicatie.route('/register', methods=['GET', 'POST'])
def pagina_inregistrare():
    if request.method == 'POST':
        email_introdus = request.form['email']
        parola_introdusa = request.form['password']

        verificare_existenta = Utilizator.query.filter_by(email=email_introdus).first()
        if verificare_existenta:
            return render_template('register.html', error="Email is already registered!")

        parola_codata = generare_hash_simplu(parola_introdusa)
        utilizator_nou = Utilizator(email=email_introdus, parola_hash=parola_codata)

        baza_date.session.add(utilizator_nou)
        baza_date.session.commit()

        return redirect(url_for('pagina_login'))

    return render_template('register.html')


@aplicatie.route('/login', methods=['GET', 'POST'])
def pagina_login():
    if request.method == 'POST':
        email_formular = request.form['email']
        parola_formular = request.form['password']

        utilizator_gasit = Utilizator.query.filter_by(email=email_formular).first()

        if not utilizator_gasit:
            return render_template('login.html', error="User does not exist in the database!")

        hash_parola_curenta = generare_hash_simplu(parola_formular)

        if utilizator_gasit.parola_hash != hash_parola_curenta:
            return render_template('login.html', error="Incorrect password for this user!")

        inregistrare_log = LogAudit(
            id_utilizator=utilizator_gasit.id,
            actiune_facuta="LOGIN_ATTEMPT",
            resursa_afectata="Sistem",
            adresa_ip=request.remote_addr
        )
        baza_date.session.add(inregistrare_log)
        baza_date.session.commit()

        raspuns_server = make_response(redirect(url_for('pagina_principala')))
        raspuns_server.set_cookie('user_session', str(utilizator_gasit.id))

        return raspuns_server

    return render_template('login.html')


@aplicatie.route('/ticket/add', methods=['POST'])
def adaugare_tichet():
    id_sesiune_curenta = request.cookies.get('user_session')

    titlu_formular = request.form['title']
    descriere_formular = request.form['description']

    tichet_nou_creat = Tichet(
        titlu_tichet=titlu_formular,
        descriere_tichet=descriere_formular,
        id_proprietar=int(id_sesiune_curenta)
    )

    baza_date.session.add(tichet_nou_creat)
    baza_date.session.commit()

    return redirect(url_for('pagina_principala'))


@aplicatie.route('/ticket/delete/<int:id_tichet_url>', methods=['POST'])
def stergere_tichet(id_tichet_url):
    tichet_ales = baza_date.session.get(Tichet, id_tichet_url)

    if tichet_ales:
        baza_date.session.delete(tichet_ales)
        baza_date.session.commit()

    return redirect(url_for('pagina_principala'))


@aplicatie.route('/forgot_password', methods=['GET', 'POST'])
def pagina_uitat_parola():
    if request.method == 'POST':
        email_cautat = request.form['email']
        utilizator_baza = Utilizator.query.filter_by(email=email_cautat).first()

        if utilizator_baza:
            token_simplu = f"reset-{utilizator_baza.email}"
            link_generat = url_for('pagina_resetare_parola', token_url=token_simplu, _external=True)
            mesaj_afisat = f"Reset link generated: {link_generat}"
            return render_template('forgot_password.html', msg=mesaj_afisat)
        else:
            return render_template('forgot_password.html', msg="If the email exists, a link was sent.")

    return render_template('forgot_password.html')


@aplicatie.route('/reset_password/<token_url>', methods=['GET', 'POST'])
def pagina_resetare_parola(token_url):
    if not token_url.startswith("reset-"):
        return "Invalid token format!", 400

    email_extras_din_token = token_url.replace("reset-", "")
    utilizator_gasit = Utilizator.query.filter_by(email=email_extras_din_token).first()

    if not utilizator_gasit:
        return "User not found!", 404

    if request.method == 'POST':
        parola_noua_introdusa = request.form['new_password']
        utilizator_gasit.parola_hash = generare_hash_simplu(parola_noua_introdusa)
        baza_date.session.commit()
        return redirect(url_for('pagina_login'))

    return render_template('reset_password.html')


@aplicatie.route('/logout')
def delogare_utilizator():
    raspuns_server = make_response(redirect(url_for('pagina_login')))
    raspuns_server.set_cookie('user_session', '', expires=0)
    return raspuns_server


if __name__ == '__main__':
    aplicatie.run(debug=True)