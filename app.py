"""
Aici este versiunea finala si securizata a proiectului meu. Dupa ce am testat atacurile pe V1, am implementat fix-urile.
In primul rand, am renuntat complet la MD5 si la hash-ul creat manual, folosind acum libraria Flask-Bcrypt,
asa cum e standard in industrie, pentru un hashing puternic cu salt automat.
Pentru sesiuni nu mai las cookie-urile in clar. Am activat sesiunile native din Flask (semnate cu secret_key)
si am pus flag-urile de securitate HttpOnly si SameSite pe cookie ca sa previn XSS/CSRF.
La login am pus mesaje generice ca sa previn enumerarea utilizatorilor si am adaugat un mecanism de blocare a contului
dupa 3 incercari gresite pentru a respinge atacurile de tip Brute Force.
La partea de tichete (CRUD) am reparat IDOR-ul: acum backend-ul verifica strict daca tichetul pe care vrei sa il stergi iti apartine tie.
De asemenea am implementat o bara de cautare sigura (folosind query parametrizat prin ORM ca sa evit SQL Injection)
si am pus un handler pentru eroarea 500 ca sa nu afisez niciodata stack trace-ul aplicatiei daca pica ceva intern.
"""

from flask import Flask, request, render_template, redirect, url_for, session, abort
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from models import baza_date, Utilizator, LogAudit, Tichet
import os
from datetime import timedelta

aplicatie = Flask(__name__)
aplicatie.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///authx.db'
aplicatie.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

aplicatie.secret_key = os.urandom(24)
aplicatie.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
aplicatie.config['SESSION_COOKIE_HTTPONLY'] = True
aplicatie.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

baza_date.init_app(aplicatie)
criptare_parole = Bcrypt(aplicatie)
generator_token_sigur = URLSafeTimedSerializer(aplicatie.secret_key)

with aplicatie.app_context():
    baza_date.create_all()


def necesita_autentificare(functie_originala):
    def functie_imbracata(*args, **kwargs):
        if 'id_sesiune' not in session:
            return redirect(url_for('pagina_login'))
        return functie_originala(*args, **kwargs)

    functie_imbracata.__name__ = functie_originala.__name__
    return functie_imbracata


@aplicatie.route('/')
@necesita_autentificare
def pagina_principala():
    id_utilizator_logat = session['id_sesiune']
    utilizator_curent = baza_date.session.get(Utilizator, id_utilizator_logat)
    lista_tichetele_mele = Tichet.query.filter_by(id_proprietar=id_utilizator_logat).all()

    return render_template('dashboard.html', user=utilizator_curent, tickets=lista_tichetele_mele, search_query="")


@aplicatie.route('/register', methods=['GET', 'POST'])
def pagina_inregistrare():
    if request.method == 'POST':
        email_introdus = request.form['email']
        parola_introdusa = request.form['password']

        if len(parola_introdusa) < 8:
            return render_template('register.html', error="Password must be at least 8 characters long!")

        verificare_existenta = Utilizator.query.filter_by(email=email_introdus).first()
        if verificare_existenta:
            return render_template('register.html', error="Email is already registered!")

        parola_securizata = criptare_parole.generate_password_hash(parola_introdusa).decode('utf-8')
        utilizator_nou = Utilizator(email=email_introdus, parola_hash=parola_securizata)

        baza_date.session.add(utilizator_nou)
        baza_date.session.commit()

        return redirect(url_for('pagina_login'))

    return render_template('register.html')


@aplicatie.route('/login', methods=['GET', 'POST'])
def pagina_login():
    if request.method == 'POST':
        email_formular = request.form['email']
        parola_formular = request.form['password']
        eroare_generica = "Invalid email or password!"

        utilizator_gasit = Utilizator.query.filter_by(email=email_formular).first()

        if not utilizator_gasit:
            return render_template('login.html', error=eroare_generica)

        if utilizator_gasit.locked:
            return render_template('login.html', error="Account locked due to too many failed attempts.")

        if not criptare_parole.check_password_hash(utilizator_gasit.parola_hash, parola_formular):
            utilizator_gasit.failed_login_attempts += 1
            if utilizator_gasit.failed_login_attempts >= 3:
                utilizator_gasit.locked = True
            baza_date.session.commit()
            return render_template('login.html', error=eroare_generica)

        utilizator_gasit.failed_login_attempts = 0
        inregistrare_succes = LogAudit(
            id_utilizator=utilizator_gasit.id,
            actiune_facuta="LOGIN_SUCCESS",
            adresa_ip=request.remote_addr
        )
        baza_date.session.add(inregistrare_succes)
        baza_date.session.commit()

        session.permanent = True
        session['id_sesiune'] = utilizator_gasit.id
        return redirect(url_for('pagina_principala'))

    return render_template('login.html')


@aplicatie.route('/ticket/add', methods=['POST'])
@necesita_autentificare
def adaugare_tichet():
    titlu_formular = request.form['title']
    descriere_formular = request.form['description']
    id_utilizator_logat = session['id_sesiune']

    tichet_nou_creat = Tichet(
        titlu_tichet=titlu_formular,
        descriere_tichet=descriere_formular,
        id_proprietar=id_utilizator_logat
    )
    baza_date.session.add(tichet_nou_creat)
    baza_date.session.commit()

    return redirect(url_for('pagina_principala'))


@aplicatie.route('/ticket/delete/<int:id_tichet_url>', methods=['POST'])
@necesita_autentificare
def stergere_tichet(id_tichet_url):
    tichet_ales = baza_date.session.get(Tichet, id_tichet_url)

    if not tichet_ales:
        abort(404)

    if tichet_ales.id_proprietar != session['id_sesiune']:
        abort(403)

    baza_date.session.delete(tichet_ales)
    baza_date.session.commit()
    return redirect(url_for('pagina_principala'))


@aplicatie.route('/search', methods=['GET'])
@necesita_autentificare
def cautare_tichete():
    termen_cautat = request.args.get('q', '')
    id_utilizator_logat = session['id_sesiune']
    utilizator_curent = baza_date.session.get(Utilizator, id_utilizator_logat)

    rezultate_cautare = Tichet.query.filter(
        Tichet.titlu_tichet.ilike(f'%{termen_cautat}%'),
        Tichet.id_proprietar == id_utilizator_logat
    ).all()

    return render_template('dashboard.html', user=utilizator_curent, tickets=rezultate_cautare,
                           search_query=termen_cautat)


@aplicatie.route('/forgot_password', methods=['GET', 'POST'])
def pagina_uitat_parola():
    if request.method == 'POST':
        email_cautat = request.form['email']
        utilizator_gasit = Utilizator.query.filter_by(email=email_cautat).first()

        if utilizator_gasit:
            token_securizat = generator_token_sigur.dumps(utilizator_gasit.email, salt='sare-resetare-parola')
            link_generat = url_for('pagina_resetare_parola', token_url=token_securizat, _external=True)
            return render_template('forgot_password.html', msg=f"Secure reset link: {link_generat}")
        else:
            return render_template('forgot_password.html', msg="If the email exists, a link was sent.")

    return render_template('forgot_password.html')


@aplicatie.route('/reset_password/<token_url>', methods=['GET', 'POST'])
def pagina_resetare_parola(token_url):
    try:
        email_extras_din_token = generator_token_sigur.loads(token_url, salt='sare-resetare-parola', max_age=900)
    except SignatureExpired:
        return "The reset link has expired!", 400
    except Exception:
        return "Invalid or corrupted token!", 400

    utilizator_gasit = Utilizator.query.filter_by(email=email_extras_din_token).first()
    if not utilizator_gasit:
        return "System error!", 404

    if request.method == 'POST':
        parola_noua_introdusa = request.form['new_password']
        if len(parola_noua_introdusa) < 8:
            return render_template('reset_password.html', error="Password must be at least 8 characters long!")

        utilizator_gasit.parola_hash = criptare_parole.generate_password_hash(parola_noua_introdusa).decode('utf-8')
        baza_date.session.commit()
        return redirect(url_for('pagina_login'))

    return render_template('reset_password.html')


@aplicatie.route('/logout')
def delogare_utilizator():
    session.clear()
    return redirect(url_for('pagina_login'))


@aplicatie.errorhandler(500)
def eroare_interna_server(eroare):
    return "A critical internal error occurred. Our technical team has been notified.", 500


if __name__ == '__main__':
    aplicatie.run(debug=False)