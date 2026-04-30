"""
Pentru versiunea V2 am actualizat modelul bazei de date.
Am adaugat coloanele 'locked' si 'failed_login_attempts' la tabelul Utilizator
pentru a putea implementa protectia impotriva atacurilor de tip Brute Force.
Acestea vor numara cate incercari gresite are utilizatorul si ii vor bloca temporar contul.
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

baza_date = SQLAlchemy()


class Utilizator(baza_date.Model):
    __tablename__ = 'utilizatori'
    id = baza_date.Column(baza_date.Integer, primary_key=True)
    email = baza_date.Column(baza_date.String(120), unique=True, nullable=False)
    parola_hash = baza_date.Column(baza_date.String(255), nullable=False)
    rol_utilizator = baza_date.Column(baza_date.String(20), default='USER')
    data_creare = baza_date.Column(baza_date.DateTime, default=datetime.utcnow)

    # Campuri adaugate pentru securitatea anti Brute-Force
    locked = baza_date.Column(baza_date.Boolean, default=False)
    failed_login_attempts = baza_date.Column(baza_date.Integer, default=0)


class Tichet(baza_date.Model):
    __tablename__ = 'tichete'
    id = baza_date.Column(baza_date.Integer, primary_key=True)
    titlu_tichet = baza_date.Column(baza_date.String(100), nullable=False)
    descriere_tichet = baza_date.Column(baza_date.Text, nullable=False)
    severitate = baza_date.Column(baza_date.String(20), default='LOW')
    status_curent = baza_date.Column(baza_date.String(20), default='OPEN')
    id_proprietar = baza_date.Column(baza_date.Integer, baza_date.ForeignKey('utilizatori.id'), nullable=False)
    data_adaugare = baza_date.Column(baza_date.DateTime, default=datetime.utcnow)


class LogAudit(baza_date.Model):
    __tablename__ = 'loguri_audit'
    id = baza_date.Column(baza_date.Integer, primary_key=True)
    id_utilizator = baza_date.Column(baza_date.Integer, baza_date.ForeignKey('utilizatori.id'), nullable=True)
    actiune_facuta = baza_date.Column(baza_date.String(50), nullable=False)
    resursa_afectata = baza_date.Column(baza_date.String(50))
    data_actiune = baza_date.Column(baza_date.DateTime, default=datetime.utcnow)
    adresa_ip = baza_date.Column(baza_date.String(50))