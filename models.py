"""
Aici am definit baza de date folosind SQLAlchemy pentru proiect.
Am creat tabelele pentru utilizatori, tichete si loguri de audit conform cerintelor.
Momentan la utilizatori nu am bagat reguli complexe, iar parola o sa o salvez cu un hash simplu in aplicatie.
Pentru logurile de audit am lasat un camp de adresa ip ca sa arate mai realist in caz ca trebuie sa verificam cine a dat login.
Nu am facut relatii foreign key foarte complicate ca sa nu ma incurc la query-uri mai tarziu.
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