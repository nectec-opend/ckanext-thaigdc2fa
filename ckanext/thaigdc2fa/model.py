from sqlalchemy import (
    Table, Column, Integer, UnicodeText, Boolean, DateTime, ForeignKey
)
from sqlalchemy.orm import mapper
from ckan.model.meta import metadata, Session
import datetime

class TwoFASecret(object):
    pass

thaigdc2fa_user_secret_table = Table(
    'thaigdc2fa_user_secret',
    metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False),
    Column('secret', UnicodeText, nullable=False),
    Column('enabled', Boolean, default=True, nullable=False),
    Column('created_at', DateTime, default=datetime.datetime.utcnow),
    Column('verified_at', DateTime),
    Column('updated_at', DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow),
)

mapper(TwoFASecret, thaigdc2fa_user_secret_table)

def get_secret_by_user_id(user_id):
    return Session.query(TwoFASecret).filter_by(user_id=user_id, enabled=True).first()

def create_secret(user_id, encrypted_secret):
    secret = TwoFASecret()
    secret.user_id = user_id
    secret.secret = encrypted_secret
    Session.add(secret)
    Session.commit()
    return secret

def update_verified_at(secret):
    secret.verified_at = datetime.datetime.utcnow()
    Session.add(secret)
    Session.commit()
