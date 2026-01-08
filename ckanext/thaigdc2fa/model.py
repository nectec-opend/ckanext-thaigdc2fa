from sqlalchemy import (
    Table, Column, Integer, UnicodeText, Boolean, DateTime, ForeignKey
)
from sqlalchemy.orm import mapper
from sqlalchemy.exc import ProgrammingError
from ckan.model.meta import metadata, Session, engine
import datetime

class TwoFASecret(object):
    pass

thaigdc2fa_user_secret_table = Table(
    'thaigdc2fa_user_secret',
    metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', UnicodeText, ForeignKey('user.id', ondelete='CASCADE'), nullable=False),
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

def disable_secret(secret_obj):
    """
    Disable current 2FA secret (soft-disable - ไม่ลบออก)
    """
    secret_obj.enabled = False
    secret_obj.updated_at = datetime.datetime.utcnow()
    Session.add(secret_obj)
    Session.commit()
    log.info(f"[2FA] Disabled secret id={secret_obj.id} for user_id={secret_obj.user_id}")


def setup():
    try:
        metadata.create_all(engine)
    except ProgrammingError:
        pass
