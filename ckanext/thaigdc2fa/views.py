# ckanext/thaigdc2fa/views.py
import base64
import datetime
import hashlib
import io
import logging
import os

import pyotp
import qrcode
from cryptography.fernet import Fernet
from flask import Blueprint, redirect, render_template

import ckan.plugins.toolkit as toolkit
from ckan.common import _, config, g, request, session
from ckan.model import meta
from ckanext.thaigdc2fa.model import create_secret, get_secret_by_user_id, update_verified_at, disable_secret
from ckan.views.user import next_page_or_default, rotate_token
from ckan.lib.authenticator import default_authenticate

from ckanext.thaigdc2fa import auth_helper

log = logging.getLogger(__name__)

blueprint = Blueprint("thaigdc2fa", __name__, url_prefix="/2fa")


def get_cipher():
    key = os.environ.get("CKANEXT__THAIGDC2FA_CIPHER_KEY") or config.get(
        "ckanext.thaigdc2fa.cipher_key"
    )
    if not key:
        raise Exception(
            "ไม่พบคีย์การเข้ารหัส CKANEXT__THAIGDC2FA_CIPHER_KEY (env) หรือ ckanext.thaigdc2fa.cipher_key (ini)"
        )
    key = hashlib.sha256(key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def _current_or_pending_user():
    pending = auth_helper.get_pending_user()
    if pending:
        from ckan import model
        user = model.User.get(pending["username"])
        return user, True

    user = None
    try:
        user = toolkit.c.userobj
    except Exception:
        user = getattr(g, "userobj", None)
    return user, False


def _user_has_twofa(user):
    
    return get_secret_by_user_id(user.id) is not None


def setup():
    user, is_pending = _current_or_pending_user()
    if not user:
        toolkit.h.flash_error(_("กรุณาเข้าสู่ระบบก่อน"))
        return toolkit.redirect_to("user.login")
        
    if _user_has_twofa(user):
        return toolkit.redirect_to("thaigdc2fa.verify")

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        temp_secret = session.get("twofa_temp_secret")

        if not temp_secret:
            toolkit.h.flash_error(_("Session หมดอายุ กรุณาลองใหม่อีกครั้ง"))
            return redirect(toolkit.url_for("thaigdc2fa.setup"))

        totp = pyotp.TOTP(temp_secret)
        if not totp.verify(code, valid_window=1):
            toolkit.h.flash_error(_("รหัสยืนยันไม่ถูกต้อง กรุณาลองใหม่"))
        else:
            try:
                cipher = get_cipher()
                encrypted_secret = cipher.encrypt(temp_secret.encode()).decode()

                create_secret(user.id, encrypted_secret)
                
                if is_pending:
                    auth_helper.create_login_session(user)
                    auth_helper.clear_pending_user()
                else:
                    session["2fa_validated"] = True
                    session["2fa_user_id"] = user.id
                    session.pop("twofa_temp_secret", None)
                    session.save()

                toolkit.login_user(user)
                toolkit.h.flash_success(_("เปิดใช้งาน 2FA สำเร็จ"))

                next_url = session.get("2fa_next_url") or toolkit.url_for("home.index")
                return redirect(next_url)

            except Exception as e:
                log.error("Error saving 2FA setup: %s", e, exc_info=True)
                toolkit.h.flash_error(_("เกิดข้อผิดพลาดในการบันทึก กรุณาลองใหม่"))

    secret = session.get("twofa_temp_secret")
    if not secret:
        secret = pyotp.random_base32()
        session["twofa_temp_secret"] = secret
        session.save()

    totp = pyotp.TOTP(secret)
    site_domain = config.get("ckan.site_url", "http://localhost").split("//")[-1].split("/")[0]

    uri = totp.provisioning_uri(f"{user.name}", issuer_name=f"{site_domain}")

    img_b64 = None
    try:
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
    except Exception as e:
        log.error("Error generating QR code: %s", e, exc_info=True)

    return render_template(
        "thaigdc2fa/setup.html",
        img_b64=img_b64,
        secret=secret,
        user=user,
    )


def verify():
    user, is_pending = _current_or_pending_user()
    if not user:
        toolkit.h.flash_error(_("กรุณาเข้าสู่ระบบก่อน"))
        return toolkit.redirect_to("user.login")
        
    secret_obj = get_secret_by_user_id(user.id)
    if not secret_obj:
        return toolkit.redirect_to("thaigdc2fa.setup")

    try:
        cipher = get_cipher()
        secret = cipher.decrypt(secret_obj.secret.encode()).decode()
    except Exception as e:
        log.error("Decrypt Error for %s: %s", user.name, e, exc_info=True)
        toolkit.h.flash_error(_("ถอดรหัส 2FA ไม่ได้ กรุณาติดต่อผู้ดูแลระบบ"))
        return toolkit.redirect_to("home.index")

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(secret)

        if not totp.verify(code, valid_window=1):
            return render_template("thaigdc2fa/verify.html", error=True, user=user)

        try:
            update_verified_at(secret_obj)

            if is_pending:
                auth_helper.create_login_session(user)
                auth_helper.clear_pending_user()
            else:
                session["2fa_validated"] = True
                session["2fa_user_id"] = user.id
                session.save()

            toolkit.login_user(user)

            next_url = (
                request.args.get("next")
                or session.get("2fa_next_url")
                or toolkit.url_for("home.index")
            )
            return redirect(next_url)

        except Exception as e:
            log.error("Error updating 2FA verification: %s", e, exc_info=True)
            toolkit.h.flash_error(_("เกิดข้อผิดพลาดในการบันทึก"))

    return render_template("thaigdc2fa/verify.html", user=user)


def disable():
    user = getattr(g, "userobj", None)
    if not user:
        return toolkit.abort(401, _("Unauthorized"))
    if not user.sysadmin:
        toolkit.h.flash_error(_("คุณไม่มีสิทธิ์ในการปิด 2FA"))
        return toolkit.redirect_to("user.read", id=user.name)

    if request.method == "POST":
        secret_obj = get_secret_by_user_id(user.id)

        if secret_obj:
            code = request.form.get("code", "").strip()
            try:
                cipher = get_cipher()
                secret = cipher.decrypt(secret_obj.secret.encode()).decode()
                totp = pyotp.TOTP(secret)

                if not totp.verify(code, valid_window=1):
                    toolkit.h.flash_error(_("รหัสยืนยันไม่ถูกต้อง"))
                else:
                    disable_secret(secret_obj)

                    auth_helper.clear_2fa_session()
                    toolkit.h.flash_success(_("ปิดการใช้งาน 2FA สำเร็จ"))

            except Exception as e:
                log.error("Error disabling 2FA: %s", e, exc_info=True)
                toolkit.h.flash_error(_("เกิดข้อผิดพลาด"))

    return toolkit.redirect_to("user.read", id=user.name)


def authenticate(identity):
    return default_authenticate(identity)


def login():
    if toolkit.current_user.is_authenticated:
        return toolkit.render("user/logout_first.html", {})

    if request.method != "POST":
        return toolkit.render("user/login.html", {})

    login_value = toolkit.get_or_bust(request.form, "login")
    password = toolkit.get_or_bust(request.form, "password")

    user_obj = authenticate({"login": login_value, "password": password})
    if user_obj is None:
        toolkit.h.flash_error(_("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"))
        return toolkit.render("user/login.html", {})

    rotate_token()

    next_url = request.args.get("next") or request.form.get("next") or toolkit.url_for("home.index")
    auth_helper.set_pending_user(user_obj.name, user_obj.id, next_url=next_url)

    if _user_has_twofa(user_obj):
        return redirect(toolkit.url_for("thaigdc2fa.verify", next=next_url))
    return redirect(toolkit.url_for("thaigdc2fa.setup", next=next_url))


def get_blueprints():
    return [blueprint]


blueprint.add_url_rule("/setup", "setup", view_func=setup, methods=["GET", "POST"])
blueprint.add_url_rule("/verify", "verify", view_func=verify, methods=["GET", "POST"])
blueprint.add_url_rule("/disable", "disable", view_func=disable, methods=["POST"])
