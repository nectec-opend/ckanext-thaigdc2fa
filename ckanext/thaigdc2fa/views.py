import base64
import datetime
import hashlib
import io
import logging
import os
from urllib.parse import urlparse

import pyotp
import qrcode
from cryptography.fernet import Fernet
from flask import Blueprint, redirect, render_template

import ckan.plugins.toolkit as toolkit
from ckan.common import _, config, g, request, session
from ckan.model import meta, User
from ckanext.thaigdc2fa.model import create_secret, get_secret_by_user_id, update_verified_at, disable_secret, TwoFASecret
from ckan.views.user import next_page_or_default, rotate_token
from ckan.lib.authenticator import default_authenticate
from sqlalchemy import desc

from ckanext.thaigdc2fa import auth_helper

log = logging.getLogger(__name__)

blueprint = Blueprint("thaigdc2fa", __name__, url_prefix="/2fa")

def _is_safe_redirect_url(url):
    """ตรวจสอบว่า URL ปลอดภัยสำหรับ redirect (ต้องเป็น relative path เท่านั้น)"""
    if not url:
        return False
    parsed = urlparse(url)
    return (
        parsed.scheme == ""
        and parsed.netloc == ""
        and url.startswith("/")
        and not url.startswith("//")
    )


def _safe_next_url(url, fallback=None):
    """คืน URL ที่ปลอดภัย ถ้าไม่ปลอดภัยให้ใช้ fallback"""
    if fallback is None:
        fallback = toolkit.url_for("home.index")
    if _is_safe_redirect_url(url):
        return url
    return fallback


# ---------------------------------------------------------------------------
# Rate limiting (in-memory, เหมาะสำหรับ single-process — ถ้าใช้ multi-process ให้เปลี่ยนเป็น Redis)
# ---------------------------------------------------------------------------

_otp_fail_tracker = {}   # key: user_id → {"count": int, "locked_until": datetime|None}
_FAIL_LIMIT = 5          # จำนวนครั้งที่ fail ได้
_LOCKOUT_SECONDS = 900   # 15 นาที


def _check_otp_rate_limit(user_id):
    """
    คืน (is_blocked, seconds_remaining)
    """
    now = datetime.datetime.utcnow()
    state = _otp_fail_tracker.get(user_id)
    if not state:
        return False, 0
    locked_until = state.get("locked_until")
    if locked_until and now < locked_until:
        remaining = int((locked_until - now).total_seconds())
        return True, remaining
    if locked_until and now >= locked_until:
        # หมด lockout แล้ว reset
        _otp_fail_tracker.pop(user_id, None)
    return False, 0


def _record_otp_fail(user_id):
    """บันทึกการ fail และ lock ถ้าเกิน limit"""
    now = datetime.datetime.utcnow()
    state = _otp_fail_tracker.setdefault(user_id, {"count": 0, "locked_until": None})
    state["count"] += 1
    if state["count"] >= _FAIL_LIMIT:
        state["locked_until"] = now + datetime.timedelta(seconds=_LOCKOUT_SECONDS)
        log.warning("2FA rate limit triggered for user_id=%s, locked for %ds", user_id, _LOCKOUT_SECONDS)


def _clear_otp_fail(user_id):
    """เมื่อ verify สำเร็จ ให้ reset counter"""
    _otp_fail_tracker.pop(user_id, None)


# ---------------------------------------------------------------------------
# OTP Replay prevention (in-memory used-token cache)
# ---------------------------------------------------------------------------

_used_otps = {}  # key: user_id → set of (totp_counter)


def _is_otp_replayed(user_id, totp_counter):
    """ตรวจว่า OTP counter นี้ถูกใช้ไปแล้วหรือยัง"""
    used = _used_otps.get(user_id, set())
    return totp_counter in used


def _mark_otp_used(user_id, totp_counter):
    """บันทึกว่า OTP counter นี้ถูกใช้แล้ว (เก็บแค่ 3 counter ล่าสุด)"""
    used = _used_otps.setdefault(user_id, set())
    used.add(totp_counter)
    # ตัดของเก่าออก: เก็บแค่ counter ที่ยังอยู่ใน window ±2
    now_counter = int(datetime.datetime.utcnow().timestamp()) // 30
    _used_otps[user_id] = {c for c in used if abs(c - now_counter) <= 2}


def get_cipher():
    key = os.environ.get("CKANEXT__THAIGDC2FA__CIPHER_KEY") or config.get(
        "ckanext.thaigdc2fa.cipher_key"
    )
    if not key:
        raise Exception(
            "ไม่พบคีย์การเข้ารหัส CKANEXT__THAIGDC2FA__CIPHER_KEY (env) หรือ ckanext.thaigdc2fa.cipher_key (ini)"
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

    # [FIX] ตรวจ rate limit บน setup ด้วย
    is_blocked, remaining = _check_otp_rate_limit("setup:" + user.id)
    if is_blocked:
        mins = remaining // 60
        toolkit.h.flash_error(_(f"พยายาม setup ผิดมากเกินไป กรุณารอ {mins} นาทีแล้วลองใหม่"))
        return toolkit.redirect_to("user.logout")

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        temp_secret = session.get("twofa_temp_secret")

        if not temp_secret:
            toolkit.h.flash_error(_("Session หมดอายุ กรุณาลองใหม่อีกครั้ง"))
            return redirect(toolkit.url_for("thaigdc2fa.setup"))

        totp = pyotp.TOTP(temp_secret)
        # [FIX] ลด valid_window=0
        if not totp.verify(code, valid_window=0):
            _record_otp_fail("setup:" + user.id)
            toolkit.h.flash_error(_("รหัสยืนยันไม่ถูกต้อง กรุณาลองใหม่"))
        else:
            try:
                cipher = get_cipher()
                encrypted_secret = cipher.encrypt(temp_secret.encode()).decode()

                create_secret(user.id, encrypted_secret)
                _clear_otp_fail("setup:" + user.id)

                # [FIX] set session state ก่อน login_user (atomic)
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

                # [FIX] ตรวจสอบ next URL ก่อน redirect
                raw_next = session.get("2fa_next_url")
                next_url = _safe_next_url(raw_next)
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

    # [FIX] ตรวจ rate limit ก่อน render form
    is_blocked, remaining = _check_otp_rate_limit(user.id)
    if is_blocked:
        mins = remaining // 60
        toolkit.h.flash_error(_(f"พยายาม verify ผิดมากเกินไป กรุณารอ {mins} นาทีแล้วลองใหม่"))
        return toolkit.redirect_to("user.logout")

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(secret)

        # [FIX] ลด valid_window=0 และตรวจ replay
        now_counter = int(datetime.datetime.utcnow().timestamp()) // 30
        if not totp.verify(code, valid_window=0):
            _record_otp_fail(user.id)
            is_blocked_now, remaining_now = _check_otp_rate_limit(user.id)
            return render_template(
                "thaigdc2fa/verify.html",
                error=True,
                user=user,
                locked=is_blocked_now,
                locked_mins=remaining_now // 60,
            )

        # [FIX] ป้องกัน OTP replay
        if _is_otp_replayed(user.id, now_counter):
            toolkit.h.flash_error(_("รหัสนี้ถูกใช้ไปแล้ว กรุณารอรหัสใหม่ (30 วินาที)"))
            return render_template("thaigdc2fa/verify.html", error=True, user=user)

        _mark_otp_used(user.id, now_counter)

        try:
            update_verified_at(secret_obj)
            _clear_otp_fail(user.id)

            # [FIX] set session state ก่อน login_user (atomic)
            if is_pending:
                auth_helper.create_login_session(user)
                auth_helper.clear_pending_user()
            else:
                session["2fa_validated"] = True
                session["2fa_user_id"] = user.id
                session.save()

            toolkit.login_user(user)

            # [FIX] ตรวจสอบ next URL ก่อน redirect
            raw_next = request.args.get("next") or session.get("2fa_next_url")
            next_url = _safe_next_url(raw_next)
            return redirect(next_url)

        except Exception as e:
            log.error("Error updating 2FA verification: %s", e, exc_info=True)
            toolkit.h.flash_error(_("เกิดข้อผิดพลาดในการบันทึก"))

    return render_template("thaigdc2fa/verify.html", user=user)

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

    # [FIX] ตรวจสอบ next URL ว่าเป็น relative path เท่านั้น
    raw_next = request.args.get("next") or request.form.get("next")
    safe_next = _safe_next_url(raw_next)
    auth_helper.set_pending_user(user_obj.name, user_obj.id, next_url=safe_next)

    if _user_has_twofa(user_obj):
        return redirect(toolkit.url_for("thaigdc2fa.verify"))
    return redirect(toolkit.url_for("thaigdc2fa.setup"))

def admin_users():
    """
    Admin page: manage 2FA users
    """
    user = getattr(g, "userobj", None)

    if not user or not user.sysadmin:
        return toolkit.abort(403, _("Sysadmin only"))

    db = meta.Session()

    rows = (
        db.query(TwoFASecret.created_at, TwoFASecret.verified_at, User.name, User.email, User.fullname, User.id.label("user_id"))
        .join(User, User.id == TwoFASecret.user_id)
        .filter(TwoFASecret.enabled == True)
        .order_by(desc(TwoFASecret.created_at))
        .all()
    )

    return toolkit.render("thaigdc2fa/admin_users.html", {"rows": rows})

def admin_reset(user_id):
    """
    Reset 2FA for a user — sysadmin only, with audit log
    """
    admin = getattr(g, "userobj", None)

    if not admin or not admin.sysadmin:
        return toolkit.abort(403, _("Sysadmin only"))

    # [FIX] ตรวจสอบ CSRF token สำหรับ POST action ที่ sensitive
    # CKAN จัดการ CSRF ผ่าน toolkit แต่ admin_reset form ควรมี csrf_input ด้วย
    # (ตรวจสอบ template ด้วย — ควรมี {{ h.csrf_input() }} ใน admin_users.html)

    secret = get_secret_by_user_id(user_id)

    if secret:
        disable_secret(secret)
        # [FIX] เพิ่ม audit log ว่าใครทำ reset ของใคร
        log.warning(
            "2FA ADMIN RESET: admin=%s reset 2FA for user_id=%s (remote_ip=%s)",
            admin.name,
            user_id,
            request.remote_addr,
        )

    toolkit.h.flash_success(_("2FA reset สำเร็จ"))
    return toolkit.redirect_to("thaigdc2fa.admin_users")

def get_blueprints():
    return [blueprint]


blueprint.add_url_rule("/setup", "setup", view_func=setup, methods=["GET", "POST"])
blueprint.add_url_rule("/verify", "verify", view_func=verify, methods=["GET", "POST"])
blueprint.add_url_rule(
    "/admin/users",
    "admin_users",
    view_func=admin_users,
    methods=["GET"],
)
blueprint.add_url_rule(
    "/admin/reset/<user_id>",
    "admin_reset",
    view_func=admin_reset,
    methods=["POST"],
)