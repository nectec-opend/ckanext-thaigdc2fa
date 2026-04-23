import logging
from ckan.common import request, session

log = logging.getLogger(__name__)

def create_login_session(user):
    """
    สร้าง login session จริงหลังจาก 2FA สำเร็จ
    [FIX] ตั้ง 2fa_validated ใน session ก่อน แล้วค่อย set REMOTE_USER
    เพื่อป้องกัน race condition ที่อาจเกิดจาก concurrent request
    """
    try:
        # [FIX] Step 1: set session state ก่อน (2fa_validated ต้องเป็น True ก่อน REMOTE_USER)
        session["user"] = user.name
        session["2fa_validated"] = True
        session["2fa_user_id"] = user.id
        session.pop("twofa_temp_secret", None)
        session.save()

        # [FIX] Step 2: ค่อย set REMOTE_USER หลังจาก session ถูก save แล้ว
        environ = request.environ
        identity = {
            "repoze.who.userid": user.name,
            "user": user.name,
            "userobj": user,
        }
        environ["repoze.who.identity"] = identity
        environ["REMOTE_USER"] = user.name

        log.info("Login session created successfully for %s", user.name)
        return True
    except Exception as e:
        log.error("Error creating login session: %s", e, exc_info=True)
        return False


def set_pending_user(username, user_id, next_url=None):
    session["2fa_pending_user"] = username
    session["2fa_pending_user_id"] = user_id
    session["2fa_validated"] = False
    if next_url:
        session["2fa_next_url"] = next_url
    session.save()


def get_pending_user():
    u = session.get("2fa_pending_user")
    uid = session.get("2fa_pending_user_id")
    if u and uid:
        return {"username": u, "user_id": uid}
    return None


def clear_pending_user():
    session.pop("2fa_pending_user", None)
    session.pop("2fa_pending_user_id", None)
    session.pop("2fa_next_url", None)
    session.save()


def clear_2fa_session():
    session.pop("2fa_validated", None)
    session.pop("2fa_user_id", None)
    session.pop("2fa_pending_user", None)
    session.pop("2fa_pending_user_id", None)
    session.pop("2fa_next_url", None)
    session.pop("twofa_temp_secret", None)
    session.save()