# ckanext/thaigdc2fa/plugin.py
import logging

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckan.common import request, session

from ckanext.thaigdc2fa import auth_helper
from ckanext.thaigdc2fa.model import setup as model_setup

log = logging.getLogger(__name__)


class Thaigdc2faPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IBlueprint)

    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("assets", "thaigdc2fa")
        model_setup()

    # -------- IAuthenticator --------

    def login(self):
        # ให้ CKAN ใช้ login ของเราแทน
        from ckanext.thaigdc2fa import views
        return views.login()

    def logout(self):
        auth_helper.clear_2fa_session()

    def identify(self):
        """
        บังคับ flow:
        - ถ้ามี pending user -> อนุญาตแค่ /2fa/* และ /user/logout และ static
        - ถ้ามี REMOTE_USER แล้ว แต่ session ไม่ validated -> บังคับ logout
        """
        path = request.path or ""

        # allowlist ตอน pending
        allow_when_pending = (
            path.startswith("/2fa/")
            or path.startswith("/user/logout")
            or path.startswith("/user/_logout")
            or path.startswith("/api/")
            or path.startswith("/fanstatic/")
            or path.startswith("/webassets/")
            or path.startswith("/base/")
            or path.startswith("/images/")
            or path.startswith("/styles/")
            or path == "/favicon.ico"
        )

        pending = auth_helper.get_pending_user()
        if pending:
            if not allow_when_pending:
                # ตัดสินว่าจะ setup หรือ verify
                from ckan import model
                user = model.User.get(pending["username"])
                if user:
                    plugin_extras = user.plugin_extras or {}
                    has_twofa = (
                        plugin_extras.get("twofa_enabled") == "true"
                        and plugin_extras.get("twofa_secret")
                    )
                    target = "thaigdc2fa.verify" if has_twofa else "thaigdc2fa.setup"
                else:
                    target = "user.login"
                return toolkit.redirect_to(target)
            return

        # ถ้า login จริงแล้ว แต่ session ไม่ผ่าน 2FA -> บังคับ logout แล้วให้ login ใหม่
        if request.environ.get("REMOTE_USER"):
            validated = session.get("2fa_validated", False)
            if not validated and not path.startswith("/2fa/"):
                auth_helper.clear_2fa_session()
                toolkit.h.flash_error("กรุณายืนยัน 2FA ก่อนใช้งาน")
                return toolkit.redirect_to("user.login")

    # -------- IBlueprint --------

    def get_blueprint(self):
        from ckanext.thaigdc2fa import views
        return views.get_blueprints()
