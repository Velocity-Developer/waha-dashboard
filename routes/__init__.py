from .auth import bp as auth_bp
from .dashboard import bp as dashboard_bp
from .gateway import bp as gateway_bp
from .admin import bp as admin_bp


def register_routes(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(gateway_bp)
    app.register_blueprint(admin_bp)
