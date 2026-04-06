"""
app/__init__.py — Flask Application Factory
"""

from flask import Flask
from app.config import get_config
from app.models.database import close_db, init_db
from app.middleware.rate_limiter import init_limiter


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Load config
    cfg = get_config()
    app.config.from_object(cfg)

    # Initialize extensions
    init_limiter(app)
    init_db(app)

    # Register teardown
    app.teardown_appcontext(close_db)

    # Register blueprints
    from app.routes.auth_routes import auth_bp
    from app.routes.page_routes import page_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(page_bp)

    return app
