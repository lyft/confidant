from confidant import settings
from confidant.app import create_app

if __name__ == '__main__':
    app = create_app()
    app.run(
        host=settings.get('HOST', '127.0.0.1'),
        port=settings.get('PORT', 5000),
        debug=settings.get('DEBUG', True)
    )
