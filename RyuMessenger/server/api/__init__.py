from flask import Blueprint

api_bp = Blueprint('api', __name__, url_prefix='/api')

# Импортируем маршруты здесь, чтобы они были зарегистрированы в blueprint
# Делаем это в конце файла, чтобы избежать циклических импортов
from . import routes 