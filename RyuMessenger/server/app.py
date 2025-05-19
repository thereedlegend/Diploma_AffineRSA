from flask import Flask, g, request
from flask_cors import CORS
import os
import secrets # Добавлено для генерации SECRET_KEY
import logging
from logging.handlers import RotatingFileHandler
from collections import defaultdict
import time
import jwt

from RyuMessenger.server.core.database import init_db, get_db_connection
from RyuMessenger.server.core.key_manager import ServerKeyManager
from RyuMessenger.server.core.encryption_service import EncryptionService
from RyuMessenger.server.services.user_service import UserService
from RyuMessenger.server.services.message_service import MessageService
from RyuMessenger.server.api import api_bp

# Определяем абсолютный путь к директории instance и файлу БД
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_FOLDER_PATH = os.path.join(BASE_DIR, 'instance')
DATABASE_PATH = os.path.join(INSTANCE_FOLDER_PATH, 'ryumessenger.sqlite3')
LOG_PATH = os.path.join(BASE_DIR, 'logs.txt')

# Словарь для отслеживания первых запросов от каждого пользователя
# Ключ: (user_id, endpoint_type), значение: временная метка первого запроса
first_requests = {}

# Функция для очистки старых записей
def cleanup_first_requests():
    current_time = time.time()
    # Очищаем записи старше 12 часов
    to_remove = []
    for key, timestamp in first_requests.items():
        if current_time - timestamp > 12 * 3600:  # 12 часов в секундах
            to_remove.append(key)
    
    for key in to_remove:
        del first_requests[key]

# Класс фильтра для исключения регулярных запросов из логов
class RegularRequestsFilter(logging.Filter):
    def filter(self, record):
        # Пропускаем все сообщения не от werkzeug
        if not hasattr(record, 'name') or 'werkzeug' not in record.name.lower():
            return True
        
        # Проверяем флаг skip_logging, установленный в before_request
        try:
            if hasattr(request, 'skip_logging'):
                # Если это первый запрос - логируем
                if hasattr(request, 'is_first_request') and request.is_first_request:
                    return True
                # Если нужно пропустить логирование - пропускаем
                if request.skip_logging:
                    return False
        except:
            # В случае ошибки доступа к объекту request (например, вне контекста запроса)
            pass
            
        return True

def create_app(config_object='RyuMessenger.server.core.config'):
    app = Flask(__name__, instance_path=INSTANCE_FOLDER_PATH, instance_relative_config=False)
    app.config.from_object(config_object)
    # app.config.from_pyfile('config.py', silent=True) # Если есть config.py в instance folder
    
    # Настройка кодировки и локали
    import locale
    import sys
    if sys.platform == 'win32':
        # На Windows указываем явно русскую локаль и UTF-8
        try:
            locale.setlocale(locale.LC_ALL, 'Russian_Russia.UTF-8')
        except locale.Error:
            try:
                # Пробуем более общую локаль
                locale.setlocale(locale.LC_ALL, 'Russian_Russia.1251')
            except locale.Error:
                app.logger.warning("Не удалось установить русскую локаль")
    else:
        # На Unix-подобных системах
        try:
            locale.setlocale(locale.LC_ALL, 'ru_RU.UTF-8')
        except locale.Error:
            app.logger.warning("Не удалось установить русскую локаль")
    
    # Настройка логирования
    if not os.path.exists(os.path.dirname(LOG_PATH)):
        os.makedirs(os.path.dirname(LOG_PATH))
    
    # Удаляем все существующие обработчики логов
    for handler in app.logger.handlers:
        app.logger.removeHandler(handler)
    
    # Создаем форматтер для логов
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )
    
    # Файловый обработчик
    file_handler = RotatingFileHandler(LOG_PATH, maxBytes=10485760, backupCount=3, encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    # Консольный обработчик
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG)  # В консоль выводим все уровни для отладки
    app.logger.addHandler(console_handler)
    
    app.logger.setLevel(logging.DEBUG)  # Устанавливаем уровень логирования DEBUG для всех логгеров
    
    # Добавляем фильтр для исключения регулярных запросов
    app.logger.addFilter(RegularRequestsFilter())
    
    # Настраиваем логгер werkzeug для использования того же фильтра
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.addFilter(RegularRequestsFilter())
    
    # Убираем существующие обработчики и добавляем новые с правильной кодировкой
    for handler in werkzeug_logger.handlers:
        werkzeug_logger.removeHandler(handler)
    
    werkzeug_file_handler = RotatingFileHandler(LOG_PATH, maxBytes=10485760, backupCount=3, encoding='utf-8')
    werkzeug_file_handler.setFormatter(formatter)
    werkzeug_logger.addHandler(werkzeug_file_handler)
    
    werkzeug_console_handler = logging.StreamHandler()
    werkzeug_console_handler.setFormatter(formatter)
    werkzeug_console_handler.setLevel(logging.DEBUG)
    werkzeug_logger.addHandler(werkzeug_console_handler)
    
    # Также фильтруем логи от самого Flask
    flask_logger = logging.getLogger('flask')
    flask_logger.addFilter(RegularRequestsFilter())
    
    # Убираем существующие обработчики и добавляем новые с правильной кодировкой
    for handler in flask_logger.handlers:
        flask_logger.removeHandler(handler)
    
    flask_file_handler = RotatingFileHandler(LOG_PATH, maxBytes=10485760, backupCount=3, encoding='utf-8')
    flask_file_handler.setFormatter(formatter)
    flask_logger.addHandler(flask_file_handler)
    
    flask_console_handler = logging.StreamHandler()
    flask_console_handler.setFormatter(formatter)
    flask_console_handler.setLevel(logging.DEBUG)
    flask_logger.addHandler(flask_console_handler)
    
    # И наконец настраиваем корневой логгер
    root_logger = logging.getLogger()
    root_logger.addFilter(RegularRequestsFilter())
    
    # Добавляем обработчики для корневого логгера
    root_file_handler = RotatingFileHandler(LOG_PATH, maxBytes=10485760, backupCount=3, encoding='utf-8')
    root_file_handler.setFormatter(formatter)
    root_logger.addHandler(root_file_handler)
    
    root_console_handler = logging.StreamHandler()
    root_console_handler.setFormatter(formatter)
    root_console_handler.setLevel(logging.DEBUG)
    root_logger.addHandler(root_console_handler)
    
    app.logger.info('RyuMessenger server startup')
    
    # Отключаем распространение логов на родительские логгеры (включая корневой)
    app.logger.propagate = False
    
    # Установка SECRET_KEY, если он еще не установлен
    if not app.config.get('SECRET_KEY'):
        app.config['SECRET_KEY'] = secrets.token_hex(32)
        app.logger.info(f"Generated and set SECRET_KEY: {app.config['SECRET_KEY']}") # Логирование для отладки

    CORS(app) # Разрешаем CORS для всех доменов (для разработки)

    # Инициализация менеджера ключей и сервиса шифрования
    # Они будут созданы один раз при запуске приложения
    # и доступны через app.extensions или напрямую, если передать в контекст запроса
    if not hasattr(app, 'extensions') or 'key_manager' not in app.extensions:
        app.key_manager = ServerKeyManager(keys_file=os.path.join(app.instance_path, 'server_keys.json'))
        app.encryption_service = EncryptionService(
            server_rsa_cipher=app.key_manager.get_rsa_cipher()
        )
        app.user_service = UserService(encryption_service=app.encryption_service)
        app.message_service = MessageService(encryption_service=app.encryption_service, user_service=app.user_service)

    with app.app_context():
        # Инициализация БД только если файл не существует
        if not os.path.exists(DATABASE_PATH):
            app.logger.info(f"База данных не найдена, создаём новую: {DATABASE_PATH}")
            init_db()
        else:
            app.logger.info(f"База данных уже существует: {DATABASE_PATH}")

    # Регистрация Blueprint API
    app.register_blueprint(api_bp)

    @app.route('/')
    def hello():
        # Просто для проверки, что сервер работает
        server_pub_key = app.key_manager.get_rsa_public_key()
        return f"RyuMessenger Server is running! Server RSA_n: {str(server_pub_key[0])[:30]}..."

    # Используем before_request для более точной фильтрации частых запросов
    @app.before_request
    def skip_logging_for_regular_updates():
        # Получаем идентификатор пользователя из JWT токена
        user_id = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1] # Ожидаем "Bearer <token>"
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                user_id = data.get('user_id')
            except Exception as e:
                pass
        
        # Если пользователь не авторизован, используем IP-адрес как идентификатор
        if not user_id:
            user_id = request.remote_addr or 'anonymous'
            
        endpoint_type = None
        # Определяем тип эндпоинта
        if request.path.endswith('/chats') or '/chats' in request.path:
            endpoint_type = 'chats'
        elif request.path.endswith('/messages') or '/messages' in request.path:
            endpoint_type = 'messages'
        
        # Проверяем, является ли это запросом на обновление
        is_update_request = False
        if endpoint_type and (
            request.method == 'GET' or (
                request.method == 'POST' and (
                    'last_message_id' in request.args or
                    'last_update_time' in request.args or
                    (request.is_json and request.json and (
                        'last_message_id' in request.json or
                        'last_update_time' in request.json
                    ))
                )
            )
        ):
            is_update_request = True
            
        # Если это запрос на обновление
        if is_update_request and endpoint_type:
            request_key = (user_id, endpoint_type)
            
            # Проверяем, первый ли это запрос для данного пользователя и эндпоинта
            if not first_requests.get(request_key):
                # Маркируем как первый запрос
                request.is_first_request = True
                first_requests[request_key] = time.time()
                app.logger.info(f"First {endpoint_type} update request from user {user_id}")
            else:
                # Последующие запросы пропускаем
                request.skip_logging = True
        
        # Не пропускаем фактическую обработку запроса
        return None

    # Установка таймера для периодической очистки устаревших первых запросов
    # Запускаем очистку каждый час
    if not hasattr(app, '_first_requests_cleanup_timer'):
        from threading import Timer
        
        def scheduled_cleanup():
            with app.app_context():
                try:
                    cleanup_first_requests()
                    app.logger.info(f"Cleaned up first requests tracking. Current size: {len(first_requests)}")
                except Exception as e:
                    app.logger.error(f"Error during first requests cleanup: {e}")
                
                # Перезапускаем таймер
                app._first_requests_cleanup_timer = Timer(3600, scheduled_cleanup)  # 1 час
                app._first_requests_cleanup_timer.daemon = True
                app._first_requests_cleanup_timer.start()
        
        # Запускаем первый таймер
        app._first_requests_cleanup_timer = Timer(3600, scheduled_cleanup)
        app._first_requests_cleanup_timer.daemon = True
        app._first_requests_cleanup_timer.start()

    return app

if __name__ == '__main__':
    # Это для запуска через `python app.py` (не рекомендуется для продакшена)
    # Используйте `flask run` или Gunicorn/uWSGI
    
    # Настройка консольного вывода
    import sys
    if sys.platform == 'win32':
        # Для Windows устанавливаем кодировку консоли в UTF-8
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
        # Дополнительно можно изменить кодовую страницу консоли Windows
        try:
            import subprocess
            subprocess.run(['chcp', '65001'], shell=True, check=True)  # 65001 = UTF-8
        except Exception as e:
            print(f"Ошибка при изменении кодовой страницы консоли: {e}")
    
    app = create_app()
    # Путь к ключам сервера относительно instance папки
    app.logger.info(f"Путь к instance: {app.instance_path}")
    app.logger.info(f"Ключи сервера ожидаются по пути: {os.path.join(app.instance_path, 'server_keys.json')}")
    app.logger.info(f"База данных ожидается по пути: {DATABASE_PATH}")
    app.logger.info(f"Логи сохраняются в файл: {LOG_PATH}")
    
    # Регистрируем функцию для остановки таймера при закрытии приложения
    import atexit
    @atexit.register
    def cleanup_on_exit():
        if hasattr(app, '_first_requests_cleanup_timer'):
            app._first_requests_cleanup_timer.cancel()
            app.logger.info("Cleanup timer stopped on application exit")
    
    # Отключаем вывод от werkzeug в консоль
    log = logging.getLogger('werkzeug')
    log.disabled = True
    app.run(debug=True, host='0.0.0.0', port=5000) # debug=True для разработки 