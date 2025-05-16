from RyuMessenger.server.app import create_app
import os

# Этот скрипт удобен для запуска приложения с помощью отладчика IDE
# или если вы хотите явно указать конфигурацию.

# Определяем путь к директории instance, если он не установлен
# Это важно, чтобы Flask нашел instance папку для server_keys.json и БД
config_name = os.getenv('FLASK_CONFIG') or 'default' # Можно добавить разные конфиги (dev, prod, test)

app = create_app() # Использует config по умолчанию из create_app

if __name__ == '__main__':
    # Получаем хост и порт из переменных окружения или используем значения по умолчанию
    HOST = os.environ.get('SERVER_HOST', '0.0.0.0')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5000'))
    except ValueError:
        PORT = 5000
    
    # Вывод информации о запуске
    instance_path = app.instance_path
    db_path = os.path.join(instance_path, 'ryumessenger.sqlite3')
    keys_path = os.path.join(instance_path, 'server_keys.json')

    print(f"--- Сервер RyuMessenger --- ")
    print(f"Запуск сервера разработки на http://{HOST}:{PORT}")
    print(f"Папка instance: {instance_path}")
    print(f"База данных: {db_path}")
    print(f"Ключи сервера: {keys_path}")
    print("---------------------------")

    # Запуск Flask development server
    # Для продакшена используйте Gunicorn или uWSGI
    # app.run(host=HOST, port=PORT, debug=app.config.get('DEBUG', True))
    # Используем debug=True для разработки, как указано в app.py, если там не переопределено
    app.run(host=HOST, port=PORT, debug=True) 