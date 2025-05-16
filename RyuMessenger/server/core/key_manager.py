import json
import os
from .affine_cipher import generate_affine_params, AffineCipher
from .rsa_cipher import RSACipher

SERVER_KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'keys')
SERVER_KEYS_FILE = os.path.join(SERVER_KEYS_DIR, "server_keys.json")
SERVER_PRIVATE_KEY_FILE = os.path.join(SERVER_KEYS_DIR, "server_private_key.json")

class ServerKeyManager:
    def __init__(self, keys_file=SERVER_KEYS_FILE, private_key_file=SERVER_PRIVATE_KEY_FILE):
        self.keys_file = keys_file
        self.private_key_file = private_key_file
        self.rsa_cipher = RSACipher()
        self.affine_params = None # {"ru": {"a": ..., "b": ...}, "en": ...}
        self.ensure_keys_directory()
        self._load_or_generate_keys()

    def ensure_keys_directory(self):
        if not os.path.exists(SERVER_KEYS_DIR):
            os.makedirs(SERVER_KEYS_DIR)
            print(f"Создана директория для ключей сервера: {SERVER_KEYS_DIR}")

    def _load_or_generate_keys(self):
        # Публичный ключ и аффинные параметры
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, 'r') as f:
                    keys_data = json.load(f)
                rsa_pub = keys_data['rsa_public_key']
                self.rsa_cipher.set_public_key(rsa_pub['n'], rsa_pub['e'])
                self.affine_params = keys_data['affine_params']
                if not (self.affine_params.get('ru') and self.affine_params.get('en')):
                    print("Отсутствуют аффинные параметры для одного или нескольких языков в файле ключей. Перегенерирую.")
                    self._generate_and_save_keys()
                else:
                    # Приватный ключ
                    if os.path.exists(self.private_key_file):
                        with open(self.private_key_file, 'r') as f:
                            priv_data = json.load(f)
                        n = priv_data['n']
                        d = priv_data['d']
                        self.rsa_cipher.set_private_key(n, d)
                        print(f"Приватный ключ сервера загружен из {self.private_key_file}")
                    else:
                        print("Файл приватного ключа сервера не найден. Генерирую новый приватный ключ.")
                        self._generate_and_save_private_key()
                    print(f"Ключи сервера загружены из {self.keys_file}")
            except (IOError, KeyError, json.JSONDecodeError) as e:
                print(f"Ошибка при загрузке ключей сервера: {e}. Перегенерирую ключи.")
                self._generate_and_save_keys()
        else:
            print("Файл ключей сервера не найден. Генерирую новые ключи.")
            self._generate_and_save_keys()

    def _generate_and_save_keys(self):
        # Генерация RSA ключей
        rsa_pub, rsa_priv = self.rsa_cipher.generate_keys()
        self.affine_params = generate_affine_params()
        keys_data = {
            "rsa_public_key": {"n": str(rsa_pub[0]), "e": str(rsa_pub[1])},
            "affine_params": self.affine_params
        }
        try:
            with open(self.keys_file, 'w') as f:
                json.dump(keys_data, f, indent=4)
            print(f"Ключи сервера сгенерированы и сохранены в {self.keys_file}")
            # Сохраняем приватный ключ отдельно
            self._generate_and_save_private_key()
        except IOError as e:
            print(f"ФАТАЛЬНО: Не удалось записать ключи сервера в {self.keys_file}: {e}")
            raise

    def _generate_and_save_private_key(self):
        n, d = self.rsa_cipher.private_key
        priv_data = {"n": str(n), "d": str(d)}
        try:
            with open(self.private_key_file, 'w') as f:
                json.dump(priv_data, f, indent=4)
            print(f"Приватный ключ сервера сохранён в {self.private_key_file}")
        except IOError as e:
            print(f"ФАТАЛЬНО: Не удалось записать приватный ключ сервера в {self.private_key_file}: {e}")
            raise

    def get_rsa_public_key(self):
        return self.rsa_cipher.public_key

    def get_affine_params(self):
        return self.affine_params

    def get_rsa_cipher(self):
        return self.rsa_cipher

# Инициализация менеджера ключей при импорте модуля, чтобы ключи были доступны
# Это создаст файл ключей при первом запуске, если его нет.
# server_key_manager = ServerKeyManager() 