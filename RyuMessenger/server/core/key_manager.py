import json
import os
import secrets
# from .affine_cipher import generate_affine_params, AffineCipher # generate_affine_params удален
from .affine_cipher import AffineCipher # Оставляем AffineCipher, если он нужен где-то еще
from .rsa_cipher import RSACipher

SERVER_KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'keys')
SERVER_KEYS_FILE = os.path.join(SERVER_KEYS_DIR, "server_keys.json")
SERVER_PRIVATE_KEY_FILE = os.path.join(SERVER_KEYS_DIR, "server_private_key.json")

# Глобальные DH_P, DH_G УДАЛЕНЫ

class ServerKeyManager:
    def __init__(self, keys_file=SERVER_KEYS_FILE, private_key_file=SERVER_PRIVATE_KEY_FILE):
        self.keys_file = keys_file
        self.private_key_file = private_key_file
        self.rsa_cipher = RSACipher()
        # self.affine_params = None # Удалено
        self.dh_p = None 
        self.dh_g = None  # <<< ДОБАВЛЕНО для хранения G
        self.dh_private_key_x = None
        self.dh_public_key_y = None
        self.ensure_keys_directory()
        self._load_or_generate_keys()

    def _generate_new_dh_parameters(self):
        """Имитирует генерацию новых параметров DH. Возвращает (P, G)."""
        # !!! ВАЖНО: ЭТИ ПАРАМЕТРЫ DH (P, G) ИСПОЛЬЗУЮТСЯ ТОЛЬКО ДЛЯ ИЛЛЮСТРАЦИИ !!!
        # !!! ОНИ НЕ ЯВЛЯЮТСЯ БЕЗОПАСНЫМИ ДЛЯ РЕАЛЬНОГО ИСПОЛЬЗОВАНИЯ !!!
        print("Имитация генерации новых DH параметров (P=23, G=5) - НЕБЕЗОПАСНО!")
        return 23, 5

    def ensure_keys_directory(self):
        if not os.path.exists(SERVER_KEYS_DIR):
            os.makedirs(SERVER_KEYS_DIR)
            print(f"Создана директория для ключей сервера: {SERVER_KEYS_DIR}")

    def _load_or_generate_keys(self):
        keys_loaded_successfully = False
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, 'r') as f:
                    keys_data = json.load(f)
                
                rsa_pub = keys_data['rsa_public_key']
                self.rsa_cipher.set_public_key(rsa_pub['n'], rsa_pub['e'])
                # self.affine_params = keys_data['affine_params'] # Удалено

                loaded_dh_params = keys_data.get('dh_parameters')
                if loaded_dh_params and 'p' in loaded_dh_params and 'g' in loaded_dh_params:
                    self.dh_p = int(loaded_dh_params['p'])
                    self.dh_g = int(loaded_dh_params['g'])
                    self.dh_public_key_y = int(keys_data['dh_public_key_y'])
                    print(f"Загружены DH параметры P={self.dh_p}, G={self.dh_g} и Y={self.dh_public_key_y}")
                else:
                    print("DH параметры отсутствуют или некорректны в файле ключей. Будут сгенерированы новые.")
                    # Оставляем dh_p, dh_g как None, чтобы _generate_and_save_keys их сгенерировал

                # Проверка на affine_params удалена, т.к. они больше не загружаются
                # if not (self.affine_params.get('ru') and self.affine_params.get('en')):
                #    print("Отсутствуют аффинные параметры. Будут сгенерированы новые.")
                #    # Позволим _generate_and_save_keys обработать это
                # else:
                #    keys_loaded_successfully = True # Основные части загружены
                keys_loaded_successfully = True # Считаем успешным, если RSA и DH (если есть) загружены

            except (IOError, KeyError, ValueError, json.JSONDecodeError) as e:
                print(f"Ошибка при частичной загрузке ключей сервера: {e}. Ключи будут перегенерированы.")
                # Сбрасываем все, чтобы обеспечить полную перегенерацию
                self.rsa_cipher = RSACipher() # Сброс RSA
                # self.affine_params = None # Удалено
                self.dh_p = None; self.dh_g = None; self.dh_public_key_y = None; self.dh_private_key_x = None
        
        if not keys_loaded_successfully or not self.dh_p or not self.dh_g:
            print("Полная или частичная перегенерация ключей (включая DH параметры)...")
            self._generate_and_save_keys()
            keys_loaded_successfully = True # После генерации считаем успешным

        # Загрузка или генерация приватных ключей (RSA и DH)
        # Это должно происходить ПОСЛЕ того, как P и G для DH точно установлены (загружены или сгенерированы)
        if keys_loaded_successfully:
            if os.path.exists(self.private_key_file):
                try:
                    with open(self.private_key_file, 'r') as f:
                        priv_data = json.load(f)
                    self.rsa_cipher.set_private_key(priv_data['n'], priv_data['d'])
                    
                    if 'dh_private_key_x' in priv_data:
                        self.dh_private_key_x = int(priv_data['dh_private_key_x'])
                        # Валидация приватного DH ключа x с публичным Y и параметрами P,G
                        if self.dh_p and self.dh_g and self.dh_public_key_y:
                            expected_y = pow(self.dh_g, self.dh_private_key_x, self.dh_p)
                            if expected_y != self.dh_public_key_y:
                                print("Обнаружено несоответствие приватного DH ключа (x) с публичным (Y) и параметрами (P,G). Перегенерация всех ключей.")
                                self._generate_and_save_keys() # Полная перегенерация
                            else:
                                print(f"Приватные ключи сервера (RSA, DH) успешно загружены и верифицированы из {self.private_key_file}")
                        else:
                             print("Невозможно верифицировать приватный DH ключ x, так как P,G или Y не установлены. Ошибка логики.")
                    else:
                        print("Приватный ключ DH (x) отсутствует в файле приватных ключей. Генерация...")
                        self._generate_and_save_private_key() # Попытка сгенерировать только приватные
                except (IOError, KeyError, ValueError, json.JSONDecodeError) as e:
                    print(f"Ошибка загрузки приватных ключей из {self.private_key_file}: {e}. Генерация...")
                    self._generate_and_save_private_key()
            else:
                print(f"Файл приватных ключей {self.private_key_file} не найден. Генерация...")
                self._generate_and_save_private_key()
            
            if not self.dh_private_key_x or not self.rsa_cipher.private_key:
                 print("Один из приватных ключей (RSA или DH) не был установлен после попыток загрузки/генерации. Критическая ошибка.")
                 # В идеале здесь нужно либо остановить приложение, либо обеспечить генерацию
                 # Для простоты пока просто лог, но это плохая ситуация.

    def _generate_and_save_keys(self):
        # Генерация RSA ключей
        rsa_pub, _ = self.rsa_cipher.generate_keys()
        # self.affine_params = generate_affine_params() # Удалено
        
        # Генерация DH параметров P и G, если они еще не установлены
        if not self.dh_p or not self.dh_g:
            self.dh_p, self.dh_g = self._generate_new_dh_parameters()
            print(f"Сгенерированы (имитация) новые DH параметры: P={self.dh_p}, G={self.dh_g}")
        
        # Генерация DH ключей (x, Y) на основе текущих P, G
        self.dh_private_key_x = secrets.randbelow(self.dh_p - 2) + 1 
        self.dh_public_key_y = pow(self.dh_g, self.dh_private_key_x, self.dh_p)
        print(f"Сгенерированы DH ключи: x={self.dh_private_key_x}, Y={self.dh_public_key_y} (для P={self.dh_p}, G={self.dh_g})")

        keys_data = {
            "rsa_public_key": {"n": str(rsa_pub[0]), "e": str(rsa_pub[1])},
            # "affine_params": self.affine_params, # Удалено
            "dh_public_key_y": str(self.dh_public_key_y),
            "dh_parameters": {"p": str(self.dh_p), "g": str(self.dh_g)}
        }
        try:
            with open(self.keys_file, 'w') as f:
                json.dump(keys_data, f, indent=4)
            print(f"Публичные ключи сервера (RSA, Affine, DH) и DH параметры сохранены в {self.keys_file}")
            # Сохраняем приватные ключи (RSA и DH) отдельно, т.к. dh_private_key_x теперь известен
            self._generate_and_save_private_key() 
        except IOError as e:
            print(f"ФАТАЛЬНО: Не удалось записать публичные ключи/DH параметры в {self.keys_file}: {e}")
            raise

    def _generate_and_save_private_key(self):
        # Убедимся, что RSA приватный ключ существует (он генерируется в self.rsa_cipher.generate_keys())
        if not self.rsa_cipher.private_key:
            print("RSA приватный ключ отсутствует перед сохранением. Попытка генерации RSA.")
            self.rsa_cipher.generate_keys() # Это установит self.rsa_cipher.private_key
        
        n_rsa, d_rsa = self.rsa_cipher.private_key
        
        # Убедимся, что приватный DH ключ x существует, если P и G известны
        if not self.dh_private_key_x and self.dh_p:
            print("Генерация приватного DH ключа (x) в _generate_and_save_private_key, так как он отсутствует, а P известно.")
            self.dh_private_key_x = secrets.randbelow(self.dh_p - 2) + 1
            # Важно: если x здесь генерируется, то Y должен быть пересчитан и keys_file обновлен.
            # Однако, основная генерация x и Y происходит в _generate_and_save_keys.
            # Здесь мы только сохраняем x, если он был сгенерирован там.
            # Если _generate_and_save_keys не вызывался, а x генерируется тут, то Y может быть неактуальным.
            # Эта логика требует аккуратности. Безопаснее всего, если _generate_and_save_keys всегда устанавливает x.

        if not self.dh_private_key_x:
            print("КРИТИЧЕСКАЯ ОШИБКА: Приватный ключ DH (x) не может быть сохранен, так как он не был сгенерирован (возможно, P не было установлено).")
            # Не сохраняем dh_private_key_x, если его нет
            priv_data = {"n": str(n_rsa), "d": str(d_rsa)}
        else:
            priv_data = {
                "n": str(n_rsa), 
                "d": str(d_rsa),
                "dh_private_key_x": str(self.dh_private_key_x)
            }

        try:
            with open(self.private_key_file, 'w') as f:
                json.dump(priv_data, f, indent=4)
            print(f"Приватные ключи сервера сохранены в {self.private_key_file}. Наличие DH приватного ключа: {'dh_private_key_x' in priv_data}")
        except IOError as e:
            print(f"ФАТАЛЬНО: Не удалось записать приватные ключи в {self.private_key_file}: {e}")
            raise

    def get_rsa_public_key(self):
        return self.rsa_cipher.public_key

    # def get_affine_params(self): # Удалено
    # return self.affine_params

    def get_rsa_cipher(self):
        return self.rsa_cipher

    def get_dh_public_key_y(self):
        return self.dh_public_key_y

    def get_dh_parameters(self):
        if self.dh_p and self.dh_g:
            return {"p": str(self.dh_p), "g": str(self.dh_g)}
        return None # Или возбуждать исключение, если параметры не загружены/сгенерированы

# server_key_manager = ServerKeyManager() 