from .rsa_cipher import RSACipher
from .affine_cipher import AffineCipher
import json
import random
import hmac
import hashlib
import time
from flask import current_app
from typing import Optional, Tuple

class EncryptionService:
    # def __init__(self, server_rsa_cipher: RSACipher, server_affine_params: dict):
    def __init__(self, server_rsa_cipher: RSACipher):
        self.server_rsa_cipher = server_rsa_cipher
        # self.server_affine_params = server_affine_params # Удалено
        self.message_cache = {}  # Кэш для предотвращения replay-атак
        self.max_message_age = 300  # 5 минут в секундах
        self.max_message_length = 4096  # Максимальная длина сообщения

    def _generate_nonce(self) -> str:
        """Генерирует случайный nonce для защиты от replay-атак."""
        return hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()

    def _calculate_hmac(self, data: str, key: bytes) -> str:
        """Вычисляет HMAC для проверки целостности данных."""
        return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

    def _validate_message(self, message: dict) -> bool:
        """Проверяет валидность сообщения."""
        required_fields = ['content', 'timestamp', 'nonce', 'hmac']
        if not all(field in message for field in required_fields):
            return False

        # Проверка длины сообщения
        if len(message['content']) > self.max_message_length:
            return False

        # Проверка времени жизни сообщения
        message_age = time.time() - message['timestamp']
        if message_age > self.max_message_age:
            return False

        # Проверка на replay-атаку
        if message['nonce'] in self.message_cache:
            return False

        return True

    def encrypt_for_client(self, plaintext_data: str, client_rsa_public_key_tuple: tuple) -> Optional[str]:
        """Шифрует данные для клиента с проверкой целостности."""
        if not plaintext_data or len(plaintext_data) > self.max_message_length:
            current_app.logger.error("Invalid message length")
            return None

        try:
            # Создаем сообщение с метаданными
            message = {
                'content': plaintext_data,
                'timestamp': time.time(),
                'nonce': self._generate_nonce()
            }
            message_str = json.dumps(message)

            # Вычисляем HMAC
            hmac_value = self._calculate_hmac(message_str, self.server_rsa_cipher.get_private_key_bytes())
            message['hmac'] = hmac_value

            # Шифруем сообщение
            encrypted_message = self.server_rsa_cipher.encrypt_text_chunked(json.dumps(message))

            # Сохраняем nonce в кэше
            self.message_cache[message['nonce']] = time.time()

            # Очищаем старые записи из кэша
            current_time = time.time()
            self.message_cache = {k: v for k, v in self.message_cache.items() 
                                if current_time - v <= self.max_message_age}

            return encrypted_message
        except Exception as e:
            current_app.logger.error(f"Error encrypting message: {str(e)}")
            return None

    def decrypt_from_client(self, encrypted_data: str) -> Optional[str]:
        """Расшифровывает данные от клиента с проверкой целостности."""
        if not encrypted_data:
            return None

        try:
            # Расшифровываем данные
            decrypted_data = self.server_rsa_cipher.decrypt_text_chunked(encrypted_data)
            message = json.loads(decrypted_data)

            # Проверяем валидность сообщения
            if not self._validate_message(message):
                current_app.logger.error("Invalid message format or replay attack detected")
                return None

            # Проверяем HMAC
            received_hmac = message.pop('hmac')
            message_str = json.dumps(message)
            calculated_hmac = self._calculate_hmac(message_str, self.server_rsa_cipher.get_private_key_bytes())

            if not hmac.compare_digest(received_hmac, calculated_hmac):
                current_app.logger.error("HMAC verification failed")
                return None

            return message['content']
        except Exception as e:
            current_app.logger.error(f"Error decrypting message: {str(e)}")
            return None

    # --- Методы для обработки сообщений между пользователями (через сервер) ---

    def prepare_message_for_recipient(self, original_message: str, recipient_rsa_public_key_tuple: tuple):
        """Сервер получил оригинальное сообщение и шифрует его для получателя."""
        # 1. Шифруем оригинальное сообщение Аффинным шифром СЕРВЕРА
        # affine_cipher = AffineCipher()
        # affine_cipher.set_keys(self.server_affine_params["a"], self.server_affine_params["b"]) # Требует self.server_affine_params
        # server_affine_encrypted_msg = affine_cipher.encrypt(original_message)
        # Пока что возвращаем None или вызываем ошибку, т.к. логика аффинного шифра изменится
        current_app.logger.error("prepare_message_for_recipient: Логика аффинного шифрования требует обновления из-за удаления server_affine_params.")
        return None # Или можно возбудить исключение
        
        # # 2. Формируем полезную нагрузку: шифротекст + Аффинные параметры СЕРВЕРА
        # payload = {
        #     "cipher_text": server_affine_encrypted_msg,
        #     "affine_params": self.server_affine_params # Требует self.server_affine_params
        # }
        # payload_str = json.dumps(payload)

        # # 3. Шифруем публичным RSA ключом ПОЛУЧАТЕЛЯ
        # recipient_rsa = RSACipher()
        # recipient_rsa.set_public_key(recipient_rsa_public_key_tuple[0], recipient_rsa_public_key_tuple[1])
        # encrypted_payload_for_recipient = recipient_rsa.encrypt_text_chunked(payload_str)
        # return encrypted_payload_for_recipient

    def encrypt_data_for_storage(self, original_data: str):
        """Шифрует данные для хранения в БД сервера: Аффинный шифр сервера, затем RSA сервера."""
        # 1. Аффинное шифрование серверными ключами
        # affine_cipher = AffineCipher()
        # affine_cipher.set_keys(self.server_affine_params["a"], self.server_affine_params["b"]) # Требует self.server_affine_params
        # affine_encrypted_data = affine_cipher.encrypt(original_data)
        current_app.logger.error("encrypt_data_for_storage: Логика аффинного шифрования требует обновления.")
        # Пока что просто шифруем RSA без аффинного, чтобы сервер мог запуститься
        # Это НЕПРАВИЛЬНО с точки зрения исходной логики, но позволит проверить остальное.
        # Впоследствии это нужно будет заменить на новую логику аффинного шифрования.
        payload_for_storage = {
            "cipher_text": original_data, # Сохраняем пока как есть, без аффинного
             # "affine_params": self.server_affine_params # Удалено
        }
        payload_str = json.dumps(payload_for_storage)
        encrypted_data_for_db = self.server_rsa_cipher.encrypt_text_chunked(payload_str)
        return encrypted_data_for_db

    def decrypt_data_from_storage(self, encrypted_data_from_db: str):
        """Расшифровывает данные из БД сервера: RSA сервера, затем Аффинный шифр сервера."""
        # 1. RSA расшифровка приватным ключом СЕРВЕРА
        payload_str = self.server_rsa_cipher.decrypt_text_chunked(encrypted_data_from_db)
        
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON payload from storage: {e} Payload: {payload_str[:200]}")
        
        # required_fields = ["cipher_text", "affine_params"] # affine_params удалены
        required_fields = ["cipher_text"]
        for field in required_fields:
            if field not in payload:
                raise ValueError(f"Missing field '{field}' in storage payload: {payload_str[:200]}")
        server_affine_ciphertext = payload["cipher_text"]
        
        # 3. Аффинная расшифровка серверными ключами - пока пропускаем
        # affine_cipher = AffineCipher()
        # affine_cipher.set_keys(self.server_affine_params["a"], self.server_affine_params["b"]) # Требует self.server_affine_params
        # original_data = affine_cipher.decrypt(server_affine_ciphertext)
        # return original_data
        current_app.logger.warn("decrypt_data_from_storage: Аффинная расшифровка пропускается, возвращается текст после RSA.")
        return server_affine_ciphertext # Возвращаем то, что было после RSA (ранее server_affine_ciphertext)

    def generate_random_affine_b(self, modulus: int) -> int:
        """Генерирует случайное значение b для аффинного шифра (0 <= b < modulus)."""
        if modulus <= 0:
            raise ValueError("Modulus must be positive for affine cipher.")
        return random.randint(0, modulus - 1)

    def verify_affine_password(self, client_provided_affine_encrypted_password: str, client_provided_affine_params: dict, stored_password_info: dict) -> bool:
        """Проверяет предоставленный клиентом аффинно-зашифрованный пароль."""
        current_app.logger.debug("Starting password verification")
        current_app.logger.debug(f"Client-provided affine encrypted length: {len(client_provided_affine_encrypted_password)}")
        current_app.logger.debug(f"Client-provided params: {client_provided_affine_params}")
        current_app.logger.debug(f"Stored password info keys: {list(stored_password_info.keys())}")

        try:
            # 1. Расшифровать пароль, предоставленный клиентом
            client_cipher = AffineCipher()
            client_cipher.set_keys(client_provided_affine_params["a"], client_provided_affine_params["b"])
            client_plain_password = client_cipher.decrypt(client_provided_affine_encrypted_password)
            current_app.logger.debug(f"Client plain password length: {len(client_plain_password) if client_plain_password else 0}")

            # 2. Расшифровать сохраненный пароль
            stored_cipher = AffineCipher()
            stored_cipher.set_keys(stored_password_info['affine_a'], stored_password_info['affine_b'])
            stored_plain_password = stored_cipher.decrypt(stored_password_info['password_ciphertext'])
            current_app.logger.debug(f"Stored plain password length: {len(stored_plain_password) if stored_plain_password else 0}")

            # 3. Сравнить
            passwords_match = client_plain_password == stored_plain_password
            if passwords_match:
                current_app.logger.info("Password verification successful")
            else:
                current_app.logger.warning("Password verification failed - passwords do not match")
            return passwords_match
        except Exception as e:
            current_app.logger.error(f"Error during password verification: {e}", exc_info=True)
            return False

    def decrypt_with_server_rsa(self, encrypted_data_hex: str) -> str | None:
        """Расшифровывает данные, зашифрованные RSA публичным ключом сервера."""
        current_app.logger.debug(f"Attempting RSA decryption of data length: {len(encrypted_data_hex)}")
        try:
            result = self.server_rsa_cipher.decrypt(encrypted_data_hex)
            current_app.logger.debug(f"RSA decryption successful, result length: {len(result) if result else 0}")
            return result
        except Exception as e:
            current_app.logger.error(f"RSA decryption failed: {e}", exc_info=True)
            return None

    def encrypt_for_client_rsa(self, data: str, client_rsa_public_key_n: str, client_rsa_public_key_e: str) -> str | None:
        current_app.logger.debug(f"Attempting RSA encryption for client, data length: {len(data)}")
        try:
            client_rsa_cipher = RSACipher()
            client_rsa_cipher.set_public_key(int(client_rsa_public_key_n), int(client_rsa_public_key_e))
            result = client_rsa_cipher.encrypt(data)
            current_app.logger.debug(f"RSA encryption successful, result length: {len(result) if result else 0}")
            return result
        except Exception as e:
            current_app.logger.error(f"RSA encryption for client failed: {e}", exc_info=True)
            return None

    def encrypt_with_server_affine(self, data: str) -> Optional[str]:
        """Шифрует данные аффинным шифром сервера."""
        if not data or len(data) > self.max_message_length:
            current_app.logger.error("Invalid message length")
            return None

        try:
            # affine_cipher = AffineCipher()
            # affine_cipher.set_keys(self.server_affine_params["a"], self.server_affine_params["b"]) # Требует self.server_affine_params
            # return affine_cipher.encrypt(data)
            current_app.logger.error("encrypt_with_server_affine: Логика требует обновления.")
            return None # Заглушка
        except Exception as e:
            current_app.logger.error(f"Server Affine encryption failed: {str(e)}")
            return None

    def decrypt_with_server_affine(self, encrypted_data: str) -> Optional[str]:
        """Расшифровывает данные аффинным шифром сервера."""
        if not encrypted_data:
            current_app.logger.error("Invalid encrypted data") # Добавлено логирование
            return None
        try:
            # affine_cipher = AffineCipher()
            # affine_cipher.set_keys(self.server_affine_params["a"], self.server_affine_params["b"]) # Требует self.server_affine_params
            # return affine_cipher.decrypt(encrypted_data)
            current_app.logger.error("decrypt_with_server_affine: Логика требует обновления.")
            return None # Заглушка
        except Exception as e:
            current_app.logger.error(f"Server Affine decryption failed: {str(e)}")
            return None 