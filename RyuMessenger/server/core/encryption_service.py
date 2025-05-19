from .rsa_cipher import RSACipher
from .affine_cipher import AffineCipher
import json
import random
from flask import current_app

class EncryptionService:
    def __init__(self, server_rsa_cipher: RSACipher, server_affine_params: dict):
        self.server_rsa_cipher = server_rsa_cipher
        self.server_affine_params = server_affine_params

    def encrypt_for_client(self, plaintext_data: str, client_rsa_public_key_tuple: tuple):
        """Шифрует данные для клиента: сначала Аффинный шифр сервера, потом RSA клиента."""
        # 1. Шифруем данные Аффинным шифром сервера
        affine_cipher = AffineCipher()
        affine_cipher.set_keys(self.server_affine_params["a"], self.server_affine_params["b"])
        affine_encrypted_data = affine_cipher.encrypt(plaintext_data)
        
        # 2. Формируем полезную нагрузку: шифротекст + параметры аффина
        payload = {
            "cipher_text": affine_encrypted_data,
            "affine_params": self.server_affine_params
        }
        payload_str = json.dumps(payload)
        
        # 3. Шифруем полезную нагрузку публичным RSA ключом клиента
        client_rsa = RSACipher()
        client_rsa.set_public_key(client_rsa_public_key_tuple[0], client_rsa_public_key_tuple[1])
        encrypted_payload = client_rsa.encrypt_text_chunked(payload_str)
        return encrypted_payload

    def decrypt_from_client(self, encrypted_payload_str: str):
        """Расшифровывает данные от клиента: сначала RSA сервера, потом Аффинный шифр клиента."""
        # 1. Расшифровываем RSA ключом сервера
        payload_str = self.server_rsa_cipher.decrypt_text_chunked(encrypted_payload_str)
        
        # 2. Разбираем полезную нагрузку и валидируем структуру
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON payload from client: {e} Payload: {payload_str[:200]}")
        required_fields = ["cipher_text", "affine_params"]
        for field in required_fields:
            if field not in payload:
                raise ValueError(f"Missing field '{field}' in client payload: {payload_str[:200]}")
        client_affine_ciphertext = payload["cipher_text"]
        client_affine_params = payload["affine_params"]
        
        # 3. Расшифровываем Аффинным шифром, используя параметры клиента
        affine_cipher = AffineCipher()
        affine_cipher.set_keys(client_affine_params["a"], client_affine_params["b"])
        decrypted_data = affine_cipher.decrypt(client_affine_ciphertext)
        return decrypted_data

    # --- Методы для обработки сообщений между пользователями (через сервер) ---

    def prepare_message_for_recipient(self, original_message: str, recipient_rsa_public_key_tuple: tuple):
        """Сервер получил оригинальное сообщение и шифрует его для получателя."""
        # 1. Шифруем оригинальное сообщение Аффинным шифром СЕРВЕРА
        affine_cipher = AffineCipher()
        affine_cipher.set_keys(self.server_affine_params["a"], self.server_affine_params["b"])
        server_affine_encrypted_msg = affine_cipher.encrypt(original_message)
        
        # 2. Формируем полезную нагрузку: шифротекст + Аффинные параметры СЕРВЕРА
        payload = {
            "cipher_text": server_affine_encrypted_msg,
            "affine_params": self.server_affine_params
        }
        payload_str = json.dumps(payload)

        # 3. Шифруем публичным RSA ключом ПОЛУЧАТЕЛЯ
        recipient_rsa = RSACipher()
        recipient_rsa.set_public_key(recipient_rsa_public_key_tuple[0], recipient_rsa_public_key_tuple[1])
        encrypted_payload_for_recipient = recipient_rsa.encrypt_text_chunked(payload_str)
        return encrypted_payload_for_recipient

    def encrypt_data_for_storage(self, original_data: str):
        """Шифрует данные для хранения в БД сервера: Аффинный шифр сервера, затем RSA сервера."""
        # 1. Аффинное шифрование серверными ключами
        affine_cipher = AffineCipher()
        affine_cipher.set_keys(self.server_affine_params["a"], self.server_affine_params["b"])
        affine_encrypted_data = affine_cipher.encrypt(original_data)
        
        # 2. Полезная нагрузка для хранения
        payload_for_storage = {
            "cipher_text": affine_encrypted_data,
            "affine_params": self.server_affine_params
        }
        payload_str = json.dumps(payload_for_storage)
        
        # 3. RSA шифрование публичным ключом СЕРВЕРА
        encrypted_data_for_db = self.server_rsa_cipher.encrypt_text_chunked(payload_str)
        return encrypted_data_for_db

    def decrypt_data_from_storage(self, encrypted_data_from_db: str):
        """Расшифровывает данные из БД сервера: RSA сервера, затем Аффинный шифр сервера."""
        # 1. RSA расшифровка приватным ключом СЕРВЕРА
        payload_str = self.server_rsa_cipher.decrypt_text_chunked(encrypted_data_from_db)
        
        # 2. Разбор JSON и валидация структуры
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON payload from storage: {e} Payload: {payload_str[:200]}")
        required_fields = ["cipher_text", "affine_params"]
        for field in required_fields:
            if field not in payload:
                raise ValueError(f"Missing field '{field}' in storage payload: {payload_str[:200]}")
        server_affine_ciphertext = payload["cipher_text"]
        
        # 3. Аффинная расшифровка серверными ключами
        affine_cipher = AffineCipher()
        affine_cipher.set_keys(self.server_affine_params["a"], self.server_affine_params["b"])
        original_data = affine_cipher.decrypt(server_affine_ciphertext)
        return original_data

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

    def encrypt_with_server_affine(self, data: str) -> str | None:
        current_app.logger.debug(f"Attempting server Affine encryption, data length: {len(data)}")
        try:
            affine_cipher = AffineCipher()
            affine_cipher.set_keys(self.server_affine_params["a"], self.server_affine_params["b"])
            result = affine_cipher.encrypt(data)
            current_app.logger.debug(f"Server Affine encryption successful, result length: {len(result) if result else 0}")
            return result
        except Exception as e:
            current_app.logger.error(f"Server Affine encryption failed: {e}", exc_info=True)
            return None

    def decrypt_with_server_affine(self, encrypted_data: str) -> str | None:
        current_app.logger.debug(f"Attempting server Affine decryption, data length: {len(encrypted_data)}")
        try:
            affine_cipher = AffineCipher()
            affine_cipher.set_keys(self.server_affine_params["a"], self.server_affine_params["b"])
            result = affine_cipher.decrypt(encrypted_data)
            current_app.logger.debug(f"Server Affine decryption successful, result length: {len(result) if result else 0}")
            return result
        except Exception as e:
            current_app.logger.error(f"Server Affine decryption failed: {e}", exc_info=True)
            return None 