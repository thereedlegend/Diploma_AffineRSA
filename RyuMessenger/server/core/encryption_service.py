from .rsa_cipher import RSACipher
from .affine_cipher import AffineCipher, determine_language_and_encrypt, decrypt_based_on_lang
from .crypto_utils import AFFINE_PAYLOAD_DELIMITER
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
        # (Определяем язык и шифруем)
        affine_encrypted_data, lang_used = determine_language_and_encrypt(plaintext_data, self.server_affine_params)
        
        # 2. Формируем полезную нагрузку: шифротекст + параметры аффина + язык
        # Параметры аффина сервера для этого языка и сам язык нужны клиенту для расшифровки
        payload = {
            "cipher_text": affine_encrypted_data,
            "affine_params": self.server_affine_params[lang_used],
            "lang": lang_used
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
        required_fields = ["cipher_text", "affine_params", "lang"]
        for field in required_fields:
            if field not in payload:
                raise ValueError(f"Missing field '{field}' in client payload: {payload_str[:200]}")
        client_affine_ciphertext = payload["cipher_text"]
        client_affine_params = payload["affine_params"] # это параметры клиента
        lang_used_by_client = payload["lang"] # язык, который использовал клиент
        # 3. Расшифровываем Аффинным шифром, используя параметры клиента
        decrypted_data = decrypt_based_on_lang(client_affine_ciphertext, lang_used_by_client, {lang_used_by_client: client_affine_params})
        return decrypted_data

    # --- Методы для обработки сообщений между пользователями (через сервер) ---

    def prepare_message_for_recipient(self, original_message: str, recipient_rsa_public_key_tuple: tuple):
        """
        Сервер получил оригинальное сообщение (например, от UserA).
        Он шифрует его ДЛЯ UserB: сначала своим Аффинным, потом RSA ключом UserB.
        """
        # 1. Шифруем оригинальное сообщение Аффинным шифром СЕРВЕРА
        server_affine_encrypted_msg, lang_used = determine_language_and_encrypt(original_message, self.server_affine_params)
        
        # 2. Формируем полезную нагрузку: шифротекст + Аффинные параметры СЕРВЕРА + язык
        payload = {
            "cipher_text": server_affine_encrypted_msg,
            "affine_params": self.server_affine_params[lang_used],
            "lang": lang_used
        }
        payload_str = json.dumps(payload)

        # 3. Шифруем публичным RSA ключом ПОЛУЧАТЕЛЯ (UserB)
        recipient_rsa = RSACipher()
        recipient_rsa.set_public_key(recipient_rsa_public_key_tuple[0], recipient_rsa_public_key_tuple[1])
        encrypted_payload_for_recipient = recipient_rsa.encrypt_text_chunked(payload_str)
        return encrypted_payload_for_recipient

    def encrypt_data_for_storage(self, original_data: str):
        """Шифрует данные для хранения в БД сервера: Аффинный шифр сервера, затем RSA сервера."""
        # 1. Аффинное шифрование серверными ключами
        affine_encrypted_data, lang_used = determine_language_and_encrypt(original_data, self.server_affine_params)
        
        # 2. Полезная нагрузка для хранения (чтобы сервер мог сам расшифровать)
        payload_for_storage = {
            "cipher_text": affine_encrypted_data,
            "affine_params": self.server_affine_params[lang_used],
            "lang": lang_used
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
        required_fields = ["cipher_text", "affine_params", "lang"]
        for field in required_fields:
            if field not in payload:
                raise ValueError(f"Missing field '{field}' in storage payload: {payload_str[:200]}")
        server_affine_ciphertext = payload["cipher_text"]
        lang_used_in_storage = payload["lang"]
        # 3. Аффинная расшифровка серверными ключами
        original_data = decrypt_based_on_lang(server_affine_ciphertext, lang_used_in_storage, self.server_affine_params)
        return original_data

    # Добавленные методы
    def determine_language(self, text: str) -> str:
        """Простая эвристика для определения языка."""
        if not text: # Обработка пустого текста
            return "en" # По умолчанию английский
            
        ru_chars = sum(1 for char in text if 'а' <= char.lower() <= 'я' or char.lower() == 'ё')
        en_chars = sum(1 for char in text if 'a' <= char.lower() <= 'z')

        if ru_chars > en_chars:
            return "ru"
        elif en_chars > ru_chars:
            return "en"
        else: # Если паритет или нет кириллицы/латиницы, смотрим на первый символ
            for char_code in [ord(c) for c in text if c.isalpha()]:
                if (char_code >= 0x0400 and char_code <= 0x04FF) or \
                   (char_code >= 0x0500 and char_code <= 0x052F): # Кириллические блоки Unicode
                    return "ru"
                elif (char_code >= 0x0041 and char_code <= 0x007A): # Латинские блоки Unicode
                    return "en"
            return "en" # По умолчанию английский, если не удалось определить

    def generate_random_affine_b(self, modulus: int) -> int:
        """Генерирует случайное значение b для аффинного шифра (0 <= b < modulus)."""
        if modulus <= 0:
            raise ValueError("Modulus must be positive for affine cipher.")
        return random.randint(0, modulus - 1)

    def verify_affine_password(self, client_provided_affine_encrypted_password: str, client_provided_affine_params: dict, stored_password_info: dict) -> bool:
        """
        Проверяет предоставленный клиентом аффинно-зашифрованный пароль.
        1. Расшифровывает client_provided_affine_encrypted_password используя client_provided_affine_params.
        2. Расшифровывает stored_password_info['password_ciphertext'] используя параметры из stored_password_info.
        3. Сравнивает два расшифрованных пароля.
        """
        current_app.logger.info(f"VERIFY_PW: Attempting to verify password.")
        current_app.logger.info(f"VERIFY_PW: Client-provided affine encrypted: '{client_provided_affine_encrypted_password}'")
        current_app.logger.info(f"VERIFY_PW: Client-provided params: {client_provided_affine_params}")
        current_app.logger.info(f"VERIFY_PW: Stored password info: {stored_password_info}")

        try:
            # 1. Расшифровать пароль, предоставленный клиентом
            client_plain_password = AffineCipher.decrypt_with_params(
                client_provided_affine_encrypted_password,
                client_provided_affine_params
            )
            current_app.logger.info(f"VERIFY_PW: Client plain password after decryption: '{client_plain_password}'")

            # 2. Расшифровать сохраненный пароль
            stored_affine_params = {
                "a": stored_password_info['affine_a'],
                "b": stored_password_info['affine_b'],
                "lang": stored_password_info['lang']
            }
            stored_plain_password = AffineCipher.decrypt_with_params(
                stored_password_info['password_ciphertext'],
                stored_affine_params
            )
            current_app.logger.info(f"VERIFY_PW: Stored plain password after decryption: '{stored_plain_password}'")

            # 3. Сравнить
            passwords_match = client_plain_password == stored_plain_password
            if passwords_match:
                current_app.logger.info(f"VERIFY_PW: Passwords MATCH.")
            else:
                current_app.logger.warning(
                    f"VERIFY_PW: Passwords DO NOT MATCH. Client decrypted: '{client_plain_password}', Stored decrypted: '{stored_plain_password}'"
                )
            return passwords_match
        except Exception as e:
            current_app.logger.error(f"VERIFY_PW: Error during password verification: {e}", exc_info=True)
            return False

    def decrypt_with_server_rsa(self, encrypted_data_hex: str) -> str | None:
        """Расшифровывает данные, зашифрованные RSA публичным ключом сервера."""
        try:
            return self.server_rsa_cipher.decrypt(encrypted_data_hex)
        except Exception as e:
            current_app.logger.error(f"RSA decryption failed: {e}", exc_info=True)
            return None

    def encrypt_for_client_rsa(self, data: str, client_rsa_public_key_n: str, client_rsa_public_key_e: str) -> str | None:
        # ... (existing code)
        try:
            client_rsa_cipher = RSACipher()
            client_rsa_cipher.set_public_key(int(client_rsa_public_key_n), int(client_rsa_public_key_e))
            return client_rsa_cipher.encrypt(data)
        except Exception as e:
            current_app.logger.error(f"RSA encryption for client failed: {e}", exc_info=True)
            return None

    def encrypt_with_server_affine(self, data: str, lang: str) -> str | None:
        # ... (existing code)
        try:
            # Используем параметры аффинного шифра сервера
            return determine_language_and_encrypt(data, lang, self.server_affine_params)
        except Exception as e:
            current_app.logger.error(f"Server Affine encryption failed: {e}", exc_info=True)
            return None

    def decrypt_with_server_affine(self, encrypted_data_with_lang: str) -> str | None:
        # ... (existing code)
        try:
            parts = encrypted_data_with_lang.split(AFFINE_PAYLOAD_DELIMITER)
            if len(parts) != 2:
                current_app.logger.error(f"Invalid format for affine encrypted data with lang: {encrypted_data_with_lang}")
                return None
            lang_used_in_storage, server_affine_ciphertext = parts
            
            # Расшифровка серверными ключами
            original_data = decrypt_based_on_lang(server_affine_ciphertext, lang_used_in_storage, self.server_affine_params)
            return original_data
        except Exception as e:
            current_app.logger.error(f"Server Affine decryption failed: {e}", exc_info=True)
            return None 