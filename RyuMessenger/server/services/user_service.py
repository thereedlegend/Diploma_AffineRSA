import json
import sqlite3
from RyuMessenger.server.core.database import get_db_connection, get_user_by_username, get_user_by_tag, check_username_exists, check_tag_exists, add_user, update_user_tag, update_user_password, update_user_display_name
from RyuMessenger.server.core.encryption_service import EncryptionService
from RyuMessenger.server.core.affine_cipher import decrypt_based_on_lang, AffineCipher
from flask import request, current_app

class UserService:
    def __init__(self, encryption_service: EncryptionService):
        self.encryption_service = encryption_service

    def register_user(self, username: str, encrypted_password_payload: str, client_rsa_public_key_n: str, client_rsa_public_key_e: str, tag: str, display_name: str) -> tuple[bool, str]:
        """Регистрирует нового пользователя."""
        try:
            # 1. Проверяем, не занято ли имя пользователя
            if self.get_user_by_username(username):
                return False, "Username already taken"

            # 2. Проверяем, не занят ли тег
            if check_tag_exists(tag):
                return False, "Tag already taken"

            # 3. Расшифровываем payload с паролем
            try:
                decrypted_payload = self.encryption_service.server_rsa_cipher.decrypt_text_chunked(encrypted_password_payload)
                current_app.logger.error(f"[DEBUG] Decrypted password payload: {decrypted_payload}")
                password_info = json.loads(decrypted_payload)
                current_app.logger.error(f"[DEBUG] password_info (parsed): {password_info}")
                
                if not isinstance(password_info, dict) or 'cipher_text' not in password_info or 'affine_params' not in password_info:
                    current_app.logger.error(f"[DEBUG] password_info missing fields: {password_info}")
                    return False, "Invalid password payload structure"
                
                password_ciphertext = password_info['cipher_text']
                affine_params = password_info['affine_params']
                
            except Exception as e:
                current_app.logger.error(f"Error decrypting password payload: {e}")
                return False, "Failed to decrypt password payload"
            
            # 4. Создаем запись пользователя
            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    '''INSERT INTO users 
                       (username, password_ciphertext, tag, display_name, rsa_public_key_n, rsa_public_key_e, affine_a, affine_b, lang) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (username, password_ciphertext, tag, display_name, 
                     client_rsa_public_key_n, client_rsa_public_key_e,
                     affine_params['a'], affine_params['b'], affine_params.get('lang', 'en'))
                )
                user_id = cursor.lastrowid
                conn.commit()
                current_app.logger.info(f"User {username} registered successfully with ID {user_id}")
                return True, "Registration successful"
                
            except sqlite3.Error as e:
                conn.rollback()
                current_app.logger.error(f"Database error during registration: {e}")
                return False, "Database error during registration"
            finally:
                conn.close()
                
        except Exception as e:
            current_app.logger.error(f"Error during user registration: {e}", exc_info=True)
            return False, f"Registration failed: {str(e)}"

    def authenticate_user(self, username: str, encrypted_login_payload: str) -> tuple[dict | None, str]:
        """
        Аутентифицирует пользователя по имени пользователя и зашифрованному логину.
        Возвращает (user_data, message) где user_data это словарь с данными пользователя или None при ошибке.
        """
        current_app.logger.debug(f"Attempting to authenticate user: {username}")
        
        try:
            # 1. Расшифровываем payload
            decrypted_payload = self.decrypt_affine_rsa_payload_to_text(encrypted_login_payload)
            if not decrypted_payload:
                current_app.logger.warning(f"Failed to decrypt login payload for user {username}")
                return None, "Invalid login payload"
            
            current_app.logger.debug(f"Successfully decrypted login payload for user {username}")
            
            # 2. Парсим JSON
            try:
                login_data = json.loads(decrypted_payload)
            except json.JSONDecodeError as e:
                current_app.logger.error(f"Failed to parse decrypted login payload as JSON: {e}")
                return None, "Invalid login data format"
            
            # 3. Проверяем наличие обязательных полей
            required_fields = ['password', 'affine_params']
            missing_fields = [field for field in required_fields if field not in login_data]
            if missing_fields:
                current_app.logger.warning(f"Missing required fields in login data: {missing_fields}")
                return None, f"Missing required fields: {', '.join(missing_fields)}"
            
            # 4. Получаем пользователя из БД
            conn = get_db_connection()
            try:
                user = conn.execute(
                    'SELECT * FROM users WHERE username = ?', 
                    (username,)
                ).fetchone()
                
                if not user:
                    current_app.logger.warning(f"User not found: {username}")
                    return None, "Invalid username or password"
                
                # 5. Проверяем пароль
                stored_password_info = {
                    'password_ciphertext': user['password_ciphertext'],
                    'affine_a': user['affine_a'],
                    'affine_b': user['affine_b'],
                    'lang': user['lang']
                }
                
                if not self.encryption_service.verify_affine_password(
                    login_data['password'],
                    login_data['affine_params'],
                    stored_password_info
                ):
                    current_app.logger.warning(f"Invalid password for user: {username}")
                    return None, "Invalid username or password"
                
                current_app.logger.info(f"User {username} authenticated successfully")
                
                # 6. Возвращаем данные пользователя
                return {
                    'id': user['id'],
                    'username': user['username'],
                    'tag': user['tag'],
                    'created_at': user['created_at']
                }, "Login successful"
                
            finally:
                conn.close()
                
        except Exception as e:
            current_app.logger.error(f"Error during user authentication: {e}", exc_info=True)
            return None, "Authentication failed"

    def find_user_by_tag(self, tag: str):
        user_row = get_user_by_tag(tag)
        if user_row:
            user_info = {
                "id": user_row['id'],
                "tag": user_row['tag'],
                "display_name": user_row['display_name'],
                "rsa_public_key": {
                    "n": user_row['rsa_public_key_n'],
                    "e": user_row['rsa_public_key_e']
                }
            }
            print(f"[FIND_USER_BY_TAG] Найден пользователь: {user_info}")
            return user_info
        print(f"[FIND_USER_BY_TAG] Пользователь не найден: {tag}")
        return None

    def get_user_public_key(self, user_id: int):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username, tag, display_name, rsa_public_key_n, rsa_public_key_e FROM users WHERE id = ?", (user_id,))
        key_row = cursor.fetchone()
        conn.close()
        if key_row:
            user_info = {
                "id": user_id,
                "username": key_row['username'],
                "tag": key_row['tag'],
                "display_name": key_row['display_name'],
                "rsa_public_key": {
                    "n": key_row['rsa_public_key_n'],
                    "e": key_row['rsa_public_key_e']
                }
            }
            print(f"[GET_USER_PUBLIC_KEY] Найден пользователь: {user_info}")
            return user_info
        print(f"[GET_USER_PUBLIC_KEY] Пользователь не найден: {user_id}")
        return None

    def update_user_credentials(self, user_id: int, new_tag: str = None, new_display_name: str = None, new_encrypted_password_payload: str = None):
        """
        Обновляет тег пользователя и/или пароль.
        """
        updates = []
        try:
            if new_tag:
                if check_tag_exists(new_tag):
                    print(f"[UPDATE_USER] Тег уже занят: {new_tag}")
                    return False, "New tag is already taken."
                update_user_tag(user_id, new_tag)
                updates.append("tag")
            if new_display_name:
                update_user_display_name(user_id, new_display_name)
                updates.append("display_name")
            if new_encrypted_password_payload:
                try:
                    decrypted_new_password_info_json = self.encryption_service.server_rsa_cipher.decrypt_text_chunked(new_encrypted_password_payload)
                    payload = json.loads(decrypted_new_password_info_json)
                    if not (isinstance(payload, dict) and 'cipher_text' in payload and 'affine_params' in payload and 'lang' in payload):
                        print(f"[UPDATE_USER] Некорректная структура нового пароля")
                        return False, "Corrupted new password payload structure."
                    update_user_password(user_id, decrypted_new_password_info_json)
                    updates.append("password")
                except (ValueError, json.JSONDecodeError) as e:
                    print(f"[UPDATE_USER] Ошибка при расшифровке нового пароля: {e}")
                    return False, f"Failed to decrypt or parse new password payload: {e}"
            if not updates:
                print(f"[UPDATE_USER] Нет изменений для пользователя {user_id}")
                return False, "No changes provided."
            print(f"[UPDATE_USER] Данные пользователя {user_id} успешно обновлены: {', '.join(updates)}")
            return True, "User credentials updated successfully."
        except Exception as e:
            print(f"[UPDATE_USER] Ошибка базы данных: {e}")
            return False, f"Database error during update: {e}"

    def find_users_by_tag_partial(self, tag: str):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, tag, display_name, rsa_public_key_n, rsa_public_key_e FROM users WHERE LOWER(tag) LIKE ? COLLATE NOCASE", (f"%{tag}%",))
        users = cursor.fetchall()
        conn.close()
        result = []
        for user_row in users:
            result.append({
                "id": user_row['id'],
                "tag": user_row['tag'],
                "display_name": user_row['display_name'],
                "rsa_public_key": {
                    "n": user_row['rsa_public_key_n'],
                    "e": user_row['rsa_public_key_e']
                }
            })
        print(f"[USER SEARCH] Найдено пользователей: {len(result)} -> {[u['tag'] for u in result]}")
        return result

    def find_users_by_tag_partial_encrypted(self, encrypted_query_payload: str):
        """
        Ищет пользователей по части тега. Тег приходит зашифрованным (Affine+RSA).
        encrypted_query_payload: RSA(JSON{"cipher_text"=affine_encrypted_tag, "params", "lang"})
        """
        current_app.logger.debug(f"find_users_by_tag_partial_encrypted: received payload (first 100) {encrypted_query_payload[:100]}...")
        # Используем новый стандартизированный метод
        decrypted_tag_query = self.decrypt_affine_rsa_payload_to_text(encrypted_query_payload)
        
        if decrypted_tag_query is None:
            current_app.logger.error("find_users_by_tag_partial_encrypted: Failed to decrypt tag query from payload.")
            return [] 
        
        current_app.logger.info(f"find_users_by_tag_partial_encrypted: Decrypted tag query to '{decrypted_tag_query}'. Searching...")
        
        # Используем существующий метод find_users_by_tag_partial, который ищет в БД
        found_users_list = self.find_users_by_tag_partial(decrypted_tag_query.lower()) # Приводим к нижнему регистру для поиска без учета регистра
        current_app.logger.info(f"find_users_by_tag_partial_encrypted: Found {len(found_users_list)} users for query '{decrypted_tag_query}'.")
        return found_users_list

    def decrypt_user_id_from_payload(self, encrypted_user_id_payload: str) -> str | None:
        """
        Расшифровывает payload, содержащий ID пользователя (ожидается аффинно-RSA шифрование).
        Возвращает расшифрованный ID как строку или None при ошибке.
        """
        current_app.logger.debug(f"Decrypting user_id_from_payload. Input payload (first 100 chars): {encrypted_user_id_payload[:100]}...")
        decrypted_id = self.decrypt_affine_rsa_payload_to_text(encrypted_user_id_payload)
        if decrypted_id:
            current_app.logger.info(f"Successfully decrypted user_id: {decrypted_id}")
            # ВАЖНО: Не пытаемся конвертировать в int здесь, т.к. ID может быть UUID в будущем, или routes хотят строку.
        else:
            current_app.logger.error(f"Failed to decrypt user_id_from_payload. Payload (first 100): {encrypted_user_id_payload[:100]}...")
        return decrypted_id

    def decrypt_generic_payload_to_dict(self, encrypted_payload: str) -> dict | None:
        """
        Расшифровывает RSA(JSON_dict) -> JSON_dict.
        Используется для /user/update, где payload содержит различные поля.
        """
        current_app.logger.debug(f"Decrypting generic_payload_to_dict. Input (first 100): {encrypted_payload[:100]}...")
        decrypted_dict = self._decrypt_rsa_payload_to_inner_json_dict(encrypted_payload)
        if decrypted_dict:
            current_app.logger.info(f"Successfully decrypted generic_payload_to_dict.")
        else:
            current_app.logger.error(f"Failed to decrypt generic_payload_to_dict. Payload (first 100): {encrypted_payload[:100]}...")
        return decrypted_dict

    def decrypt_generic_payload_to_text(self, encrypted_payload: str) -> str | None:
        """
        Расшифровывает RSA(JSON{"cipher_text", "params", "lang"}) -> PlainText.
        Алиас для decrypt_affine_rsa_payload_to_text.
        Используется для расшифровки текста сообщений, ID и т.п.
        """
        current_app.logger.debug(f"Decrypting generic_payload_to_text. Input (first 100): {encrypted_payload[:100]}...")
        decrypted_text = self.decrypt_affine_rsa_payload_to_text(encrypted_payload)
        if decrypted_text:
            current_app.logger.info(f"Successfully decrypted generic_payload_to_text. Text (first 30): {decrypted_text[:30]}...")
        else:
            current_app.logger.error(f"Failed to decrypt generic_payload_to_text. Payload (first 100): {encrypted_payload[:100]}...")
        return decrypted_text

    def prepare_encrypted_messages_for_client(self, messages, requesting_user_id):
        client_info = self.get_user_public_key(requesting_user_id)
        if not client_info:
            print(f"[PREPARE_MSG] Не найден публичный ключ пользователя: {requesting_user_id}")
            return []
        try:
            client_pub_key_n = int(client_info['rsa_public_key']['n'])
            client_pub_key_e = int(client_info['rsa_public_key']['e'])
            client_rsa_public_key = (client_pub_key_n, client_pub_key_e)
        except Exception as e:
            print(f"[PREPARE_MSG] Ошибка парсинга ключа: {e}")
            return []
        encrypted_messages_for_client = []
        for msg in messages:
            try:
                encrypted_text_for_client = self.encryption_service.encrypt_for_client(msg['text'], client_rsa_public_key)
                encrypted_messages_for_client.append({
                    "id": msg['id'],
                    "sender_id": msg['sender_id'],
                    "encrypted_text_payload": encrypted_text_for_client,
                    "sent_at": msg['sent_at']
                })
                print(f"[PREPARE_MSG] Сообщение {msg['id']} подготовлено для пользователя {requesting_user_id}")
            except Exception as e:
                print(f"[PREPARE_MSG] Ошибка при подготовке сообщения {msg['id']}: {e}")
                encrypted_messages_for_client.append({
                    "id": msg['id'],
                    "sender_id": msg['sender_id'],
                    "encrypted_text_payload": self.encryption_service.encrypt_for_client("[Error preparing message]", client_rsa_public_key),
                    "sent_at": msg['sent_at']
                })
        return encrypted_messages_for_client

    def decrypt_affine_rsa_payload_to_text(self, encrypted_payload: str) -> str | None:
        """
        Расшифровывает RSA(JSON{"cipher_text", "params", "lang"}) -> PlainText.
        Специальный случай для тегов: если приходит {"tag_query": "query"}, возвращает значение тега.
        """
        current_app.logger.debug(f"Decrypting affine_rsa_payload_to_text. Input (first 100): {encrypted_payload[:100]}...")
        
        # Сначала расшифровываем RSA слой и получаем JSON
        json_dict_str = self._decrypt_rsa_payload_to_inner_json_dict(encrypted_payload)
        if not json_dict_str:
            current_app.logger.error(f"Failed to decrypt RSA layer in affine_rsa_payload_to_text.")
            return None
            
        try:
            # Парсим расшифрованный JSON
            json_dict = json.loads(json_dict_str)
            
            # Специальная обработка для поиска тегов
            if isinstance(json_dict, dict) and "tag_query" in json_dict:
                tag_query = json_dict["tag_query"]
                current_app.logger.info(f"Found tag_query in payload: {tag_query}")
                return tag_query
                
            # Стандартная обработка для формата с аффинным шифрованием
            if isinstance(json_dict, dict) and \
               "cipher_text" in json_dict and \
               "affine_params" in json_dict and \
               "lang" in json_dict:
                
                cipher_text = json_dict["cipher_text"]
                affine_params = json_dict["affine_params"]
                lang = json_dict["lang"]
                
                # Создаем словарь параметров для выбранного языка
                affine_params_dict = {lang: affine_params}
                
                # Расшифровываем аффинным шифром
                decrypted_text = decrypt_based_on_lang(cipher_text, lang, affine_params_dict)
                current_app.logger.info(f"Successfully decrypted affine layer. Text (first 30): {decrypted_text[:30]}...")
                return decrypted_text
            else:
                # Если нет аффинного слоя, возвращаем как есть
                current_app.logger.info(f"No affine layer found, returning JSON as string. First 30: {json_dict_str[:30]}...")
                return json_dict_str
                
        except json.JSONDecodeError as e:
            current_app.logger.error(f"JSON parsing error in affine_rsa_payload_to_text: {e}")
            return None
        except Exception as e:
            current_app.logger.error(f"Unexpected error in affine_rsa_payload_to_text: {e}")
            return None

    def _decrypt_rsa_payload_to_inner_json_dict(self, encrypted_payload: str) -> str | None:
        """
        Внутренняя функция для расшифровки RSA(JSON_dict) -> JSON_dict_string.
        """
        current_app.logger.debug(f"Decrypting rsa_payload_to_inner_json_dict. Input (first 100): {encrypted_payload[:100]}...")
        try:
            decrypted_json_str = self.encryption_service.server_rsa_cipher.decrypt_text_chunked(encrypted_payload)
            if decrypted_json_str:
                current_app.logger.info(f"Successfully decrypted rsa_payload_to_inner_json_dict.")
                return decrypted_json_str
            else:
                current_app.logger.error(f"Failed to decrypt in server_rsa_cipher.")
                return None
        except Exception as e:
            current_app.logger.error(f"Error in _decrypt_rsa_payload_to_inner_json_dict: {e}")
            return None

    def get_user_by_username(self, username: str):
        """Возвращает пользователя по username или None."""
        return get_user_by_username(username)

    def get_user_by_tag(self, tag: str):
        """Возвращает пользователя по tag или None."""
        return get_user_by_tag(tag) 