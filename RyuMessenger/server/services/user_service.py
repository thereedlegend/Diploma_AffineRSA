import json
import sqlite3
from RyuMessenger.server.core.database import get_db_connection, get_user_by_username, get_user_by_tag, check_username_exists, check_tag_exists, add_user, update_user_tag, update_user_password, update_user_display_name
from RyuMessenger.server.core.encryption_service import EncryptionService
from RyuMessenger.server.core.affine_cipher import decrypt_based_on_lang, AffineCipher
from flask import request, current_app

class UserService:
    def __init__(self, encryption_service: EncryptionService):
        self.encryption_service = encryption_service

    def register_user(self, username: str, encrypted_password_payload: str, client_rsa_public_key_n: str, client_rsa_public_key_e: str, tag: str = None, display_name: str = None):
        """
        Регистрирует нового пользователя.
        encrypted_password_payload: RSA-зашифрованная строка JSON от клиента, содержащая:
                                    { "username": "...", "password": "...", "display_name": "...", "tag": "..." }
        client_rsa_public_key_n, client_rsa_public_key_e: Публичный RSA ключ клиента.
        """
        if tag is None:
            tag = username
        if not display_name or not display_name.strip():
            current_app.logger.warning(f"Registration attempt failed for {username}: Display name is required.")
            return None, "Display name is required."
        if check_username_exists(username):
            current_app.logger.warning(f"Registration attempt failed for {username}: Username already exists.")
            return None, "User with this username already exists."
        if check_tag_exists(tag):
            current_app.logger.warning(f"Registration attempt failed for {username} (tag {tag}): Tag already exists.")
            return None, "User with this tag already exists."
        
        try:
            # 1. Расшифровать RSA payload от клиента
            decrypted_client_payload_json = self.encryption_service.server_rsa_cipher.decrypt_text_chunked(encrypted_password_payload)
            client_payload = json.loads(decrypted_client_payload_json)

            # 2. Извлечь пароль из расшифрованного JSON
            # Убедимся, что необходимые поля присутствуют в расшифрованном JSON от клиента
            if not (isinstance(client_payload, dict) and \
                    'username' in client_payload and \
                    'password' in client_payload and \
                    'display_name' in client_payload and \
                    'tag' in client_payload):
                current_app.logger.error(f"Invalid client payload structure after RSA decryption: {client_payload}")
                return None, "Decrypted client payload is not valid JSON or missing required fields (username, password, display_name, tag)."

            plain_password = client_payload.get('password')
            if not plain_password: # Дополнительная проверка, хотя 'password' in client_payload уже это покрывает
                current_app.logger.error(f"Password missing in decrypted client payload for {username}")
                return None, "Password missing in decrypted client payload."

            # 3. Подготовить пароль для хранения (аффинное шифрование)
            # Определяем язык для аффинного шифра (можно взять из display_name или username, или передавать явно)
            # В реальном приложении язык лучше определять более надежно или дать пользователю выбор.
            lang_for_affine = self.encryption_service.determine_language(plain_password) # Используем метод из EncryptionService
            
            # Создаем экземпляр AffineCipher для нужного языка, чтобы получить m
            # и затем использовать его для шифрования
            cipher = AffineCipher(lang=lang_for_affine)
            m = cipher.m # Получаем m из экземпляра
            
            # Генерируем случайный b для аффинного шифра (a=1)
            affine_a = 1 
            affine_b = self.encryption_service.generate_random_affine_b(m)

            # Устанавливаем ключи для этого же экземпляра cipher и шифруем пароль
            cipher.set_keys(affine_a, affine_b)
            affine_cipher_text_password = cipher.encrypt(plain_password)

            # 4. Создать JSON для хранения информации о пароле в БД
            password_info_for_db = {
                "cipher_text": affine_cipher_text_password,
                "affine_params": {"a": affine_a, "b": affine_b, "m": m},
                "lang": lang_for_affine
            }
            password_info_for_db_json = json.dumps(password_info_for_db)
            current_app.logger.debug(f"Storing password info for {username}: {password_info_for_db_json}")

        except json.JSONDecodeError as e:
            current_app.logger.error(f"JSONDecodeError while processing payload for {username}: {e}. Payload: {decrypted_client_payload_json[:200]}")
            return None, "Failed to parse decrypted client payload."
        except KeyError as e:
            current_app.logger.error(f"KeyError: Missing expected key in client payload for {username}: {e}. Payload: {client_payload}")
            return None, f"Missing expected data in client payload: {e}."
        except Exception as e: # Общий обработчик ошибок шифрования/расшифровки
            current_app.logger.error(f"Error processing password payload for {username} during registration: {e}", exc_info=True)
            return None, f"Error processing password for registration: {e}"

        # 5. Сохранить пользователя в БД
        # Используем username, tag, display_name из НЕЗАШИФРОВАННОЙ части запроса, как и раньше
        # А password_info_for_db_json - это наш новый JSON для хранения пароля
        user_id = add_user(username, tag, display_name, password_info_for_db_json, str(client_rsa_public_key_n), str(client_rsa_public_key_e))
        if user_id:
            current_app.logger.info(f"User {username} (tag: {tag}) registered successfully with ID: {user_id}")
            return user_id, "User registered successfully."
        else:
            # Эта ветка маловероятна, если add_user не возвращает None при ошибке, а кидает исключение,
            # но оставим для полноты, если add_user может вернуть None по какой-то причине без исключения.
            current_app.logger.error(f"Failed to add user {username} to database, add_user returned None.")
            return None, "Failed to register user due to a database error."

    def authenticate_user(self, username: str, encrypted_login_payload: str):
        """
        Аутентифицирует пользователя по тегу.
        encrypted_login_payload: RSA-зашифрованная строка JSON от клиента, содержащая:
                                   { "cipher_text": "аффинный_шифротекст_пароля_для_входа",
                                     "affine_params": { "a": ..., "b": ..., "m": ...},
                                     "lang": "ru" или "en" }
        """
        user_row = get_user_by_username(username)
        if not user_row:
            print(f"[AUTH] Пользователь не найден: {username}")
            return None, "Invalid username or password."
        try:
            client_provided_login_info_json = self.encryption_service.server_rsa_cipher.decrypt_text_chunked(encrypted_login_payload)
            client_provided_login_info = json.loads(client_provided_login_info_json)
            if not (isinstance(client_provided_login_info, dict) and 'cipher_text' in client_provided_login_info and 'affine_params' in client_provided_login_info and 'lang' in client_provided_login_info):
                return None, "Login payload is not valid JSON or missing required fields."
        except (ValueError, json.JSONDecodeError) as e:
            return None, f"Failed to decrypt or parse login payload: {e}"
        stored_password_info_json = user_row['password_info']
        try:
            stored_password_info = json.loads(stored_password_info_json)
            if not (isinstance(stored_password_info, dict) and 'cipher_text' in stored_password_info and 'affine_params' in stored_password_info and 'lang' in stored_password_info):
                return None, "Corrupted stored password information for user."
        except json.JSONDecodeError:
            return None, "Corrupted stored password information for user."
        try:
            if not isinstance(client_provided_login_info, dict):
                return None, f"Invalid login payload structure: {type(client_provided_login_info)}."
            if not isinstance(stored_password_info, dict):
                return None, f"Invalid stored password structure: {type(stored_password_info)}."
            decrypted_password_attempt = decrypt_based_on_lang(
                client_provided_login_info['cipher_text'],
                client_provided_login_info['lang'],
                {client_provided_login_info['lang']: client_provided_login_info['affine_params']}
            )
            if not isinstance(decrypted_password_attempt, str):
                print(f"[ERROR] decrypted_password_attempt не строка: {type(decrypted_password_attempt)} -> {repr(decrypted_password_attempt)}")
                return None, f"Ошибка дешифровки пароля: результат не строка ({type(decrypted_password_attempt)})."
            decrypted_stored_password = decrypt_based_on_lang(
                stored_password_info['cipher_text'],
                stored_password_info['lang'],
                {stored_password_info['lang']: stored_password_info['affine_params']}
            )
            if not isinstance(decrypted_stored_password, str):
                print(f"[ERROR] decrypted_stored_password не строка: {type(decrypted_stored_password)} -> {repr(decrypted_stored_password)}")
                return None, f"Ошибка дешифровки пароля из БД: результат не строка ({type(decrypted_stored_password)})."
        except Exception as e:
             return None, f"Error processing password for authentication: {e}"
        if decrypted_password_attempt == decrypted_stored_password:
            user_data = {
                "id": user_row['id'],
                "username": user_row['username'],
                "tag": user_row['tag'],
                "display_name": user_row['display_name'],
                "rsa_public_key": {
                    "n": user_row['rsa_public_key_n'],
                    "e": user_row['rsa_public_key_e']
                }
            }
            print(f"[AUTH] Успешная аутентификация: {user_data}")
            return user_data, "Authentication successful."
        else:
            print(f"[AUTH] Неверный пароль для пользователя: {username}")
            return None, "Invalid username or password."

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