import datetime
from flask import request, jsonify, current_app
from functools import wraps # <--- Добавлено
from . import api_bp # Импорт Blueprint
import json # Для парсинга RSA ключей, если они приходят как строки
import jwt # Добавлено
from RyuMessenger.server.core.database import get_db_connection

# --- Начало: Декоратор для JWT ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1] # Ожидаем "Bearer <token>"
            except IndexError:
                return jsonify({'message': 'Bearer token malformed'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            # Передаем user_id в kwargs, чтобы он был доступен в функции маршрута
            kwargs['current_user_id'] = data['user_id'] 
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            current_app.logger.error(f"Token validation error: {e}")
            return jsonify({'message': 'Token validation failed!'}), 401
        
        return f(*args, **kwargs) # Вызываем исходную функцию с обновленными kwargs
    return decorated

def get_user_id_from_token():
    """Извлекает user_id из JWT токена в заголовке Authorization."""
    token = None
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        try:
            token = auth_header.split(" ")[1]
        except IndexError:
            current_app.logger.warning("get_user_id_from_token: Bearer token malformed")
            return None
    
    if not token:
        current_app.logger.warning("get_user_id_from_token: Token is missing from Authorization header")
        return None

    try:
        data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
        user_id = data.get('user_id')
        if not user_id:
            current_app.logger.error("get_user_id_from_token: user_id not found in token payload")
            return None
        return user_id
    except jwt.ExpiredSignatureError:
        current_app.logger.warning("get_user_id_from_token: Token has expired")
        return None
    except jwt.InvalidTokenError:
        current_app.logger.warning("get_user_id_from_token: Token is invalid")
        return None
    except Exception as e:
        current_app.logger.error(f"get_user_id_from_token: General token decoding error: {e}", exc_info=True)
        return None
# --- Конец: Декоратор для JWT ---

# Эндпоинт для получения публичного ключа RSA сервера и его афинных параметров
@api_bp.route('/keys', methods=['GET'])
def get_server_keys():
    key_manager = current_app.key_manager
    server_rsa_public_key = key_manager.get_rsa_public_key()
    server_dh_public_key_y = key_manager.get_dh_public_key_y()
    server_dh_parameters = key_manager.get_dh_parameters()

    if server_rsa_public_key and server_dh_public_key_y and server_dh_parameters:
        response_data = {
            "rsa_public_key": {"n": str(server_rsa_public_key[0]), "e": str(server_rsa_public_key[1])},
            "dh_public_key_y": str(server_dh_public_key_y),
            "dh_parameters": server_dh_parameters
        }
        return jsonify(response_data), 200
    else:
        current_app.logger.error("Server keys (RSA, DH, or DH params) not available during /keys request.")
        return jsonify({"error": "Server keys not available"}), 500

@api_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get('username')
    tag = data.get('tag')
    display_name = data.get('display_name')
    encrypted_password_payload = data.get('encrypted_password_payload') 
    client_rsa_pub_key_n = data.get('rsa_public_key_n')
    client_rsa_pub_key_e = data.get('rsa_public_key_e')

    if not all([username, encrypted_password_payload, client_rsa_pub_key_n, client_rsa_pub_key_e, display_name]):
        return jsonify({"error": "Missing data for registration"}), 400

    user_service = current_app.user_service
    user_id, message = user_service.register_user(
        username, 
        encrypted_password_payload, 
        str(client_rsa_pub_key_n),
        str(client_rsa_pub_key_e),
        tag,
        display_name
    )

    if user_id:
        return jsonify({"message": message, "user_id": user_id}), 201
    else:
        return jsonify({"error": message}), 409

@api_bp.route('/login', methods=['POST'])
def login():
    current_app.logger.debug("Login attempt received")
    
    try:
        data = request.get_json()
        if not data:
            current_app.logger.warning("Login attempt failed: Invalid JSON")
            return jsonify({"error": "Invalid JSON"}), 400

        username = data.get('username')
        encrypted_login_payload = data.get('encrypted_login_payload')

        current_app.logger.debug(f"Login attempt for username: {username}")
        current_app.logger.debug(f"Encrypted payload length: {len(encrypted_login_payload) if encrypted_login_payload else 0}")

        if not all([username, encrypted_login_payload]):
            missing_fields = []
            if not username:
                missing_fields.append('username')
            if not encrypted_login_payload:
                missing_fields.append('encrypted_login_payload')
            current_app.logger.warning(f"Login attempt failed: Missing required fields: {', '.join(missing_fields)}")
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400

        user_service = current_app.user_service
        user_data, message = user_service.authenticate_user(username, encrypted_login_payload)

        if user_data:
            # Генерация JWT токена
            try:
                token_payload = {
                    'user_id': user_data['id'],
                    'username': user_data['username'],
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24) # Токен действителен 24 часа
                }
                token = jwt.encode(
                    token_payload, 
                    current_app.config['SECRET_KEY'], 
                    algorithm='HS256'
                )
                current_app.logger.info(f"Login successful for user_id: {user_data['id']}")
                return jsonify({"message": message, "user": user_data, "token": token}), 200
            except Exception as e:
                current_app.logger.error(f"Error generating JWT token: {e}", exc_info=True)
                return jsonify({"error": "Failed to generate authentication token."}), 500
        else:
            current_app.logger.warning(f"Login failed for username {username}: {message}")
            return jsonify({"error": message}), 401
    except Exception as e:
        current_app.logger.error(f"Unexpected error during login: {e}", exc_info=True)
        return jsonify({"error": "Internal server error during login"}), 500

@api_bp.route('/users/search', methods=['POST'])
def search_user():
    data = request.get_json()
    if not data or 'encrypted_tag_payload' not in data:
        return jsonify({"error": "Missing encrypted_tag_payload"}), 400

    user_service = current_app.user_service
    found_users = user_service.find_users_by_tag_partial_encrypted(data['encrypted_tag_payload'])

    if found_users:
        return jsonify({"users": found_users}), 200
    else:
        return jsonify({"message": "No users found"}), 404

@api_bp.route('/chats', methods=['POST'])
@token_required
def get_chat_list(current_user_id):
    data = request.get_json()
    message_service = current_app.message_service
    last_update_time = data.get('last_update_time') if data else None
    chats = message_service.get_chat_list(str(current_user_id), last_update_time)
    return jsonify({"chats": chats}), 200

@api_bp.route('/chats/find-or-create', methods=['POST'])
@token_required
def find_or_create_chat(current_user_id):
    data = request.get_json()
    if not data or 'encrypted_target_user_id_payload' not in data:
        return jsonify({"error": "Missing encrypted_target_user_id_payload"}), 400

    encrypted_payload = data['encrypted_target_user_id_payload']
    
    user_service = current_app.user_service 
    decrypted_target_user_id = user_service.decrypt_user_id_from_payload(encrypted_payload)

    if decrypted_target_user_id is None:
        current_app.logger.warning(f"Failed to decrypt target_user_id from payload for find_or_create_chat by user {current_user_id}. Payload: {encrypted_payload[:200]}")
        return jsonify({"error": "Invalid or undecryptable payload for target_user_id"}), 400

    message_service = current_app.message_service
    current_app.logger.info(f"Attempting to find/create chat for current_user_id {current_user_id} with target_user_id: {decrypted_target_user_id}")
    
    chat = message_service.find_or_create_chat_with_users(str(current_user_id), str(decrypted_target_user_id))

    if chat:
        return jsonify(chat), 200
    else:
        return jsonify({"error": "Could not find or create chat"}), 500

@api_bp.route('/messages', methods=['POST'])
@token_required
def get_messages(current_user_id):
    data = request.get_json()
    if not data or 'encrypted_chat_partner_id_payload' not in data:
        return jsonify({"error": "Missing encrypted_chat_partner_id_payload"}), 400

    message_service = current_app.message_service
    user_service = current_app.user_service
    
    chat_partner_id = user_service.decrypt_user_id_from_payload(data['encrypted_chat_partner_id_payload'])
    
    if chat_partner_id is None:
        current_app.logger.warning(f"Failed to decrypt chat_partner_id for get_messages by user {current_user_id}. Payload: {data['encrypted_chat_partner_id_payload'][:200]}")
        return jsonify({"error": "Invalid or undecryptable chat_partner_id_payload"}), 400
    
    limit = data.get('limit', 50)
    offset = data.get('offset', 0)
    last_message_id = data.get('last_message_id')
    
    messages = message_service.get_messages_for_chat(
        str(current_user_id), 
        str(chat_partner_id), 
        limit, 
        offset,
        last_message_id
    )
    encrypted_messages_for_client = user_service.prepare_encrypted_messages_for_client(messages, str(current_user_id))
    return jsonify({"messages": encrypted_messages_for_client}), 200

@api_bp.route('/message/send', methods=['POST'])
@token_required
def send_message_api(current_user_id):
    data = request.get_json()
    if not data or \
        'encrypted_receiver_id_payload' not in data or \
        'encrypted_message_payload' not in data:
        return jsonify({"error": "Missing encrypted_receiver_id_payload or encrypted_message_payload"}), 400

    user_service = current_app.user_service
    message_service = current_app.message_service
    
    receiver_id = user_service.decrypt_user_id_from_payload(data['encrypted_receiver_id_payload'])
    if receiver_id is None:
        current_app.logger.warning(f"send_message_api: Failed to decrypt receiver_id by user {current_user_id}. Payload: {data['encrypted_receiver_id_payload'][:200]}...")
        return jsonify({"error": "Invalid or undecryptable receiver_id_payload"}), 400
    
    message_text_plain = user_service.decrypt_generic_payload_to_text(data['encrypted_message_payload'])
    
    if message_text_plain is None:
        current_app.logger.error(f"send_message_api: Failed to decrypt message_payload. User: {current_user_id}. Payload: {data['encrypted_message_payload'][:200]}")
        return jsonify({"error": "Invalid or undecryptable message_payload"}), 400
    
    # Перехватываем все возможные исключения при шифровании, чтобы обеспечить надежную работу
    try:
        # Шифруем сообщение для хранения в БД
        message_to_store_encrypted = message_service.encryption_service.encrypt_data_for_storage(message_text_plain)
        
        message_id, message_status = message_service.send_message(
            str(current_user_id), 
            str(receiver_id), 
            message_to_store_encrypted 
        )
        
        if message_id:
            # Формируем полноценный объект сообщения для возврата клиенту
            timestamp = int(datetime.datetime.now().timestamp() * 1000)  # Текущее время в миллисекундах
            message_object = {
                "id": str(message_id),  # Преобразуем ID в строку для совместимости с клиентом
                "text": message_text_plain,
                "senderId": str(current_user_id),
                "sentAt": timestamp,
                "fromCurrentUser": True,
                "chatId": f"{min(int(current_user_id), int(receiver_id))}-{max(int(current_user_id), int(receiver_id))}"
            }
            return jsonify(message_object), 201
        else:
            return jsonify({"error": message_status}), 400
    except Exception as e:
        current_app.logger.error(f"send_message_api: Error while encrypting or saving message: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@api_bp.route('/user/update', methods=['POST'])
@token_required
def update_user(current_user_id):
    data = request.get_json()
    if not data or 'encrypted_update_payload' not in data:
        return jsonify({"error": "Missing encrypted_update_payload"}), 400

    user_service = current_app.user_service
    # Используем decrypt_generic_payload_to_dict для получения словаря с параметрами обновления
    update_params = user_service.decrypt_generic_payload_to_dict(data['encrypted_update_payload'])
    
    if update_params is None or not isinstance(update_params, dict):
        current_app.logger.error(f"update_user: Failed to decrypt update_payload or not a dict. User: {current_user_id}. Payload: {data['encrypted_update_payload'][:200]}")
        return jsonify({"error": "Invalid or undecryptable update_payload"}), 400
    
    user_id_from_payload = update_params.get('user_id')
    if user_id_from_payload and str(user_id_from_payload) != str(current_user_id):
        current_app.logger.warning(f"Attempt to update user {user_id_from_payload} by user {current_user_id} (from token). Denied.")
        return jsonify({"error": "User ID in payload does not match authenticated user"}), 403
    
    new_tag = update_params.get('new_tag')
    new_display_name = update_params.get('new_display_name')
    # new_encrypted_password_payload - это payload, который user_service.update_user_credentials должен расшифровать (аффинно-RSA)
    new_encrypted_password_payload = update_params.get('new_encrypted_password_payload') 

    # Перед вызовом update_user_credentials, убедимся, что если new_tag пустой, он не будет передан как None, а как отсутствие изменения.
    # Это зависит от реализации user_service.update_user_credentials (обрабатывает ли он None как "не менять")
    # Для безопасности, лучше передавать только те параметры, которые действительно пришли.
    kwargs_update = {}
    if new_tag is not None: kwargs_update['new_tag'] = new_tag
    if new_display_name is not None: kwargs_update['new_display_name'] = new_display_name
    if new_encrypted_password_payload is not None: kwargs_update['new_encrypted_password_payload'] = new_encrypted_password_payload

    if not kwargs_update: # Если нечего обновлять
        return jsonify({"message": "No update parameters provided"}), 200

    success, message = user_service.update_user_credentials(
        str(current_user_id), 
        **kwargs_update
    )
    
    if success:
        updated_user_data = user_service.get_user_by_id_as_dict(str(current_user_id)) 
        if not updated_user_data:
            current_app.logger.error(f"update_user: Successfully updated user {current_user_id} but failed to retrieve updated data.")
            # Это не должно произойти, если update_user_credentials успешен и get_user_by_id_as_dict работает
            return jsonify({"message": message, "warning": "Could not retrieve updated user data, but update was successful."}), 200 

        new_token = None
        # Проверяем, изменился ли 'tag' (который используется как 'username' в токене)
        auth_header = request.headers.get('Authorization')
        if auth_header and new_tag and updated_user_data.get('tag') == new_tag:
            try:
                old_token_payload = jwt.decode(auth_header.split(" ")[1], current_app.config['SECRET_KEY'], algorithms=["HS256"])
                old_username_in_token = old_token_payload.get('username')
                
                if new_tag != old_username_in_token:
                    current_app.logger.info(f"Tag changed for user {current_user_id} from '{old_username_in_token}' to '{new_tag}'. Generating new token.")
                    token_payload_data = {
                        'user_id': updated_user_data['id'],
                        'username': new_tag, # Используем новый тег (username)
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=current_app.config.get('JWT_EXPIRATION_HOURS', 24))
                    }
                    new_token = jwt.encode(
                        token_payload_data, 
                        current_app.config['SECRET_KEY'], 
                        algorithm='HS256'
                    )
                    current_app.logger.info(f"New JWT token generated after tag update for user_id: {updated_user_data['id']}")
            except Exception as e:
                current_app.logger.error(f"Error generating new JWT token after update for user {current_user_id}: {e}", exc_info=True)
        
        response_data = {"message": message, "user": updated_user_data}
        if new_token:
            response_data["token"] = new_token
        return jsonify(response_data), 200
    else:
        return jsonify({"error": message}), 400

@api_bp.route('/message/<string:message_id>/delete', methods=['POST'])
@token_required
def delete_message_api(current_user_id, message_id):
    # Права на удаление: сообщение должно принадлежать current_user_id
    # или пользователь должен быть администратором (если такая роль есть)
    message_service = current_app.message_service
    success, status_message = message_service.delete_message(message_id, str(current_user_id))
    if success:
        return jsonify({"message": status_message}), 200
    else:
        # status_message содержит причину ошибки (например, "Message not found" или "User not authorized")
        status_code = 403 if "not authorized" in status_message.lower() else 404 if "not found" in status_message.lower() else 400
        return jsonify({"error": status_message}), status_code

@api_bp.route('/message/<string:message_id>/edit', methods=['POST'])
@token_required
def edit_message_api(current_user_id, message_id):
    data = request.get_json()
    if not data or 'new_content_encrypted' not in data: 
        return jsonify({"error": "Missing new_content_encrypted"}), 400

    new_content_encrypted_for_server = data['new_content_encrypted']
    
    user_service = current_app.user_service 
    message_service = current_app.message_service

    # Используем decrypt_generic_payload_to_text для расшифровки нового контента
    plain_new_content = user_service.decrypt_generic_payload_to_text(new_content_encrypted_for_server)
    
    if plain_new_content is None:
         current_app.logger.error(f"edit_message_api: Failed to decrypt new_content_encrypted. User: {current_user_id}, MsgId: {message_id}. Payload: {new_content_encrypted_for_server[:200]}")
         return jsonify({"error": "Invalid or undecryptable new_content_encrypted"}), 400
    
    content_to_store_encrypted = message_service.encryption_service.encrypt_data_for_storage(plain_new_content)

    success, result_info = message_service.edit_message(message_id, str(current_user_id), content_to_store_encrypted)
    
    if success:
        current_app.logger.info(f"Message {message_id} edited by user {current_user_id}")
        
        # Получаем информацию о чате (для получения chatId)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT sender_id, receiver_id, sent_at FROM messages WHERE id = ?
        """, (message_id,))
        message_info = cursor.fetchone()
        conn.close()
        
        if message_info:
            sender_id = message_info['sender_id']
            receiver_id = message_info['receiver_id']
            timestamp = message_info['sent_at']
            
            # Формируем полноценный объект сообщения для возврата клиенту
            message_object = {
                "id": str(message_id),
                "text": plain_new_content,
                "senderId": str(sender_id),
                "sentAt": timestamp,
                "fromCurrentUser": str(sender_id) == str(current_user_id),
                "chatId": f"{min(int(sender_id), int(receiver_id))}-{max(int(sender_id), int(receiver_id))}"
            }
            return jsonify(message_object), 200
        else:
            # Если по какой-то причине не удалось получить информацию о сообщении
            return jsonify({"message": "Message updated successfully", "id": message_id}), 200
    else:
        # result_info здесь это сообщение об ошибке
        status_code = 403 if "not authorized" in str(result_info).lower() else 404 if "not found" in str(result_info).lower() else 400
        return jsonify({"error": str(result_info)}), status_code 

@api_bp.route('/chats/<string:chat_id>/messages', methods=['GET'])
@token_required
def get_chat_messages(current_user_id, chat_id):
    """
    Получает сообщения для указанного чата.
    Поддерживает параметры запроса:
    - last_message_id: ID последнего известного сообщения (для получения только новых)
    - limit: максимальное количество сообщений (по умолчанию 50)
    - offset: смещение (по умолчанию 0)
    """
    message_service = current_app.message_service
    
    # Получаем параметры запроса
    last_message_id = request.args.get('last_message_id')
    try:
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
    except ValueError:
        return jsonify({"error": "Invalid limit or offset parameter"}), 400
    
    # Проверяем, является ли пользователь участником чата
    # ID чата должен быть в формате "user_id1-user_id2" (меньший ID всегда первый)
    try:
        user_ids = chat_id.split('-')
        if len(user_ids) != 2:
            return jsonify({"error": "Invalid chat_id format"}), 400
        
        user_id1 = int(user_ids[0])
        user_id2 = int(user_ids[1])
        
        if user_id1 > user_id2:
            return jsonify({"error": "Invalid chat_id format. Smaller ID should be first."}), 400
        
        if int(current_user_id) != user_id1 and int(current_user_id) != user_id2:
            return jsonify({"error": "Access denied to this chat"}), 403
    except ValueError:
        return jsonify({"error": "Invalid chat_id format"}), 400
    
    try:
        # Получаем и форматируем сообщения
        raw_messages = message_service.get_messages_for_chat(user_id1, user_id2, limit, offset, last_message_id)
        formatted_messages = []
        
        for msg in raw_messages:
            try:
                formatted_message = {
                    "id": str(msg["id"]),
                    "text": msg["text"],
                    "sentAt": msg["sent_at"],
                    "senderId": str(msg["sender_id"]),
                    "fromCurrentUser": str(msg["sender_id"]) == str(current_user_id),
                    "chatId": chat_id
                }
                
                # Если в сообщении был Error, добавляем флаг error
                if "[Error" in msg["text"]:
                    formatted_message["error"] = True
                
                formatted_messages.append(formatted_message)
            except Exception as e:
                current_app.logger.error(f"Error processing message {msg.get('id', 'unknown')} for chat {chat_id}: {e}")
                
                # Добавляем сообщение с ошибкой вместо пропуска
                formatted_messages.append({
                    "id": str(msg.get("id", "unknown")),
                    "text": f"[Error: Unable to process message]",
                    "sentAt": msg.get("sent_at", int(datetime.datetime.now().timestamp() * 1000)),
                    "senderId": str(msg.get("sender_id", current_user_id)),
                    "fromCurrentUser": str(msg.get("sender_id", "")) == str(current_user_id),
                    "chatId": chat_id,
                    "error": True
                })
        
        return jsonify({"messages": formatted_messages}), 200
    except Exception as e:
        current_app.logger.error(f"Error getting messages for chat {chat_id}: {e}")
        return jsonify({"error": f"Failed to retrieve messages: {str(e)}"}), 500 