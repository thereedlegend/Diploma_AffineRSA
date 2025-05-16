import sqlite3
import json
from RyuMessenger.server.core.database import (
    get_db_connection, add_message, get_messages_for_chat, get_chat_list as db_get_chat_list, get_user_by_tag, get_user_by_username, get_chat_list_with_empty_chats
)
from RyuMessenger.server.core.encryption_service import EncryptionService
from RyuMessenger.server.services.user_service import UserService # Нужен для получения ключа получателя

class MessageService:
    def __init__(self, encryption_service: EncryptionService, user_service: UserService):
        self.encryption_service = encryption_service
        self.user_service = user_service

    def send_message(self, sender_id: int, receiver_id: int, encrypted_message: str):
        """
        Обрабатывает отправку сообщения от одного пользователя другому.
        sender_id: ID отправителя.
        receiver_id: ID получателя.
        encrypted_message: Сообщение, уже зашифрованное для хранения в БД.
        """
        # Проверяем, существует ли получатель
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE id = ?", (receiver_id,))
        receiver = cursor.fetchone()
        conn.close()
        if not receiver:
            return None, "Recipient not found."
        try:
            message_id = add_message(sender_id, receiver_id, encrypted_message)
            return message_id, "Message sent and stored successfully."
        except Exception as e:
            return None, f"Database error while saving message: {e}"

    def get_messages_for_chat(self, user_id1: int, user_id2: int, limit=50, offset=0, last_message_id=None):
        """
        Получает сообщения для чата между двумя пользователями.
        Если указан last_message_id, возвращает только сообщения с ID больше указанного.
        """
        try:
            if last_message_id is not None:
                messages = get_messages_for_chat(user_id1, user_id2, limit, offset, last_message_id)
            else:
                messages = get_messages_for_chat(user_id1, user_id2, limit, offset)
                
            decrypted_messages = []
            for row in messages:
                try:
                    # Попытка расшифровать сообщение
                    encrypted_message = row['encrypted_message_for_db']
                    if encrypted_message: 
                        original_message_text = self.encryption_service.decrypt_data_from_storage(encrypted_message)
                    else:
                        # Если сообщение не зашифровано (пустое), обрабатываем это как особый случай
                        original_message_text = "[Empty message]"
                    
                    decrypted_messages.append({
                        "id": row['id'],
                        "sender_id": row['sender_id'],
                        "receiver_id": row['receiver_id'],
                        "text": original_message_text,
                        "sent_at": row['sent_at']
                    })
                except Exception as e:
                    # В случае ошибки расшифровки добавляем сообщение с информацией об ошибке
                    print(f"Error decrypting message_id {row['id']}: {e}")
                    decrypted_messages.append({
                        "id": row['id'],
                        "sender_id": row['sender_id'],
                        "receiver_id": row['receiver_id'],
                        "text": f"[Error decrypting message]",
                        "sent_at": row['sent_at']
                    })
            return decrypted_messages
        except Exception as e:
            print(f"General error in get_messages_for_chat: {e}")
            return []

    def get_chat_list(self, user_id: int, last_update_time=None):
        """
        Получает список чатов пользователя.
        Если указан last_update_time, возвращает только чаты, обновленные после указанного времени.
        """
        # Используем новую функцию, возвращающую также пустые чаты
        chats_raw = get_chat_list_with_empty_chats(user_id, last_update_time)
        chats = []
        
        # Преобразуем результаты в список чатов
        for row in chats_raw:
            last_message_preview = "[Error decrypting preview]"
            if row['last_encrypted_message_for_db']:
                try:
                    # Расшифровываем превью сообщения
                    decrypted_preview = self.encryption_service.decrypt_data_from_storage(row['last_encrypted_message_for_db'])
                    last_message_preview = decrypted_preview[:50] + "..." if len(decrypted_preview) > 50 else decrypted_preview
                except Exception as e:
                    print(f"Error decrypting message preview: {e}")
                    last_message_preview = "[Error decrypting preview]"
            else:
                # Если сообщений нет (пустой чат)
                last_message_preview = ""
            
            chats.append({
                'id': f"{min(int(user_id), int(row['chat_partner_id']))}-{max(int(user_id), int(row['chat_partner_id']))}",
                'display_name': row['chat_partner_username'],
                'tag': row['chat_partner_tag'],
                'chatPartnerId': row['chat_partner_id'],
                'lastMessage': last_message_preview,
                'lastMessageTime': row['last_message_time'] if row['last_message_time'] else "",
                'unreadCount': 0,  # TODO: подсчет непрочитанных сообщений
                'lastMessageFromCurrentUser': False  # TODO: определение отправителя последнего сообщения
            })
        
        return chats

    def find_or_create_chat_with_users(self, user_id1: str, user_id2: str):
        """
        Находит или создает чат между двумя пользователями.
        Возвращает словарь с информацией о чате.
        """
        # Проверяем, существуют ли пользователи
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT u1.id, u1.username, u1.tag, u1.display_name, u1.rsa_public_key_n, u1.rsa_public_key_e 
            FROM users u1 
            WHERE u1.id = ?
        """, (user_id2,))
        user2_data = cursor.fetchone()
        
        if not user2_data:
            print(f"[CHAT] Пользователь с ID {user_id2} не найден")
            conn.close()
            return None
            
        # Проверяем, существует ли уже чат (есть ли сообщения)
        messages = get_messages_for_chat(user_id1, user_id2, 1, 0)
        
        # Проверяем, существует ли запись в таблице chats
        cursor.execute("""
            SELECT id FROM chats 
            WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
        """, (user_id1, user_id2, user_id2, user_id1))
        chat_record = cursor.fetchone()
        
        # Если записи нет, создаем ее
        if not chat_record:
            cursor.execute("""
                INSERT OR IGNORE INTO chats (user1_id, user2_id) 
                VALUES (?, ?)
            """, (min(int(user_id1), int(user_id2)), max(int(user_id1), int(user_id2))))
            conn.commit()
            print(f"[CHAT] Создана запись о чате между пользователями {user_id1} и {user_id2}")
        
        conn.close()
        
        # Формируем информацию о чате
        chat_info = {
            'id': f"{min(int(user_id1), int(user_id2))}-{max(int(user_id1), int(user_id2))}", # Формируем ID чата как "меньший_ID-больший_ID"
            'user': {
                'id': user2_data['id'],
                'username': user2_data['username'],
                'tag': user2_data['tag'],
                'display_name': user2_data['display_name'],
                'rsa_public_key': {
                    'n': user2_data['rsa_public_key_n'],
                    'e': user2_data['rsa_public_key_e']
                }
            },
            'has_messages': len(messages) > 0
        }
        
        print(f"[CHAT] Чат между пользователями {user_id1} и {user_id2} {'найден' if chat_info['has_messages'] else 'создан'}")
        return chat_info 