import sqlite3
import os
import json

# Путь к директории instance, где будет храниться файл БД
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, '..', 'instance')
DATABASE_FILE = os.path.join(INSTANCE_DIR, 'ryumessenger.sqlite3')

if not os.path.exists(INSTANCE_DIR):
    os.makedirs(INSTANCE_DIR)

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row # Доступ к колонкам по именам
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Удаляем старые таблицы для чистого старта
    cursor.execute("DROP TABLE IF EXISTS messages")
    cursor.execute("DROP TABLE IF EXISTS users")
    # Если будут другие таблицы — добавить сюда

    # Создаём таблицу пользователей
    cursor.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        tag TEXT UNIQUE COLLATE NOCASE,
        display_name TEXT NOT NULL,
        password_info TEXT NOT NULL,             -- JSON: {cipher_text, affine_params, lang}
        rsa_public_key_n TEXT NOT NULL,
        rsa_public_key_e TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cursor.execute("CREATE INDEX idx_users_username_nocase ON users (username COLLATE NOCASE)")
    cursor.execute("CREATE INDEX idx_users_tag_nocase ON users (tag COLLATE NOCASE)")

    # Создаём таблицу сообщений
    cursor.execute("""
    CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        encrypted_message_for_db TEXT NOT NULL, -- Зашифровано для хранения (Affine_S -> RSA_S_pub)
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users (id),
        FOREIGN KEY (receiver_id) REFERENCES users (id)
    )
    """)
    cursor.execute("CREATE INDEX idx_messages_sender ON messages (sender_id, sent_at DESC)")
    cursor.execute("CREATE INDEX idx_messages_receiver ON messages (receiver_id, sent_at DESC)")
    cursor.execute("CREATE INDEX idx_messages_chat ON messages (sender_id, receiver_id, sent_at DESC)")

    conn.commit()
    conn.close()
    print(f"База данных создана с нуля и полностью чиста: {DATABASE_FILE}")

# -- Функции для работы с пользователями --
def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_tag(tag):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE tag = ? COLLATE NOCASE", (tag,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def check_username_exists(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def check_tag_exists(tag):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE tag = ? COLLATE NOCASE", (tag,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def update_user_tag(user_id, new_tag):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET tag = ? WHERE id = ?", (new_tag, user_id))
    conn.commit()
    conn.close()

def update_user_password(user_id, new_password_info):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_info = ? WHERE id = ?", (new_password_info, user_id))
    conn.commit()
    conn.close()

def add_user(username, tag, display_name, password_info, rsa_public_key_n, rsa_public_key_e):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, tag, display_name, password_info, rsa_public_key_n, rsa_public_key_e) VALUES (?, ?, ?, ?, ?, ?)",
                   (username, tag, display_name, password_info, rsa_public_key_n, rsa_public_key_e))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id

def update_user_display_name(user_id, new_display_name):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET display_name = ? WHERE id = ?", (new_display_name, user_id))
    conn.commit()
    conn.close()

# -- Функции для работы с сообщениями --
def add_message(sender_id, receiver_id, encrypted_message_for_db):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender_id, receiver_id, encrypted_message_for_db) VALUES (?, ?, ?)",
                   (sender_id, receiver_id, encrypted_message_for_db))
    message_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return message_id

def get_messages_for_chat(user_id1: int, user_id2: int, limit=50, offset=0, last_message_id=None):
    """
    Получает сообщения для чата между двумя пользователями.
    Если указан last_message_id, возвращает только сообщения с ID больше указанного.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if last_message_id is not None:
        cursor.execute("""
            SELECT id, sender_id, receiver_id, encrypted_message_for_db, sent_at
            FROM messages
            WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
            AND id > ?
            ORDER BY sent_at DESC
            LIMIT ? OFFSET ?
        """, (user_id1, user_id2, user_id2, user_id1, last_message_id, limit, offset))
    else:
        cursor.execute("""
            SELECT id, sender_id, receiver_id, encrypted_message_for_db, sent_at
            FROM messages
            WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
            ORDER BY sent_at DESC
            LIMIT ? OFFSET ?
        """, (user_id1, user_id2, user_id2, user_id1, limit, offset))
    
    messages = cursor.fetchall()
    conn.close()
    return [dict(row) for row in messages]

def get_chat_list(user_id: int, last_update_time=None):
    """
    Получает список чатов пользователя.
    Если указан last_update_time, возвращает только чаты, обновленные после указанного времени.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if last_update_time is not None:
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN m1.sender_id = ? THEN m1.receiver_id 
                    ELSE m1.sender_id 
                END as chat_partner_id,
                u.username as chat_partner_username,
                u.tag as chat_partner_tag,
                m1.sent_at as last_message_time,
                m1.encrypted_message_for_db as last_encrypted_message_for_db,
                m1.id as last_message_id
            FROM messages m1
            JOIN users u ON u.id = CASE 
                WHEN m1.sender_id = ? THEN m1.receiver_id 
                ELSE m1.sender_id 
            END
            WHERE (m1.sender_id = ? OR m1.receiver_id = ?)
            AND m1.sent_at > ?
            AND m1.id = (
                SELECT MAX(m2.id)
                FROM messages m2
                WHERE (m2.sender_id = m1.sender_id AND m2.receiver_id = m1.receiver_id)
                OR (m2.sender_id = m1.receiver_id AND m2.receiver_id = m1.sender_id)
            )
            ORDER BY m1.sent_at DESC
        """, (user_id, user_id, user_id, user_id, last_update_time))
    else:
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN m1.sender_id = ? THEN m1.receiver_id 
                    ELSE m1.sender_id 
                END as chat_partner_id,
                u.username as chat_partner_username,
                u.tag as chat_partner_tag,
                m1.sent_at as last_message_time,
                m1.encrypted_message_for_db as last_encrypted_message_for_db,
                m1.id as last_message_id
            FROM messages m1
            JOIN users u ON u.id = CASE 
                WHEN m1.sender_id = ? THEN m1.receiver_id 
                ELSE m1.sender_id 
            END
            WHERE (m1.sender_id = ? OR m1.receiver_id = ?)
            AND m1.id = (
                SELECT MAX(m2.id)
                FROM messages m2
                WHERE (m2.sender_id = m1.sender_id AND m2.receiver_id = m1.receiver_id)
                OR (m2.sender_id = m1.receiver_id AND m2.receiver_id = m1.sender_id)
            )
            ORDER BY m1.sent_at DESC
        """, (user_id, user_id, user_id, user_id))
    
    chats = cursor.fetchall()
    conn.close()
    return chats

def get_chat_list_with_empty_chats(user_id: int, last_update_time=None):
    """
    Получает список чатов пользователя, включая пустые чаты (созданные через find_or_create).
    Если указан last_update_time, возвращает только чаты, обновленные после указанного времени.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Сначала получаем список чатов с сообщениями
    chats_with_messages = get_chat_list(user_id, last_update_time)
    
    # Собираем ID пользователей, с которыми есть чаты с сообщениями
    chat_partner_ids = set()
    for chat in chats_with_messages:
        chat_partner_ids.add(chat['chat_partner_id'])
    
    # Ищем пары пользователей в таблице chats (если она существует)
    try:
        # Проверка на существование таблицы chats
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chats'")
        if cursor.fetchone():
            # Таблица chats существует, выполняем запрос
            if last_update_time is not None:
                cursor.execute("""
                    SELECT 
                        c.user2_id as chat_partner_id,
                        u.username as chat_partner_username,
                        u.tag as chat_partner_tag,
                        c.created_at as last_message_time,
                        NULL as last_encrypted_message_for_db,
                        NULL as last_message_id
                    FROM chats c
                    JOIN users u ON u.id = c.user2_id
                    WHERE c.user1_id = ? AND c.user2_id NOT IN (?)
                    AND c.created_at > ?
                    UNION
                    SELECT 
                        c.user1_id as chat_partner_id,
                        u.username as chat_partner_username,
                        u.tag as chat_partner_tag,
                        c.created_at as last_message_time,
                        NULL as last_encrypted_message_for_db,
                        NULL as last_message_id
                    FROM chats c
                    JOIN users u ON u.id = c.user1_id
                    WHERE c.user2_id = ? AND c.user1_id NOT IN (?)
                    AND c.created_at > ?
                """, (user_id, ','.join([str(id) for id in chat_partner_ids]), last_update_time, 
                       user_id, ','.join([str(id) for id in chat_partner_ids]), last_update_time))
            else:
                chat_partner_ids_str = ','.join([str(id) for id in chat_partner_ids]) if chat_partner_ids else "0"
                cursor.execute("""
                    SELECT 
                        c.user2_id as chat_partner_id,
                        u.username as chat_partner_username,
                        u.tag as chat_partner_tag,
                        c.created_at as last_message_time,
                        NULL as last_encrypted_message_for_db,
                        NULL as last_message_id
                    FROM chats c
                    JOIN users u ON u.id = c.user2_id
                    WHERE c.user1_id = ? AND c.user2_id NOT IN ({0})
                    UNION
                    SELECT 
                        c.user1_id as chat_partner_id,
                        u.username as chat_partner_username,
                        u.tag as chat_partner_tag,
                        c.created_at as last_message_time,
                        NULL as last_encrypted_message_for_db,
                        NULL as last_message_id
                    FROM chats c
                    JOIN users u ON u.id = c.user1_id
                    WHERE c.user2_id = ? AND c.user1_id NOT IN ({0})
                """.format(chat_partner_ids_str), (user_id, user_id))
                
            empty_chats = cursor.fetchall()
        else:
            empty_chats = []
    except Exception as e:
        print(f"Error querying chats table: {e}")
        empty_chats = []
    
    # Создаем таблицу chats, если она еще не существует
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id INTEGER NOT NULL,
            user2_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user1_id) REFERENCES users (id),
            FOREIGN KEY (user2_id) REFERENCES users (id),
            UNIQUE(user1_id, user2_id)
        )
    """)
    conn.commit()
    
    # Объединяем результаты
    all_chats = list(chats_with_messages)
    all_chats.extend(empty_chats)
    
    conn.close()
    return all_chats

if __name__ == '__main__':
    # Это можно запустить для инициализации БД: python -m RyuMessenger.server.core.database
    print("Инициализация базы данных...")
    init_db()
    print("Инициализация базы данных завершена.") 