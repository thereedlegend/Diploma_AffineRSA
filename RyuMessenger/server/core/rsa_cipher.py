import random
from .crypto_utils import generate_large_prime, gcd, mod_inverse, str_to_int, int_to_str

RSA_KEY_SIZE_BITS = 2048
# Максимальный размер данных для одного блока RSA (в байтах)
# Для RSA 2048 бит (256 байт), если без паддинга, можно чуть меньше n.
# Если с паддингом PKCS#1 v1.5, то это n_bytes - 11.
# Так как "ручная реализация", будем считать, что чанк должен быть меньше n.
# Размер чанка текста перед преобразованием в int. Возьмем с запасом.
RSA_CHUNK_SIZE_BYTES = (RSA_KEY_SIZE_BITS // 8) - 64 # Оставляем запас для преобразования в число < n

class RSACipher:
    def __init__(self):
        self.public_key = None  # (n, e)
        self.private_key = None # (n, d) or (p, q, d, dP, dQ, qInv) for CRT
        self.n_bytes = RSA_KEY_SIZE_BITS // 8

    def generate_keys(self, bits=RSA_KEY_SIZE_BITS):
        """Генерирует пару RSA ключей (публичный, приватный)."""
        # 1. Выбрать два различных больших простых числа p и q
        # Длина p и q должна быть примерно bits/2
        p = generate_large_prime(bits // 2)
        q = generate_large_prime(bits // 2)
        while p == q:
            q = generate_large_prime(bits // 2)

        # 2. Вычислить n = p * q
        n = p * q

        # 3. Вычислить функцию Эйлера phi(n) = (p-1)(q-1)
        phi_n = (p - 1) * (q - 1)

        # 4. Выбрать целое число e (публичная экспонента) такое, что 1 < e < phi(n) и gcd(e, phi(n)) = 1
        # Часто используется e = 65537
        e = 65537
        if gcd(e, phi_n) != 1:
            # Если 65537 не подходит (очень маловероятно для больших phi_n), ищем другое
            e = random.randrange(2, phi_n -1)
            while gcd(e, phi_n) != 1:
                e = random.randrange(2, phi_n -1)
        
        # 5. Вычислить d (приватная экспонента) как d = e^(-1) mod phi(n)
        d = mod_inverse(e, phi_n)

        self.public_key = (n, e)
        self.private_key = (n, d) # Храним (n,d) для простоты, можно p,q,d для CRT
        self.n_bytes = (n.bit_length() + 7) // 8
        return self.public_key, self.private_key

    def set_public_key(self, n, e):
        self.public_key = (int(n), int(e))
        self.n_bytes = (self.public_key[0].bit_length() + 7) // 8

    def set_private_key(self, n, d):
        self.private_key = (int(n), int(d))
        self.n_bytes = (self.private_key[0].bit_length() + 7) // 8

    def _encrypt_int(self, message_int):
        if self.public_key is None:
            raise ValueError("Публичный ключ не установлен.")
        n, e = self.public_key
        if message_int >= n:
            raise ValueError(f"Число сообщения ({message_int}) слишком велико для n ({n}).")
        return pow(message_int, e, n)

    def _decrypt_int(self, ciphertext_int):
        if self.private_key is None:
            raise ValueError("Приватный ключ не установлен.")
        n, d = self.private_key
        if ciphertext_int >= n:
            raise ValueError(f"Шифротекст ({ciphertext_int}) слишком велик для n ({n}).")
        return pow(ciphertext_int, d, n)

    def encrypt_text_chunked(self, plaintext_str):
        """Шифрует текстовую строку, разбивая на чанки, если необходимо. Каждый чанк кодируется как <len>:<encryptedInt>."""
        if self.public_key is None:
            raise ValueError("Публичный ключ не установлен для шифрования.")
        n, _ = self.public_key
        chunk_size = RSA_CHUNK_SIZE_BYTES
        plaintext_bytes = plaintext_str.encode('utf-8')
        encrypted_chunks = []
        for i in range(0, len(plaintext_bytes), chunk_size):
            chunk = plaintext_bytes[i:i+chunk_size]
            message_int = int.from_bytes(chunk, 'big')
            if message_int >= n:
                raise ValueError(f"Преобразование чанка в число дало результат ({message_int}) >= n ({n}). Размер чанка: {len(chunk)} байт. Уменьшите RSA_CHUNK_SIZE_BYTES.")
            encrypted_int = self._encrypt_int(message_int)
            # Формат: <len>:<encryptedInt>
            encrypted_chunks.append(f"{len(chunk)}:{encrypted_int}")
        return "||RSA_CHUNK||".join(encrypted_chunks)

    def decrypt_text_chunked(self, ciphertext_str):
        """Расшифровывает строку, которая была зашифрована по чанкам с длиной."""
        if self.private_key is None:
            raise ValueError("Приватный ключ не установлен для расшифровки.")
        n, _ = self.private_key

        print(f"[DEBUG] decrypt_text_chunked input: {repr(ciphertext_str)[:500]}")

        encrypted_chunks_strs = ciphertext_str.split("||RSA_CHUNK||")
        decrypted_bytes = b''

        for chunk_str in encrypted_chunks_strs:
            if not chunk_str:
                continue
            # Новый формат: <len>:<encryptedInt>
            if ':' not in chunk_str:
                raise ValueError(f"Некорректный формат чанка: нет длины. Чанк: {chunk_str}")
            len_str, encrypted_int_str = chunk_str.split(':', 1)
            chunk_len = int(len_str)
            encrypted_int = int(encrypted_int_str)
            decrypted_int = self._decrypt_int(encrypted_int)
            decrypted_bytes_arr = decrypted_int.to_bytes(chunk_len, 'big')
            decrypted_bytes += decrypted_bytes_arr

        try:
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            raise ValueError("Не удалось декодировать расшифрованные байты в UTF-8. Возможна проблема с чанками/расшифровкой.") 