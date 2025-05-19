import random
from .crypto_utils import gcd, mod_inverse

class AffineCipher:
    def __init__(self):
        # ASCII алфавит (32-126) - все печатные символы
        self.alphabet = ''.join(chr(i) for i in range(32, 127))
        self.m = len(self.alphabet)  # размер алфавита
        self.a = 1  # множитель
        self.b = 0  # сдвиг

    def set_keys(self, a: int, b: int):
        """Устанавливает ключи шифрования."""
        if not self._is_valid_key(a):
            raise ValueError(f"Invalid key 'a': {a}. Must be coprime with {self.m}")
        self.a = a
        self.b = b % self.m

    def _is_valid_key(self, a: int) -> bool:
        """Проверяет, является ли ключ 'a' взаимно простым с размером алфавита."""
        return self._gcd(a, self.m) == 1

    def _gcd(self, a: int, b: int) -> int:
        """Вычисляет наибольший общий делитель."""
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, a: int) -> int:
        """Вычисляет обратный элемент по модулю."""
        for x in range(1, self.m):
            if (a * x) % self.m == 1:
                return x
        raise ValueError(f"No modular inverse exists for {a} modulo {self.m}")

    def generate_keys(self) -> tuple[int, int]:
        """Генерирует пару ключей (a, b) для аффинного шифра."""
        # Генерируем a, взаимно простое с размером алфавита
        while True:
            a = random.randint(2, self.m - 1)
            if self._is_valid_key(a):
                break
        
        # Генерируем случайное b
        b = random.randint(0, self.m - 1)
        
        return a, b

    def encrypt(self, text: str) -> str:
        """Шифрует текст."""
        if not text:
            return text
            
        result = []
        for char in text:
            if char in self.alphabet:
                # Находим индекс символа в алфавите
                x = self.alphabet.index(char)
                # Применяем формулу шифрования: (ax + b) mod m
                y = (self.a * x + self.b) % self.m
                # Получаем зашифрованный символ
                result.append(self.alphabet[y])
            else:
                # Если символ не в алфавите, оставляем как есть
                result.append(char)
        return ''.join(result)

    def decrypt(self, ciphertext: str) -> str:
        """Расшифровывает текст."""
        if not ciphertext:
            return ciphertext
            
        # Вычисляем обратный элемент для a
        a_inv = self._mod_inverse(self.a)
        
        result = []
        for char in ciphertext:
            if char in self.alphabet:
                # Находим индекс символа в алфавите
                y = self.alphabet.index(char)
                # Применяем формулу расшифровки: a^(-1)(y - b) mod m
                x = (a_inv * (y - self.b)) % self.m
                # Получаем расшифрованный символ
                result.append(self.alphabet[x])
            else:
                # Если символ не в алфавите, оставляем как есть
                result.append(char)
        return ''.join(result)

def generate_affine_params():
    """Генерирует параметры аффинного шифра."""
    cipher = AffineCipher()
    key_a, key_b = cipher.generate_keys()
    
    return {
        "a": key_a,
        "b": key_b,
        "m": cipher.m
    }

def encrypt_with_params(text, lang, params):
    """Шифрует текст, используя предоставленные параметры аффинного шифра."""
    cipher = AffineCipher()
    cipher.set_keys(params['a'], params['b'])
    return cipher.encrypt(text)

def decrypt_with_params(ciphertext, lang, params):
    """Расшифровывает текст, используя предоставленные параметры аффинного шифра."""
    cipher = AffineCipher()
    cipher.set_keys(params['a'], params['b'])
    return cipher.decrypt(ciphertext)


def determine_language_and_encrypt(text, affine_params_dict):
    """Определяет язык (грубо) и шифрует аффинным шифром, возвращая также использованный язык."""
    # Простая эвристика: если больше русских букв, то русский, иначе английский
    ru_chars = sum(1 for char in text if 'а' <= char.lower() <= 'я')
    en_chars = sum(1 for char in text if 'a' <= char.lower() <= 'z')

    if ru_chars > en_chars:
        lang = 'ru'
        params = affine_params_dict['ru']
    else:
        lang = 'en' # По умолчанию или если поровну/нет букв
        params = affine_params_dict['en']
    
    cipher = AffineCipher()
    cipher.set_keys(params['a'], params['b'])
    encrypted_text = cipher.encrypt(text)
    return encrypted_text, lang

def decrypt_based_on_lang(ciphertext, lang, affine_params_dict):
    """Расшифровывает текст на основе указанного языка и словаря параметров."""
    if lang not in affine_params_dict:
        raise ValueError(f"Affine parameters for language '{lang}' not found.")
    params = affine_params_dict[lang]
    cipher = AffineCipher()
    cipher.set_keys(params['a'], params['b'])
    return cipher.decrypt(ciphertext) 