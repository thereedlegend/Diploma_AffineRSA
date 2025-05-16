import random
from .crypto_utils import gcd, mod_inverse, get_char_map_and_modulus, get_inv_char_map, SUPPORTED_CHARS_RU, SUPPORTED_CHARS_EN

class AffineCipher:
    def __init__(self, lang='ru'):
        self.lang = lang
        self.char_to_int, self.m = get_char_map_and_modulus(lang)
        self.int_to_char = get_inv_char_map(lang)
        self.key_a = None
        self.key_b = None

    def generate_keys(self):
        """Генерирует ключи a и b для аффинного шифра."""
        # key_a должно быть взаимно простым с m
        self.key_a = random.choice([i for i in range(1, self.m) if gcd(i, self.m) == 1])
        self.key_b = random.randint(0, self.m - 1)
        return self.key_a, self.key_b

    def set_keys(self, a, b):
        if gcd(a, self.m) != 1:
            raise ValueError(f"Ключ 'a' ({a}) должен быть взаимно простым с модулем {self.m} для языка {self.lang}")
        self.key_a = a
        self.key_b = b

    def encrypt(self, plaintext):
        if self.key_a is None or self.key_b is None:
            raise ValueError("Ключи не установлены или не сгенерированы.")
        
        ciphertext = []
        for char in plaintext:
            if char in self.char_to_int:
                char_code = self.char_to_int[char]
                encrypted_code = (self.key_a * char_code + self.key_b) % self.m
                ciphertext.append(self.int_to_char[encrypted_code])
            else:
                # Если символ не из алфавита, оставляем его как есть (или можно выбросить ошибку)
                # В ТЗ указано два языка, так что символы должны быть в одном из них
                # Однако, смешанный текст или спецсимволы потребуют более сложной обработки
                # или расширенного алфавита SUPPORTED_CHARS
                ciphertext.append(char) 
        return "".join(ciphertext)

    def decrypt(self, ciphertext):
        if self.key_a is None or self.key_b is None:
            raise ValueError("Ключи не установлены или не сгенерированы.")
        
        plaintext = []
        a_inv = mod_inverse(self.key_a, self.m)
        for char in ciphertext:
            if char in self.char_to_int:
                char_code = self.char_to_int[char]
                decrypted_code = (a_inv * (char_code - self.key_b + self.m)) % self.m
                plaintext.append(self.int_to_char[decrypted_code])
            else:
                plaintext.append(char)
        return "".join(plaintext)

def generate_affine_params():
    """Генерирует параметры аффинного шифра для русского и английского языков."""
    cipher_ru = AffineCipher(lang='ru')
    key_a_ru, key_b_ru = cipher_ru.generate_keys()

    cipher_en = AffineCipher(lang='en')
    key_a_en, key_b_en = cipher_en.generate_keys()
    
    return {
        "ru": {"a": key_a_ru, "b": key_b_ru, "m": cipher_ru.m},
        "en": {"a": key_a_en, "b": key_b_en, "m": cipher_en.m}
    }

def encrypt_with_params(text, lang, params):
    """Шифрует текст, используя предоставленные параметры аффинного шифра."""
    cipher = AffineCipher(lang=lang)
    cipher.set_keys(params['a'], params['b'])
    return cipher.encrypt(text)

def decrypt_with_params(ciphertext, lang, params):
    """Расшифровывает текст, используя предоставленные параметры аффинного шифра."""
    cipher = AffineCipher(lang=lang)
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
    
    cipher = AffineCipher(lang=lang)
    cipher.set_keys(params['a'], params['b'])
    encrypted_text = cipher.encrypt(text)
    return encrypted_text, lang

def decrypt_based_on_lang(ciphertext, lang, affine_params_dict):
    """Расшифровывает текст на основе указанного языка и словаря параметров."""
    if lang not in affine_params_dict:
        raise ValueError(f"Affine parameters for language '{lang}' not found.")
    params = affine_params_dict[lang]
    cipher = AffineCipher(lang=lang)
    cipher.set_keys(params['a'], params['b'])
    return cipher.decrypt(ciphertext) 