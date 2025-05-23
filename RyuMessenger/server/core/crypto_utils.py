import random
import math

# Разделитель для параметров аффинного шифра и данных
AFFINE_PAYLOAD_DELIMITER = "|"
RSA_CHUNK_DELIMITER = "||RSA_CHUNK||"

def gcd(a, b):
    """Наибольший общий делитель."""
    while b:
        a, b = b, a % b
    return abs(a)

def extended_gcd(a, b):
    """Расширенный алгоритм Евклида. Возвращает (gcd, x, y) так, что ax + by = gcd."""
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def mod_inverse(a, m):
    """Модульное мультипликативное обратное a по модулю m."""
    d, x, y = extended_gcd(a, m)
    if d != 1:
        raise ValueError(f"Модульное обратное не существует для {a} и {m}")
    return (x % m + m) % m

def is_prime_miller_rabin(n, k=5):
    """Тест Миллера-Рабина на простоту числа n."""
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0 or n % 3 == 0: return False

    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime_candidate(length):
    """Генерирует нечетное число заданной битовой длины."""
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1
    return p

def generate_large_prime(length=1024):
    """Генерирует большое простое число заданной битовой длины."""
    p = 4
    while not is_prime_miller_rabin(p, 5):
        p = generate_prime_candidate(length)
    return p

def str_to_int(text_data, encoding='utf-8'):
    """Преобразует строку в большое целое число."""
    return int.from_bytes(text_data.encode(encoding), 'big')

def int_to_str(int_data, encoding='utf-8'):
    """Преобразует большое целое число обратно в строку."""
    length = (int_data.bit_length() + 7) // 8
    return int_data.to_bytes(length, 'big').decode(encoding) 