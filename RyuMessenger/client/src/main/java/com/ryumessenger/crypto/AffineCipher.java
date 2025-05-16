package com.ryumessenger.crypto;

public class AffineCipher {

    // Совместимые с сервером алфавиты (SUPPORT_CHARS_RU и SUPPORT_CHARS_EN)
    private static final String ALPHABET_RU = "абвгдежзийклмнопрстуфхцчшщъыьэюяАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ0123456789!@#$%^&*()_+-=[]{}|;':,.\\/<>? ";
    private static final String ALPHABET_EN = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':,.\\/<>? ";

    // Enum для языка
    public enum Language {
        RUSSIAN, ENGLISH
    }

    // Поля экземпляра (final, инициализируются в конструкторе)
    private final int a;
    private final int b;
    private final int aInverse;
    private final Language language;
    public final String alphabet; // Актуальный алфавит для этого экземпляра
    public final int m;           // Актуальный модуль (размер алфавита)

    /**
     * Основной конструктор, принимающий ключи и язык.
     * Вычисляет обратный элемент для 'a'.
     * @param a Ключ 'a', должен быть взаимно прост с размером алфавита m.
     * @param b Ключ 'b'.
     * @param language Язык (для выбора алфавита).
     */
    public AffineCipher(int a, int b, Language language) {
        this.language = language;
        AlphabetInfo info = getAlphabetAndModulus(language); // Получаем алфавит и модуль
        this.alphabet = info.alphabet;
        this.m = info.m;

        if (!isCoprime(a, this.m)) {
            throw new IllegalArgumentException("Key 'a' (" + a + ") must be coprime with alphabet size (" + this.m + ") for language " + language);
        }
        this.a = a;
        // Ключ b может быть любым, но приведем его по модулю m для каноничности
        this.b = Math.floorMod(b, this.m); 
        
        // Вычисляем и сохраняем обратное к 'a' по модулю m
        this.aInverse = modInverse(a, this.m);
    }

    /**
     * Статический фабричный метод для создания шифра со случайными ключами.
     * @param language Язык.
     * @return Новый экземпляр AffineCipher со случайными допустимыми ключами.
     */
    public static AffineCipher createWithRandomKeys(Language language) {
        AlphabetInfo info = getAlphabetAndModulus(language);
        int m = info.m;
        java.util.Random random = new java.util.Random();
        int randomA, randomB;
        // Генерируем 'a' взаимно простое с m
        do {
            randomA = random.nextInt(m - 1) + 1; // a > 0
        } while (!isCoprime(randomA, m));
        // 'b' может быть любым от 0 до m-1
        randomB = random.nextInt(m);
        // Проверка (дополнительно, для отладки)
        if (!isCoprime(randomA, m)) {
            throw new IllegalStateException("Генерация некорректного ключа a для аффинного шифра: a=" + randomA + ", m=" + m);
        }
        System.out.println("Generated Affine keys for " + language + ": a=" + randomA + ", b=" + randomB + ", m=" + m);
        return new AffineCipher(randomA, randomB, language);
    }

    // --- Геттеры для ключей и языка ---
    public int getKeyA() { return a; }
    public int getKeyB() { return b; }
    public Language getLanguage() { return language; }
    public int getModulus() { return m; } // Геттер для модуля


    // --- Вспомогательные статические методы ---

    // Внутренний класс для хранения информации об алфавите
    public static class AlphabetInfo {
        final String alphabet;
        final int m;
        AlphabetInfo(String alphabet, int m) { this.alphabet = alphabet; this.m = m; }
    }

    // Метод для получения алфавита и модуля по языку
    public static AlphabetInfo getAlphabetAndModulus(Language lang) {
        switch (lang) {
            case RUSSIAN:
                return new AlphabetInfo(ALPHABET_RU, ALPHABET_RU.length());
            case ENGLISH:
                return new AlphabetInfo(ALPHABET_EN, ALPHABET_EN.length());
            default:
                 // Эта ветка не должна достигаться, если используются только значения enum
                throw new IllegalArgumentException("Unsupported language specified: " + lang);
        }
    }

    // Набольший общий делитель (алгоритм Евклида)
    public static int gcd(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return Math.abs(a); // НОД всегда положительный
    }

    // Поиск мультипликативного обратного a^-1 mod m (расширенный алгоритм Евклида)
    // Возвращает x, такой что (a*x) % m == 1
     public static int modInverse(int a, int m) {
         a = Math.floorMod(a, m); // Приводим a по модулю m
         if (a == 0 && m == 1) return 0; // Особый случай

         int m0 = m;
         int y = 0, x = 1;

         if (m == 1) return 0;

         while (a > 1) {
             if (m == 0) throw new ArithmeticException("Modular inverse does not exist (a and m are not coprime, gcd != 1)");
             // q - частное
             int q = a / m;
             int t = m;

             // m - остаток от деления a на m
             m = a % m;
             a = t;
             t = y;

             // Обновляем y и x
             y = x - q * y;
             x = t;
         }

         // Приводим x к положительному значению в диапазоне [0, m0-1]
         if (x < 0) x = x + m0;
         
         // Проверка, что обратное найдено корректно (на всякий случай)
          if (gcd(Math.floorMod(a, m0), m0) != 1 && m0 != 1) { // a теперь содержит gcd(изначальные a, m)
               throw new ArithmeticException("Modular inverse does not exist (a and m are not coprime, gcd != 1)");
          }

         return x;
     }


    // Проверка на взаимную простоту
    public static boolean isCoprime(int a, int m) {
         return gcd(a, m) == 1;
    }

    // --- Методы шифрования/дешифрования ---

    public String encrypt(String plaintext) {
        if (plaintext == null) return null;
        StringBuilder ciphertext = new StringBuilder(plaintext.length());
        for (char plainChar : plaintext.toCharArray()) {
             // Обрабатываем только символы, присутствующие в выбранном алфавите
            int charIndex = alphabet.indexOf(plainChar); // Поиск с учетом регистра
            
            if (charIndex != -1) {
                // E(x) = (ax + b) mod m
                int encryptedIndex = Math.floorMod((a * charIndex + b), m);
                ciphertext.append(alphabet.charAt(encryptedIndex));
            } else {
                 // Если символа нет в алфавите, оставляем его без изменений
                ciphertext.append(plainChar);
            }
        }
        return ciphertext.toString();
    }

    public String decrypt(String ciphertext) {
        if (ciphertext == null) return null;
        StringBuilder plaintext = new StringBuilder(ciphertext.length());
        for (char cipherChar : ciphertext.toCharArray()) {
            // Обрабатываем только символы из алфавита
             int charIndex = alphabet.indexOf(cipherChar); // Поиск с учетом регистра

            if (charIndex != -1) {
                // D(y) = a^-1 * (y - b) mod m
                 int decryptedIndex = Math.floorMod(aInverse * (charIndex - b), m);
                 // Эквивалентно: int decryptedIndex = Math.floorMod(aInverse * Math.floorMod(charIndex - b, m), m);
                plaintext.append(alphabet.charAt(decryptedIndex));
            } else {
                // Если символа нет в алфавите, оставляем без изменений
                plaintext.append(cipherChar);
            }
        }
        return plaintext.toString();
    }
}