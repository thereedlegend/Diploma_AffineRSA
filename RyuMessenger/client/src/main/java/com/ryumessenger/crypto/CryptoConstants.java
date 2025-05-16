package com.ryumessenger.crypto;

public class CryptoConstants {
    public static final String ALPHABET_RU = "абвгдежзийклмнопрстуфхцчшщъыьэюя";
    public static final String ALPHABET_EN = "abcdefghijklmnopqrstuvwxyz";
    public static final String ALPHABET_RU_UPPER = ALPHABET_RU.toUpperCase();
    public static final String ALPHABET_EN_UPPER = ALPHABET_EN.toUpperCase();
    public static final String DIGITS = "0123456789";
    // Убедитесь, что символы здесь совпадают с серверными (особенно кавычки и пробелы)
    public static final String SYMBOLS = "!@#$%^&*()_+-=[]{}|;':,.\\/<>? "; // Двойной обратный слеш для Java строки

    public static final String SUPPORTED_CHARS_RU = ALPHABET_RU + ALPHABET_RU_UPPER + DIGITS + SYMBOLS;
    public static final String SUPPORTED_CHARS_EN = ALPHABET_EN + ALPHABET_EN_UPPER + DIGITS + SYMBOLS;

    public static final String AFFINE_PAYLOAD_DELIMITER = "||AFFINE_PARAMS||"; // Должен совпадать с серверным
    public static final String RSA_CHUNK_DELIMITER = "||RSA_CHUNK||"; // Должен совпадать с серверным

    public static final int RSA_KEY_SIZE_BITS = 2048;
    // Размер чанка для RSA на клиенте, должен быть согласован с логикой сервера или быть безопасным.
    // (KEY_SIZE_BITS / 8) - N, где N - запас. На сервере было -64.
    public static final int RSA_CHUNK_SIZE_BYTES = (RSA_KEY_SIZE_BITS / 8) - 64; 

    public static final String KEYS_DIR_NAME = "keys";
    public static final String CLIENT_KEYS_FILE_NAME = "client_keys.json";
} 