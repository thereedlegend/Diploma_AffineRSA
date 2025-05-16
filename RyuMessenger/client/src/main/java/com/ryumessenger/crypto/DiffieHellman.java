package com.ryumessenger.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Реализация протокола Диффи-Хеллмана для обмена ключами афинного шифрования
 */
public class DiffieHellman {
    
    // Безопасные предопределенные простые числа и генераторы для Диффи-Хеллмана
    // Используется 1024-битное простое число для большей безопасности
    private static final BigInteger DEFAULT_P = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        + "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    
    // Генератор g для протокола DH (обычно используется 2 или 5)
    private static final BigInteger DEFAULT_G = BigInteger.valueOf(2);
    
    private final BigInteger p; // Большое простое число
    private final BigInteger g; // Генератор (примитивный корень по модулю p)
    private BigInteger privateKey; // Закрытый ключ
    private BigInteger publicKey; // Открытый ключ
    private final SecureRandom random;
    
    /**
     * Конструктор с использованием параметров по умолчанию
     */
    public DiffieHellman() {
        this(DEFAULT_P, DEFAULT_G);
    }
    
    /**
     * Конструктор с указанием p и g
     * @param p Простое число
     * @param g Генератор
     */
    public DiffieHellman(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;
        this.random = new SecureRandom();
        generateKeys();
    }
    
    /**
     * Генерирует пару ключей (закрытый и открытый)
     */
    private void generateKeys() {
        // Генерируем случайный закрытый ключ (1 < privateKey < p-1)
        int bitLength = p.bitLength() - 1; // На 1 бит меньше, чем у p
        privateKey = new BigInteger(bitLength, random);
        
        // Проверяем, что 1 < privateKey < p-1
        if (privateKey.compareTo(BigInteger.ONE) <= 0 || 
            privateKey.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            // Если не удовлетворяет условиям, пробуем еще раз
            generateKeys();
            return;
        }
        
        // Вычисляем открытый ключ: publicKey = g^privateKey mod p
        publicKey = g.modPow(privateKey, p);
    }
    
    /**
     * Возвращает открытый ключ
     * @return Открытый ключ
     */
    public BigInteger getPublicKey() {
        return publicKey;
    }
    
    /**
     * Вычисляет общий секретный ключ на основе открытого ключа другой стороны
     * @param otherPublicKey Открытый ключ другой стороны
     * @return Общий секретный ключ
     */
    public BigInteger computeSharedSecret(BigInteger otherPublicKey) {
        // Проверка валидности открытого ключа другой стороны
        if (otherPublicKey.compareTo(BigInteger.ONE) <= 0 || 
            otherPublicKey.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            throw new IllegalArgumentException("Invalid public key from other party");
        }
        
        // Вычисляем общий секрет: sharedSecret = otherPublicKey^privateKey mod p
        return otherPublicKey.modPow(privateKey, p);
    }
    
    /**
     * Генерирует массив коэффициентов для афинного шифрования из общего секрета
     * @param sharedSecret Общий секретный ключ
     * @param keyLength Желаемая длина массива ключей
     * @return Массив индексов для выбора значений a из VALID_A_VALUES
     */
    public static int[] generateAffineIndices(BigInteger sharedSecret, int keyLength) {
        // Преобразуем общий секрет в байтовый массив
        byte[] secretBytes = sharedSecret.toByteArray();
        
        // Создаем массив для индексов
        int[] indices = new int[keyLength];
        
        // Заполняем массив значениями, полученными из общего секрета
        for (int i = 0; i < keyLength; i++) {
            // Используем значения из secretBytes циклически
            int byteIndex = i % secretBytes.length;
            // Преобразуем байт в положительное число (0-255)
            int value = secretBytes[byteIndex] & 0xFF;
            indices[i] = value;
        }
        
        return indices;
    }
    
    /**
     * Генерирует массив значений b для афинного шифрования из общего секрета
     * @param sharedSecret Общий секретный ключ
     * @param keyLength Желаемая длина массива ключей
     * @return Массив значений b
     */
    public static int[] generateAffineBValues(BigInteger sharedSecret, int keyLength) {
        // Преобразуем общий секрет в байтовый массив
        byte[] secretBytes = sharedSecret.toByteArray();
        
        // Создаем массив для значений b
        int[] bValues = new int[keyLength];
        
        // Заполняем массив значениями, полученными из общего секрета
        // Используем смещение в половину массива, чтобы значения не совпадали с индексами a
        for (int i = 0; i < keyLength; i++) {
            // Используем циклически значения из второй половины secretBytes 
            // (или с конца, если массив слишком короткий)
            int byteIndex = (i + (secretBytes.length / 2)) % secretBytes.length;
            // Преобразуем байт в положительное число (0-255)
            int value = secretBytes[byteIndex] & 0xFF;
            bValues[i] = value;
        }
        
        return bValues;
    }
    
    /**
     * Создает AffineCipher на основе общего секрета Диффи-Хеллмана
     * @param sharedSecret Общий секретный ключ
     * @param keyLength Желаемая длина массива ключей
     * @return Экземпляр AffineCipher
     */
    public static AffineCipher createAffineCipher(BigInteger sharedSecret, int keyLength) {
        int[] aIndices = generateAffineIndices(sharedSecret, keyLength);
        int[] bValues = generateAffineBValues(sharedSecret, keyLength);
        
        return AffineCipher.fromIndices(aIndices, bValues);
    }
} 