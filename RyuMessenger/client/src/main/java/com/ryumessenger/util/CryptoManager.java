package com.ryumessenger.util;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class CryptoManager {

    private static CryptoManager instance;
    private KeyPair keyPair;
    private PublicKey serverPublicKey;
    private static final String RSA_ALGORITHM = "RSA";
    private static final int RSA_KEY_SIZE = 2048;

    private CryptoManager() {
        try {
            generateRsaKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("CryptoManager: Ошибка инициализации RSA - " + e.getMessage());
            // В реальном приложении здесь должна быть более серьезная обработка ошибки
        }
    }

    public static synchronized CryptoManager getInstance() {
        if (instance == null) {
            instance = new CryptoManager();
        }
        return instance;
    }

    private void generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(RSA_KEY_SIZE);
        this.keyPair = keyGen.generateKeyPair();
        System.out.println("CryptoManager: Новая пара RSA ключей сгенерирована.");
    }

    public PublicKey getPublicKey() {
        if (keyPair == null) {
            // Попытка регенерации, если ключи не были созданы (маловероятно при текущей логике)
            try {
                generateRsaKeyPair();
            } catch (NoSuchAlgorithmException e) {
                 System.err.println("CryptoManager: Не удалось получить публичный ключ - " + e.getMessage());
                return null;
            }
        }
        return keyPair.getPublic();
    }

    public String getPublicKeyString() {
        PublicKey publicKey = getPublicKey();
        if (publicKey != null) {
            return Base64.getEncoder().encodeToString(publicKey.getEncoded());
        }
        return null;
    }

    public PrivateKey getPrivateKey() {
         if (keyPair == null) {
            try {
                generateRsaKeyPair();
            } catch (NoSuchAlgorithmException e) {
                System.err.println("CryptoManager: Не удалось получить приватный ключ - " + e.getMessage());
                return null;
            }
        }
        return keyPair.getPrivate();
    }

    // Методы для работы с открытым ключом сервера
    public PublicKey getServerPublicKey() {
        return serverPublicKey;
    }

    public void setServerPublicKey(String base64PublicKey) throws Exception {
        if (base64PublicKey == null || base64PublicKey.isEmpty()) {
            this.serverPublicKey = null;
            System.err.println("CryptoManager: Получена пустая строка ключа сервера.");
            return;
        }
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            this.serverPublicKey = keyFactory.generatePublic(spec);
            System.out.println("CryptoManager: Открытый ключ сервера успешно установлен.");
        } catch (Exception e) {
            this.serverPublicKey = null;
            System.err.println("CryptoManager: Ошибка установки открытого ключа сервера: " + e.getMessage());
            throw e; // Пробрасываем исключение, чтобы вызывающий код мог его обработать
        }
    }

    // RSA шифрование
    public String encryptRSA(String plainText, PublicKey publicKey) throws Exception {
        if (publicKey == null) throw new IllegalArgumentException("Публичный ключ не может быть null для шифрования");
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // RSA дешифрование
    public String decryptRSA(String encryptedTextBase64, PrivateKey privateKey) throws Exception {
        if (privateKey == null) throw new IllegalArgumentException("Приватный ключ не может быть null для дешифрования");
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedTextBase64);
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, "UTF-8");
    }
    
    // --- Методы для Афинного шифра ---
    private static final int DEFAULT_ALPHABET_SIZE = 256; // Для примера, работаем с байтами/расширенным ASCII

    // Генерация случайных ключей для Афинного шифра (a, b)
    public static int[] generateAffineKeys() {
        return generateAffineKeys(DEFAULT_ALPHABET_SIZE);
    }
    
    public static int[] generateAffineKeys(int alphabetSize) {
        int a, b;
        java.util.Random random = new java.util.Random();
        do {
            a = random.nextInt(alphabetSize - 1) + 1; // a не должно быть 0
        } while (gcd(a, alphabetSize) != 1);
        b = random.nextInt(alphabetSize);
        return new int[]{a, b};
    }

    // Шифрование Афинным шифром
    public static String encryptAffine(String text, int a, int b) {
        return encryptAffine(text, a, b, DEFAULT_ALPHABET_SIZE);
    }
    
    public static String encryptAffine(String text, int a, int b, int alphabetSize) {
        StringBuilder result = new StringBuilder();
        for (char character : text.toCharArray()) {
            // Простое предположение: работаем с символами как с их числовыми значениями.
            // Для более сложных алфавитов (например, только буквы) потребуется другая логика отображения.
            int charValue = (int) character;
            // Применяем шифрование, если символ попадает в "алфавит"
            // В данном случае, если мы считаем alphabetSize = 256, то это любой символ, который может быть байтом.
            // Для Unicode символов > 255 это не будет работать корректно без нормализации.
            // Для простоты, предположим, что текст предварительно обработан или содержит символы в диапазоне 0..alphabetSize-1
            if (charValue >= 0 && charValue < alphabetSize) { // Ограничение для примера
                 result.append((char) ((a * charValue + b) % alphabetSize));
            } else {
                 result.append(character); // Символы вне диапазона оставляем как есть (небезопасно)
            }
        }
        return result.toString();
    }

    // Дешифрование Афинным шифром
    public static String decryptAffine(String cipherText, int a, int b) {
        return decryptAffine(cipherText, a, b, DEFAULT_ALPHABET_SIZE);
    }

    public static String decryptAffine(String cipherText, int a, int b, int alphabetSize) {
        StringBuilder result = new StringBuilder();
        int aInv = modInverse(a, alphabetSize);
        if (aInv == -1) {
            throw new IllegalArgumentException("Ключ 'a' не взаимно прост с размером алфавита, дешифрование невозможно.");
        }
        for (char character : cipherText.toCharArray()) {
            int charValue = (int) character;
            if (charValue >= 0 && charValue < alphabetSize) { // Ограничение для примера
                int decryptedChar = (aInv * (charValue - b + alphabetSize)) % alphabetSize;
                result.append((char) decryptedChar);
            } else {
                result.append(character); // Символы вне диапазона оставляем как есть
            }
        }
        return result.toString();
    }

    // Наибольший общий делитель (НОД)
    private static int gcd(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    // Модульное мультипликативное обратное (расширенный алгоритм Евклида)
    private static int modInverse(int a, int m) {
        a = a % m;
        for (int x = 1; x < m; x++) {
            if ((a * x) % m == 1) {
                return x;
            }
        }
        return -1; // Обратного не существует
    }
} 