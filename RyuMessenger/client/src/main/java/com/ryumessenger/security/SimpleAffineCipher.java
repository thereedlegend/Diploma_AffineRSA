package com.ryumessenger.security;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Упрощенная версия улучшенного аффинного шифра с динамическими коэффициентами
 */
public class SimpleAffineCipher {
    private static final Logger LOG = Logger.getLogger(SimpleAffineCipher.class.getName());
    
    // Размер алфавита по умолчанию (ASCII)
    private static final int DEFAULT_MODULUS = 256;
    
    // Массивы коэффициентов для каждого символа
    private int[] aValues;
    private int[] bValues;
    private int modulus;
    
    // Язык для совместимости с сервером
    private String language = "en";
    
    /**
     * Создает экземпляр шифра с заданным seed для генерации коэффициентов
     */
    public SimpleAffineCipher(byte[] seed, int modulus) {
        this.modulus = modulus;
        generateCoefficients(seed);
    }
    
    /**
     * Создает экземпляр шифра с модулем по умолчанию (ASCII - 256 символов)
     */
    public SimpleAffineCipher(byte[] seed) {
        this(seed, DEFAULT_MODULUS);
    }
    
    /**
     * Генерирует разрешенные значения для коэффициента a (взаимно простые с модулем)
     */
    private List<Integer> generateAllowedAValues() {
        List<Integer> allowedValues = new ArrayList<>();
        for (int a = 1; a < modulus; a++) {
            if (gcd(a, modulus) == 1) {
                allowedValues.add(a);
            }
        }
        return allowedValues;
    }
    
    /**
     * Генерирует коэффициенты шифрования на основе seed
     */
    private void generateCoefficients(byte[] seed) {
        try {
            // Получаем список разрешенных значений a
            List<Integer> allowedAValues = generateAllowedAValues();
            
            // Инициализируем генератор случайных чисел с seed
            SecureRandom random = new SecureRandom(seed);
            
            // Создаем массивы коэффициентов
            int size = 1024; // Размер с запасом
            aValues = new int[size];
            bValues = new int[size];
            
            // Заполняем массивы значениями
            for (int i = 0; i < size; i++) {
                // Выбираем a из списка допустимых (взаимно простых с модулем)
                aValues[i] = allowedAValues.get(random.nextInt(allowedAValues.size()));
                
                // Для b берем любое значение от 0 до (modulus-1)
                bValues[i] = random.nextInt(modulus);
            }
            
            LOG.info("Сгенерированы коэффициенты аффинного шифра");
        } catch (Exception e) {
            LOG.severe("Ошибка при генерации коэффициентов: " + e.getMessage());
            throw new RuntimeException("Ошибка при генерации коэффициентов", e);
        }
    }
    
    /**
     * Шифрует строку, используя индивидуальный коэффициент для каждого символа
     */
    public String encrypt(String plainText) {
        if (plainText == null || plainText.isEmpty()) {
            return "";
        }
        
        StringBuilder cipherText = new StringBuilder();
        char[] chars = plainText.toCharArray();
        
        for (int i = 0; i < chars.length; i++) {
            // Используем коэффициенты по индексу символа
            int a = aValues[i % aValues.length];
            int b = bValues[i % bValues.length];
            
            // Конвертируем символ в число
            int x = (int) chars[i];
            
            // Применяем аффинное преобразование: y = (a*x + b) mod m
            int y = (a * x + b) % modulus;
            
            // Конвертируем обратно в символ и добавляем к результату
            cipherText.append((char) y);
        }
        
        return cipherText.toString();
    }
    
    /**
     * Расшифровывает строку
     */
    public String decrypt(String cipherText) {
        if (cipherText == null || cipherText.isEmpty()) {
            return "";
        }
        
        StringBuilder plainText = new StringBuilder();
        char[] chars = cipherText.toCharArray();
        
        for (int i = 0; i < chars.length; i++) {
            // Используем коэффициенты по индексу символа
            int a = aValues[i % aValues.length];
            int b = bValues[i % bValues.length];
            
            // Конвертируем символ в число
            int y = (int) chars[i];
            
            // Вычисляем мультипликативный обратный элемент для a по модулю m
            int aInverse = modInverse(a, modulus);
            
            // Применяем обратное аффинное преобразование: x = (aInverse * (y - b)) mod m
            int x = ((aInverse * (y - b + modulus)) % modulus + modulus) % modulus;
            
            // Конвертируем обратно в символ и добавляем к результату
            plainText.append((char) x);
        }
        
        return plainText.toString();
    }
    
    /**
     * Вычисляет наибольший общий делитель двух чисел
     */
    private int gcd(int a, int b) {
        if (b == 0) return a;
        return gcd(b, a % b);
    }
    
    /**
     * Вычисляет мультипликативный обратный элемент для a по модулю m
     */
    private int modInverse(int a, int m) {
        a = a % m;
        for (int x = 1; x < m; x++) {
            if ((a * x) % m == 1) {
                return x;
            }
        }
        throw new RuntimeException("Мультипликативный обратный не существует");
    }
    
    /**
     * Возвращает параметры для сервера
     */
    public AffineCipherParams getParams(int textLength) {
        AffineCipherParams params = new AffineCipherParams();
        params.a = new int[textLength];
        params.b = new int[textLength];
        params.m = modulus;
        params.lang = language;
        
        for (int i = 0; i < textLength; i++) {
            params.a[i] = aValues[i % aValues.length];
            params.b[i] = bValues[i % bValues.length];
        }
        
        return params;
    }
    
    /**
     * Возвращает массив коэффициентов a
     */
    public int[] getAValues() {
        return aValues;
    }
    
    /**
     * Возвращает массив коэффициентов b
     */
    public int[] getBValues() {
        return bValues;
    }
    
    /**
     * Возвращает модуль
     */
    public int getModulus() {
        return modulus;
    }
    
    /**
     * Устанавливает язык
     */
    public void setLanguage(String language) {
        this.language = language;
    }
    
    /**
     * Возвращает язык
     */
    public String getLanguage() {
        return language;
    }
    
    /**
     * Класс для хранения параметров шифра
     */
    public static class AffineCipherParams {
        public int[] a;
        public int[] b;
        public int m;
        public String lang;
        
        public org.json.JSONObject toJSON() {
            org.json.JSONObject json = new org.json.JSONObject();
            
            // Добавляем массив a
            org.json.JSONArray aArray = new org.json.JSONArray();
            for (int value : a) {
                aArray.put(value);
            }
            json.put("a", aArray);
            
            // Добавляем массив b
            org.json.JSONArray bArray = new org.json.JSONArray();
            for (int value : b) {
                bArray.put(value);
            }
            json.put("b", bArray);
            
            // Добавляем остальные параметры
            json.put("m", m);
            json.put("lang", lang);
            
            return json;
        }
    }
} 