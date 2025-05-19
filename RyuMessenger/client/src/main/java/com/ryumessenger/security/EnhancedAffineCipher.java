package com.ryumessenger.security;

// import java.security.MessageDigest; // Не используется напрямую
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Улучшенный аффинный шифр с динамическими коэффициентами для каждого символа,
 * основанными на секрете Диффи-Хеллмана
 */
public class EnhancedAffineCipher {
    private static final Logger LOG = Logger.getLogger(EnhancedAffineCipher.class.getName());
    
    // Модуль преобразования (количество символов в алфавите)
    private static final int DEFAULT_MODULUS = 256; // ASCII
    
    // Массивы коэффициентов a и b для каждого символа
    private int[] aValues;
    private int[] bValues;
    private int modulus;

    /**
     * Создает экземпляр шифра с использованием общего секрета DH
     * и заданного модуля (размера алфавита)
     */
    public EnhancedAffineCipher(byte[] dhSharedSecret, int modulus) {
        this.modulus = modulus;
        generateCoefficients(dhSharedSecret);
    }
    
    /**
     * Создает экземпляр шифра с использованием общего секрета DH
     * и модуля по умолчанию (ASCII - 256 символов)
     */
    public EnhancedAffineCipher(byte[] dhSharedSecret) {
        this(dhSharedSecret, DEFAULT_MODULUS);
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
     * Расширяет общий секрет DH в массивы коэффициентов a и b
     */
    private void generateCoefficients(byte[] dhSharedSecret) {
        try {
            // Получаем список допустимых значений a (взаимно простых с модулем)
            List<Integer> allowedAValues = generateAllowedAValues();
            
            // Используем HMAC для генерации псевдослучайных значений на основе секрета
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(dhSharedSecret, "HmacSHA256");
            hmac.init(keySpec);
            
            // Создаем начальные массивы коэффициентов
            byte[] seed = hmac.doFinal("affine_seed".getBytes());
            SecureRandom random = new SecureRandom(seed);
            
            // Резервируем массивы на 1024 символа (с запасом)
            aValues = new int[1024];
            bValues = new int[1024];
            
            // Заполняем массивы значениями
            for (int i = 0; i < 1024; i++) {
                // Для a выбираем значение из списка допустимых (взаимно простых с модулем)
                aValues[i] = allowedAValues.get(random.nextInt(allowedAValues.size()));
                
                // Для b берем любое значение от 0 до (modulus-1)
                bValues[i] = random.nextInt(modulus);
            }
            
            LOG.info("Сгенерированы динамические коэффициенты аффинного шифра. " +
                     "Пример первых 5 коэффициентов a: " + formatArray(aValues, 5) + 
                     ", b: " + formatArray(bValues, 5));
        } catch (Exception e) {
            LOG.severe("Ошибка при генерации коэффициентов: " + e.getMessage());
            throw new RuntimeException("Ошибка при генерации коэффициентов аффинного шифра", e);
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
            // Используем коэффициенты по индексу символа (с зацикливанием, если символов > 1024)
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
     * Расшифровывает строку, закодированную с помощью тех же коэффициентов
     */
    public String decrypt(String cipherText) {
        if (cipherText == null || cipherText.isEmpty()) {
            return "";
        }
        
        StringBuilder plainText = new StringBuilder();
        char[] chars = cipherText.toCharArray();
        
        for (int i = 0; i < chars.length; i++) {
            // Используем коэффициенты по индексу символа (с зацикливанием, если символов > 1024)
            int a = aValues[i % aValues.length];
            int b = bValues[i % bValues.length];
            
            // Конвертируем символ в число
            int y = (int) chars[i];
            
            // Вычисляем мультипликативный обратный элемент для a по модулю m
            int aInverse = modInverse(a, modulus);
            
            // Применяем обратное аффинное преобразование: x = (aInverse * (y - b)) mod m
            int x = (aInverse * (y - b + modulus)) % modulus;
            
            // Конвертируем обратно в символ и добавляем к результату
            plainText.append((char) x);
        }
        
        return plainText.toString();
    }
    
    /**
     * Возвращает параметры шифрования для передачи на сервер
     */
    public AffineCipherParams getParams(int textLength) {
        AffineCipherParams params = new AffineCipherParams();
        params.setM(modulus);
        
        // Копируем только нужное количество коэффициентов (по длине текста)
        int[] aSubset = new int[textLength];
        int[] bSubset = new int[textLength];
        
        for (int i = 0; i < textLength; i++) {
            aSubset[i] = aValues[i % aValues.length];
            bSubset[i] = bValues[i % bValues.length];
        }
        
        params.setA(aSubset);
        params.setB(bSubset);
        
        return params;
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
     * (такое число aInverse, что (a * aInverse) % m = 1)
     */
    private int modInverse(int a, int m) {
        for (int x = 1; x < m; x++) {
            if ((a * x) % m == 1) {
                return x;
            }
        }
        throw new RuntimeException("Мультипликативный обратный не существует");
    }
    
    /**
     * Форматирует массив для вывода в лог
     */
    private String formatArray(int[] array, int limit) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < Math.min(array.length, limit); i++) {
            if (i > 0) sb.append(", ");
            sb.append(array[i]);
        }
        sb.append(", ...]");
        return sb.toString();
    }
    
    /**
     * Класс для хранения параметров шифрования (для передачи на сервер)
     */
    public static class AffineCipherParams {
        private int[] a;
        private int[] b;
        private int m;
        
        public int[] getA() {
            return a;
        }
        
        public void setA(int[] a) {
            this.a = a;
        }
        
        public int[] getB() {
            return b;
        }
        
        public void setB(int[] b) {
            this.b = b;
        }
        
        public int getM() {
            return m;
        }
        
        public void setM(int m) {
            this.m = m;
        }
    }
} 