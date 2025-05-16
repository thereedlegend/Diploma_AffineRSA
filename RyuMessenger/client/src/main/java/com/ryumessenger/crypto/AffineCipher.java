package com.ryumessenger.crypto;

public class AffineCipher {

    // ASCII алфавит (от 0 до 255) вместо конкретных языков
    private static final int ASCII_SIZE = 256;
    
    // Массив допустимых значений для коэффициента a (взаимно простые с 256)
    private static final int[] VALID_A_VALUES = generateValidAValues(ASCII_SIZE);
    
    // Поля для хранения ключей
    private final int[] aValues; // Массив коэффициентов a для разных позиций
    private final int[] bValues; // Массив коэффициентов b для разных позиций
    
    /**
     * Конструктор с указанием массивов коэффициентов a и b
     * @param aValues Массив коэффициентов a для разных позиций
     * @param bValues Массив коэффициентов b для разных позиций
     */
    public AffineCipher(int[] aValues, int[] bValues) {
        // Проверка валидности массива aValues
        this.aValues = new int[aValues.length];
        for (int i = 0; i < aValues.length; i++) {
            if (!isCoprime(aValues[i], ASCII_SIZE)) {
                throw new IllegalArgumentException("Key 'a' at position " + i + " (" + aValues[i] + 
                    ") must be coprime with ASCII_SIZE (" + ASCII_SIZE + ")");
            }
            this.aValues[i] = aValues[i];
        }
        
        // Ключи b могут быть любыми, но приведем их по модулю m для каноничности
        this.bValues = new int[bValues.length];
        for (int i = 0; i < bValues.length; i++) {
            this.bValues[i] = Math.floorMod(bValues[i], ASCII_SIZE);
        }
    }
    
    /**
     * Конструктор с указанием индексов в массиве VALID_A_VALUES и значений b
     * @param aIndices Массив индексов для выбора значений из VALID_A_VALUES
     * @param bValues Массив значений b
     */
    public static AffineCipher fromIndices(int[] aIndices, int[] bValues) {
        // Преобразуем индексы в значения a
        int[] aValues = new int[aIndices.length];
        for (int i = 0; i < aIndices.length; i++) {
            int index = Math.floorMod(aIndices[i], VALID_A_VALUES.length);
            aValues[i] = VALID_A_VALUES[index];
        }
        
        // Преобразуем значения b по модулю ASCII_SIZE
        int[] canonicalBValues = new int[bValues.length];
        for (int i = 0; i < bValues.length; i++) {
            canonicalBValues[i] = Math.floorMod(bValues[i], ASCII_SIZE);
        }
        
        return new AffineCipher(aValues, canonicalBValues);
    }
    
    /**
     * Конструктор обратной совместимости с одним коэффициентом b
     * @param aValues Массив коэффициентов a
     * @param b Одно значение b, которое будет использоваться для всех позиций
     */
    public AffineCipher(int[] aValues, int b) {
        // Создаем массив b той же длины, что и a, заполненный одним значением
        int[] bValues = new int[aValues.length];
        for (int i = 0; i < aValues.length; i++) {
            bValues[i] = b;
        }
        
        // Используем основной конструктор
        // Проверка валидности массива aValues
        this.aValues = new int[aValues.length];
        for (int i = 0; i < aValues.length; i++) {
            if (!isCoprime(aValues[i], ASCII_SIZE)) {
                throw new IllegalArgumentException("Key 'a' at position " + i + " (" + aValues[i] + 
                    ") must be coprime with ASCII_SIZE (" + ASCII_SIZE + ")");
            }
            this.aValues[i] = aValues[i];
        }
        
        // Ключи b могут быть любыми, но приведем их по модулю m для каноничности
        this.bValues = bValues;
    }
    
    /**
     * Простой конструктор с одним коэффициентом a и b для всех символов (для обратной совместимости)
     * @param a Коэффициент a
     * @param b Смещение (коэффициент b)
     */
    public AffineCipher(int a, int b) {
        if (!isCoprime(a, ASCII_SIZE)) {
            throw new IllegalArgumentException("Key 'a' (" + a + 
                ") must be coprime with ASCII_SIZE (" + ASCII_SIZE + ")");
        }
        
        this.aValues = new int[1]; // Один элемент для всех позиций
        this.aValues[0] = a;
        
        this.bValues = new int[1]; // Один элемент для всех позиций
        this.bValues[0] = Math.floorMod(b, ASCII_SIZE);
    }
    
    /**
     * Генерирует статический массив допустимых значений a (взаимно простых с m)
     */
    private static int[] generateValidAValues(int m) {
        // Подсчет взаимно простых с m чисел
        int count = 0;
        for (int i = 1; i < m; i++) {
            if (gcd(i, m) == 1) {
                count++;
            }
        }
        
        // Создание и заполнение массива
        int[] validValues = new int[count];
        int index = 0;
        for (int i = 1; i < m; i++) {
            if (gcd(i, m) == 1) {
                validValues[index++] = i;
            }
        }
        
        return validValues;
    }
    
    /**
     * Получение массива допустимых значений a
     */
    public static int[] getValidAValues() {
        return VALID_A_VALUES.clone(); // Возвращаем копию для безопасности
    }
    
    /**
     * Создает AffineCipher со случайными коэффициентами a и b
     * @param keyLength Длина ключа (количество разных коэффициентов)
     * @return Новый экземпляр AffineCipher
     */
    public static AffineCipher createWithRandomKeys(int keyLength) {
        java.util.Random random = new java.util.Random();
        
        // Генерация случайных индексов для выбора значений a
        int[] aIndices = new int[keyLength];
        for (int i = 0; i < keyLength; i++) {
            aIndices[i] = random.nextInt(VALID_A_VALUES.length);
        }
        
        // Генерация случайных значений b
        int[] bValues = new int[keyLength];
        for (int i = 0; i < keyLength; i++) {
            bValues[i] = random.nextInt(ASCII_SIZE);
        }
        
        return fromIndices(aIndices, bValues);
    }
    
    /**
     * Возвращает коэффициент a для указанной позиции
     * @param position Позиция символа
     * @return Коэффициент a
     */
    public int getAForPosition(int position) {
        // Циклически используем значения из массива aValues
        return aValues[position % aValues.length];
    }
    
    /**
     * Возвращает коэффициент b для указанной позиции
     * @param position Позиция символа
     * @return Коэффициент b
     */
    public int getBForPosition(int position) {
        // Циклически используем значения из массива bValues
        return bValues[position % bValues.length];
    }
    
    /**
     * Возвращает обратный элемент к a для указанной позиции
     * @param position Позиция символа
     * @return Обратный элемент a^-1 mod m
     */
    public int getAInverseForPosition(int position) {
        int a = getAForPosition(position);
        return modInverse(a, ASCII_SIZE);
    }
    
    // Вспомогательные статические методы
    
    /**
     * Наибольший общий делитель (алгоритм Евклида)
     */
    public static int gcd(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return Math.abs(a); // НОД всегда положительный
    }
    
    /**
     * Проверка на взаимную простоту
     */
    public static boolean isCoprime(int a, int m) {
        return gcd(a, m) == 1;
    }
    
    /**
     * Поиск мультипликативного обратного a^-1 mod m (расширенный алгоритм Евклида)
     */
    public static int modInverse(int a, int m) {
        a = Math.floorMod(a, m); // Приводим a по модулю m
        if (a == 0 && m == 1) return 0; // Особый случай
        
        int m0 = m;
        int y = 0, x = 1;
        
        if (m == 1) return 0;
        
        while (a > 1) {
            if (m == 0) 
                throw new ArithmeticException("Modular inverse does not exist (a and m are not coprime, gcd != 1)");
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
        
        // Проверка, что обратное найдено корректно
        if (gcd(Math.floorMod(a, m0), m0) != 1 && m0 != 1) {
            throw new ArithmeticException("Modular inverse does not exist (a and m are not coprime, gcd != 1)");
        }
        
        return x;
    }
    
    // Методы шифрования/дешифрования
    
    /**
     * Шифрует строку, используя ASCII и коэффициенты a и b для разных позиций
     * @param plaintext Исходный текст
     * @return Зашифрованный текст
     */
    public String encrypt(String plaintext) {
        if (plaintext == null) return null;
        
        StringBuilder ciphertext = new StringBuilder(plaintext.length());
        for (int i = 0; i < plaintext.length(); i++) {
            char plainChar = plaintext.charAt(i);
            int x = plainChar; // ASCII код символа
            
            // Получаем коэффициенты a и b для текущей позиции
            int a = getAForPosition(i);
            int b = getBForPosition(i);
            
            // E(x) = (a*x + b) mod 256
            int encryptedValue = Math.floorMod((a * x + b), ASCII_SIZE);
            
            // Преобразуем обратно в символ
            ciphertext.append((char)encryptedValue);
        }
        
        return ciphertext.toString();
    }
    
    /**
     * Дешифрует строку
     * @param ciphertext Зашифрованный текст
     * @return Исходный текст
     */
    public String decrypt(String ciphertext) {
        if (ciphertext == null) return null;
        
        StringBuilder plaintext = new StringBuilder(ciphertext.length());
        for (int i = 0; i < ciphertext.length(); i++) {
            char cipherChar = ciphertext.charAt(i);
            int y = cipherChar; // ASCII код символа
            
            // Получаем обратный элемент a^-1 и коэффициент b для текущей позиции
            int aInverse = getAInverseForPosition(i);
            int b = getBForPosition(i);
            
            // D(y) = a^-1 * (y - b) mod 256
            int decryptedValue = Math.floorMod(aInverse * (y - b), ASCII_SIZE);
            
            // Преобразуем обратно в символ
            plaintext.append((char)decryptedValue);
        }
        
        return plaintext.toString();
    }
    
    /**
     * Возвращает количество разных коэффициентов a и b
     * @return Длина массива коэффициентов
     */
    public int getKeyLength() {
        return aValues.length;
    }
    
    /**
     * Возвращает коэффициент b для индекса 0 (для обратной совместимости)
     * @return Коэффициент b
     */
    public int getB() {
        return bValues[0];
    }
    
    /**
     * Возвращает массив коэффициентов a
     * @return Копия массива aValues
     */
    public int[] getAValues() {
        return aValues.clone();
    }
    
    /**
     * Возвращает массив коэффициентов b
     * @return Копия массива bValues
     */
    public int[] getBValues() {
        return bValues.clone();
    }
}