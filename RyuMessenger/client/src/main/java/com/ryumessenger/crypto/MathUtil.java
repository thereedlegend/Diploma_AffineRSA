package com.ryumessenger.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class MathUtil {

    private static final Random random = new SecureRandom();

    /**
     * Наибольший общий делитель (НОД) для BigInteger.
     */
    public static BigInteger gcd(BigInteger a, BigInteger b) {
        return a.gcd(b);
    }

    /**
     * Расширенный алгоритм Евклида.
     * Возвращает массив [d, x, y] такой, что d = gcd(a, b) и ax + by = d.
     */
    public static BigInteger[] extendedGcd(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[]{a, BigInteger.ONE, BigInteger.ZERO};
        }
        BigInteger[] vals = extendedGcd(b, a.mod(b));
        BigInteger d = vals[0];
        BigInteger x = vals[2];
        BigInteger y = vals[1].subtract(a.divide(b).multiply(vals[2]));
        return new BigInteger[]{d, x, y};
    }

    /**
     * Модульное мультипликативное обратное a по модулю m.
     * a * x = 1 (mod m)
     */
    public static BigInteger modInverse(BigInteger a, BigInteger m) {
        // BigInteger предоставляет встроенный метод modInverse
        try {
            return a.modInverse(m);
        } catch (ArithmeticException e) {
            // Это происходит, если a и m не взаимно просты
            throw new IllegalArgumentException("Модульное обратное не существует для " + a + " и " + m, e);
        }
    }
    
    /**
     * Тест Миллера-Рабина на простоту числа n.
     * @param n число для проверки
     * @param k количество раундов (чем больше, тем точнее, но медленнее)
     * @return true, если n вероятно простое, false иначе.
     */
    public static boolean isPrimeMillerRabin(BigInteger n, int k) {
        // BigInteger.isProbablePrime использует тест Миллера-Рабина (и Люка для некоторых случаев)
        // k здесь интерпретируется как "certainty" (уверенность)
        // certainty = 1 -> 1 - 1/2^1 (50%)
        // certainty = 5 -> 1 - 1/2^5 (около 96%)
        // certainty = 100 -> очень высокая уверенность
        // Для RSA ключей рекомендуется высокая уверенность, например, 100.
        return n.isProbablePrime(k); 
    }

    /**
     * Генерирует большое вероятно простое число заданной битовой длины.
     * @param bitLength битовая длина числа
     * @param certainty уровень уверенности для isProbablePrime
     * @return вероятно простое BigInteger
     */
    public static BigInteger generateLargePrime(int bitLength, int certainty) {
        return BigInteger.probablePrime(bitLength, random);
    }
     /**
     * Генерирует случайное число 'a' для аффинного шифра, взаимно простое с m.
     * @param m модуль (размер алфавита)
     * @return случайное число a, 1 < a < m, gcd(a, m) = 1
     */
    public static int generateAffineA(int m) {
        java.util.List<Integer> coprimeNumbers = new java.util.ArrayList<>();
        for (int i = 2; i < m; i++) { // Начинаем с 2, т.к. a=1 не очень хорошо для шифрования
            if (BigInteger.valueOf(i).gcd(BigInteger.valueOf(m)).equals(BigInteger.ONE)) {
                coprimeNumbers.add(i);
            }
        }
        if (coprimeNumbers.isEmpty()) {
            // Это может произойти, если m очень маленькое (например, m=2)
            // Для наших алфавитов m будет > 30, так что всегда найдутся взаимно простые.
            // Если m=1, то список будет пуст. gcd(i,1)=1 для любого i.
            // Но размер алфавита не будет 1.
             throw new IllegalArgumentException("Невозможно найти взаимно простое число 'a' для модуля " + m);
        }
        return coprimeNumbers.get(random.nextInt(coprimeNumbers.size()));
    }

    /**
     * Генерирует случайное число 'b' для аффинного шифра.
     * @param m модуль (размер алфавита)
     * @return случайное число b, 0 <= b < m
     */
    public static int generateAffineB(int m) {
        if (m <= 0) {
            throw new IllegalArgumentException("Модуль m должен быть положительным.");
        }
        return random.nextInt(m); // от 0 до m-1
    }
} 