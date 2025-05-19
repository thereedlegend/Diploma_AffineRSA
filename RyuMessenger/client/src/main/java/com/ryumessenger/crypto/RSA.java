package com.ryumessenger.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class RSA {
    private BigInteger n, e, d; // n - модуль, e - публичная экспонента, d - приватная экспонента
    private static final SecureRandom random = new SecureRandom();
    private static final int CERTAINTY = 100; // Уверенность для генерации простых чисел

    public static class KeyPair {
        public final PublicKey publicKey;
        public final PrivateKey privateKey;

        public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
    }

    public static class PublicKey {
        public final BigInteger n;
        public final BigInteger e;

        public PublicKey(BigInteger n, BigInteger e) {
            this.n = n;
            this.e = e;
        }
    }

    public static class PrivateKey {
        public final BigInteger n;
        public final BigInteger d;
        // Можно также хранить p, q, dP, dQ, qInv для оптимизации с CRT, но для ТЗ это избыточно.

        public PrivateKey(BigInteger n, BigInteger d) {
            this.n = n;
            this.d = d;
        }

        public byte[] toByteArray() {
            return d.toByteArray();
        }
    }

    public RSA() {}

    public KeyPair generateKeys(int bitLength) {
        // 1. Выбрать два различных больших простых числа p и q
        BigInteger p = MathUtil.generateLargePrime(bitLength / 2, CERTAINTY);
        BigInteger q;
        do {
            q = MathUtil.generateLargePrime(bitLength / 2, CERTAINTY);
        } while (p.equals(q));

        // 2. Вычислить n = p * q
        this.n = p.multiply(q);

        // 3. Вычислить функцию Эйлера phi(n) = (p-1)(q-1)
        BigInteger phi_n = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // 4. Выбрать целое число e (публичная экспонента) такое, что 1 < e < phi(n) и gcd(e, phi(n)) = 1
        // Часто используется e = 65537 (в виде BigInteger)
        this.e = BigInteger.valueOf(65537);
        while (MathUtil.gcd(this.e, phi_n).intValue() != 1) {
            // Если 65537 не подходит, генерируем случайное e
            // Это очень маловероятно для больших p и q
            this.e = new BigInteger(phi_n.bitLength() -1, random); // e < phi_n
            if (this.e.compareTo(BigInteger.ONE) <= 0) {
                this.e = BigInteger.valueOf(3); // Альтернативное небольшое простое, если случайное <=1
            }
        }

        // 5. Вычислить d (приватная экспонента) как d = e^(-1) mod phi(n)
        this.d = MathUtil.modInverse(this.e, phi_n);
        
        return new KeyPair(new PublicKey(this.n, this.e), new PrivateKey(this.n, this.d));
    }
    
    public void setPublicKey(BigInteger n, BigInteger e) {
        this.n = n;
        this.e = e;
        this.d = null; // Если устанавливаем только публичный ключ, приватный неизвестен
    }

    public void setPrivateKey(BigInteger n, BigInteger d) {
        this.n = n;
        this.d = d;
        this.e = null; // Если устанавливаем только приватный ключ, публичный (e) может быть неизвестен
                       // Хотя для симметрии лучше всегда иметь n, и либо (e), либо (d)
    }
    
    public void setKeyPair(PublicKey pub, PrivateKey priv) {
        if (!pub.n.equals(priv.n)) {
            throw new IllegalArgumentException("N must be the same for public and private keys.");
        }
        this.n = pub.n;
        this.e = pub.e;
        this.d = priv.d;
    }

    private BigInteger encryptInt(BigInteger message) {
        if (this.n == null || this.e == null) {
            throw new IllegalStateException("Public key (n, e) is not set for encryption.");
        }
        if (message.compareTo(this.n) >= 0) {
            throw new IllegalArgumentException("Message integer (" + message + ") is too large for n (" + this.n + "). Chunking error?");
        }

        // Защита от timing-атак: добавляем случайную задержку
        try {
            Thread.sleep(new SecureRandom().nextInt(10));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return message.modPow(this.e, this.n);
    }

    private BigInteger decryptInt(BigInteger ciphertext) {
        if (this.n == null || this.d == null) {
            throw new IllegalStateException("Private key (n, d) is not set for decryption.");
        }
        if (ciphertext.compareTo(this.n) >= 0) {
            throw new IllegalArgumentException("Ciphertext integer (" + ciphertext + ") is too large for n (" + this.n + ").");
        }

        // Защита от timing-атак: добавляем случайную задержку
        try {
            Thread.sleep(new SecureRandom().nextInt(10));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return ciphertext.modPow(this.d, this.n);
    }

    public String encryptTextChunked(String plaintext) {
        if (this.n == null || this.e == null) {
            throw new IllegalStateException("Public key (n, e) is not set for encryption.");
        }
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        List<String> encryptedChunkStrings = new ArrayList<>();
        int chunkSize = CryptoConstants.RSA_CHUNK_SIZE_BYTES;

        for (int i = 0; i < plaintextBytes.length; i += chunkSize) {
            int end = Math.min(plaintextBytes.length, i + chunkSize);
            byte[] chunk = new byte[end - i];
            System.arraycopy(plaintextBytes, i, chunk, 0, chunk.length);
            BigInteger messageInt = new BigInteger(1, chunk); // 1 для positive signum
            if (messageInt.compareTo(this.n) >= 0) {
                throw new RuntimeException("Chunk to integer conversion resulted in a number (" + messageInt +
                                           ") >= n (" + this.n + "). Chunk size: " + chunk.length +
                                           " bytes. Reduce RSA_CHUNK_SIZE_BYTES or check data.");
            }
            BigInteger encryptedInt = encryptInt(messageInt);
            // Сохраняем длину чанка вместе с числом: <len>:<encryptedInt>
            encryptedChunkStrings.add(chunk.length + ":" + encryptedInt.toString());
        }
        return String.join(CryptoConstants.RSA_CHUNK_DELIMITER, encryptedChunkStrings);
    }

    public String decryptTextChunked(String ciphertext) {
        if (this.n == null || this.d == null) {
            throw new IllegalStateException("Private key (n, d) is not set for decryption.");
        }
        String[] encryptedChunks = ciphertext.split(java.util.regex.Pattern.quote(CryptoConstants.RSA_CHUNK_DELIMITER));
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        for (String chunkStr : encryptedChunks) {
            if (chunkStr.isEmpty()) continue;
            // Новый формат: <len>:<encryptedInt>
            int colonIdx = chunkStr.indexOf(":");
            if (colonIdx == -1) throw new RuntimeException("Invalid chunk format: missing length prefix");
            int chunkLen = Integer.parseInt(chunkStr.substring(0, colonIdx));
            BigInteger encryptedInt = new BigInteger(chunkStr.substring(colonIdx + 1));
            BigInteger decryptedInt = decryptInt(encryptedInt);
            byte[] decryptedBytes = decryptedInt.toByteArray();
            // Восстанавливаем массив нужной длины (с ведущими нулями, если нужно)
            byte[] chunkBytes = new byte[chunkLen];
            int copyStart = decryptedBytes.length > chunkLen ? decryptedBytes.length - chunkLen : 0;
            int copyLen = Math.min(decryptedBytes.length, chunkLen);
            System.arraycopy(decryptedBytes, copyStart, chunkBytes, chunkLen - copyLen, copyLen);
            baos.write(chunkBytes, 0, chunkBytes.length);
        }
        return new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }
} 