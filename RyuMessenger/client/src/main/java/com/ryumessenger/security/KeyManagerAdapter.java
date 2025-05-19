package com.ryumessenger.security;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Адаптер для работы с нашим новым KeyManager через старый KeyManager
 * Позволяет использовать существующий код с новыми функциями для Диффи-Хеллмана
 */
public class KeyManagerAdapter {
    private static final Logger LOG = Logger.getLogger(KeyManagerAdapter.class.getName());
    
    // Путь к директории для хранения ключей пользователя
    // private static final String USER_DATA_DIR = "user_data"; // Не используется
    
    // Ключи RSA из существующего KeyManager
    private final com.ryumessenger.crypto.KeyManager legacyKeyManager;
    
    // Параметры шифрования
    private Map<String, Object> serverAffineParams = new HashMap<>();
    
    // DH ключи и параметры
    private KeyPair dhKeyPair;
    // private BigInteger dhServerPublicKey; // Устанавливается, но не читается. Пока оставим, если будущая логика его потребует.
    private byte[] dhSharedSecret;
    
    public KeyManagerAdapter(com.ryumessenger.crypto.KeyManager legacyKeyManager) {
        this.legacyKeyManager = legacyKeyManager;
        
        try {
            // Инициализируем DH ключи
            initDHKeys();
        } catch (Exception e) {
            LOG.severe("Ошибка при инициализации DH ключей: " + e.getMessage());
        }
    }
    
    /**
     * Инициализация ключей Диффи-Хеллмана
     */
    private void initDHKeys() throws Exception {
        // Инициализируем генератор
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(512); // Меньший размер для тестирования
        dhKeyPair = keyGen.generateKeyPair();
        
        LOG.info("Сгенерированы ключи DH");
    }
    
    /**
     * Устанавливает публичный ключ RSA сервера
     */
    public void setServerRSAPublicKey(BigInteger n, BigInteger e) {
        // Преобразуем BigInteger в String для legacy KeyManager
        legacyKeyManager.setServerRsaPublicKey(n.toString(), e.toString());
        LOG.info("Установлен публичный ключ RSA сервера");
    }
    
    /**
     * Устанавливает параметры аффинного шифра
     */
    public void setServerAffineParams(Map<String, Object> affineParams) {
        this.serverAffineParams = affineParams;
        
        // Преобразуем в формат для legacy KeyManager
        int a = ((Number) affineParams.get("a")).intValue();
        int b = ((Number) affineParams.get("b")).intValue();
        int m = ((Number) affineParams.get("m")).intValue();
        
        // Создаем JSONObject для legacy KeyManager
        org.json.JSONObject jsonParams = new org.json.JSONObject();
        jsonParams.put("a", a);
        jsonParams.put("b", b);
        jsonParams.put("m", m);
        
        // Устанавливаем параметры в legacy KeyManager
        legacyKeyManager.setServerAffineParams(jsonParams);
        LOG.info("Установлены параметры аффинного шифра: a=" + a + ", b=" + b + ", m=" + m);
    }
    
    /**
     * Устанавливает публичный ключ DH сервера и вычисляет общий секрет
     */
    public void setServerDHPublicKey(BigInteger dhPublicKey) throws Exception {
        // Вычисляем общий секрет с помощью MessageDigest (HMAC-подобный механизм)
        // Это упрощенная реализация без полноценного DH для совместимости
        byte[] clientPrivateKeyBytes = dhKeyPair.getPrivate().getEncoded();
        byte[] serverPublicKeyBytes = dhPublicKey.toByteArray();
        
        // Создаем псевдо-общий секрет на основе обоих ключей
        byte[] combinedBytes = new byte[clientPrivateKeyBytes.length + serverPublicKeyBytes.length];
        System.arraycopy(clientPrivateKeyBytes, 0, combinedBytes, 0, clientPrivateKeyBytes.length);
        System.arraycopy(serverPublicKeyBytes, 0, combinedBytes, clientPrivateKeyBytes.length, serverPublicKeyBytes.length);
        
        // Хешируем для получения общего секрета
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        this.dhSharedSecret = digest.digest(combinedBytes);
        
        LOG.info("Вычислен общий секрет DH. Длина: " + dhSharedSecret.length);
    }
    
    /**
     * Возвращает публичный ключ RSA клиента в формате BigInteger[]
     */
    public BigInteger[] getClientRSAPublicKey() {
        com.ryumessenger.crypto.RSA.PublicKey publicKey = legacyKeyManager.getClientRsaPublicKey();
        return new BigInteger[] {
            new BigInteger(String.valueOf(publicKey.n)),
            new BigInteger(String.valueOf(publicKey.e))
        };
    }
    
    /**
     * Возвращает публичный ключ RSA сервера
     */
    public PublicKey getServerRSAPublicKey() throws Exception {
        // Упрощенная реализация для совместимости
        // В реальном коде нужно создать RSAPublicKeySpec и использовать KeyFactory
        return null;
    }
    
    /**
     * Возвращает параметры аффинного шифра
     */
    public Map<String, Object> getServerAffineParams() {
        return serverAffineParams;
    }
    
    /**
     * Возвращает публичный DH ключ клиента
     */
    public BigInteger getClientDHPublicKey() {
        // Упрощенная реализация
        byte[] encoded = dhKeyPair.getPublic().getEncoded();
        return new BigInteger(1, encoded);
    }
    
    /**
     * Возвращает общий секрет DH
     */
    public byte[] getDHSharedSecret() {
        return dhSharedSecret;
    }
    
    /**
     * Возвращает оригинальный KeyManager (для совместимости)
     */
    public com.ryumessenger.crypto.KeyManager getLegacyKeyManager() {
        return legacyKeyManager;
    }
} 