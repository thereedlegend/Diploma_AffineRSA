package com.ryumessenger.security;

// import java.util.Base64; // Действительно не используется
// import java.util.HashMap; // Действительно не используется
// import java.util.Map; // Действительно не используется

import java.util.logging.Logger;
import org.json.JSONObject;

/**
 * Класс для безопасного форматирования сообщений с использованием улучшенного аффинного шифра
 */
public class SecureMessageFormatter {
    private static final Logger LOG = Logger.getLogger(SecureMessageFormatter.class.getName());
    
    private final KeyManagerAdapter keyManager;
    
    public SecureMessageFormatter(KeyManagerAdapter keyManager) {
        this.keyManager = keyManager;
    }
    
    /**
     * Формирует защищенное сообщение с использованием улучшенного аффинного шифра и RSA
     */
    public String formatSecureMessage(String messageText) {
        try {
            // 1. Получаем DH общий секрет (или используем запасной вариант)
            byte[] seed = keyManager.getDHSharedSecret();
            if (seed == null) {
                LOG.warning("DH-секрет не установлен. Используем запасной вариант.");
                seed = "fallback_secure_message_seed".getBytes();
            }
            
            // 2. Создаем аффинный шифр с использованием seed
            SimpleAffineCipher cipher = new SimpleAffineCipher(seed);
            
            // 3. Шифруем текст сообщения
            String encryptedText = cipher.encrypt(messageText);
            
            // 4. Получаем параметры шифрования
            SimpleAffineCipher.AffineCipherParams params = cipher.getParams(messageText.length());
            
            // 5. Создаем JSON-payload с зашифрованным текстом и параметрами
            JSONObject payload = new JSONObject();
            payload.put("cipher_text", encryptedText);
            payload.put("affine_params", params.toJSON());
            payload.put("lang", cipher.getLanguage());
            
            // 6. Шифруем JSON-payload с помощью RSA ключа сервера
            com.ryumessenger.crypto.EncryptionService encryptionService = 
                new com.ryumessenger.crypto.EncryptionService(keyManager.getLegacyKeyManager());
            
            String encryptedPayload = encryptionService.encryptForServer(payload.toString());
            
            // 7. Возвращаем зашифрованное сообщение
            return encryptedPayload;
            
        } catch (Exception e) {
            LOG.severe("Ошибка при форматировании защищенного сообщения: " + e.getMessage());
            throw new RuntimeException("Не удалось сформировать защищенное сообщение", e);
        }
    }
    
    /**
     * Расшифровывает защищенное сообщение
     */
    public String decryptSecureMessage(String encryptedPayload) {
        try {
            // 1. Расшифровываем RSA-слой с помощью приватного ключа клиента
            com.ryumessenger.crypto.EncryptionService encryptionService = 
                new com.ryumessenger.crypto.EncryptionService(keyManager.getLegacyKeyManager());
            
            String decryptedPayload = encryptionService.decryptFromServer(encryptedPayload);
            
            // 2. Парсим JSON-payload
            JSONObject payload = new JSONObject(decryptedPayload);
            
            // 3. Извлекаем параметры
            String encryptedText = payload.getString("cipher_text");
            String lang = payload.getString("lang");
            
            // 4. Получаем DH общий секрет (или используем запасной вариант)
            byte[] seed = keyManager.getDHSharedSecret();
            if (seed == null) {
                LOG.warning("DH-секрет не установлен. Используем запасной вариант.");
                seed = "fallback_secure_message_seed".getBytes();
            }
            
            // 5. Создаем аффинный шифр с использованием seed и параметров из payload
            SimpleAffineCipher cipher = new SimpleAffineCipher(seed);
            
            // Устанавливаем параметры из payload
            cipher.setLanguage(lang);
            
            // 6. Расшифровываем текст
            String decryptedText = cipher.decrypt(encryptedText);
            
            return decryptedText;
            
        } catch (Exception e) {
            LOG.severe("Ошибка при расшифровке защищенного сообщения: " + e.getMessage());
            throw new RuntimeException("Не удалось расшифровать защищенное сообщение", e);
        }
    }
    
    /**
     * Форматирует параметры запроса для поиска пользователей
     */
    public String formatUserSearchQuery(String query) {
        try {
            // Создаем JSON с запросом
            JSONObject queryJson = new JSONObject();
            queryJson.put("tag_query", query);
            
            // Шифруем RSA-ключом сервера
            com.ryumessenger.crypto.EncryptionService encryptionService = 
                new com.ryumessenger.crypto.EncryptionService(keyManager.getLegacyKeyManager());
            
            String encryptedQuery = encryptionService.encryptForServer(queryJson.toString());
            
            return encryptedQuery;
            
        } catch (Exception e) {
            LOG.severe("Ошибка при форматировании запроса поиска: " + e.getMessage());
            throw new RuntimeException("Не удалось сформировать запрос поиска", e);
        }
    }
    
    /**
     * Форматирует зашифрованный пароль для регистрации или изменения пароля
     */
    public String formatSecurePassword(String password) {
        try {
            // 1. Получаем DH общий секрет (или используем запасной вариант)
            byte[] seed = keyManager.getDHSharedSecret();
            if (seed == null) {
                LOG.warning("DH-секрет не установлен. Используем запасной вариант.");
                seed = "fallback_secure_password_seed".getBytes();
            }
            
            // 2. Создаем аффинный шифр с использованием seed
            SimpleAffineCipher cipher = new SimpleAffineCipher(seed);
            
            // 3. Шифруем пароль
            String encryptedPassword = cipher.encrypt(password);
            
            // 4. Получаем параметры шифрования
            SimpleAffineCipher.AffineCipherParams params = cipher.getParams(password.length());
            
            // 5. Создаем JSON-payload с зашифрованным паролем и параметрами
            JSONObject payload = new JSONObject();
            payload.put("cipher_text", encryptedPassword);
            payload.put("affine_params", params.toJSON());
            payload.put("lang", cipher.getLanguage());
            
            // 6. Шифруем JSON-payload с помощью RSA ключа сервера
            com.ryumessenger.crypto.EncryptionService encryptionService = 
                new com.ryumessenger.crypto.EncryptionService(keyManager.getLegacyKeyManager());
            
            String encryptedPayload = encryptionService.encryptForServer(payload.toString());
            
            return encryptedPayload;
            
        } catch (Exception e) {
            LOG.severe("Ошибка при форматировании защищенного пароля: " + e.getMessage());
            throw new RuntimeException("Не удалось сформировать защищенный пароль", e);
        }
    }
} 