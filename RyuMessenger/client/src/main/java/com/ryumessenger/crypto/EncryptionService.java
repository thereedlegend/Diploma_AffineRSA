package com.ryumessenger.crypto;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;

import com.ryumessenger.ui.CryptoLogWindow;

public class EncryptionService {
    private final KeyManager clientKeyManager;
    private RSA.PublicKey serverRsaPublicKey; // Будет получен от сервера
    private RSA clientRsaInstance;
    
    // Кэш для предотвращения повторного дешифрования одних и тех же данных
    private final Map<String, String> decryptionCache = new HashMap<>();
    private static final int MAX_CACHE_SIZE = 50;

    public EncryptionService(KeyManager clientKeyManager) {
        this.clientKeyManager = clientKeyManager;
        this.clientRsaInstance = new RSA();
        if (this.clientKeyManager.getClientRsaKeyPair() != null) {
            this.clientRsaInstance.setKeyPair(
                this.clientKeyManager.getClientRsaPublicKey(),
                this.clientKeyManager.getClientRsaPrivateKey()
            );
        }
    }

    public void setServerRsaPublicKey(BigInteger n, BigInteger e) {
        this.serverRsaPublicKey = new RSA.PublicKey(n, e);
    }

    public RSA.PublicKey getServerRsaPublicKey() {
        return serverRsaPublicKey;
    }

    public KeyManager getClientKeyManager() {
        return clientKeyManager;
    }

    /**
     * Шифрует данные для отправки на сервер.
     * На вход подаётся только исходный текст сообщения (String),
     * не сериализованный и не зашифрованный.
     */
    public String encryptForServer(String plaintext) {
        CryptoLogWindow.logOperation("Начинаем шифрование", "Исходный текст: " + plaintext);
        
        if (serverRsaPublicKey == null) {
            System.err.println("Публичный RSA-ключ сервера не установлен. Невозможно зашифровать для сервера.");
            CryptoLogWindow.logOperation("Ошибка", "Публичный RSA-ключ сервера не установлен");
            return null;
        }
        if (clientKeyManager.getClientRsaKeyPair() == null) {
            System.err.println("RSA-ключи клиента недоступны. Операция невозможна.");
            CryptoLogWindow.logOperation("Ошибка", "RSA-ключи клиента недоступны");
            return null;
        }
        
        // Генерируем случайные ключи для афинного шифрования с ASCII
        // Используем 16 разных коэффициентов a и b для каждой позиции
        int keyLength = 16;
        int[] bValues = new int[keyLength];
        int[] aValues = new int[keyLength];
        int[] validAValues = AffineCipher.getValidAValues();
        
        CryptoLogWindow.logOperation("Генерация ключей для афинного шифрования", 
            "Создаем массивы из " + keyLength + " коэффициентов a и b");
        
        // Заполняем массивы случайными значениями
        java.util.Random random = new java.util.Random();
        for (int i = 0; i < keyLength; i++) {
            // Для a выбираем из допустимых значений (взаимно простых с 256)
            int index = random.nextInt(validAValues.length);
            aValues[i] = validAValues[index];
            
            // Для b можно использовать любое значение от 0 до 255
            bValues[i] = random.nextInt(256);
            
            CryptoLogWindow.logOperation("Генерация ключей для позиции " + i, 
                "a=" + aValues[i] + " (взаимно простой с 256), b=" + bValues[i]);
        }
        
        // Создаем афинный шифр с разными коэффициентами a и b для разных позиций
        AffineCipher affineCipher = new AffineCipher(aValues, bValues);
        
        CryptoLogWindow.logOperation("Шифруем текст афинным шифром", 
            "Используем ASCII с модулем m=256");
        
        String affineCipherText = affineCipher.encrypt(plaintext);
        CryptoLogWindow.logOperation("Результат афинного шифрования", affineCipherText);
        
        JSONObject payload = new JSONObject();
        try {
            // Добавляем зашифрованный текст
            payload.put("cipher_text", affineCipherText);
            
            // Добавляем массив коэффициентов a
            JSONArray aValuesArray = new JSONArray();
            for (int a : aValues) {
                aValuesArray.put(a);
            }
            
            // Добавляем массив коэффициентов b
            JSONArray bValuesArray = new JSONArray();
            for (int b : bValues) {
                bValuesArray.put(b);
            }
            
            // Создаем объект с параметрами афинного шифра
            JSONObject affineParams = new JSONObject();
            affineParams.put("a_values", aValuesArray);
            affineParams.put("b_values", bValuesArray);
            affineParams.put("m", 256); // ASCII
            
            // Добавляем параметры и модуль шифрования
            payload.put("affine_params", affineParams);
            payload.put("cipher_type", "ascii_affine_multi_a_b");
            
            CryptoLogWindow.logOperation("Создаем JSON-пакет", payload.toString());
        } catch (JSONException e) {
            System.err.println("Ошибка при создании JSON для шифрования на сервер: " + e.getMessage());
            CryptoLogWindow.logOperation("Ошибка", "Ошибка при создании JSON: " + e.getMessage());
            return null;
        }
        
        RSA serverRsaEncrypter = new RSA();
        serverRsaEncrypter.setPublicKey(serverRsaPublicKey.n, serverRsaPublicKey.e);
        
        CryptoLogWindow.logOperation("Шифруем открытым ключом RSA сервера", 
            "n=" + serverRsaPublicKey.n.toString().substring(0, 20) + "..., e=" + serverRsaPublicKey.e);
        
        try {
            String encrypted = serverRsaEncrypter.encryptTextChunked(payload.toString());
            CryptoLogWindow.logOperation("Результат RSA шифрования", 
                encrypted.substring(0, Math.min(50, encrypted.length())) + "...");
            return encrypted;
        } catch (Exception e) {
            System.err.println("Ошибка RSA-шифрования данных для сервера: " + e.getMessage());
            e.printStackTrace();
            CryptoLogWindow.logOperation("Ошибка", "Ошибка RSA-шифрования: " + e.getMessage());
            return null;
        }
    }

    /**
     * Расшифровывает данные, полученные от сервера.
     * Ожидается, что данные были зашифрованы по схеме: Аффинный_сервера -> RSA_клиента.
     * 1. Расшифровывает входящую строку приватным RSA ключом КЛИЕНТА.
     * 2. Парсит полученный JSON: {cipher_text, affine_params (сервера), cipher_type}
     * 3. Расшифровывает cipher_text Аффинным шифром, используя параметры сервера.
     * @param rsaEncryptedPayload Строка, зашифрованная RSA от сервера.
     * @return Расшифрованный исходный текст, или null при ошибке.
     */
    public String decryptFromServer(String rsaEncryptedPayload) {
        // Добавляем "отпечаток" зашифрованной строки для логирования и отладки
        String payloadHash = String.valueOf(rsaEncryptedPayload.hashCode());
        
        // Проверяем кэш расшифровки
        if (decryptionCache.containsKey(payloadHash)) {
            CryptoLogWindow.logOperation("Используем кэш расшифровки", "Хэш: " + payloadHash);
            return decryptionCache.get(payloadHash);
        }
        
        CryptoLogWindow.logOperation("Начинаем расшифровку", "Хэш зашифрованных данных: " + payloadHash);
        
        // Проверка входных данных
        if (rsaEncryptedPayload == null || rsaEncryptedPayload.isEmpty()) {
            CryptoLogWindow.logOperation("Ошибка", "Получены пустые зашифрованные данные");
            return null;
        }
        
        if (clientKeyManager.getClientRsaKeyPair() == null) {
            System.err.println("RSA-ключи клиента недоступны. Невозможно расшифровать данные от сервера.");
            CryptoLogWindow.logOperation("Ошибка", "RSA-ключи клиента недоступны");
            return null;
        }
        
        String decryptedPayloadJson;
        try {
            // Используем clientRsaInstance, у которого уже установлены ключи клиента
            CryptoLogWindow.logOperation("Расшифровываем приватным RSA ключом клиента", "");
            decryptedPayloadJson = this.clientRsaInstance.decryptTextChunked(rsaEncryptedPayload);
            CryptoLogWindow.logOperation("Результат RSA расшифровки", decryptedPayloadJson);
        } catch (Exception e) {
            System.err.println("Error RSA decrypting payload from server: " + e.getMessage());
            e.printStackTrace();
            CryptoLogWindow.logOperation("Ошибка", "Ошибка RSA расшифровки: " + e.getMessage());
            return null;
        }

        try {
            JSONObject payload = new JSONObject(decryptedPayloadJson);
            String cipherText = payload.getString("cipher_text");
            JSONObject affineParamsJson = payload.getJSONObject("affine_params");
            String cipherType = payload.optString("cipher_type", "default");

            CryptoLogWindow.logOperation("Извлечен тип шифра", cipherType);
            
            // Проверяем тип шифрования
            if ("ascii_affine_multi_a_b".equals(cipherType)) {
                // Для нового типа шифрования с разными a и b для разных позиций
                return decryptAsciiAffineMultiAB(cipherText, affineParamsJson, payloadHash);
            } else if ("ascii_affine_multi_a".equals(cipherType)) {
                // Для типа шифрования с разными a для разных позиций
                return decryptAsciiAffineMultiA(cipherText, affineParamsJson, payloadHash);
            } else {
                // Для обратной совместимости (старый формат с языками RU/EN)
                return decryptLegacyAffine(cipherText, affineParamsJson, payload.getString("lang"), payloadHash);
            }
        } catch (JSONException e) {
            System.err.println("Ошибка при разборе JSON-данных от сервера: " + e.getMessage());
            System.err.println("Полученная JSON-строка: " + decryptedPayloadJson.substring(0, Math.min(decryptedPayloadJson.length(), 200)));
            CryptoLogWindow.logOperation("Ошибка", "Ошибка при разборе JSON: " + e.getMessage());
            return null;
        } catch (Exception e) {
            System.err.println("Ошибка при расшифровке данных от сервера: " + e.getMessage());
            e.printStackTrace();
            CryptoLogWindow.logOperation("Ошибка", "Ошибка расшифровки: " + e.getMessage());
            return null;
        }
    }

    /**
     * Расшифровывает данные с использованием афинного шифра с ASCII и разными коэффициентами a
     */
    private String decryptAsciiAffineMultiA(String cipherText, JSONObject affineParamsJson, String payloadHash) {
        try {
            // Получаем список коэффициентов a
            JSONArray aValuesArray = affineParamsJson.getJSONArray("a_values");
            int[] aValues = new int[aValuesArray.length()];
            for (int i = 0; i < aValuesArray.length(); i++) {
                aValues[i] = aValuesArray.getInt(i);
            }
            
            int[] bValues = new int[aValues.length];
            JSONArray bValuesArray = affineParamsJson.getJSONArray("b_values");
            for (int i = 0; i < bValuesArray.length(); i++) {
                bValues[i] = bValuesArray.getInt(i);
            }
            
            CryptoLogWindow.logOperation("Извлечены параметры для ASCII Affine Multi-A", 
                "Количество коэффициентов a: " + aValues.length + ", количество коэффициентов b: " + bValues.length);
            
            // Создаем афинный шифр с извлеченными параметрами
            AffineCipher affineDecrypter = new AffineCipher(aValues, bValues);
            
            // Расшифровываем
            String decryptedText = affineDecrypter.decrypt(cipherText);
            CryptoLogWindow.logOperation("Результат расшифровки ASCII Affine Multi-A", decryptedText);
            
            // Добавляем результат в кэш
            addToDecryptionCache(payloadHash, decryptedText);
            
            return decryptedText;
        } catch (Exception e) {
            CryptoLogWindow.logOperation("Ошибка расшифровки ASCII Affine Multi-A", e.getMessage());
            throw e; // Пробрасываем исключение дальше
        }
    }

    /**
     * Расшифровывает данные с использованием старого формата афинного шифра (для обратной совместимости)
     */
    private String decryptLegacyAffine(String cipherText, JSONObject affineParamsJson, String lang, String payloadHash) {
        try {
            int serverA = affineParamsJson.getInt("a");
            int serverB = affineParamsJson.getInt("b");
            
            CryptoLogWindow.logOperation("Извлечены параметры Legacy Affine", 
                "a=" + serverA + ", b=" + serverB + ", язык=" + lang);
            
            // Создаем обратно-совместимый экземпляр AffineCipher
            AffineCipher legacyDecrypter = new AffineCipher(serverA, serverB);
            
            String decryptedText = legacyDecrypter.decrypt(cipherText);
            CryptoLogWindow.logOperation("Результат расшифровки Legacy Affine", decryptedText);
            
            // Добавляем результат в кэш
            addToDecryptionCache(payloadHash, decryptedText);
            
            return decryptedText;
        } catch (Exception e) {
            CryptoLogWindow.logOperation("Ошибка расшифровки Legacy Affine", e.getMessage());
            throw e; // Пробрасываем исключение дальше
        }
    }

    /**
     * Расшифровывает данные с использованием афинного шифра с ASCII, разными коэффициентами a и разными b
     */
    private String decryptAsciiAffineMultiAB(String cipherText, JSONObject affineParamsJson, String payloadHash) {
        try {
            // Получаем список коэффициентов a
            JSONArray aValuesArray = affineParamsJson.getJSONArray("a_values");
            int[] aValues = new int[aValuesArray.length()];
            for (int i = 0; i < aValuesArray.length(); i++) {
                aValues[i] = aValuesArray.getInt(i);
            }
            
            // Получаем список коэффициентов b
            JSONArray bValuesArray = affineParamsJson.getJSONArray("b_values");
            int[] bValues = new int[bValuesArray.length()];
            for (int i = 0; i < bValuesArray.length(); i++) {
                bValues[i] = bValuesArray.getInt(i);
            }
            
            CryptoLogWindow.logOperation("Извлечены параметры для ASCII Affine Multi-A-B", 
                "Количество коэффициентов a: " + aValues.length + ", количество коэффициентов b: " + bValues.length);
            
            // Создаем афинный шифр с извлеченными параметрами
            AffineCipher affineDecrypter = new AffineCipher(aValues, bValues);
            
            // Расшифровываем
            String decryptedText = affineDecrypter.decrypt(cipherText);
            CryptoLogWindow.logOperation("Результат расшифровки ASCII Affine Multi-A-B", decryptedText);
            
            // Добавляем результат в кэш
            addToDecryptionCache(payloadHash, decryptedText);
            
            return decryptedText;
        } catch (Exception e) {
            CryptoLogWindow.logOperation("Ошибка расшифровки ASCII Affine Multi-A-B", e.getMessage());
            throw e; // Пробрасываем исключение дальше
        }
    }

    /**
     * Добавляет результат расшифровки в кэш
     */
    private void addToDecryptionCache(String payloadHash, String decryptedText) {
        // Если кэш слишком большой, удаляем случайную запись
        if (decryptionCache.size() >= MAX_CACHE_SIZE) {
            String keyToRemove = decryptionCache.keySet().iterator().next();
            decryptionCache.remove(keyToRemove);
        }
        decryptionCache.put(payloadHash, decryptedText);
    }

    /**
     * Шифрует JSON-строку только RSA-ключом сервера (без аффинного слоя).
     */
    public String encryptJsonForServer(String json) {
        CryptoLogWindow.logOperation("Шифруем JSON для сервера", "JSON: " + json);
        
        refreshServerKeysFromKeyManager();
        if (serverRsaPublicKey == null) {
            System.err.println("Публичный RSA-ключ сервера не установлен. Невозможно зашифровать для сервера.");
            CryptoLogWindow.logOperation("Ошибка", "Публичный RSA-ключ сервера не установлен");
            return null;
        }
        RSA serverRsaEncrypter = new RSA();
        serverRsaEncrypter.setPublicKey(serverRsaPublicKey.n, serverRsaPublicKey.e);
        
        CryptoLogWindow.logOperation("Шифруем открытым ключом RSA сервера", "");
        
        try {
            String encrypted = serverRsaEncrypter.encryptTextChunked(json);
            CryptoLogWindow.logOperation("Результат RSA шифрования", encrypted.substring(0, Math.min(50, encrypted.length())) + "...");
            return encrypted;
        } catch (Exception e) {
            e.printStackTrace();
            CryptoLogWindow.logOperation("Ошибка", "Ошибка RSA-шифрования: " + e.getMessage());
            return null;
        }
    }

    private void refreshServerKeysFromKeyManager() {
        if (this.clientKeyManager != null) {
            this.serverRsaPublicKey = this.clientKeyManager.getServerRsaPublicKey();
            // this.serverAffineParamsJson = this.clientKeyManager.getServerAffineParamsJson();
        }
    }

    private String encryptJsonWithServerKey(String jsonPayload) {
        refreshServerKeysFromKeyManager(); // Обновляем ключи сервера на случай, если они были получены после инициализации сервиса
        if (this.serverRsaPublicKey == null) {
            System.err.println("EncryptionService: Публичный RSA-ключ сервера не установлен. Невозможно зашифровать.");
            return null;
        }
        RSA serverRsaEncrypter = new RSA();
        serverRsaEncrypter.setPublicKey(this.serverRsaPublicKey.n, this.serverRsaPublicKey.e);
        try {
            return serverRsaEncrypter.encryptTextChunked(jsonPayload);
        } catch (Exception e) {
            System.err.println("EncryptionService: Ошибка RSA шифрования для сервера: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public String encryptLoginPayloadForServer(String username, String password, RSA.PublicKey clientRsaPublicKey) {
        // clientRsaPublicKey здесь не используется для шифрования самого payload для сервера,
        // но может быть полезен, если сервер захочет его проверить или сохранить.
        // В данном случае, для login, он не критичен для помещения ВНУТРЬ шифруемого JSON.

        if (password == null || password.isEmpty()) {
            System.err.println("EncryptionService: Пароль для логина пустой.");
            return null;
        }

        try {
            // Генерируем случайный ключ для афинного шифрования с ASCII
            int keyLength = 8; // Используем 8 разных коэффициентов a 
            int b = MathUtil.generateAffineB(256);
            int[] validAValues = AffineCipher.getValidAValues();
            
            // Создаем массив коэффициентов a
            int[] aValues = new int[keyLength];
            java.util.Random random = new java.util.Random();
            for (int i = 0; i < keyLength; i++) {
                int index = random.nextInt(validAValues.length);
                aValues[i] = validAValues[index];
            }
            
            // Создаем афинный шифр и шифруем пароль
            AffineCipher affineCipher = new AffineCipher(aValues, b);
            String encryptedPassword = affineCipher.encrypt(password);

            // Создаем JSON-пакет для шифрования
            JSONObject rsaPayload = new JSONObject();
            rsaPayload.put("cipher_text", encryptedPassword);
            
            // Добавляем информацию о ключах
            JSONArray aValuesArray = new JSONArray();
            for (int a : aValues) {
                aValuesArray.put(a);
            }
            
            JSONObject affineParams = new JSONObject();
            affineParams.put("a_values", aValuesArray);
            affineParams.put("b", b);
            affineParams.put("m", 256); // ASCII
            
            rsaPayload.put("affine_params", affineParams);
            rsaPayload.put("cipher_type", "ascii_affine_multi_a");
            
            // Шифруем RSA-ключом сервера
            return encryptJsonWithServerKey(rsaPayload.toString());
        } catch (JSONException e) {
            System.err.println("EncryptionService: Ошибка создания JSON для login payload: " + e.getMessage());
            return null;
        } catch (Exception e) {
            System.err.println("EncryptionService: Общая ошибка при создании login payload: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public String encryptRegistrationPayloadForServer(String username, String password, String displayName, String tag, RSA.PublicKey clientRsaPublicKey) {
        if (clientRsaPublicKey == null) { // Хотя для регистрации n и e передаются отдельно, payload сам по себе не требует их внутри шифра
            System.err.println("EncryptionService: RSA публичный ключ клиента (для информации) не предоставлен для registration payload.");
            // Не критично для самого шифрования payload, но хорошо бы иметь для консистентности если другие payload его требуют
        }
        try {
            JSONObject payload = new JSONObject();
            payload.put("username", username);
            payload.put("password", password); // Сервер ожидает 'password'
            payload.put("display_name", displayName);
            payload.put("tag", tag);
            // n и e ключа клиента передаются серверу ОТДЕЛЬНО, не внутри этого зашифрованного payload
            return encryptJsonWithServerKey(payload.toString());
        } catch (JSONException e) {
            System.err.println("EncryptionService: Ошибка создания JSON для registration payload: " + e.getMessage());
            return null;
        }
    }

    public String encryptChangePasswordPayloadForServer(String userId, String currentPassword, String newPassword) {
         // userId нужен, чтобы сервер знал, для какого пользователя менять пароль,
         // если это не определяется из сессии/токена на сервере явно для этого запроса.
         // Серверный /user/update ожидает user_id внутри 'encrypted_update_payload'.
        try {
            JSONObject payload = new JSONObject();
            payload.put("user_id", userId); // Предполагаем, что серверу нужен ID пользователя
            payload.put("current_password", currentPassword);
            payload.put("new_password", newPassword);
            return encryptJsonWithServerKey(payload.toString());
        } catch (JSONException e) {
            System.err.println("EncryptionService: Ошибка создания JSON для change password payload: " + e.getMessage());
            return null;
        }
    }

    public String encryptTagSearchPayloadForServer(String tagQuery) {
        if (tagQuery == null || tagQuery.isEmpty()) {
            System.err.println("EncryptionService: Тег для поиска пустой.");
            return null;
        }
        try {
            // Убираем потенциальный @ в начале тега, если он есть
            if (tagQuery.startsWith("@")) {
                tagQuery = tagQuery.substring(1);
            }
            
            // Используем ASCII для передачи тега 
            JSONObject rsaPayload = new JSONObject();
            rsaPayload.put("tag_query", tagQuery);
            rsaPayload.put("cipher_type", "plain_ascii"); // Указываем, что тег передается в явном виде
            
            CryptoLogWindow.logOperation("Создан JSON-пакет для поиска тега", rsaPayload.toString());
            
            return encryptJsonWithServerKey(rsaPayload.toString());
        } catch (JSONException e) {
            System.err.println("EncryptionService: Ошибка создания JSON для tag search payload: " + e.getMessage());
            return null;
        } catch (Exception e) {
            System.err.println("EncryptionService: Общая ошибка при создании tag search payload: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public String encryptUserIdForServerPayload(String userId) {
        if (userId == null || userId.isEmpty()) {
            System.err.println("EncryptionService: User ID для шифрования пустой.");
            return null;
        }
        try {
            // Генерируем ключ для шифрования ID
            int keyLength = 4; // Используем 4 разных коэффициента a
            int b = MathUtil.generateAffineB(256);
            int[] validAValues = AffineCipher.getValidAValues();
            
            // Создаем массив коэффициентов a
            int[] aValues = new int[keyLength];
            java.util.Random random = new java.util.Random();
            for (int i = 0; i < keyLength; i++) {
                int index = random.nextInt(validAValues.length);
                aValues[i] = validAValues[index];
            }
            
            // Создаем афинный шифр и шифруем userId
            AffineCipher affineCipher = new AffineCipher(aValues, b);
            String encryptedUserId = affineCipher.encrypt(userId);
            
            // Создаем JSON-пакет для шифрования
            JSONObject rsaPayload = new JSONObject();
            rsaPayload.put("cipher_text", encryptedUserId);
            
            // Добавляем информацию о ключах
            JSONArray aValuesArray = new JSONArray();
            for (int a : aValues) {
                aValuesArray.put(a);
            }
            
            JSONObject affineParams = new JSONObject();
            affineParams.put("a_values", aValuesArray);
            affineParams.put("b", b);
            affineParams.put("m", 256); // ASCII
            
            rsaPayload.put("affine_params", affineParams);
            rsaPayload.put("cipher_type", "ascii_affine_multi_a");
            
            // Шифруем RSA-ключом сервера
            return encryptJsonWithServerKey(rsaPayload.toString());
        } catch (JSONException e) {
            System.err.println("EncryptionService: Ошибка создания JSON для user ID payload: " + e.getMessage());
            return null;
        } catch (Exception e) {
            System.err.println("EncryptionService: Общая ошибка при создании user ID payload: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Шифрует target_user_id для отправки на сервер (сначала Аффинный, потом RSA).
     * Используется для эндпоинта /api/chats/find-or-create.
     * @param targetUserId ID целевого пользователя.
     * @return Зашифрованная строка (RSA(JSON(Affine))) или null при ошибке.
     */
    public String encryptTargetUserIdForServerPayload(String targetUserId) {
        if (targetUserId == null || targetUserId.isEmpty()) {
            System.err.println("EncryptionService: target_user_id для шифрования пустой.");
            return null;
        }

        try {
            // Генерируем ключ для шифрования ID
            int keyLength = 4; // Используем 4 разных коэффициента a
            int b = MathUtil.generateAffineB(256);
            int[] validAValues = AffineCipher.getValidAValues();
            
            // Создаем массив коэффициентов a
            int[] aValues = new int[keyLength];
            java.util.Random random = new java.util.Random();
            for (int i = 0; i < keyLength; i++) {
                int index = random.nextInt(validAValues.length);
                aValues[i] = validAValues[index];
            }
            
            // Создаем афинный шифр и шифруем targetUserId
            AffineCipher affineCipher = new AffineCipher(aValues, b);
            String encryptedTargetUserId = affineCipher.encrypt(targetUserId);
            
            // Создаем JSON-пакет для шифрования
            JSONObject rsaPayload = new JSONObject();
            rsaPayload.put("cipher_text", encryptedTargetUserId);
            
            // Добавляем информацию о ключах
            JSONArray aValuesArray = new JSONArray();
            for (int a : aValues) {
                aValuesArray.put(a);
            }
            
            JSONObject affineParams = new JSONObject();
            affineParams.put("a_values", aValuesArray);
            affineParams.put("b", b);
            affineParams.put("m", 256); // ASCII
            
            rsaPayload.put("affine_params", affineParams);
            rsaPayload.put("cipher_type", "ascii_affine_multi_a");
            
            // Шифруем RSA-ключом сервера
            return encryptJsonWithServerKey(rsaPayload.toString());
        } catch (JSONException e) {
            System.err.println("EncryptionService: Ошибка создания JSON для target_user_id payload: " + e.getMessage());
            return null;
        } catch (Exception e) {
            System.err.println("EncryptionService: Общая ошибка при создании target_user_id payload: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Подготавливает данные для обмена ключами по протоколу Диффи-Хеллмана
     * @return Зашифрованная JSON строка с публичным ключом DH
     */
    public String prepareDHKeyExchange() {
        // Получаем публичный ключ Диффи-Хеллмана
        BigInteger dhPublicKey = clientKeyManager.getDiffieHellmanPublicKey();
        
        try {
            // Формируем JSON объект с публичным ключом DH
            JSONObject payload = new JSONObject();
            payload.put("dh_public_key", dhPublicKey.toString());
            payload.put("protocol_version", "1.0");
            
            CryptoLogWindow.logOperation("Подготовка обмена ключами DH", 
                "Публичный ключ DH: " + dhPublicKey.toString().substring(0, 20) + "...");
            
            // Шифруем RSA-ключом сервера
            return encryptJsonWithServerKey(payload.toString());
        } catch (JSONException e) {
            System.err.println("Ошибка при создании JSON для обмена ключами DH: " + e.getMessage());
            CryptoLogWindow.logOperation("Ошибка", "Ошибка при создании JSON для DH: " + e.getMessage());
            return null;
        }
    }

    /**
     * Обрабатывает ответ сервера на запрос обмена ключами и создает общий афинный шифр
     * @param encryptedResponse Зашифрованный ответ сервера
     * @param keyLength Желаемая длина ключа (количество разных коэффициентов a и b)
     * @return Афинный шифр, созданный из общего секрета, или null при ошибке
     */
    public AffineCipher processDHKeyExchangeResponse(String encryptedResponse, int keyLength) {
        if (encryptedResponse == null || encryptedResponse.isEmpty()) {
            CryptoLogWindow.logOperation("Ошибка", "Получен пустой ответ от сервера");
            return null;
        }
        
        try {
            // Расшифровываем ответ приватным RSA ключом клиента
            String decryptedResponse = clientRsaInstance.decryptTextChunked(encryptedResponse);
            JSONObject responseJson = new JSONObject(decryptedResponse);
            
            // Получаем публичный ключ DH сервера
            BigInteger serverDHPublicKey = new BigInteger(responseJson.getString("server_dh_public_key"));
            
            CryptoLogWindow.logOperation("Получен публичный ключ DH сервера", 
                serverDHPublicKey.toString().substring(0, 20) + "...");
            
            // Вычисляем общий секрет и создаем афинный шифр
            AffineCipher sharedCipher = clientKeyManager.computeSharedAffineCipher(serverDHPublicKey, keyLength);
            
            // Логируем информацию о созданном шифре
            int[] aValues = sharedCipher.getAValues();
            int[] bValues = sharedCipher.getBValues();
            
            StringBuilder aValuesStr = new StringBuilder();
            for (int i = 0; i < Math.min(5, aValues.length); i++) {
                aValuesStr.append(aValues[i]).append(", ");
            }
            if (aValues.length > 5) {
                aValuesStr.append("... (всего ").append(aValues.length).append(" элементов)");
            }
            
            StringBuilder bValuesStr = new StringBuilder();
            for (int i = 0; i < Math.min(5, bValues.length); i++) {
                bValuesStr.append(bValues[i]).append(", ");
            }
            if (bValues.length > 5) {
                bValuesStr.append("... (всего ").append(bValues.length).append(" элементов)");
            }
            
            CryptoLogWindow.logOperation("Создан общий афинный шифр", 
                "Коэффициенты a: [" + aValuesStr + "], коэффициенты b: [" + bValuesStr + "]");
            
            return sharedCipher;
        } catch (Exception e) {
            System.err.println("Ошибка при обработке ответа обмена ключами DH: " + e.getMessage());
            CryptoLogWindow.logOperation("Ошибка", "Не удалось обработать ответ DH: " + e.getMessage());
            return null;
        }
    }

    /**
     * Шифрует сообщение с использованием шифра, полученного через Диффи-Хеллман
     * @param plaintext Исходный текст
     * @param dhAffineCipher Афинный шифр, созданный из общего секрета DH
     * @return Зашифрованная строка для отправки на сервер
     */
    public String encryptWithSharedKey(String plaintext, AffineCipher dhAffineCipher) {
        if (plaintext == null || dhAffineCipher == null) {
            CryptoLogWindow.logOperation("Ошибка", "Текст или шифр равны null");
            return null;
        }
        
        if (serverRsaPublicKey == null) {
            CryptoLogWindow.logOperation("Ошибка", "Публичный RSA-ключ сервера не установлен");
            return null;
        }
        
        CryptoLogWindow.logOperation("Начинаем шифрование общим ключом", "Исходный текст: " + plaintext);
        
        try {
            // Шифруем текст афинным шифром, созданным через DH
            String affineCipherText = dhAffineCipher.encrypt(plaintext);
            CryptoLogWindow.logOperation("Результат афинного шифрования", 
                affineCipherText.substring(0, Math.min(50, affineCipherText.length())) + 
                (affineCipherText.length() > 50 ? "..." : ""));
            
            // Создаем JSON-пакет с зашифрованным текстом
            JSONObject payload = new JSONObject();
            payload.put("cipher_text", affineCipherText);
            payload.put("cipher_type", "dh_shared_key");
            
            // Шифруем JSON-пакет публичным RSA ключом сервера
            RSA serverRsaEncrypter = new RSA();
            serverRsaEncrypter.setPublicKey(serverRsaPublicKey.n, serverRsaPublicKey.e);
            
            String encrypted = serverRsaEncrypter.encryptTextChunked(payload.toString());
            CryptoLogWindow.logOperation("Результат RSA шифрования", 
                encrypted.substring(0, Math.min(50, encrypted.length())) + "...");
            
            return encrypted;
        } catch (Exception e) {
            System.err.println("Ошибка при шифровании с общим ключом: " + e.getMessage());
            CryptoLogWindow.logOperation("Ошибка", "Ошибка шифрования с общим ключом: " + e.getMessage());
            return null;
        }
    }

    /**
     * Шифрует общий секрет Диффи-Хеллмана публичным ключом RSA получателя
     * для безопасной передачи между отправителем и получателем.
     * 
     * @param sharedSecret Общий секрет для шифрования
     * @param recipientPublicKey Публичный ключ RSA получателя
     * @return Зашифрованная строка с общим секретом или null при ошибке
     */
    public String encryptSharedSecret(BigInteger sharedSecret, RSA.PublicKey recipientPublicKey) {
        if (sharedSecret == null || recipientPublicKey == null) {
            CryptoLogWindow.logOperation("Ошибка", "Не указан общий секрет или публичный ключ получателя");
            return null;
        }
        
        try {
            // Создаем объект для шифрования
            RSA rsaEncrypter = new RSA();
            rsaEncrypter.setPublicKey(recipientPublicKey.n, recipientPublicKey.e);
            
            // Создаем JSON с данными общего секрета
            JSONObject secretPayload = new JSONObject();
            secretPayload.put("shared_secret", sharedSecret.toString());
            secretPayload.put("timestamp", System.currentTimeMillis());
            secretPayload.put("sender_id", "user_" + clientKeyManager.getClientRsaPublicKey().n.toString().substring(0, 8));
            
            CryptoLogWindow.logOperation("Шифрование общего секрета", 
                "Шифруем общий секрет публичным ключом RSA получателя");
            
            // Шифруем JSON с данными общего секрета
            String encryptedSecret = rsaEncrypter.encryptTextChunked(secretPayload.toString());
            
            CryptoLogWindow.logOperation("Общий секрет зашифрован", 
                "Размер зашифрованных данных: " + encryptedSecret.length() + " символов");
            
            return encryptedSecret;
        } catch (Exception e) {
            System.err.println("Ошибка при шифровании общего секрета: " + e.getMessage());
            CryptoLogWindow.logOperation("Ошибка", "Не удалось зашифровать общий секрет: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Расшифровывает полученный общий секрет Диффи-Хеллмана, зашифрованный 
     * публичным ключом RSA получателя.
     * 
     * @param encryptedSecret Зашифрованный общий секрет
     * @return Расшифрованный общий секрет или null при ошибке
     */
    public BigInteger decryptSharedSecret(String encryptedSecret) {
        if (encryptedSecret == null || encryptedSecret.isEmpty()) {
            CryptoLogWindow.logOperation("Ошибка", "Пустой зашифрованный секрет");
            return null;
        }
        
        if (clientKeyManager.getClientRsaKeyPair() == null) {
            CryptoLogWindow.logOperation("Ошибка", "RSA-ключи клиента недоступны");
            return null;
        }
        
        try {
            // Расшифровываем полученные данные приватным ключом RSA
            String decryptedJson = clientRsaInstance.decryptTextChunked(encryptedSecret);
            JSONObject secretPayload = new JSONObject(decryptedJson);
            
            // Извлекаем общий секрет
            String secretString = secretPayload.getString("shared_secret");
            BigInteger sharedSecret = new BigInteger(secretString);
            
            // Получаем дополнительную информацию (для логирования)
            long timestamp = secretPayload.getLong("timestamp");
            String senderId = secretPayload.getString("sender_id");
            
            CryptoLogWindow.logOperation("Общий секрет расшифрован", 
                "От отправителя: " + senderId + ", временная метка: " + 
                new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date(timestamp)));
            
            return sharedSecret;
        } catch (Exception e) {
            System.err.println("Ошибка при расшифровке общего секрета: " + e.getMessage());
            CryptoLogWindow.logOperation("Ошибка", "Не удалось расшифровать общий секрет: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Создает зашифрованный пакет с общим секретом для отправки получателю.
     * Комбинирует шифрование общего секрета с RSA и отправку через стандартный
     * канал связи с сервером.
     * 
     * @param sharedSecret Общий секрет для отправки
     * @param recipientPublicKey Публичный ключ RSA получателя
     * @return Зашифрованный пакет для отправки на сервер или null при ошибке
     */
    public String prepareEncryptedSharedSecretPackage(BigInteger sharedSecret, RSA.PublicKey recipientPublicKey) {
        if (sharedSecret == null || recipientPublicKey == null) {
            CryptoLogWindow.logOperation("Ошибка", "Не указан общий секрет или публичный ключ получателя");
            return null;
        }
        
        if (serverRsaPublicKey == null) {
            CryptoLogWindow.logOperation("Ошибка", "Публичный RSA-ключ сервера не установлен");
            return null;
        }
        
        try {
            // Шифруем общий секрет публичным ключом получателя
            String encryptedSecret = encryptSharedSecret(sharedSecret, recipientPublicKey);
            if (encryptedSecret == null) {
                return null;
            }
            
            // Создаем пакет для отправки на сервер
            JSONObject packagePayload = new JSONObject();
            packagePayload.put("encrypted_shared_secret", encryptedSecret);
            packagePayload.put("sender_public_key_n", clientKeyManager.getClientRsaPublicKey().n.toString());
            packagePayload.put("sender_public_key_e", clientKeyManager.getClientRsaPublicKey().e.toString());
            packagePayload.put("message_type", "shared_secret_transfer");
            packagePayload.put("protocol_version", "1.0");
            
            // Шифруем весь пакет публичным ключом сервера для передачи
            RSA serverRsaEncrypter = new RSA();
            serverRsaEncrypter.setPublicKey(serverRsaPublicKey.n, serverRsaPublicKey.e);
            
            CryptoLogWindow.logOperation("Подготовка пакета с общим секретом", 
                "Шифруем пакет для передачи через сервер");
            
            String encryptedPackage = serverRsaEncrypter.encryptTextChunked(packagePayload.toString());
            
            CryptoLogWindow.logOperation("Пакет с общим секретом готов", 
                "Размер пакета: " + encryptedPackage.length() + " символов");
            
            return encryptedPackage;
        } catch (Exception e) {
            System.err.println("Ошибка при подготовке пакета с общим секретом: " + e.getMessage());
            CryptoLogWindow.logOperation("Ошибка", "Не удалось подготовить пакет: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Обрабатывает зашифрованный пакет с общим секретом от отправителя.
     * 
     * @param encryptedPackage Зашифрованный пакет от сервера
     * @return Общий секрет или null при ошибке
     */
    public BigInteger processEncryptedSharedSecretPackage(String encryptedPackage) {
        if (encryptedPackage == null || encryptedPackage.isEmpty()) {
            CryptoLogWindow.logOperation("Ошибка", "Пустой зашифрованный пакет");
            return null;
        }
        
        try {
            // Расшифровываем пакет приватным ключом RSA клиента
            String decryptedPackageJson = clientRsaInstance.decryptTextChunked(encryptedPackage);
            JSONObject packagePayload = new JSONObject(decryptedPackageJson);
            
            // Извлекаем зашифрованный общий секрет
            String encryptedSecret = packagePayload.getString("encrypted_shared_secret");
            
            // Получаем информацию об отправителе
            String senderPublicKeyN = packagePayload.getString("sender_public_key_n");
            String senderPublicKeyE = packagePayload.getString("sender_public_key_e");
            
            CryptoLogWindow.logOperation("Получен пакет с общим секретом", 
                "Отправитель: " + senderPublicKeyN.substring(0, 8) + "..., e=" + senderPublicKeyE);
            
            // Проверяем корректность публичного ключа отправителя
            try {
                RSA.PublicKey senderPublicKey = new RSA.PublicKey(
                    new BigInteger(senderPublicKeyN), 
                    new BigInteger(senderPublicKeyE));
                
                // Сохраняем информацию об отправителе (опционально)
                // Здесь можно было бы добавить отправителя в список доверенных контактов
                
                // Проверка на корректность открытой экспоненты (должна быть нечетной и > 1)
                if (senderPublicKey.e.compareTo(BigInteger.ONE) <= 0 || 
                    senderPublicKey.e.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
                    CryptoLogWindow.logOperation("Предупреждение", 
                        "Необычная экспонента в публичном ключе отправителя: " + senderPublicKey.e);
                }
            } catch (Exception e) {
                CryptoLogWindow.logOperation("Предупреждение", 
                    "Невалидный формат публичного ключа отправителя: " + e.getMessage());
                // Продолжаем выполнение, так как это не критическая ошибка
            }
            
            // Расшифровываем общий секрет
            BigInteger sharedSecret = decryptSharedSecret(encryptedSecret);
            
            if (sharedSecret != null) {
                CryptoLogWindow.logOperation("Общий секрет успешно получен", 
                    "Первые 8 символов: " + sharedSecret.toString().substring(0, 
                    Math.min(8, sharedSecret.toString().length())) + "...");
            }
            
            return sharedSecret;
        } catch (Exception e) {
            System.err.println("Ошибка при обработке пакета с общим секретом: " + e.getMessage());
            CryptoLogWindow.logOperation("Ошибка", "Не удалось обработать пакет: " + e.getMessage());
            return null;
        }
    }
} 