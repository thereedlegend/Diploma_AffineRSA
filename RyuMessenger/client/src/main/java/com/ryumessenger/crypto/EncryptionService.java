package com.ryumessenger.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

// Java Security API
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// JSON
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

// Проектные классы
import com.ryumessenger.ui.CryptoLogWindow;
import com.ryumessenger.model.UserPublicKeys;

import java.security.interfaces.RSAPrivateKey; // Импорт для RSAPrivateKey

public class EncryptionService {
    private final KeyManager clientKeyManager;
    private RSA.PublicKey serverRsaPublicKey; // Будет получен от сервера
    private RSA clientRsaInstance;
    
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int MAX_MESSAGE_LENGTH = 4096;
    private static final long MESSAGE_TIMEOUT_MS = 300000; // 5 минут

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
        if (plaintext == null || plaintext.length() > MAX_MESSAGE_LENGTH) {
            throw new IllegalArgumentException("Invalid message length");
        }

        CryptoLogWindow.logOperation("Начинаем шифрование", "Исходный текст: " + plaintext);
        
        if (serverRsaPublicKey == null) {
            throw new IllegalStateException("Публичный RSA-ключ сервера не установлен");
        }
        if (clientKeyManager.getClientRsaKeyPair() == null) {
            throw new IllegalStateException("RSA-ключи клиента недоступны");
        }

        try {
            // Добавляем временную метку и случайный nonce
            JSONObject messageData = new JSONObject();
            messageData.put("content", plaintext);
            messageData.put("timestamp", System.currentTimeMillis());
            messageData.put("nonce", generateNonce());
            
            String messageJson = messageData.toString();
            
            // Вычисляем HMAC для проверки целостности
            String hmac = calculateHMAC(messageJson);
            
            // Добавляем HMAC в сообщение
            JSONObject finalMessage = new JSONObject();
            finalMessage.put("data", messageJson);
            finalMessage.put("hmac", hmac);
            
            // Шифруем финальное сообщение
            RSA serverRsaEncrypter = new RSA();
            serverRsaEncrypter.setPublicKey(serverRsaPublicKey.n, serverRsaPublicKey.e);
            
            String encrypted = serverRsaEncrypter.encryptTextChunked(finalMessage.toString());
            CryptoLogWindow.logOperation("Результат RSA шифрования", 
                encrypted.substring(0, Math.min(50, encrypted.length())) + "...");
            
            return encrypted;
        } catch (Exception e) {
            CryptoLogWindow.logOperation("Ошибка", "Ошибка шифрования: " + e.getMessage());
            throw new RuntimeException("Ошибка шифрования", e);
        }
    }

    public String decryptFromServer(String encryptedData) {
        if (encryptedData == null || encryptedData.isEmpty()) {
            throw new IllegalArgumentException("Пустые данные для расшифровки");
        }

        try {
            // Расшифровываем данные
            String decrypted = clientRsaInstance.decryptTextChunked(encryptedData);
            JSONObject message = new JSONObject(decrypted);
            
            // Проверяем наличие всех необходимых полей
            if (!message.has("data") || !message.has("hmac")) {
                throw new IllegalArgumentException("Некорректный формат сообщения");
            }
            
            String data = message.getString("data");
            String receivedHmac = message.getString("hmac");
            
            // Проверяем HMAC
            String calculatedHmac = calculateHMAC(data);
            if (!MessageDigest.isEqual(calculatedHmac.getBytes(), receivedHmac.getBytes())) {
                throw new SecurityException("Ошибка проверки целостности данных");
            }
            
            // Проверяем временную метку
            JSONObject dataObj = new JSONObject(data);
            long timestamp = dataObj.getLong("timestamp");
            if (System.currentTimeMillis() - timestamp > MESSAGE_TIMEOUT_MS) {
                throw new SecurityException("Сообщение устарело");
            }
            
            return dataObj.getString("content");
        } catch (Exception e) {
            CryptoLogWindow.logOperation("Ошибка", "Ошибка расшифровки: " + e.getMessage());
            throw new RuntimeException("Ошибка расшифровки", e);
        }
    }

    private String generateNonce() {
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);
        return Base64.getEncoder().encodeToString(nonce);
    }

    private String calculateHMAC(String data) throws Exception {
        byte[] keyBytes = clientKeyManager.getClientRsaPrivateKey().d.toByteArray(); // Используем d напрямую
        SecretKeySpec signingKey = new SecretKeySpec(keyBytes, HMAC_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(signingKey);
        byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(rawHmac);
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
            // Расшифровываем пакет приватным ключом RSA клиента (т.к. пакет шифровался ключом сервера для НАС)
            String decryptedPackageJson = clientRsaInstance.decryptTextChunked(encryptedPackage);
            JSONObject packagePayload = new JSONObject(decryptedPackageJson);
            
            String messageType = packagePayload.optString("message_type", "");
            if (!"shared_secret_transfer".equals(messageType)) {
                CryptoLogWindow.logOperation("Ошибка", "Неверный тип сообщения в пакете, ожидался shared_secret_transfer");
                return null;
            }

            String encryptedSecretPayload = packagePayload.getString("encrypted_shared_secret");
            
            // Расшифровываем сам общий секрет (он был зашифрован RSA ключом ТЕКУЩЕГО пользователя)
            String decryptedSecretJson = clientRsaInstance.decryptTextChunked(encryptedSecretPayload);
            JSONObject secretPayload = new JSONObject(decryptedSecretJson);
            
            BigInteger sharedSecretValue = new BigInteger(secretPayload.getString("shared_secret"));
            long timestamp = secretPayload.getLong("timestamp");
            // String senderId = secretPayload.getString("sender_id"); // Можно использовать для логгирования

            if (System.currentTimeMillis() - timestamp > MESSAGE_TIMEOUT_MS) {
                CryptoLogWindow.logOperation("Ошибка", "Пакет с общим секретом устарел");
                return null;
            }
            
            CryptoLogWindow.logOperation("Общий секрет извлечен", 
                "Значение секрета (начало): " + sharedSecretValue.toString().substring(0, Math.min(10, sharedSecretValue.toString().length())) + "...");
            
            return sharedSecretValue; 
        } catch (Exception e) {
            System.err.println("Ошибка при обработке пакета с общим секретом: " + e.getMessage());
            e.printStackTrace();
            CryptoLogWindow.logOperation("Ошибка обработки пакета", e.getMessage());
            return null;
        }
    }

    /**
     * Шифрует текстовое сообщение для указанного получателя согласно схеме:
     * 1. Аффинное шифрование текста (случайные коэффициенты a_arr, b_arr).
     * 2. Выработка общего DH-секрета с получателем.
     * 3. Шифрование (a_arr, b_arr) этим DH-секретом (например, AES-GCM, пока упростим).
     * 4. Шифрование аффинного шифртекста публичным RSA-ключом получателя.
     * 5. Формирование JSON-пакета со всеми компонентами.
     *
     * @param plaintext Исходный текст сообщения.
     * @param recipientPublicKeys Публичные ключи получателя (RSA и DH-Y).
     * @param keyManagerSecurity KeyManager текущего пользователя (отправителя) - com.ryumessenger.security.KeyManager.
     * @return JSON-строка с зашифрованным пакетом или null в случае ошибки.
     */
    public String encryptForUser(String plaintext, UserPublicKeys recipientPublicKeys, com.ryumessenger.security.KeyManager keyManagerSecurity) {
        if (plaintext == null || recipientPublicKeys == null || keyManagerSecurity == null) {
            CryptoLogWindow.logOperation("Ошибка encryptForUser", "Некорректные входные параметры.");
            return null;
        }

        try {
            CryptoLogWindow.logOperation("encryptForUser", "Начало шифрования для пользователя: " + recipientPublicKeys.getRsaModulus().toString().substring(0,10) + "...");

            AffineCipher affineCipher = AffineCipher.createWithRandomKeys(16);
            String affineCiphertext = affineCipher.encrypt(plaintext);
            CryptoLogWindow.logOperation("encryptForUser", "Текст зашифрован афинным шифром.");

            int[] aValues = affineCipher.getAValues();
            int[] bValues = affineCipher.getBValues();
            JSONObject affineParamsJson = new JSONObject();
            JSONArray aJsonArray = new JSONArray();
            for (int a : aValues) aJsonArray.put(a);
            JSONArray bJsonArray = new JSONArray();
            for (int b : bValues) bJsonArray.put(b);
            affineParamsJson.put("a_arr", aJsonArray);
            affineParamsJson.put("b_arr", bJsonArray);
            String serializedAffineParams = affineParamsJson.toString();

            if (!keyManagerSecurity.areDHParametersSet()) {
                CryptoLogWindow.logOperation("Ошибка encryptForUser", "DH параметры P,G не установлены у отправителя.");
                return null;
            }
            KeyPair senderDhKeyPair = keyManagerSecurity.getDhKeyPair(); 
            if (senderDhKeyPair == null) {
                 CryptoLogWindow.logOperation("Ошибка encryptForUser", "DH KeyPair отправителя не инициализирован.");
                 return null; 
            }

            KeyFactory dhKeyFactory = KeyFactory.getInstance("DH", "BC");
            DHPublicKeySpec recipientDhPublicSpec = new DHPublicKeySpec(
                recipientPublicKeys.getDhPublicKeyY(), 
                keyManagerSecurity.getClientDhP(),
                keyManagerSecurity.getClientDhG()
            );
            PublicKey recipientDhPublicKeyJava = dhKeyFactory.generatePublic(recipientDhPublicSpec);

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", "BC");
            keyAgreement.init(senderDhKeyPair.getPrivate());
            keyAgreement.doPhase(recipientDhPublicKeyJava, true);
            byte[] sharedDhSecret = keyAgreement.generateSecret();
            CryptoLogWindow.logOperation("encryptForUser", "Общий DH-секрет вычислен.");

            SecretKey aesKey = new SecretKeySpec(sharedDhSecret, 0, 32, "AES"); 
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            byte[] iv = new byte[12]; 
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); 

            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
            byte[] encryptedAffineParamsBytes = aesCipher.doFinal(serializedAffineParams.getBytes(StandardCharsets.UTF_8));
            String encryptedAffineParamsB64 = Base64.getEncoder().encodeToString(encryptedAffineParamsBytes);
            String ivB64 = Base64.getEncoder().encodeToString(iv);
            CryptoLogWindow.logOperation("encryptForUser", "Аффинные коэффициенты зашифрованы AES-GCM.");

            com.ryumessenger.crypto.RSA rsaEncrypter = new com.ryumessenger.crypto.RSA();
            rsaEncrypter.setPublicKey(recipientPublicKeys.getRsaModulus(), recipientPublicKeys.getRsaExponent());
            String rsaEncryptedAffineCiphertext = rsaEncrypter.encryptTextChunked(affineCiphertext);
            CryptoLogWindow.logOperation("encryptForUser", "Аффинный шифртекст зашифрован RSA получателя.");

            JSONObject finalPayload = new JSONObject();
            finalPayload.put("rsa_encrypted_text", rsaEncryptedAffineCiphertext);
            finalPayload.put("encrypted_coeffs_package", new JSONObject()
                .put("coeffs_b64", encryptedAffineParamsB64)
                .put("iv_b64", ivB64)
                .put("cipher_algo", "AES/GCM/NoPadding")
            );
            DHPublicKey senderDhPublicKeyObj = (DHPublicKey) senderDhKeyPair.getPublic();
            finalPayload.put("sender_dh_public_key_y", senderDhPublicKeyObj.getY().toString());
            finalPayload.put("message_content_type", "e2e_v1"); 

            CryptoLogWindow.logOperation("encryptForUser", "Финальный пакет сформирован.");
            return finalPayload.toString();

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | JSONException e) {
            CryptoLogWindow.logOperation("Ошибка encryptForUser", "Криптографическое исключение или JSON: " + e.getMessage());
            e.printStackTrace();
            return null;
        } catch (Exception e) { 
            CryptoLogWindow.logOperation("Ошибка encryptForUser", "Непредвиденное общее исключение: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Расшифровывает сообщение, полученное от другого пользователя.
     * 1. Разбирает JSON-пакет.
     * 2. Извлекает публичный DH-ключ отправителя.
     * 3. Вычисляет общий DH-секрет с отправителем.
     * 4. Расшифровывает пакет с аффинными коэффициентами (AES-GCM).
     * 5. Расшифровывает основной текст (RSA приватным ключом получателя).
     * 6. Расшифровывает аффинный шифртекст.
     *
     * @param encryptedPayload JSON-строка с зашифрованным пакетом.
     * @param keyManagerSecurity KeyManager текущего пользователя (получателя) - com.ryumessenger.security.KeyManager.
     * @return Исходный текст сообщения или null в случае ошибки.
     */
    public String decryptForUser(String encryptedPayload, com.ryumessenger.security.KeyManager keyManagerSecurity) {
        if (encryptedPayload == null || keyManagerSecurity == null) {
            CryptoLogWindow.logOperation("Ошибка decryptForUser", "Некорректные входные параметры.");
            return null;
        }

        try {
            CryptoLogWindow.logOperation("decryptForUser", "Начало расшифровки от пользователя.");
            JSONObject payload = new JSONObject(encryptedPayload);

            if (!"e2e_v1".equals(payload.optString("message_content_type"))) {
                CryptoLogWindow.logOperation("Ошибка decryptForUser", "Неподдерживаемый тип контента сообщения.");
                return null;
            }

            String rsaEncryptedText = payload.getString("rsa_encrypted_text");
            JSONObject encryptedCoeffsPackage = payload.getJSONObject("encrypted_coeffs_package");
            String coeffsB64 = encryptedCoeffsPackage.getString("coeffs_b64");
            String ivB64 = encryptedCoeffsPackage.getString("iv_b64");
            BigInteger senderDhPublicKeyY = new BigInteger(payload.getString("sender_dh_public_key_y"));

            if (!keyManagerSecurity.areDHParametersSet()) {
                CryptoLogWindow.logOperation("Ошибка decryptForUser", "DH параметры P,G не установлены у получателя.");
                return null;
            }
            KeyPair recipientDhKeyPair = keyManagerSecurity.getDhKeyPair();
            if (recipientDhKeyPair == null) {
                CryptoLogWindow.logOperation("Ошибка decryptForUser", "DH KeyPair получателя не инициализирован.");
                return null;
            }

            KeyFactory dhKeyFactory = KeyFactory.getInstance("DH", "BC");
            DHPublicKeySpec senderDhPublicSpec = new DHPublicKeySpec(
                senderDhPublicKeyY,
                keyManagerSecurity.getClientDhP(), 
                keyManagerSecurity.getClientDhG()
            );
            PublicKey senderDhPublicKeyJava = dhKeyFactory.generatePublic(senderDhPublicSpec);

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", "BC");
            keyAgreement.init(recipientDhKeyPair.getPrivate());
            keyAgreement.doPhase(senderDhPublicKeyJava, true);
            byte[] sharedDhSecret = keyAgreement.generateSecret();
            CryptoLogWindow.logOperation("decryptForUser", "Общий DH-секрет с отправителем вычислен.");

            SecretKey aesKey = new SecretKeySpec(sharedDhSecret, 0, 32, "AES");
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            byte[] iv = Base64.getDecoder().decode(ivB64);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
            byte[] encryptedAffineParamsBytes = Base64.getDecoder().decode(coeffsB64);
            byte[] decryptedAffineParamsBytes = aesCipher.doFinal(encryptedAffineParamsBytes);
            String serializedAffineParams = new String(decryptedAffineParamsBytes, StandardCharsets.UTF_8);
            CryptoLogWindow.logOperation("decryptForUser", "Аффинные коэффициенты расшифрованы.");

            JSONObject affineParamsJson = new JSONObject(serializedAffineParams);
            JSONArray aJsonArray = affineParamsJson.getJSONArray("a_arr");
            JSONArray bJsonArray = affineParamsJson.getJSONArray("b_arr");
            int[] aValues = new int[aJsonArray.length()];
            int[] bValues = new int[bJsonArray.length()];
            for (int i = 0; i < aJsonArray.length(); i++) aValues[i] = aJsonArray.getInt(i);
            for (int i = 0; i < bJsonArray.length(); i++) bValues[i] = bJsonArray.getInt(i);

            // --- 3. Расшифрование основного текста (RSA приватным ключом получателя) ---
            java.security.PrivateKey recipientJavaRsaPrivateKey = keyManagerSecurity.getRsaPrivateKeyObject();
            if (recipientJavaRsaPrivateKey == null) {
                 CryptoLogWindow.logOperation("Ошибка decryptForUser", "Приватный RSA ключ получателя (java.security) не найден.");
                 return null;
            }

            if (!(recipientJavaRsaPrivateKey instanceof RSAPrivateKey)) {
                CryptoLogWindow.logOperation("Ошибка decryptForUser", "Приватный RSA ключ имеет неверный тип, ожидался RSAPrivateKey.");
                return null;
            }
            RSAPrivateKey rsaPrivKey = (RSAPrivateKey) recipientJavaRsaPrivateKey;
            BigInteger rsaD = rsaPrivKey.getPrivateExponent();
            BigInteger rsaN = rsaPrivKey.getModulus();
            
            RSA rsaDecrypter = new RSA();
            rsaDecrypter.setPrivateKey(rsaD, rsaN); 
            String affineCiphertext = rsaDecrypter.decryptTextChunked(rsaEncryptedText);
            CryptoLogWindow.logOperation("decryptForUser", "Основной текст (аффинный шифртекст) расшифрован RSA.");

            AffineCipher affineCipher = new AffineCipher(aValues, bValues);
            String plaintext = affineCipher.decrypt(affineCiphertext);
            CryptoLogWindow.logOperation("decryptForUser", "Финальный текст расшифрован: " + plaintext.substring(0, Math.min(20, plaintext.length())) + "...");

            return plaintext;

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | JSONException e) {
            CryptoLogWindow.logOperation("Ошибка decryptForUser", "Криптографическое исключение или JSON: " + e.getMessage());
            e.printStackTrace();
            return null;
        } catch (Exception e) { 
            CryptoLogWindow.logOperation("Ошибка decryptForUser", "Непредвиденное общее исключение: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
} 