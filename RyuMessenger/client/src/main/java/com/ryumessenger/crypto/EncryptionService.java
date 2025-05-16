package com.ryumessenger.crypto;

import java.math.BigInteger;

import org.json.JSONException;
import org.json.JSONObject;

import com.ryumessenger.ui.CryptoLogWindow;

public class EncryptionService {
    private final KeyManager clientKeyManager;
    private RSA.PublicKey serverRsaPublicKey; // Будет получен от сервера
    private RSA clientRsaInstance;

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

    private String determineLanguage(String text) {
        // Простая эвристика для определения языка
        long ruChars = text.chars().filter(ch -> ch >= 'а' && ch <= 'я').count();
        ruChars += text.chars().filter(ch -> ch >= 'А' && ch <= 'Я').count();
        long enChars = text.chars().filter(ch -> ch >= 'a' && ch <= 'z').count();
        enChars += text.chars().filter(ch -> ch >= 'A' && ch <= 'Z').count();

        if (ruChars > enChars) {
            return "ru";
        } else {
            return "en"; // По умолчанию английский, если паритет или нет букв
        }
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
        // На входе только исходный текст, не сериализованный объект!
        String lang = determineLanguage(plaintext);
        AffineCipher.Language affineLang = "ru".equalsIgnoreCase(lang) ? AffineCipher.Language.RUSSIAN : AffineCipher.Language.ENGLISH;
        
        CryptoLogWindow.logOperation("Определение языка", "Обнаружен " + (affineLang == AffineCipher.Language.RUSSIAN ? "русский" : "английский") + " язык");
        
        int m = AffineCipher.getAlphabetAndModulus(affineLang).m;
        int caesarShift = MathUtil.generateAffineB(m); // b - сдвиг
        AffineCipher caesarAffine = new AffineCipher(1, caesarShift, affineLang); // a=1
        
        CryptoLogWindow.logOperation("Шифруем Аффинным преобразованием Цезаря", "a=1, b=" + caesarShift + ", m=" + m);
        
        String caesarCipherText = caesarAffine.encrypt(plaintext);
        CryptoLogWindow.logOperation("Результат Аффинного шифрования", caesarCipherText);
        
        JSONObject payload = new JSONObject();
        try {
            payload.put("cipher_text", caesarCipherText);
            JSONObject affineParams = new JSONObject();
            affineParams.put("a", 1);
            affineParams.put("b", caesarShift);
            affineParams.put("m", m);
            payload.put("affine_params", affineParams);
            payload.put("lang", lang);
            
            CryptoLogWindow.logOperation("Создаем JSON-пакет", payload.toString());
        } catch (JSONException e) {
            System.err.println("Ошибка при создании JSON для шифрования на сервер: " + e.getMessage());
            CryptoLogWindow.logOperation("Ошибка", "Ошибка при создании JSON: " + e.getMessage());
            return null;
        }
        RSA serverRsaEncrypter = new RSA();
        serverRsaEncrypter.setPublicKey(serverRsaPublicKey.n, serverRsaPublicKey.e);
        
        CryptoLogWindow.logOperation("Шифруем открытым ключом RSA сервера", "n=" + serverRsaPublicKey.n.toString().substring(0, 20) + "..., e=" + serverRsaPublicKey.e);
        
        try {
            String encrypted = serverRsaEncrypter.encryptTextChunked(payload.toString());
            CryptoLogWindow.logOperation("Результат RSA шифрования", encrypted.substring(0, Math.min(50, encrypted.length())) + "...");
            System.out.println("ENCRYPTED PAYLOAD: " + encrypted);
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
     * 2. Парсит полученный JSON: {cipher_text, affine_params (сервера), lang}
     * 3. Расшифровывает cipher_text Аффинным шифром, используя параметры сервера.
     * @param rsaEncryptedPayload Строка, зашифрованная RSA от сервера.
     * @return Расшифрованный исходный текст, или null при ошибке.
     */
    public String decryptFromServer(String rsaEncryptedPayload) {
        CryptoLogWindow.logOperation("Начинаем расшифровку", "Зашифрованные данные от сервера: " + rsaEncryptedPayload.substring(0, Math.min(50, rsaEncryptedPayload.length())) + "...");
        
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
            String serverAffineCipherText = payload.getString("cipher_text");
            JSONObject serverAffineParamsJson = payload.getJSONObject("affine_params");
            String lang = payload.getString("lang");

            int serverA = serverAffineParamsJson.getInt("a");
            int serverB = serverAffineParamsJson.getInt("b");
            // int serverM = serverAffineParamsJson.getInt("m"); // m сервера нам не нужно для создания своего дешифратора
                                                              // т.к. наш AffineCipher сам определит m по языку

            AffineCipher.Language affineLang;
            if ("ru".equalsIgnoreCase(lang)) {
                affineLang = AffineCipher.Language.RUSSIAN;
            } else {
                affineLang = AffineCipher.Language.ENGLISH; // По умолчанию
            }
            
            CryptoLogWindow.logOperation("Извлечены параметры Аффинного шифра", "a=" + serverA + ", b=" + serverB + ", язык=" + lang);
            CryptoLogWindow.logOperation("Зашифрованный Аффинным шифром текст", serverAffineCipherText);
            
            AffineCipher serverAffineDecrypter = new AffineCipher(serverA, serverB, affineLang);
            // serverAffineDecrypter.setKeys(serverA, serverB); // Удалено, ключи устанавливаются в конструкторе
            
            String decryptedText = serverAffineDecrypter.decrypt(serverAffineCipherText);
            CryptoLogWindow.logOperation("Результат Аффинной расшифровки", decryptedText);
            
            return decryptedText;
        } catch (JSONException e) {
            System.err.println("Ошибка при разборе JSON-данных от сервера: " + e.getMessage());
            System.err.println("Полученная JSON-строка: " + decryptedPayloadJson.substring(0, Math.min(decryptedPayloadJson.length(), 200)));
            CryptoLogWindow.logOperation("Ошибка", "Ошибка при разборе JSON: " + e.getMessage());
            return null;
        } catch (Exception e) {
            System.err.println("Ошибка при аффинной расшифровке данных от сервера: " + e.getMessage());
            e.printStackTrace();
            CryptoLogWindow.logOperation("Ошибка", "Ошибка Аффинной расшифровки: " + e.getMessage());
            return null;
        }
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
            // 1. Определить язык пароля и получить параметры для аффинного шифра
            String lang = determineLanguage(password);
            AffineCipher.Language affineLang = "ru".equalsIgnoreCase(lang) ? AffineCipher.Language.RUSSIAN : AffineCipher.Language.ENGLISH;
            AffineCipher.AlphabetInfo alphabetDetails = AffineCipher.getAlphabetAndModulus(affineLang);
            int m = alphabetDetails.m;

            // 2. Сгенерировать случайный 'b' для аффинного шифра (a=1)
            // Этот 'b' и 'm' будут переданы серверу вместе с шифротекстом
            int affineA = 1;
            int affineB = MathUtil.generateAffineB(m); // Используем существующий генератор b

            // 3. Зашифровать пароль аффинным шифром
            AffineCipher loginAffineCipher = new AffineCipher(affineA, affineB, affineLang);
            String affineCipherTextPassword = loginAffineCipher.encrypt(password);

            // 4. Создать JSON-payload для RSA-шифрования, содержащий аффинный шифротекст и параметры
            JSONObject rsaPayload = new JSONObject();
            rsaPayload.put("cipher_text", affineCipherTextPassword);
            JSONObject affineParamsJson = new JSONObject();
            affineParamsJson.put("a", affineA);
            affineParamsJson.put("b", affineB);
            affineParamsJson.put("m", m);
            rsaPayload.put("affine_params", affineParamsJson);
            rsaPayload.put("lang", lang);
            // Поле "username" НЕ включается в RSA-зашифрованный payload для логина,
            // так как оно уже передается открыто в основном теле запроса на сервер.
            // Сервер использует открытый username для поиска пользователя, а затем расшифровывает payload.
            
            // 5. Зашифровать этот JSON RSA-ключом сервера
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
            // Важно: убираем потенциальный @ в начале тега, если он есть
            if (tagQuery.startsWith("@")) {
                tagQuery = tagQuery.substring(1);
            }
            
            // Используем только английский язык для тегов, чтобы гарантировать совместимость
            AffineCipher.Language affineLang = AffineCipher.Language.ENGLISH;
            AffineCipher.AlphabetInfo alphabetDetails = AffineCipher.getAlphabetAndModulus(affineLang);
            int m = alphabetDetails.m;

            int affineA = 1; // Используем фиксированный 'a=1' для шифрования тегов
            int affineB = 0; // Используем фиксированный 'b=0' для шифрования тегов, то есть без шифрования!
            
            // Отладочный вывод
            System.out.println("EncryptionService: Тег для поиска: '" + tagQuery + "' с параметрами: a=" + 
                                affineA + ", b=" + affineB + ", m=" + m);
            
            // Тег останется в исходном виде, что должно соответствовать ожиданиям сервера
            JSONObject rsaPayload = new JSONObject();
            rsaPayload.put("tag_query", tagQuery); // Поменяли на прямую передачу тега вместо шифрования
            
            // Отладочный вывод полезной нагрузки
            System.out.println("EncryptionService: JSON payload для поиска тега: " + rsaPayload.toString());
            
            String encryptedResult = encryptJsonWithServerKey(rsaPayload.toString());
            System.out.println("EncryptionService: Финальный зашифрованный payload создан");
            return encryptedResult;
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
            // User ID обычно это цифры, можно считать "en" для аффинного шифра,
            // или использовать специальный числовой алфавит если аффинный шифр его поддерживает.
            // Для простоты пока используем "en" и стандартный алфавит.
            // Важно, чтобы сервер ожидал то же самое.
            String lang = "en"; // Или определить по userId, если он может содержать буквы
            AffineCipher.Language affineLang = AffineCipher.Language.ENGLISH;
            AffineCipher.AlphabetInfo alphabetDetails = AffineCipher.getAlphabetAndModulus(affineLang);
            int m = alphabetDetails.m;

            int affineA = 1; 
            int affineB = MathUtil.generateAffineB(m);

            AffineCipher idAffineCipher = new AffineCipher(affineA, affineB, affineLang);
            String affineCipherTextId = idAffineCipher.encrypt(userId);

            JSONObject rsaPayload = new JSONObject();
            rsaPayload.put("cipher_text", affineCipherTextId);
            JSONObject affineParamsJson = new JSONObject();
            affineParamsJson.put("a", affineA);
            affineParamsJson.put("b", affineB);
            affineParamsJson.put("m", m);
            rsaPayload.put("affine_params", affineParamsJson);
            rsaPayload.put("lang", lang);
            
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
            // 1. Определить язык ID (хотя для ID это может быть избыточно, но для консистентности)
            String lang = determineLanguage(targetUserId);
            AffineCipher.Language affineLang = "ru".equalsIgnoreCase(lang) ? AffineCipher.Language.RUSSIAN : AffineCipher.Language.ENGLISH;
            AffineCipher.AlphabetInfo alphabetDetails = AffineCipher.getAlphabetAndModulus(affineLang);
            int m = alphabetDetails.m;

            // 2. Сгенерировать случайный 'b' для аффинного шифра (a=1)
            int affineA = 1;
            int affineB = MathUtil.generateAffineB(m);

            // 3. Зашифровать ID аффинным шифром
            AffineCipher idAffineCipher = new AffineCipher(affineA, affineB, affineLang);
            String affineCipherTextId = idAffineCipher.encrypt(targetUserId);

            // 4. Создать JSON-payload для RSA-шифрования
            JSONObject rsaPayload = new JSONObject();
            rsaPayload.put("cipher_text", affineCipherTextId);
            JSONObject affineParamsJson = new JSONObject();
            affineParamsJson.put("a", affineA);
            affineParamsJson.put("b", affineB);
            affineParamsJson.put("m", m); // m все еще полезно для сервера, чтобы знать модуль при расшифровке
            rsaPayload.put("affine_params", affineParamsJson);
            rsaPayload.put("lang", lang);
            
            // 5. Зашифровать этот JSON RSA-ключом сервера
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
} 