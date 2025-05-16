package com.ryumessenger.network;

import java.net.URI;
import java.util.function.Consumer;

import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ryumessenger.crypto.RSA;
import com.ryumessenger.Main;
import com.ryumessenger.model.User;
import com.ryumessenger.ui.CryptoLogWindow;

public class ApiClient {

    private static final String BASE_URL = "http://localhost:5000/api";
    private final HttpClient httpClient;
    private String authToken; // Поле для хранения токена аутентификации
    private static final Logger LOGGER = Logger.getLogger(ApiClient.class.getName()); // Создание логгера

    public ApiClient() {
        this.httpClient = HttpClient.newHttpClient();
    }

    public void get(String endpoint, Consumer<ApiResponse> callback) {
        performRequest("GET", endpoint, null, callback);
    }

    public void post(String endpoint, String body, Consumer<ApiResponse> callback) {
        performRequest("POST", endpoint, body, callback);
    }

    public void put(String endpoint, String body, Consumer<ApiResponse> callback) {
        performRequest("PUT", endpoint, body, callback);
    }

    public void delete(String endpoint, Consumer<ApiResponse> callback) {
        performRequest("DELETE", endpoint, null, callback);
    }

    private void performRequest(String method, String endpoint, String body, Consumer<ApiResponse> callback) {
        LOGGER.log(Level.INFO, "ApiClient: Preparing " + method + " request to " + BASE_URL + endpoint);
        CryptoLogWindow.logOperation("Сетевой запрос", method + " " + endpoint);
        
        try {
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + endpoint))
                .timeout(java.time.Duration.ofSeconds(20));

            if (body != null) {
                LOGGER.log(Level.INFO, "ApiClient: Request body: " + body);
                CryptoLogWindow.logOperation("Отправляем на сервер", "Тело запроса: " + body.substring(0, Math.min(50, body.length())) + (body.length() > 50 ? "..." : ""));
            }

            if (authToken != null) {
                requestBuilder.header("Authorization", "Bearer " + authToken);
            }

            switch (method) {
                case "GET":
                    requestBuilder.GET();
                    break;
                case "POST":
                    requestBuilder.POST(HttpRequest.BodyPublishers.ofString(body))
                        .header("Content-Type", "application/json");
                    break;
                case "PUT":
                    requestBuilder.PUT(HttpRequest.BodyPublishers.ofString(body))
                        .header("Content-Type", "application/json");
                    break;
                case "DELETE":
                    requestBuilder.DELETE();
                    break;
            }

            HttpRequest request = requestBuilder.build();

            LOGGER.log(Level.INFO, "ApiClient: HTTP request built. Sending ASYNC request...");

            // --- АСИНХРОННЫЙ КОД ---
            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenAccept(response -> {
                    LOGGER.log(Level.INFO, "ApiClient: Entered thenAccept callback for " + request.method() + " " + request.uri());
                    try {
                        String responseBody = response.body();
                        LOGGER.log(Level.INFO, "ApiClient: Response status code: " + response.statusCode());
                        LOGGER.log(Level.INFO, "ApiClient: Response body: " + responseBody);
                        
                        CryptoLogWindow.logOperation("Получаем с сервера", "Статус: " + response.statusCode() + 
                                                   ", Тело ответа: " + (responseBody != null ? responseBody.substring(0, Math.min(50, responseBody.length())) + 
                                                   (responseBody.length() > 50 ? "..." : "") : "пусто"));

                        JSONObject json = null;
                        JSONArray jsonArray = null;

                        if (responseBody != null && !responseBody.isEmpty()) {
                            if (responseBody.trim().startsWith("[")) {
                                jsonArray = new JSONArray(responseBody);
                            } else if (responseBody.trim().startsWith("{")) {
                                json = new JSONObject(responseBody);
                                // Попытка извлечь массив из поля "data", если основной ответ - объект
                                if (json.has("data") && json.get("data") instanceof JSONArray) {
                                    jsonArray = json.getJSONArray("data");
                                }
                            } 
                        }
                        
                        callback.accept(new ApiResponse(
                            response.statusCode(),
                            responseBody,
                            json,
                            jsonArray
                        ));
                    } catch (Exception e) {
                        // Логируем ошибку парсинга, но все равно передаем ответ
                        LOGGER.log(Level.SEVERE, "ApiClient: Error parsing JSON response for " + request.method() + " " + request.uri(), e); // Логирование исключения
                        CryptoLogWindow.logOperation("Ошибка обработки ответа", "Ошибка: " + e.getMessage());
                        callback.accept(new ApiResponse(response.statusCode(), response.body(), null, null));
                    }
                })
                .exceptionally(e -> {
                    LOGGER.log(Level.SEVERE, "ApiClient: Entered exceptionally callback for " + request.method() + " " + request.uri(), e); 
                    CryptoLogWindow.logOperation("Ошибка сетевого запроса", "Ошибка: " + e.getMessage());
                    callback.accept(new ApiResponse(0, e.getMessage(), null, null)); // Статус код 0 для сетевых ошибок или ошибок до получения HTTP статуса 
                    return null;
                });
            LOGGER.log(Level.INFO, "ApiClient: sendAsync call for " + request.method() + " " + request.uri() + " finished, callbacks registered.");
            
        } catch (Exception e) { 
            LOGGER.log(Level.SEVERE, "ApiClient: Exception preparing HTTP request", e);
            CryptoLogWindow.logOperation("Ошибка подготовки запроса", "Ошибка: " + e.getMessage());
            callback.accept(new ApiResponse(500, e.getMessage(), null, null));
        }
    }

    public void fetchAndSetServerPublicKey(Consumer<Boolean> callback) {
        CryptoLogWindow.logOperation("Запрос публичного ключа сервера", "Запрашиваем RSA и Affine ключи");
        get("/keys", response -> {
            if (response.isSuccess() && response.getJson() != null && 
                response.getJson().has("rsa_public_key") && response.getJson().has("affine_params")) {
                try {
                    JSONObject rsaKeyJson = response.getJson().getJSONObject("rsa_public_key");
                    String n = rsaKeyJson.getString("n");
                    String e = rsaKeyJson.getString("e");
                    
                    JSONObject affineParamsJson = response.getJson().getJSONObject("affine_params");
                    
                    CryptoLogWindow.logOperation("Получены ключи сервера", "RSA ключ: n=" + n.substring(0, Math.min(20, n.length())) + "..., e=" + e);
                    
                    com.ryumessenger.crypto.KeyManager keyManager = com.ryumessenger.Main.getKeyManager();
                    if (keyManager != null) {
                        keyManager.setServerRsaPublicKey(n, e);
                        keyManager.setServerAffineParams(affineParamsJson);
                        LOGGER.log(Level.INFO, "ApiClient: Server public key and affine params fetched and set successfully.");
                        CryptoLogWindow.logOperation("Сохранены ключи сервера", "Ключи успешно установлены в KeyManager");
                        if (callback != null) callback.accept(true);
                    } else {
                        LOGGER.log(Level.SEVERE, "ApiClient: KeyManager not initialized. Cannot set server keys.");
                        CryptoLogWindow.logOperation("Ошибка установки ключей", "KeyManager не инициализирован");
                        if (callback != null) callback.accept(false);
                    }

                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "ApiClient: Failed to parse or set server public key and affine params.", e);
                    CryptoLogWindow.logOperation("Ошибка обработки ключей", "Ошибка: " + e.getMessage());
                    if (callback != null) callback.accept(false);
                }
            } else {
                LOGGER.log(Level.WARNING, "ApiClient: Failed to fetch server public key. Response: " + response.getBody());
                CryptoLogWindow.logOperation("Ошибка получения ключей", "Ответ сервера: " + response.getBody());
                if (callback != null) callback.accept(false);
            }
        });
    }

    public void setAuthToken(String token) {
        this.authToken = token;
        if (token != null) {
            CryptoLogWindow.logOperation("Установлен токен авторизации", "Токен: " + token.substring(0, Math.min(10, token.length())) + "...");
        } else {
            CryptoLogWindow.logOperation("Очищен токен авторизации", "");
        }
    }

    public void login(String username, String password, Consumer<ApiResponse> callback) {
        CryptoLogWindow.logOperation("Запрос на вход", "Пользователь: " + username);
        
        com.ryumessenger.crypto.EncryptionService encryptionService = Main.getEncryptionService();
        com.ryumessenger.crypto.KeyManager keyManager = Main.getKeyManager();

        if (encryptionService == null || keyManager == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: EncryptionService or KeyManager not initialized. Cannot proceed with login.");
            CryptoLogWindow.logOperation("Ошибка входа", "EncryptionService или KeyManager не инициализированы");
            if (callback != null) callback.accept(new ApiResponse(500, "Client configuration error", null, null));
            return;
        }

        RSA.PublicKey clientPublicKey = keyManager.getClientRsaPublicKey(); // Нужен для передачи в encryptLoginPayloadForServer, хотя он может быть и не использован внутри самого шифруемого JSON
        if (clientPublicKey == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: Client public key is not available for login context.");
            CryptoLogWindow.logOperation("Ошибка входа", "Отсутствует публичный ключ клиента");
            // Не фатально для самого вызова encryptLoginPayloadForServer, если он не использует clientPublicKey внутри шифруемого JSON.
            // Но если серверу он нужен для каких-то проверок, это может быть проблемой.
        }

        String encryptedLoginPayload = encryptionService.encryptLoginPayloadForServer(username, password, clientPublicKey);

        if (encryptedLoginPayload == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: Failed to create encrypted login payload.");
            CryptoLogWindow.logOperation("Ошибка входа", "Не удалось создать зашифрованные данные для входа");
            if (callback != null) callback.accept(new ApiResponse(500, "Encryption error for login", null, null));
            return;
        }

        JSONObject requestBody = new JSONObject();
        requestBody.put("username", username); // Имя пользователя передается открыто
        requestBody.put("encrypted_login_payload", encryptedLoginPayload); // Зашифрованный JSON с деталями логина

        post("/login", requestBody.toString(), callback);
    }

    public void register(String username, String password, String displayName, String tag, Consumer<ApiResponse> callback) {
        com.ryumessenger.crypto.EncryptionService encryptionService = Main.getEncryptionService();
        com.ryumessenger.crypto.KeyManager keyManager = Main.getKeyManager();

        if (encryptionService == null || keyManager == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: EncryptionService or KeyManager not initialized for registration.");
            if (callback != null) callback.accept(new ApiResponse(500, "Client configuration error", null, null));
            return;
        }

        RSA.PublicKey clientPublicKey = keyManager.getClientRsaPublicKey();
        if (clientPublicKey == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: Client public key is not available for registration. Cannot provide n, e.");
            if (callback != null) callback.accept(new ApiResponse(500, "Client key error for registration", null, null));
            return;
        }

        String encryptedPasswordPayload = encryptionService.encryptRegistrationPayloadForServer(username, password, displayName, tag, clientPublicKey);

        if (encryptedPasswordPayload == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: Failed to create encrypted registration payload.");
            if (callback != null) callback.accept(new ApiResponse(500, "Encryption error for registration", null, null));
            return;
        }

        JSONObject requestBody = new JSONObject();
        requestBody.put("username", username);
        requestBody.put("display_name", displayName);
        requestBody.put("tag", tag);
        requestBody.put("encrypted_password_payload", encryptedPasswordPayload); // Зашифрованный JSON с деталями регистрации
        requestBody.put("rsa_public_key_n", clientPublicKey.n.toString()); // Открытый ключ клиента (n,e) передается отдельно
        requestBody.put("rsa_public_key_e", clientPublicKey.e.toString());

        post("/register", requestBody.toString(), callback);
    }

    public void logout(Consumer<ApiResponse> callback) {
        post("/logout", "{}", callback);
    }

    public void changePassword(String currentPassword, String newPassword, Consumer<ApiResponse> callback) {
        com.ryumessenger.crypto.EncryptionService encryptionService = Main.getEncryptionService();
        User currentUser = Main.getCurrentUser();

        if (encryptionService == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: EncryptionService not initialized for changePassword.");
            if (callback != null) callback.accept(new ApiResponse(500, "Client configuration error", null, null));
            return;
        }
        if (currentUser == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: No current user found for changePassword.");
            if (callback != null) callback.accept(new ApiResponse(401, "User not logged in", null, null)); // 401 Unauthorized
            return;
        }

        String userId = String.valueOf(currentUser.getId());
        String encryptedUpdatePayload = encryptionService.encryptChangePasswordPayloadForServer(userId, currentPassword, newPassword);

        if (encryptedUpdatePayload == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: Failed to create encrypted change password payload.");
            if (callback != null) callback.accept(new ApiResponse(500, "Encryption error for change password", null, null));
            return;
        }

        JSONObject requestBody = new JSONObject();
        requestBody.put("encrypted_update_payload", encryptedUpdatePayload);

        post("/user/update", requestBody.toString(), callback);
    }

    public void getChats(Consumer<ApiResponse> callback) {
        get("/chats", callback);
    }

    public void getMessages(String chatId, Consumer<ApiResponse> callback) {
        get("/chats/" + chatId + "/messages", callback);
    }

    public void sendMessage(String encryptedReceiverIdPayload, String encryptedMessagePayload, Consumer<ApiResponse> callback) {
        JSONObject requestBody = new JSONObject();
        try {
            requestBody.put("encrypted_receiver_id_payload", encryptedReceiverIdPayload);
            requestBody.put("encrypted_message_payload", encryptedMessagePayload);
        } catch (org.json.JSONException e) {
            System.err.println("ApiClient: Failed to create JSON for sendMessage: " + e.getMessage());
            LOGGER.log(Level.SEVERE, "ApiClient: Failed to create JSON for sendMessage", e); // Логируем исключение
            if (callback != null) callback.accept(new ApiResponse(500, "Client error creating request for sending message", null, null));
            return;
        }
        // Отправляем POST запрос на эндпоинт /api/message/send
        post("/message/send", requestBody.toString(), callback);
    }

    public void deleteMessage(String messageId, Consumer<ApiResponse> callback) {
        delete("/messages/" + messageId, callback);
    }

    public void editMessage(String messageId, String encryptedNewContent, Consumer<ApiResponse> callback) {
        JSONObject requestBody = new JSONObject();
        try {
            requestBody.put("new_content_encrypted", encryptedNewContent);
        } catch (org.json.JSONException e) {
            System.err.println("ApiClient: Failed to create JSON for editMessage: " + e.getMessage());
            LOGGER.log(Level.SEVERE, "ApiClient: Failed to create JSON for editMessage", e); // Логируем исключение
            if (callback != null) callback.accept(new ApiResponse(500, "Client error creating request for editing message", null, null));
            return;
        }
        put("/message/" + messageId + "/edit", requestBody.toString(), callback);
    }

    public void searchUsers(String query, Consumer<ApiResponse> callback) {
        // Этот метод больше не используется напрямую ChatService, 
        // вместо него postSearchUsers. Оставляем на случай, если где-то еще нужен GET-вариант, 
        // или для будущей рефакторизации сервера на GET /users/search.
        get("/users/search?q=" + query, callback);
    }

    public void getUserProfile(String userId, Consumer<ApiResponse> callback) {
        get("/users/" + userId, callback);
    }

    public void updateUserProfile(String displayName, String tag, Consumer<ApiResponse> callback) {
        JSONObject requestBody = new JSONObject();
        requestBody.put("displayName", displayName);
        requestBody.put("tag", tag);
        put("/user/profile", requestBody.toString(), callback);
    }

    public void postSearchUsers(String encryptedTagPayload, Consumer<ApiResponse> callback) {
        org.json.JSONObject requestBody = new org.json.JSONObject();
        try {
            // Сервер ожидает поле "encrypted_tag_payload" в теле запроса
            requestBody.put("encrypted_tag_payload", encryptedTagPayload);
        } catch (org.json.JSONException e) {
            System.err.println("ApiClient: Failed to create JSON for postSearchUsers: " + e.getMessage());
            if (callback != null) callback.accept(new ApiResponse(500, "Client error creating request", null, null));
            return;
        }
        // Отладочная информация
        System.out.println("ApiClient: Отправляем запрос на поиск пользователя с payload: " + 
                          encryptedTagPayload.substring(0, Math.min(50, encryptedTagPayload.length())) + "...");
        
        // Используем /api/users/search для поиска
        post("/users/search", requestBody.toString(), callback);
    }

    // Новый обобщенный метод для обновления данных пользователя через /user/update
    public void updateUser(JSONObject changesToEncrypt, Consumer<ApiResponse> callback) {
        com.ryumessenger.crypto.EncryptionService encryptionService = Main.getEncryptionService();
        if (encryptionService == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: EncryptionService not initialized for updateUser.");
            if (callback != null) callback.accept(new ApiResponse(500, "Client configuration error for updateUser", null, null));
            return;
        }

        String encryptedUpdatePayload = encryptionService.encryptJsonForServer(changesToEncrypt.toString());
        if (encryptedUpdatePayload == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: Failed to encrypt update payload for updateUser.");
            if (callback != null) callback.accept(new ApiResponse(500, "Encryption error for updateUser", null, null));
            return;
        }

        JSONObject finalBody = new JSONObject();
        try {
            finalBody.put("encrypted_update_payload", encryptedUpdatePayload);
        } catch (JSONException e) {
            LOGGER.log(Level.SEVERE, "ApiClient: Failed to create final JSON body for updateUser", e);
            if (callback != null) callback.accept(new ApiResponse(500, "Client error creating request for updateUser", null, null));
            return;
        }
        post("/user/update", finalBody.toString(), callback);
    }

    public static class ApiResponse {
        private final int statusCode;
        private final String body;
        private final JSONObject json;
        private final JSONArray jsonArray;

        public ApiResponse(int statusCode, String body, JSONObject json, JSONArray jsonArray) {
            this.statusCode = statusCode;
            this.body = body;
            this.json = json;
            this.jsonArray = jsonArray;
        }

        public boolean isSuccess() {
            return statusCode >= 200 && statusCode < 300;
        }

        public String getBody() {
            return body;
        }

        public JSONObject getJson() {
            return json;
        }

        public JSONArray getJsonArray() {
            return jsonArray;
        }

        public int getStatusCode() {
            return statusCode;
        }
    }
}