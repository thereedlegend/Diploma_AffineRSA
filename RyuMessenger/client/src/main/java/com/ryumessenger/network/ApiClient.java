package com.ryumessenger.network;

import java.net.URI;
import java.util.function.Consumer;
import java.util.Map;
import java.math.BigInteger;
import java.util.concurrent.CompletableFuture;
import java.io.IOException;

import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.ryumessenger.Main;
import com.ryumessenger.model.User;
import com.ryumessenger.ui.CryptoLogWindow;
import com.ryumessenger.security.KeyManager;
import com.ryumessenger.security.KeyManagerAdapter;

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

    /**
     * Получает публичный ключ сервера и устанавливает его в KeyManager
     * 
     * @param callback Callback-функция, вызываемая по завершению
     */
    public void fetchAndSetServerPublicKey(Consumer<Boolean> callback) {
        LOGGER.info("ApiClient: Отправляем запрос на получение публичного ключа сервера");
        
        get("/keys", response -> {
            boolean success = false;
            
            if (response.isSuccess()) {
                try {
                    JSONObject json = response.getJson();
                    if (json != null && json.has("data")) {
                        JSONObject data = json.getJSONObject("data");
                        
                        // Получаем данные ключа RSA
                        if (data.has("rsa_public_key")) {
                            JSONObject rsaKey = data.getJSONObject("rsa_public_key");
                            String nStr = rsaKey.getString("n");
                            String eStr = rsaKey.getString("e");
                            BigInteger n = new BigInteger(nStr);
                            BigInteger e = new BigInteger(eStr);
                            
                            // Устанавливаем ключ в новый com.ryumessenger.security.KeyManager
                            KeyManager securityKeyManager = Main.getKeyManager(); // Это com.ryumessenger.security.KeyManager
                            if (securityKeyManager != null) {
                                securityKeyManager.setServerRSAPublicKey(n, e);
                                LOGGER.info("ApiClient: Публичный RSA ключ сервера успешно установлен в security.KeyManager");
                            } else {
                                LOGGER.warning("ApiClient: security.KeyManager is null. Не удалось установить RSA ключ сервера.");
                            }
                            
                            // Устанавливаем ключ в старый com.ryumessenger.crypto.KeyManager
                            com.ryumessenger.crypto.KeyManager legacyKeyManager = Main.getLegacyKeyManager();
                            if (legacyKeyManager != null) {
                                legacyKeyManager.setServerRsaPublicKey(nStr, eStr); // Старый метод принимает строки
                                LOGGER.info("ApiClient: Публичный RSA ключ сервера успешно установлен в legacy.KeyManager");
                            } else {
                                LOGGER.warning("ApiClient: legacy.KeyManager is null. Не удалось установить RSA ключ сервера.");
                            }
                        }
                        
                        // Получаем параметры Диффи-Хеллмана (публичный ключ сервера DH)
                        if (data.has("dh_public_key_y")) {
                            String dhPublicKeyYStr = data.getString("dh_public_key_y");
                            BigInteger dhPublicKeyY = new BigInteger(dhPublicKeyYStr);
                            
                            KeyManager securityKeyManager = Main.getKeyManager(); // Это com.ryumessenger.security.KeyManager
                            if (securityKeyManager != null) {
                                try {
                                    securityKeyManager.setServerDHPublicKey(dhPublicKeyY);
                                    LOGGER.info("ApiClient: Публичный DH ключ сервера успешно установлен в security.KeyManager");
                                } catch (Exception ex) {
                                    LOGGER.log(Level.SEVERE, "ApiClient: Ошибка при установке DH ключа сервера в security.KeyManager", ex);
                                }
                            }

                            // Также устанавливаем ключ и в KeyManagerAdapter, если он это поддерживает
                            // KeyManagerAdapter имеет setServerDHPublicKey(BigInteger dhPublicKey)
                            KeyManagerAdapter adapter = Main.getSecurityKeyManager();
                            if (adapter != null) {
                                try {
                                    adapter.setServerDHPublicKey(dhPublicKeyY); // Адаптер должен быть способен обработать это
                                    LOGGER.info("ApiClient: Публичный DH ключ сервера успешно установлен в KeyManagerAdapter");
                                } catch (Exception ex) {
                                    LOGGER.log(Level.WARNING, "Ошибка при установке ключа DH в KeyManagerAdapter", ex);
                                }
                            }
                        }

                        success = true; // Успех, если хотя бы что-то было установлено
                    }
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "ApiClient: Ошибка при обработке ключей сервера", e);
                }
            }
            
            if (callback != null) {
                callback.accept(success);
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

        com.ryumessenger.security.AuthPayloadFormatter authPayloadFormatter = Main.getAuthPayloadFormatter();

        if (authPayloadFormatter == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: AuthPayloadFormatter not initialized. Cannot proceed with login.");
            CryptoLogWindow.logOperation("Ошибка входа", "AuthPayloadFormatter не инициализирован");
            if (callback != null) callback.accept(new ApiResponse(500, "Client configuration error", null, null));
            return;
        }

        Map<String, Object> loginRequestMap;
        try {
            loginRequestMap = authPayloadFormatter.createLoginRequest(username, password);
            if (loginRequestMap == null) {
                throw new RuntimeException("createLoginRequest вернул null");
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "ApiClient: Failed to create login request payload using AuthPayloadFormatter.", e);
            CryptoLogWindow.logOperation("Ошибка входа", "Не удалось создать данные для входа: " + e.getMessage());
            if (callback != null) callback.accept(new ApiResponse(500, "Encryption error for login: " + e.getMessage(), null, null));
            return;
        }

        String requestBodyString = new JSONObject(loginRequestMap).toString();

        post("/login", requestBodyString, callback);
    }

    /**
     * @deprecated Используйте CompletableFuture<ApiResponse> register(Map<String, Object> registrationPayload)
     */
    @Deprecated
    public void register(String username, String password, String displayName, String tag, Consumer<ApiResponse> callback) {
        LOGGER.info("ApiClient: Регистрация пользователя " + username + " (СТАРЫЙ МЕТОД, используется Consumer)");
        CryptoLogWindow.logOperation("Регистрация (старый)", "Пользователь: " + username);
        
        try {
            JSONObject payload = new JSONObject();
            payload.put("username", username);
            payload.put("password", password); // Пароль здесь должен быть уже зашифрован?
                                             // Старый метод, вероятно, ожидал сырой или как-то иначе обработанный пароль
            payload.put("displayName", displayName);
            payload.put("tag", tag);
            
            // Этот старый метод не использует AuthPayloadFormatter и RSA шифрование всего payload
            // Он, вероятно, ожидает, что сервер сам обработает данные как есть или по-другому.
            // Для новой логики используется перегруженный метод.
            
            post("/auth/register", payload.toString(), callback);
        } catch (JSONException e) {
            LOGGER.log(Level.SEVERE, "ApiClient: Ошибка при создании JSON для регистрации", e);
            CryptoLogWindow.logOperation("Ошибка регистрации", "Ошибка JSON: " + e.getMessage());
            callback.accept(new ApiResponse(500, "Ошибка создания запроса: " + e.getMessage(), null, null));
        }
    }

    /**
     * Новый метод регистрации, принимающий Map<String, Object> и возвращающий CompletableFuture.
     * Этот payload должен быть уже подготовлен AuthPayloadFormatter.
     */
    public CompletableFuture<ApiResponse> register(Map<String, Object> registrationPayload) {
        LOGGER.info("ApiClient: Регистрация пользователя с использованием Map<String, Object> (новый метод)");
        CryptoLogWindow.logOperation("Регистрация (новый)", "Отправка подготовленного payload...");
        
        CompletableFuture<ApiResponse> future = new CompletableFuture<>();
        
        try {
            String jsonPayload = new JSONObject(registrationPayload).toString();
            
            // Используем performRequestAsync (если есть) или адаптируем performRequest
            // Для простоты создадим новую обертку, возвращающую CompletableFuture
            // или модифицируем performRequest, чтобы он мог возвращать CompletableFuture.
            // Пока что воспользуемся существующим post, который принимает Consumer.
            
            post("/auth/register", jsonPayload, apiResponse -> {
                if (apiResponse.getStatusCode() == 0 && apiResponse.getBody() != null && apiResponse.getBody().startsWith("java.net.ConnectException")) {
                     // Особая обработка ошибки соединения для CompletableFuture
                    future.completeExceptionally(new IOException("Ошибка соединения: " + apiResponse.getBody()));
                } else if (apiResponse.isSuccess()) {
                    future.complete(apiResponse);
                } else {
                    // Оборачиваем неуспешный ответ в исключение, чтобы его можно было поймать в exceptionally()
                    future.completeExceptionally(new ApiException("Ошибка регистрации: " + apiResponse.getErrorMessage(), apiResponse));
                }
            });
            
        } catch (Exception e) { // Включая JSONException, если new JSONObject(map) его бросит
            LOGGER.log(Level.SEVERE, "ApiClient: Ошибка при создании JSON для регистрации из Map", e);
            CryptoLogWindow.logOperation("Ошибка регистрации (новый)", "Ошибка JSON: " + e.getMessage());
            future.completeExceptionally(e);
        }
        return future;
    }

    public void logout(Consumer<ApiResponse> callback) {
        post("/logout", "{}", callback);
    }

    public void changePassword(String currentPassword, String newPassword, Consumer<ApiResponse> callback) {
        com.ryumessenger.security.AuthPayloadFormatter authPayloadFormatter = Main.getAuthPayloadFormatter();
        com.ryumessenger.security.KeyManager keyManager = Main.getKeyManager();
        User currentUser = Main.getCurrentUser();

        if (authPayloadFormatter == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: AuthPayloadFormatter not initialized for changePassword.");
            if (callback != null) callback.accept(new ApiResponse(500, "Client configuration error for changePassword", null, null));
            return;
        }
        if (keyManager == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: KeyManager (security) not initialized for changePassword.");
            if (callback != null) callback.accept(new ApiResponse(500, "Client configuration error (KeyManager missing) for changePassword", null, null));
            return;
        }
        if (currentUser == null) {
            LOGGER.log(Level.SEVERE, "ApiClient: No current user found for changePassword.");
            if (callback != null) callback.accept(new ApiResponse(401, "User not logged in", null, null));
            return;
        }

        String encryptedUpdatePayload;
        try {
            String clientDhPublicKeyY = keyManager.getClientDHPublicKeyY().toString();
            if (clientDhPublicKeyY == null) {
                 throw new RuntimeException("Client DH public key is null");
            }
            encryptedUpdatePayload = authPayloadFormatter.formatChangePasswordPayload(currentPassword, newPassword, clientDhPublicKeyY);
            if (encryptedUpdatePayload == null) {
                throw new RuntimeException("formatChangePasswordPayload вернул null");
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "ApiClient: Failed to create encrypted change password payload.", e);
            if (callback != null) callback.accept(new ApiResponse(500, "Encryption error for change password: " + e.getMessage(), null, null));
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

        public String getErrorMessage() {
            if (json != null && json.has("message")) {
                return json.getString("message");
            }
            if (json != null && json.has("error")) {
                return json.getString("error");
            }
            // Если тело ответа содержит сообщение об ошибке (например, при статусе 4xx, 5xx без JSON)
            if (!isSuccess() && body != null && !body.trim().isEmpty() && body.length() < 200) { // Ограничим длину, чтобы не возвращать HTML страницы ошибок
                return body; 
            }
            return "Неизвестная ошибка (код: " + statusCode + ")";
        }
    }
    
    // Вспомогательный класс исключения для CompletableFuture
    public static class ApiException extends Exception {
        private final ApiResponse apiResponse;
        public ApiException(String message, ApiResponse apiResponse) {
            super(message);
            this.apiResponse = apiResponse;
        }
        public ApiResponse getApiResponse() {
            return apiResponse;
        }
    }
}