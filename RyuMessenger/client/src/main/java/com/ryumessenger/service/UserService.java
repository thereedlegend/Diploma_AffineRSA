package com.ryumessenger.service;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.math.BigInteger;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONObject;

import com.ryumessenger.Main;
import com.ryumessenger.model.User;
import com.ryumessenger.network.ApiClient;
import com.ryumessenger.crypto.EncryptionService;
import com.ryumessenger.security.AuthPayloadFormatter;
import com.ryumessenger.security.Pair;

/**
 * Сервис для управления операциями пользователя: регистрация, вход, поиск.
 */
public class UserService {

    private static final Logger LOGGER = Logger.getLogger(UserService.class.getName());

    private final ApiClient apiClient;
    private final EncryptionService encryptionService;
    private final AuthPayloadFormatter authPayloadFormatter;

    public UserService(ApiClient apiClient, EncryptionService encryptionService) {
        this.apiClient = apiClient;
        this.encryptionService = encryptionService;
        this.authPayloadFormatter = Main.getAuthPayloadFormatter();
        if (this.authPayloadFormatter == null) {
            LOGGER.log(Level.SEVERE, "AuthPayloadFormatter is null in UserService constructor. Registration might fail.");
        }
    }

    /**
     * Выполняет регистрацию пользователя асинхронно.
     * Использует AuthPayloadFormatter для подготовки данных и новый метод ApiClient.register.
     * @param username Имя пользователя
     * @param tag Тег пользователя
     * @param displayName Отображаемое имя пользователя
     * @param password Пароль (незашифрованный)
     * @param callback Функция обратного вызова, принимающая ApiResponse
     */
    public void register(String username, String tag, String displayName, String password, Consumer<ApiClient.ApiResponse> callback) {
        if (authPayloadFormatter == null) {
            LOGGER.log(Level.SEVERE, "AuthPayloadFormatter не инициализирован в UserService. Невозможно выполнить регистрацию.");
            if (callback != null) {
                callback.accept(new ApiClient.ApiResponse(500, "Client configuration error: AuthPayloadFormatter not available.", null, null));
            }
            return;
        }

        Map<String, Object> registrationPayload;
        try {
            registrationPayload = authPayloadFormatter.createRegistrationRequest(username, password, tag, displayName);
            if (registrationPayload == null) {
                throw new RuntimeException("createRegistrationRequest вернул null, возможно, отсутствуют ключи.");
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Ошибка при создании запроса на регистрацию в UserService: " + e.getMessage(), e);
            if (callback != null) {
                callback.accept(new ApiClient.ApiResponse(500, "Error creating registration payload: " + e.getMessage(), null, null));
            }
            return;
        }

        CompletableFuture<ApiClient.ApiResponse> future = apiClient.register(registrationPayload);

        future.thenAccept(response -> {
            if (callback != null) {
                callback.accept(response);
            }
        }).exceptionally(ex -> {
            if (callback != null) {
                LOGGER.log(Level.SEVERE, "Исключение при регистрации в UserService: " + ex.getMessage(), ex);
                if (ex.getCause() instanceof ApiClient.ApiException) {
                    callback.accept(((ApiClient.ApiException) ex.getCause()).getApiResponse());
                } else {
                    callback.accept(new ApiClient.ApiResponse(0, "Network or client error during registration: " + ex.getMessage(), null, null));
                }
            }
            return null;
        });
    }
    
    /**
     * Выполняет вход пользователя асинхронно.
     * @param username Имя пользователя (тег)
     * @param password Пароль (незашифрованный)
     * @param callback Функция обратного вызова, принимающая ApiResponse. 
     *                 В случае успеха, JSON в ответе будет содержать данные пользователя.
     */
    public void login(String username, String password, Consumer<Boolean> callback) {
        apiClient.login(username, password, response -> {
            if (response.isSuccess() && response.getJson() != null) {
                JSONObject json = response.getJson();
                if (json.has("token") && json.has("user")) {
                    String token = json.getString("token");
                    User user = new User(json.getJSONObject("user"));
                    Main.setAuthToken(token);
                    Main.setCurrentUser(user);
                    callback.accept(true);
                } else {
                    callback.accept(false);
                }
            } else {
                callback.accept(false);
            }
        });
    }
    
    /**
     * Выполняет поиск пользователей по тегу (tag) асинхронно.
     *
     * @param tag    Строка для поиска (часть тега).
     * @param callback Функция обратного вызова, принимающая список JSONObject пользователей
     *                 (каждый объект содержит "id", "username", "tag") или пустой список при ошибке/отсутствии результатов.
     */
    public void searchUsers(String tagQuery, Consumer<List<User>> callback) {
        if (apiClient == null) {
            System.err.println("UserService: API клиент не инициализирован");
            if (callback != null) callback.accept(null);
            return;
        }

        if (encryptionService == null) {
            System.err.println("UserService: Сервис шифрования не инициализирован");
            if (callback != null) callback.accept(null);
            return;
        }

        // Шифруем запрос тега сначала с Affine, затем с RSA
        System.out.println("UserService: Начинаем поиск пользователя по тегу: " + tagQuery);
        String encryptedTagPayload = encryptionService.encryptTagSearchPayloadForServer(tagQuery);

        if (encryptedTagPayload == null) {
            System.err.println("UserService: Не удалось зашифровать запрос тега");
            if (callback != null) callback.accept(null);
            return;
        }

        apiClient.postSearchUsers(encryptedTagPayload, response -> {
            if (response.isSuccess()) {
                try {
                    List<User> foundUsers = new ArrayList<>();
                    if (response.getJson() != null && response.getJson().has("users")) {
                        org.json.JSONArray usersArray = response.getJson().getJSONArray("users");
                        for (int i = 0; i < usersArray.length(); i++) {
                            org.json.JSONObject userJson = usersArray.getJSONObject(i);
                            User user = new User(userJson);
                            foundUsers.add(user);
                        }
                        System.out.println("UserService: Найдено пользователей: " + foundUsers.size());
                        for (User user : foundUsers) {
                            System.out.println("UserService: - " + user.toString());
                        }
                    }
                    if (callback != null) callback.accept(foundUsers);
                } catch (Exception e) {
                    System.err.println("UserService: Ошибка при разборе ответа с пользователями: " + e.getMessage());
                    if (callback != null) callback.accept(null);
                }
            } else {
                System.err.println("UserService: " + (response.getBody() != null ? response.getBody() : "No users found for tag: " + tagQuery));
                if (callback != null) callback.accept(new ArrayList<>());
            }
        });
    }
    
    /**
     * Очищает данные о текущем пользователе, если они кешируются в этом сервисе.
     * В текущей реализации пользователь хранится в Main.currentUser, так что здесь
     * дополнительных действий не требуется, кроме логирования.
     */
    public void clearCurrentUser() {
        Main.setCurrentUser(null);
        Main.setAuthToken(null);
    }

    public void changeTag(String newTag, Consumer<Boolean> callback) {
        JSONObject changes = new JSONObject();
        changes.put("tag", newTag);
        apiClient.updateUser(changes, response -> {
            if (response.isSuccess() && response.getJson() != null) {
                // Предполагается, что ответ содержит обновленного пользователя
                // или хотя бы поле "user" с обновленными данными.
                JSONObject responseJson = response.getJson();
                if (responseJson.has("user")) {
                    User updatedUser = new User(responseJson.getJSONObject("user"));
                    Main.setCurrentUser(updatedUser);
                } else if (Main.getCurrentUser() != null) {
                    // Если полного объекта пользователя нет, но есть текущий, обновим его локально
                    Main.getCurrentUser().setTag(newTag); // Обновляем тег локально
                }
                callback.accept(true);
            } else {
                System.err.println("Failed to change tag. Status: " + response.getStatusCode() + ", Body: " + response.getBody());
                callback.accept(false);
            }
        });
    }

    public void changePassword(String currentPassword, String newPassword, Consumer<Boolean> callback) {
        apiClient.changePassword(currentPassword, newPassword, response -> {
            callback.accept(response.isSuccess());
        });
    }

    public void changeDisplayName(String newDisplayName, Consumer<Boolean> callback) {
        JSONObject changes = new JSONObject();
        changes.put("displayName", newDisplayName);
        apiClient.updateUser(changes, response -> {
            if (response.isSuccess()) {
                // Предполагается, что ответ может содержать обновленного пользователя
                // или хотя бы поле "user" с обновленными данными.
                // Или просто подтверждение успеха.
                JSONObject responseJson = response.getJson();
                if (responseJson != null && responseJson.has("user")) {
                    User updatedUser = new User(responseJson.getJSONObject("user"));
                    Main.setCurrentUser(updatedUser);
                } else if (Main.getCurrentUser() != null) {
                    // Если полного объекта пользователя нет, но есть текущий, обновим его локально
                     Main.getCurrentUser().setDisplayName(newDisplayName);
                }
                callback.accept(true);
            } else {
                System.err.println("Failed to change display name. Status: " + response.getStatusCode() + ", Body: " + response.getBody());
                callback.accept(false);
            }
        });
    }

    public void logout(Consumer<Boolean> callback) {
        apiClient.logout(response -> {
            if (response.isSuccess()) {
                Main.setAuthToken(null);
                Main.setCurrentUser(null);
                callback.accept(true);
            } else {
                callback.accept(false);
            }
        });
    }

    public void fetchCurrentUser(Consumer<User> callback) {
        apiClient.get("/user/me", response -> { 
            if (response.isSuccess() && response.getJson() != null && response.getJson().has("user")) {
                User user = new User(response.getJson().getJSONObject("user"));
                Main.setCurrentUser(user);
                callback.accept(user);
            } else {
                callback.accept(null);
            }
        });
    }

    /**
     * Регистрирует нового пользователя с использованием улучшенного шифрования
     *
     * @param username Имя пользователя
     * @param password Пароль пользователя
     * @param displayName Отображаемое имя
     * @param tag Уникальный тег пользователя
     * @param callback Коллбэк по завершению (true - успех, сообщение)
     */
    public void registerSecureUser(String username, String password, String displayName, String tag, Consumer<Pair<Boolean, String>> callback) {
        try {
            // Получаем форматтер безопасных сообщений из Main
            com.ryumessenger.security.SecureMessageFormatter secureFormatter = Main.getSecureMessageFormatter();
            
            if (secureFormatter == null) {
                System.err.println("UserService: SecureMessageFormatter не инициализирован");
                if (callback != null) {
                    callback.accept(new Pair<>(false, "Ошибка шифрования: компонент безопасности не инициализирован"));
                }
                return;
            }
            
            // Зашифровываем пароль с использованием улучшенного шифрования
            String encryptedPasswordPayload = secureFormatter.formatSecurePassword(password);
            
            // Получаем публичный ключ RSA клиента
            com.ryumessenger.security.KeyManagerAdapter keyManager = Main.getSecurityKeyManager();
            BigInteger[] rsaPublicKey = keyManager.getClientRSAPublicKey();
            
            // Создаем JSON для запроса
            JSONObject requestData = new JSONObject();
            requestData.put("username", username);
            requestData.put("display_name", displayName);
            requestData.put("tag", tag);
            requestData.put("encrypted_password_payload", encryptedPasswordPayload);
            requestData.put("rsa_public_key_n", rsaPublicKey[0].toString());
            requestData.put("rsa_public_key_e", rsaPublicKey[1].toString());
            
            // Также добавляем публичный ключ DH для будущих обменов
            BigInteger dhPublicKey = keyManager.getClientDHPublicKey();
            requestData.put("dh_public_key", dhPublicKey.toString());
            
            System.out.println("UserService: Отправляем данные для регистрации пользователя " + username);
            
            // Отправляем запрос
            apiClient.post("/register", requestData.toString(), response -> {
                if (response.isSuccess()) {
                    System.out.println("UserService: Пользователь " + username + " успешно зарегистрирован");
                    if (callback != null) {
                        callback.accept(new Pair<>(true, "Регистрация успешна. Теперь вы можете войти в систему."));
                    }
                } else {
                    String errorMessage = "Неизвестная ошибка при регистрации";
                    
                    // Пытаемся получить сообщение об ошибке из ответа
                    JSONObject json = response.getJson();
                    if (json != null && json.has("error")) {
                        errorMessage = json.getString("error");
                    }
                    
                    System.err.println("UserService: Ошибка при регистрации пользователя " + username + ": " + errorMessage);
                    
                    if (callback != null) {
                        callback.accept(new Pair<>(false, "Ошибка регистрации: " + errorMessage));
                    }
                }
            });
            
        } catch (Exception e) {
            System.err.println("UserService: Исключение при регистрации пользователя: " + e.getMessage());
            e.printStackTrace();
            
            if (callback != null) {
                callback.accept(new Pair<>(false, "Ошибка: " + e.getMessage()));
            }
        }
    }

    /**
     * Входит в систему с использованием улучшенного шифрования
     *
     * @param username Имя пользователя
     * @param password Пароль пользователя
     * @param callback Коллбэк по завершению (true - успех, сообщение)
     */
    public void loginSecure(String username, String password, Consumer<Pair<Boolean, String>> callback) {
        try {
            // Получаем форматтер безопасных сообщений из Main
            com.ryumessenger.security.SecureMessageFormatter secureFormatter = Main.getSecureMessageFormatter();
            
            if (secureFormatter == null) {
                System.err.println("UserService: SecureMessageFormatter не инициализирован");
                if (callback != null) {
                    callback.accept(new Pair<>(false, "Ошибка шифрования: компонент безопасности не инициализирован"));
                }
                return;
            }
            
            // Зашифровываем пароль с использованием улучшенного шифрования
            String encryptedPasswordPayload = secureFormatter.formatSecurePassword(password);
            
            // Создаем JSON для запроса
            JSONObject requestData = new JSONObject();
            requestData.put("username", username);
            requestData.put("encrypted_login_payload", encryptedPasswordPayload);
            
            System.out.println("UserService: Отправляем данные для входа пользователя " + username);
            
            // Отправляем запрос
            apiClient.post("/login", requestData.toString(), response -> {
                if (response.isSuccess()) {
                    try {
                        JSONObject json = response.getJson();
                        
                        // Получаем токен
                        String token = json.getJSONObject("data").getString("token");
                        
                        // Получаем данные пользователя
                        JSONObject userData = json.getJSONObject("data").getJSONObject("user");
                        int userId = userData.getInt("id");
                        String displayName = userData.getString("display_name");
                        String tag = userData.getString("tag");
                        
                        // Сохраняем данные пользователя
                        User user = new User(userId, username, displayName, tag);
                        
                        // Сохраняем текущего пользователя и токен
                        Main.setCurrentUser(user);
                        Main.setAuthToken(token);
                        
                        System.out.println("UserService: Пользователь " + username + " успешно вошел в систему");
                        
                        if (callback != null) {
                            callback.accept(new Pair<>(true, "Вход выполнен успешно"));
                        }
                    } catch (Exception e) {
                        System.err.println("UserService: Ошибка при обработке ответа сервера: " + e.getMessage());
                        
                        if (callback != null) {
                            callback.accept(new Pair<>(false, "Ошибка при обработке ответа сервера"));
                        }
                    }
                } else {
                    String errorMessage = "Неизвестная ошибка при входе";
                    
                    // Пытаемся получить сообщение об ошибке из ответа
                    JSONObject json = response.getJson();
                    if (json != null && json.has("error")) {
                        errorMessage = json.getString("error");
                    }
                    
                    System.err.println("UserService: Ошибка при входе пользователя " + username + ": " + errorMessage);
                    
                    if (callback != null) {
                        callback.accept(new Pair<>(false, "Ошибка входа: " + errorMessage));
                    }
                }
            });
            
        } catch (Exception e) {
            System.err.println("UserService: Исключение при входе пользователя: " + e.getMessage());
            e.printStackTrace();
            
            if (callback != null) {
                callback.accept(new Pair<>(false, "Ошибка: " + e.getMessage()));
            }
        }
    }
} 