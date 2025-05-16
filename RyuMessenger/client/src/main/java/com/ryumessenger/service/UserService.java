package com.ryumessenger.service;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import org.json.JSONObject;

import com.ryumessenger.Main;
import com.ryumessenger.model.User;
import com.ryumessenger.network.ApiClient;
import com.ryumessenger.crypto.EncryptionService;

/**
 * Сервис для управления операциями пользователя: регистрация, вход, поиск.
 */
public class UserService {

    private final ApiClient apiClient;
    private final EncryptionService encryptionService;

    public UserService(ApiClient apiClient, EncryptionService encryptionService) {
        this.apiClient = apiClient;
        this.encryptionService = encryptionService;
    }

    /**
     * Выполняет регистрацию пользователя асинхронно.
     * @param username Имя пользователя
     * @param tag Тег пользователя
     * @param displayName Отображаемое имя пользователя
     * @param password Пароль (незашифрованный)
     * @param callback Функция обратного вызова, принимающая ApiResponse
     */
    public void register(String username, String tag, String displayName, String password, Consumer<ApiClient.ApiResponse> callback) {
        apiClient.register(username, password, displayName, tag, response -> {
            callback.accept(response);
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
} 