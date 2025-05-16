package com.ryumessenger;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

// import org.json.JSONObject; // Не используется

import com.ryumessenger.crypto.EncryptionService;
import com.ryumessenger.crypto.KeyManager;
import com.ryumessenger.network.ApiClient;
import com.ryumessenger.service.UserService;
import com.ryumessenger.ui.LoginFrame;
import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.model.User;
import com.ryumessenger.ui.theme.AppTheme;
import com.ryumessenger.service.ChatService;
// import com.ryumessenger.ui.auth.LoginDialog; // УДАЛЕНО: Неразрешенный и, вероятно, неиспользуемый импорт
// import com.ryumessenger.ui.MainFrame; // Не используется - УДАЛЕНО

public class Main {

    private static KeyManager keyManager;
    private static EncryptionService encryptionService;
    private static ApiClient apiClient;
    private static ChatService chatService;
    private static UserService userService;
    private static User currentUser;
    private static String authToken;
    private static LoginFrame loginFrameInstance; // Добавлено поле для экземпляра LoginFrame

    private static boolean serverPublicKeyFetched = false; // Флаг успешной загрузки ключа

    public static void main(String[] args) {
        System.setProperty("file.encoding", "UTF-8");
        
        // Инициализация менеджера тем до создания UI
        // Устанавливаем тему по умолчанию. notifyComponents() будет вызван внутри setTheme.
        ThemeManager.getInstance().setTheme(AppTheme.DARK_THEME); 

        // Инициализация криптографических сервисов
        // loadOrGenerateKeys() вызывается в конструкторе KeyManager
        initializeServices();

        // Инициализируем UI сразу после запуска асинхронной задачи, чтобы приложение не завершалось
        initializeUI(); 
    }

    private static void initializeUI() {
        SwingUtilities.invokeLater(() -> {
            try {
                for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                    if ("Nimbus".equals(info.getName())) {
                        UIManager.setLookAndFeel(info.getClassName());
                        break;
                    }
                }
            } catch (Exception e) {
                System.err.println("Nimbus L&F not found, using default. Error: " + e.getMessage());
            }
            // Повторно применяем тему после установки Look and Feel, чтобы все компоненты обновились
            // Это вызовет notifyComponents() для всех зарегистрированных компонентов
            ThemeManager.getInstance().setTheme(ThemeManager.getInstance().getCurrentTheme());
            loginFrameInstance = new LoginFrame(); // Сохраняем экземпляр
            loginFrameInstance.setVisible(true); 
        });
    }

    private static void initializeServices() {
        apiClient = new ApiClient();
        
        // Создаем или загружаем ключи клиента
        keyManager = new KeyManager(System.getProperty("user.dir"));
        try {
            // KeyManager автоматически загружает или генерирует ключи в конструкторе,
            // поэтому нам не нужно явно вызывать loadClientKeys или generateAndSaveClientKeys
        } catch (Exception e) {
            System.err.println("Ошибка при инициализации ключей клиента: " + e.getMessage());
            e.printStackTrace();
        }
        
        // Инициализируем сервис шифрования
        encryptionService = new EncryptionService(keyManager);
        
        // Инициализируем другие сервисы зависящие от apiClient
        chatService = new ChatService(apiClient);
        userService = new UserService(apiClient, encryptionService); // Передаем и API клиент, и сервис шифрования
        
        // Запрашиваем публичный ключ сервера
        fetchServerPublicKey();
    }

    public static boolean isServerPublicKeyFetched() {
        return serverPublicKeyFetched;
    }

    // Методы доступа к глобальным сервисам (упрощенный подход)
    public static KeyManager getKeyManager() {
        return keyManager;
    }

    public static EncryptionService getEncryptionService() {
        return encryptionService;
    }

    public static ApiClient getApiClient() {
        return apiClient;
    }

    public static UserService getUserService() {
        return userService;
    }

    public static ChatService getChatService() {
        return chatService;
    }

    public static User getCurrentUser() {
        return currentUser;
    }

    public static void setCurrentUser(User user) {
        currentUser = user;
    }

    public static String getCurrentUserId() {
        return currentUser != null ? String.valueOf(currentUser.getId()) : null;
    }

    public static String getAuthToken() {
        return authToken;
    }

    public static void setAuthToken(String token) {
        authToken = token;
        if (apiClient != null) {
            apiClient.setAuthToken(token);
        }
    }

    public static void logout() {
        setCurrentUser(null);
        // Добавим проверку на null для userService, если он может быть не инициализирован
        if (userService != null) { 
            userService.clearCurrentUser();
        }
        // Сброс токена аутентификации в ApiClient
        if (apiClient != null) {
            apiClient.setAuthToken(null); 
        }
        serverPublicKeyFetched = false; // Сбрасываем флаг ключа сервера, т.к. сессия завершена
        // Повторно получаем ключ сервера для следующего входа
        // Это гарантирует, что если ключ изменился на сервере, мы получим актуальный
        if (apiClient != null) {
             System.out.println("Main: Attempting to re-fetch server public key after logout...");
            apiClient.fetchAndSetServerPublicKey(success -> {
                serverPublicKeyFetched = success;
                if (success) {
                    System.out.println("Main: Server public key re-fetched successfully after logout.");
                } else {
                    System.out.println("Main: Failed to re-fetch server public key after logout.");
                }
            });
        }
        System.out.println("Пользователь вышел из системы (Main context).");
    }

    private static void fetchServerPublicKey() {
        System.out.println("Main: Attempting to fetch server public key...");
        apiClient.fetchAndSetServerPublicKey(success -> {
            serverPublicKeyFetched = success;
            if (success) {
                System.out.println("Main: Server public key fetched successfully.");
            } else {
                System.out.println("Main: Failed to fetch server public key. Authentication features might be limited.");
                // В реальном приложении здесь можно показать пользователю неблокирующее уведомление
                // или диалог, если ключ критичен для ВСЕХ операций.
            }
            // После попытки получения ключа, обновить UI, если оно уже инициализировано
            SwingUtilities.invokeLater(() -> {
                if (loginFrameInstance != null && loginFrameInstance.isVisible()) {
                    loginFrameInstance.checkServerKeyStatusAndUpdateUI();
                }
            });
        });
    }
} 