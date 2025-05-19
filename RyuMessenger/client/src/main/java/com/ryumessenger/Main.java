package com.ryumessenger;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

// import org.json.JSONObject; // Не используется

import com.ryumessenger.crypto.EncryptionService;
// import com.ryumessenger.crypto.KeyManager; // Заменяем на новый KeyManager
import com.ryumessenger.network.ApiClient;
import com.ryumessenger.service.UserService;
import com.ryumessenger.ui.LoginFrame;
import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.model.User;
import com.ryumessenger.ui.theme.AppTheme;
import com.ryumessenger.service.ChatService;
// import com.ryumessenger.ui.auth.LoginDialog; // УДАЛЕНО: Неразрешенный и, вероятно, неиспользуемый импорт
// import com.ryumessenger.ui.MainFrame; // Не используется - УДАЛЕНО
import com.ryumessenger.security.KeyManagerAdapter;
import com.ryumessenger.security.SecureMessageFormatter;
import com.ryumessenger.security.KeyManager; // Новый импорт
import com.ryumessenger.security.AuthPayloadFormatter; // <--- Добавлен импорт
import com.ryumessenger.security.EnhancedAffineCipher; // <--- Добавлен импорт
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class Main {

    private static com.ryumessenger.crypto.KeyManager legacyKeyManager; // Переименовано для ясности
    private static KeyManager keyManager; // Новый менеджер ключей из com.ryumessenger.security
    private static AuthPayloadFormatter authPayloadFormatter; // <--- Добавлено поле
    private static EncryptionService encryptionService;
    private static ApiClient apiClient;
    private static ChatService chatService;
    private static UserService userService;
    private static User currentUser;
    private static String authToken;
    private static LoginFrame loginFrameInstance; // Добавлено поле для экземпляра LoginFrame

    // Сервисы безопасности
    private static KeyManagerAdapter securityKeyManagerAdapter; // Переименовано для ясности
    private static SecureMessageFormatter secureMessageFormatter;

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
        
        // Инициализируем старый KeyManager для обратной совместимости
        try {
            legacyKeyManager = new com.ryumessenger.crypto.KeyManager("."); // Используем текущую директорию как baseDir
        } catch (Exception e) {
            System.err.println("Ошибка при инициализации legacy KeyManager: " + e.getMessage());
            e.printStackTrace();
            // Рассмотреть возможность более строгой обработки, если legacyKeyManager критичен
        }

        // Инициализируем новый security.KeyManager
        try {
            keyManager = new KeyManager(); // Используем com.ryumessenger.security.KeyManager
        } catch (RuntimeException e) {
            System.err.println("КРИТИЧЕСКАЯ ОШИБКА при инициализации security.KeyManager: " + e.getMessage());
            e.printStackTrace();
            // Это может потребовать остановки приложения или уведомления пользователя
            // Для простоты пока только логируем
            // Если KeyManager не создан, дальнейшая инициализация зависимых компонентов не имеет смысла.
            return; 
        }
        
        // Инициализируем сервис шифрования со старым KeyManager
        if (legacyKeyManager != null) {
            encryptionService = new EncryptionService(legacyKeyManager);
        } else {
            System.err.println("EncryptionService не может быть инициализирован: legacyKeyManager is null");
        }
        
        // Инициализируем KeyManagerAdapter со старым KeyManager
        if (legacyKeyManager != null) {
            securityKeyManagerAdapter = new KeyManagerAdapter(legacyKeyManager);
        } else {
            System.err.println("KeyManagerAdapter не может быть инициализирован: legacyKeyManager is null");
        }
        
        // Создаем форматтер безопасных сообщений с KeyManagerAdapter
        if (securityKeyManagerAdapter != null) {
            secureMessageFormatter = new SecureMessageFormatter(securityKeyManagerAdapter);
        } else {
            System.err.println("SecureMessageFormatter не может быть инициализирован: securityKeyManagerAdapter is null");
        }
        
        chatService = new ChatService(apiClient);
        // UserService будет инициализирован позже, после попытки получить ключи сервера
        
        // Запрашиваем публичный ключ сервера и ждем его получения
        System.out.println("Main: Attempting to fetch server public key...");
        CompletableFuture<Boolean> serverKeyFuture = fetchServerPublicKey();
        
        try {
            Boolean keysFetchedSuccessfully = serverKeyFuture.get(30, TimeUnit.SECONDS); // Ожидаем до 30 секунд

            if (Boolean.TRUE.equals(keysFetchedSuccessfully) && keyManager != null && keyManager.isServerDHPublicKeyAvailable()) {
                System.out.println("Main: Server public keys fetched successfully. Initializing AuthPayloadFormatter...");
                byte[] dhSharedSecret = keyManager.getDHSharedSecret();
                if (dhSharedSecret != null) {
                    EnhancedAffineCipher enhancedAffineCipher = new EnhancedAffineCipher(dhSharedSecret);
                    authPayloadFormatter = new AuthPayloadFormatter(keyManager, enhancedAffineCipher);
                    System.out.println("Main: AuthPayloadFormatter initialized successfully.");
                } else {
                    System.err.println("Main: AuthPayloadFormatter could not be initialized: DH shared secret is still null after successful key fetch.");
                    authPayloadFormatter = null; // Явно указываем, что инициализация не удалась
                }
            } else {
                System.err.println("Main: Failed to fetch/set server public key, or DH key not available. AuthPayloadFormatter will not be initialized.");
                authPayloadFormatter = null; // Явно указываем, что инициализация не удалась
            }
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.err.println("Main: Error or timeout waiting for server public key: " + e.getMessage());
            e.printStackTrace();
            authPayloadFormatter = null; // Явно указываем, что инициализация не удалась
        }

        // Инициализируем UserService ПОСЛЕ попытки инициализации AuthPayloadFormatter
        if (encryptionService != null) {
            userService = new UserService(apiClient, encryptionService); // UserService вызовет getAuthPayloadFormatter()
        } else {
            System.err.println("UserService не может быть инициализирован: encryptionService is null");
        }
    }

    public static boolean isServerPublicKeyFetched() {
        return serverPublicKeyFetched;
    }

    // Методы доступа к глобальным сервисам
    // Этот метод теперь должен возвращать com.ryumessenger.security.KeyManager
    public static KeyManager getKeyManager() {
        if (keyManager == null) {
            System.err.println("KeyManager (security) не инициализирован! Попытка инициализации...");
            // Попытка аварийной инициализации, хотя это не лучшее место
            try {
                keyManager = new KeyManager(); // Используем com.ryumessenger.security.KeyManager
            } catch (RuntimeException e) {
                System.err.println("Аварийная инициализация KeyManager (security) не удалась: " + e.getMessage());
                e.printStackTrace();
                // Возвращаем null или выбрасываем исключение, чтобы явно указать на проблему
                return null; 
            }
        }
        return keyManager;
    }
    
    // Добавляем геттер для legacyKeyManager, если он нужен где-то еще напрямую
    public static com.ryumessenger.crypto.KeyManager getLegacyKeyManager() {
        return legacyKeyManager;
    }

    public static AuthPayloadFormatter getAuthPayloadFormatter() { // <--- Добавлен геттер
        if (authPayloadFormatter == null) {
            System.err.println("AuthPayloadFormatter is null. Attempting on-the-fly initialization.");
            if (keyManager != null && keyManager.isServerDHPublicKeyAvailable()) { 
                byte[] dhSharedSecret = keyManager.getDHSharedSecret();
                if (dhSharedSecret != null) {
                    EnhancedAffineCipher enhancedAffineCipher = new EnhancedAffineCipher(dhSharedSecret);
                    authPayloadFormatter = new AuthPayloadFormatter(keyManager, enhancedAffineCipher);
                    System.out.println("AuthPayloadFormatter successfully initialized on-the-fly.");
                } else {
                    System.err.println("On-the-fly initialization of AuthPayloadFormatter failed: DH shared secret is still null.");
                }
            } else {
                String reason = "KeyManager is " + (keyManager == null ? "null" : "available") + 
                                ", server DH public key available: " + (keyManager != null && keyManager.isServerDHPublicKeyAvailable()) + 
                                (keyManager != null && !keyManager.isServerDHPublicKeyAvailable() ? " (DH key likely not received from server or processing failed)" : "");
                System.err.println("On-the-fly initialization of AuthPayloadFormatter failed: " + reason);
            }
        }
        return authPayloadFormatter;
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

    // Метод для получения публичного ключа сервера.
    // Теперь возвращает CompletableFuture для отслеживания завершения.
    private static CompletableFuture<Boolean> fetchServerPublicKey() {
        CompletableFuture<Boolean> future = new CompletableFuture<>();
        System.out.println("[Main DEBUG] fetchServerPublicKey: Called by Main."); // DEBUG LOG
        apiClient.fetchAndSetServerPublicKey(success -> {
            System.out.println("[Main DEBUG] fetchServerPublicKey: ApiClient callback received. Success: " + success); // DEBUG LOG
            if (success) {
                System.out.println("[Main DEBUG] fetchServerPublicKey: ApiClient reported success. Checking KeyManager state..."); // DEBUG LOG
                boolean kmNotNull = keyManager != null;
                boolean dhKeyAvailable = kmNotNull && keyManager.isServerDHPublicKeyAvailable();
                boolean sharedSecretAvailable = dhKeyAvailable && keyManager.getDHSharedSecret() != null;
                
                System.out.println("[Main DEBUG] fetchServerPublicKey: KeyManager not null? " + kmNotNull); // DEBUG LOG
                System.out.println("[Main DEBUG] fetchServerPublicKey: DH Key Available in KeyManager? " + dhKeyAvailable); // DEBUG LOG
                System.out.println("[Main DEBUG] fetchServerPublicKey: DH Shared Secret Available in KeyManager? " + sharedSecretAvailable); // DEBUG LOG

                if (kmNotNull && dhKeyAvailable && sharedSecretAvailable) {
                    serverPublicKeyFetched = true; 
                    System.out.println("[Main DEBUG] fetchServerPublicKey: DH shared secret is available. Completing future with true."); // DEBUG LOG
                    future.complete(true);
                } else {
                    System.err.println("[Main DEBUG ERROR] fetchServerPublicKey: Server key processing reported success by ApiClient, but DH shared secret is NOT available in KeyManager."); // DEBUG LOG
                    serverPublicKeyFetched = false;
                    future.complete(false); 
                }
            } else {
                System.err.println("[Main DEBUG ERROR] fetchServerPublicKey: ApiClient reported failure. Completing future with false."); // DEBUG LOG
                serverPublicKeyFetched = false;
                future.complete(false);
            }
        });
        return future;
    }

    /**
     * Возвращает адаптер KeyManager с поддержкой Диффи-Хеллмана
     * Этот метод будет возвращать адаптер, инициализированный старым KeyManager.
     * Используется в ApiClient для установки ключа сервера в оба менеджера.
     * TODO: Проверить, нужен ли он еще после рефакторинга KeyManager.
     */
    public static KeyManagerAdapter getSecurityKeyManager() { // Имя этого метода может сбивать с толку теперь
        return securityKeyManagerAdapter; // Возвращаем адаптер, который обертывает legacyKeyManager
    }

    /**
     * Возвращает форматтер безопасных сообщений
     */
    public static SecureMessageFormatter getSecureMessageFormatter() {
        return secureMessageFormatter;
    }
} 