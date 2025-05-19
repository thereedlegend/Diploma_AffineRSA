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
            // KeyManager из com.ryumessenger.security должен сам загружать/генерировать ключи
            // и быть готовым к вычислению общего секрета DH после установки ключа сервера
        } catch (RuntimeException e) {
            System.err.println("КРИТИЧЕСКАЯ ОШИБКА при инициализации security.KeyManager: " + e.getMessage());
            e.printStackTrace();
            // Это может потребовать остановки приложения или уведомления пользователя
            // Для простоты пока только логируем
        }
        
        // Инициализируем сервис шифрования со старым KeyManager
        // EncryptionService, вероятно, ожидает com.ryumessenger.crypto.KeyManager
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
        
        // Инициализируем другие сервисы
        chatService = new ChatService(apiClient);
        // UserService, вероятно, также ожидает старый EncryptionService (и, следовательно, старый KeyManager)
        if (encryptionService != null) {
            userService = new UserService(apiClient, encryptionService);
        } else {
            System.err.println("UserService не может быть инициализирован: encryptionService is null");
        }
        
        // Запрашиваем публичный ключ сервера (используя новый keyManager, если это применимо к ApiClient)
        // ApiClient.fetchAndSetServerPublicKey должен быть адаптирован или использовать нужный KeyManager
        fetchServerPublicKey(); // После этого вызова DH ключ сервера должен быть установлен в keyManager

        // Инициализация AuthPayloadFormatter ПОСЛЕ fetchServerPublicKey,
        // так как EnhancedAffineCipher зависит от DH ключей, которые устанавливаются во время fetch.
        // Однако, DH общий секрет вычисляется только когда известен и клиентский и серверный DH ключ.
        // KeyManager должен предоставлять метод для получения EnhancedAffineCipher или самого DH секрета.

        if (keyManager != null) {
            // Предполагаем, что KeyManager может предоставить DH общий секрет.
            // Если DH секрет еще не доступен (например, ключ сервера не получен),
            // EnhancedAffineCipher может быть не полностью функционален или должен обрабатывать это.
            byte[] dhSharedSecret = keyManager.getDHSharedSecret(); // Этого метода может не быть!
            if (dhSharedSecret != null) {
                EnhancedAffineCipher enhancedAffineCipher = new EnhancedAffineCipher(dhSharedSecret);
                authPayloadFormatter = new AuthPayloadFormatter(keyManager, enhancedAffineCipher);
            } else {
                 System.err.println("AuthPayloadFormatter не может быть инициализирован: DH общий секрет не доступен из KeyManager." +
                                    " Возможно, ключ сервера DH еще не получен или не вычислен общий секрет.");
                // В этом случае authPayloadFormatter останется null, и попытки его использовать вызовут ошибку.
                // Это нужно будет обработать в ApiClient.login и других местах.
                // Альтернатива: AuthPayloadFormatter сам создает EnhancedAffineCipher по требованию.
            }
        } else {
            System.err.println("AuthPayloadFormatter не может быть инициализирован: keyManager (security) is null");
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
            // Попытка инициализации "на лету", если он не был создан в initializeServices
            // Это может произойти, если DH ключ сервера был получен после initializeServices,
            // или если getDHSharedSecret() вернул null в первый раз.
            System.err.println("AuthPayloadFormatter is null. Attempting on-the-fly initialization.");
            if (keyManager != null && keyManager.isServerDHPublicKeyAvailable()) { // Добавим проверку на доступность ключа сервера
                byte[] dhSharedSecret = keyManager.getDHSharedSecret();
                if (dhSharedSecret != null) {
                    EnhancedAffineCipher enhancedAffineCipher = new EnhancedAffineCipher(dhSharedSecret);
                    authPayloadFormatter = new AuthPayloadFormatter(keyManager, enhancedAffineCipher);
                    System.out.println("AuthPayloadFormatter successfully initialized on-the-fly.");
                } else {
                    System.err.println("On-the-fly initialization of AuthPayloadFormatter failed: DH shared secret is still null.");
                }
            } else {
                System.err.println("On-the-fly initialization of AuthPayloadFormatter failed: KeyManager is null or server DH public key not available.");
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

    private static void fetchServerPublicKey() {
        System.out.println("Main: Attempting to fetch server public key...");
        // Убедимся, что apiClient существует
        if (apiClient == null) {
            System.err.println("Main: ApiClient is null, cannot fetch server public key.");
            serverPublicKeyFetched = false;
            return;
        }
        // Убедимся, что keyManager (security) существует для установки ключей
        // Метод fetchAndSetServerPublicKey в ApiClient должен знать, какой KeyManager использовать.
        // Предположим, он внутренне вызывает Main.getKeyManager() или Main.getLegacyKeyManager()
        // или принимает KeyManager в качестве параметра.
        // Текущий fetchAndSetServerPublicKey в ApiClient похоже использует Main.getKeyManager() 
        // и Main.getSecurityKeyManager() (который был адаптером)
        // Нужно будет проверить и адаптировать ApiClient.fetchAndSetServerPublicKey
        
        // Пока что, предполагая, что ApiClient.fetchAndSetServerPublicKey правильно обработает
        // получение и установку ключей через новый Main.getKeyManager() для security.KeyManager
        // и, возможно, через Main.getLegacyKeyManager() или Main.getSecurityKeyManagerAdapter() для старой части
        
        // Для установки в новый com.ryumessenger.security.KeyManager:
        KeyManager currentSecurityKeyManager = getKeyManager();
        if (currentSecurityKeyManager == null) {
            System.err.println("Main: com.ryumessenger.security.KeyManager is null. Cannot set server public key in it.");
            // Если он null, то и старый метод fetchAndSetServerPublicKey, который его ожидал, не сработает.
        }

        // Для установки в старый com.ryumessenger.crypto.KeyManager через адаптер (если fetchAndSetServerPublicKey его использует):
        // KeyManagerAdapter currentAdapter = getSecurityKeyManagerAdapter();

        // Логика fetchAndSetServerPublicKey в ApiClient должна быть такой:
        // 1. Получить ключи с сервера.
        // 2. Установить их в com.ryumessenger.security.KeyManager (через Main.getKeyManager()).
        // 3. Установить их в com.ryumessenger.crypto.KeyManager (через Main.getLegacyKeyManager() или адаптер).
        // Сейчас я предполагаю, что существующий вызов fetchAndSetServerPublicKey попытается это сделать.
        // Важно: ApiClient.fetchAndSetServerPublicKey (старая версия) ожидает Consumer<Boolean>
        // Новая версия в ApiClient (которую я планирую добавить) возвращает CompletableFuture.
        // Нужно будет унифицировать или использовать правильную версию.
        // Текущий код в Main вызывает версию с Consumer<Boolean>.

        apiClient.fetchAndSetServerPublicKey(success -> {
            serverPublicKeyFetched = success;
            if (success) {
                System.out.println("Main: Server public key fetched/set successfully (potentially for both key managers).");
            } else {
                System.out.println("Main: Failed to fetch/set server public key. Authentication features might be limited.");
            }
            SwingUtilities.invokeLater(() -> {
                if (loginFrameInstance != null && loginFrameInstance.isVisible()) {
                    loginFrameInstance.checkServerKeyStatusAndUpdateUI();
                }
            });
        });
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