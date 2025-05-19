package com.ryumessenger.ui;

import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.BorderFactory;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

import com.ryumessenger.Main;
import com.ryumessenger.network.ApiClient;
import com.ryumessenger.service.UserService;
import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.ui.theme.ThemedComponent;
import com.ryumessenger.ui.theme.AppTheme;
import com.ryumessenger.security.AuthPayloadFormatter;
import com.ryumessenger.network.ApiClient.ApiResponse;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.json.JSONObject;

public class RegisterFrame extends JFrame implements ThemedComponent {

    private RoundedTextField usernameField;
    private RoundedTextField tagField;
    private RoundedTextField displayNameField;
    private RoundedPasswordField passwordField;
    private RoundedPasswordField confirmPasswordField;
    private RoundedButton registerButton;
    private RoundedButton backToLoginButton;
    private JLabel statusLabel;
    
    private final ThemeManager themeManager;
    private final boolean showCryptoLog;
    
    private JLabel titleLabel;
    private JLabel usernameLabel;
    private JLabel tagLabel;
    private JLabel displayNameLabel;
    private JLabel passwordLabel;
    private JLabel confirmPasswordLabel;

    private JPanel buttonPanel;
    private static final int BUTTON_CORNER_RADIUS = 15;
    private static final int FIELD_CORNER_RADIUS = 15;
    private JPanel mainPanel;

    public RegisterFrame(UserService userService) {
        this(userService, false);
    }

    public RegisterFrame(UserService userService, boolean showCryptoLog) {
        this.showCryptoLog = showCryptoLog;
        
        setTitle("Ryu Messenger - Регистрация");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setResizable(false);
        
        themeManager = ThemeManager.getInstance();
        
        initComponents();
        themeManager.registerThemedComponent(this);
        checkServerKeyStatusAndUpdateUI();
        
        // Отображаем журнал шифрования, если нужно
        if (showCryptoLog) {
            CryptoLogWindow.getInstance().setVisible(true);
            CryptoLogWindow.log("Окно регистрации создано");
        }
        
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                themeManager.unregisterThemedComponent(RegisterFrame.this);
            }
        });
        pack();
        setLocationRelativeTo(null);
    }

    private void initComponents() {
        mainPanel = new JPanel(new GridBagLayout());
        setContentPane(mainPanel);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 10, 8, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        titleLabel = new JLabel("Регистрация", SwingConstants.CENTER);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        mainPanel.add(titleLabel, gbc);

        gbc.gridwidth = 1;
        gbc.weightx = 0.0;
        gbc.anchor = GridBagConstraints.WEST;

        usernameLabel = new JLabel("Логин:");
        gbc.gridx = 0;
        gbc.gridy = 1;
        mainPanel.add(usernameLabel, gbc);

        usernameField = new RoundedTextField(20);
        usernameField.setCornerRadius(FIELD_CORNER_RADIUS);
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.weightx = 1.0;
        mainPanel.add(usernameField, gbc);

        tagLabel = new JLabel("Тег:     ");
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0.0;
        mainPanel.add(tagLabel, gbc);

        tagField = new RoundedTextField(20);
        tagField.setCornerRadius(FIELD_CORNER_RADIUS);
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.weightx = 1.0;
        mainPanel.add(tagField, gbc);

        displayNameLabel = new JLabel("Имя:");
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.weightx = 0.0;
        mainPanel.add(displayNameLabel, gbc);

        displayNameField = new RoundedTextField(20);
        displayNameField.setCornerRadius(FIELD_CORNER_RADIUS);
        gbc.gridx = 1;
        gbc.gridy = 3;
        gbc.weightx = 1.0;
        mainPanel.add(displayNameField, gbc);

        passwordLabel = new JLabel("Пароль:");
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.weightx = 0.0;
        mainPanel.add(passwordLabel, gbc);

        passwordField = new RoundedPasswordField(20);
        passwordField.setCornerRadius(FIELD_CORNER_RADIUS);
        gbc.gridx = 1;
        gbc.gridy = 4;
        gbc.weightx = 1.0;
        mainPanel.add(passwordField, gbc);

        confirmPasswordLabel = new JLabel("Подтвердите пароль:");
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.weightx = 0.0;
        mainPanel.add(confirmPasswordLabel, gbc);

        confirmPasswordField = new RoundedPasswordField(20);
        confirmPasswordField.setCornerRadius(FIELD_CORNER_RADIUS);
        gbc.gridx = 1;
        gbc.gridy = 5;
        gbc.weightx = 1.0;
        mainPanel.add(confirmPasswordField, gbc);

        statusLabel = new JLabel("<html>Инициализация... Ожидание ключа сервера.</html>", SwingConstants.CENTER);
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(10, 10, 0, 10);
        mainPanel.add(statusLabel, gbc);

        buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        AppTheme initialTheme = themeManager.getCurrentTheme();
        registerButton = new RoundedButton("Зарегистрироваться", BUTTON_CORNER_RADIUS, AppTheme.highlightBlue(), Color.WHITE); 
        backToLoginButton = new RoundedButton("Назад ко входу", BUTTON_CORNER_RADIUS, initialTheme.secondaryAccent(), initialTheme.text());
        
        buttonPanel.add(registerButton);
        buttonPanel.add(backToLoginButton);

        gbc.gridx = 0;
        gbc.gridy = 7;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(5, 10, 10, 10);
        mainPanel.add(buttonPanel, gbc);

        registerButton.addActionListener(this::performRegistration);
        backToLoginButton.addActionListener(_ -> openLoginFrame());
        
        confirmPasswordField.addActionListener(this::performRegistration);
        passwordField.addActionListener(this::performRegistration);
        usernameField.addActionListener(this::performRegistration);
        tagField.addActionListener(this::performRegistration);
        displayNameField.addActionListener(this::performRegistration);
        
        usernameField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            private boolean tagWasEmptyOrSameAsUsername = true;
            public void insertUpdate(javax.swing.event.DocumentEvent e) { syncTag(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { syncTag(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { syncTag(); }
            private void syncTag() {
                String currentUsername = usernameField.getText();
                String currentTag = tagField.getText();
                if ((currentTag.isEmpty() || tagWasEmptyOrSameAsUsername) && !currentUsername.isEmpty()) {
                    String suggestedTag = currentUsername.replaceAll("[^a-zA-Z0-9_]", "").toLowerCase();
                    if (!suggestedTag.isEmpty()) {
                        tagField.setText(suggestedTag);
                    }
                }
                tagWasEmptyOrSameAsUsername = currentTag.isEmpty() || currentTag.equals(currentUsername.replaceAll("[^a-zA-Z0-9_]", "").toLowerCase());
            }
        });
        getRootPane().setDefaultButton(registerButton);
    }

    private void checkServerKeyStatusAndUpdateUI() {
        boolean keyFetched = Main.isServerPublicKeyFetched();
        com.ryumessenger.security.KeyManager keyManager = Main.getKeyManager();
        boolean keyActuallySet = false;
        try {
            keyActuallySet = keyManager != null && keyManager.getServerRSAPublicKey() != null;
        } catch (Exception e) {
            CryptoLogWindow.log("Ошибка при получении RSA ключа сервера в checkServerKeyStatusAndUpdateUI: " + e.getMessage());
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка проверки ключа сервера. Регистрация невозможна.</font></html>");
            setButtonsEnabled(false);
            return;
        }

        if (keyFetched && keyActuallySet) {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightGreen()) + "'>Ключ сервера получен. Готово к регистрации.</font></html>");
            setButtonsEnabled(true);
            
            if (showCryptoLog) {
                CryptoLogWindow.log("Статус: Ключ сервера получен. Готово к регистрации.");
            }
        } else if (keyFetched && !keyActuallySet) {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка: Неверный формат ключа сервера. Регистрация невозможна.</font></html>");
            setButtonsEnabled(false);
            
            if (showCryptoLog) {
                CryptoLogWindow.log("Статус: Ошибка: Ключ сервера не получен. Регистрация невозможна.");
            }
        }
    }

    private void performRegistration(ActionEvent event) {
        if (showCryptoLog) {
            CryptoLogWindow.log("Начало процесса регистрации...");
        }
        statusLabel.setText("Выполняется регистрация...");
        setButtonsEnabled(false);

        String username = usernameField.getText().trim();
        String tag = tagField.getText().trim();
        String displayName = displayNameField.getText().trim();
        String password = new String(passwordField.getPassword());
        String confirmPassword = new String(confirmPasswordField.getPassword());

        if (username.isEmpty() || tag.isEmpty() || displayName.isEmpty() || password.isEmpty()) {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Все поля должны быть заполнены.</font></html>");
            setButtonsEnabled(true);
            return;
        }

        if (!password.equals(confirmPassword)) {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Пароли не совпадают.</font></html>");
            setButtonsEnabled(true);
            return;
        }
        
        // Получаем необходимые сервисы из Main
        AuthPayloadFormatter authPayloadFormatter = Main.getAuthPayloadFormatter();
        ApiClient apiClient = Main.getApiClient();
        com.ryumessenger.security.KeyManager securityKeyManager = Main.getKeyManager();

        if (authPayloadFormatter == null || apiClient == null || securityKeyManager == null) {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка: Клиент не инициализирован. Попробуйте перезапустить.</font></html>");
            setButtonsEnabled(true);
            CryptoLogWindow.log("Ошибка: authPayloadFormatter, apiClient или securityKeyManager не инициализированы.");
            return;
        }

        try {
            if (securityKeyManager.getServerRSAPublicKey() == null) {
                statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка: Ключ сервера недоступен. Попробуйте позже.</font></html>");
                setButtonsEnabled(true);
                CryptoLogWindow.log("Ошибка: RSA ключ сервера не доступен в securityKeyManager.");
                return;
            }
             if (securityKeyManager.getClientDHPublicKeyY() == null) {
                statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка: DH ключ клиента недоступен. Попробуйте перезапустить.</font></html>");
                setButtonsEnabled(true);
                CryptoLogWindow.log("Ошибка: DH ключ клиента не доступен в securityKeyManager.");
                return;
            }
        } catch (Exception e) {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка проверки ключей: " + e.getMessage() +"</font></html>");
            setButtonsEnabled(true);
            CryptoLogWindow.log("Критическая ошибка при проверке ключей перед регистрацией: " + e.getMessage());
            return;
        }

        Map<String, Object> registrationData;
        try {
            registrationData = authPayloadFormatter.createRegistrationRequest(username, password, tag, displayName);
            if (registrationData == null) {
                 throw new RuntimeException("createRegistrationRequest вернул null, возможно отсутствуют DH или RSA ключи клиента.");
            }
        } catch (Exception e) {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка подготовки данных: " + e.getMessage() +"</font></html>");
            setButtonsEnabled(true);
            CryptoLogWindow.log("Ошибка при создании registrationData: " + e.getMessage());
            return;
        }
        
        if (showCryptoLog) {
             CryptoLogWindow.log("Данные для регистрации сформированы: " + new JSONObject(registrationData).toString().substring(0, Math.min(100, new JSONObject(registrationData).toString().length())) + "...");
             CryptoLogWindow.log("Отправка запроса на /auth/register...");
        }

        CompletableFuture<ApiResponse> future = apiClient.register(registrationData);

        future.thenAccept(response -> {
            SwingUtilities.invokeLater(() -> {
                if (response.isSuccess()) {
                    statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightGreen()) + "'>Регистрация успешна! Переход на страницу входа...</font></html>");
                    CryptoLogWindow.log("Регистрация успешна для " + username + ". Ответ: " + response.getBody());
                    Timer timer = new Timer(2000, _ -> openLoginFrame());
                    timer.setRepeats(false);
                    timer.start();
                } else {
                    String errorMsg = response.getErrorMessage() != null ? response.getErrorMessage() : "Неизвестная ошибка.";
                    statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка регистрации: " + errorMsg + "</font></html>");
                    CryptoLogWindow.log("Ошибка регистрации для " + username + ". Статус: " + response.getStatusCode() + ", Ошибка: " + errorMsg);
                    setButtonsEnabled(true);
                }
            });
        }).exceptionally(ex -> {
            SwingUtilities.invokeLater(() -> {
                statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка сети: " + ex.getMessage() + "</font></html>");
                CryptoLogWindow.log("Сетевая ошибка или исключение при регистрации: " + ex.toString());
                 if (ex.getCause() != null) {
                    CryptoLogWindow.log("Причина: " + ex.getCause().toString());
                }
                setButtonsEnabled(true);
            });
            return null;
        });
    }
    
    private void setButtonsEnabled(boolean enabled) {
        registerButton.setEnabled(enabled);
        backToLoginButton.setEnabled(enabled);
    }

    public void openLoginFrame() {
        if (showCryptoLog) {
            CryptoLogWindow.log("Переход к экрану входа");
        }
        
        SwingUtilities.invokeLater(() -> {
            LoginFrame loginFrame = new LoginFrame(showCryptoLog);
            loginFrame.setVisible(true);
            this.dispose();
        });
    }
    
    // Метод для доступа к значению showCryptoLog
    public boolean isShowCryptoLog() {
        return showCryptoLog;
    }

    private void styleField(RoundedTextField field, boolean isValid, String tooltipOnError, AppTheme theme) {
        if (isValid) {
            field.setBorderColor(theme.inputBackground().darker());
            field.setToolTipText(null);
        } else {
            field.setBorderColor(AppTheme.highlightRed());
            field.setToolTipText(tooltipOnError);
        }
        field.updateTheme();
    }

    private void styleField(RoundedPasswordField field, boolean isValid, String tooltipOnError, AppTheme theme) {
        if (isValid) {
            field.setBorderColor(theme.inputBackground().darker());
            field.setToolTipText(null);
        } else {
            field.setBorderColor(AppTheme.highlightRed());
            field.setToolTipText(tooltipOnError);
        }
        field.updateTheme();
    }

    @Override
    public void applyTheme() {
        getContentPane().setBackground(themeManager.getCurrentTheme().background());
        mainPanel.setBackground(themeManager.getCurrentTheme().background());

        if (mainPanel != null) {
            mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        }

        if (buttonPanel != null) {
            buttonPanel.setBackground(themeManager.getCurrentTheme().background());
        }

        if (titleLabel != null) {
            titleLabel.setFont(AppTheme.FONT_HEADER);
            titleLabel.setForeground(themeManager.getCurrentTheme().text());
        }
        
        JLabel[] labels = {usernameLabel, tagLabel, displayNameLabel, passwordLabel, confirmPasswordLabel};
        for (JLabel label : labels) {
            if (label != null) {
                label.setFont(themeManager.getCurrentTheme().labelFont());
                label.setForeground(themeManager.getCurrentTheme().text());
            }
        }

        RoundedTextField[] roundedTextFields = {usernameField, tagField, displayNameField};
        for (RoundedTextField rField : roundedTextFields) {
            if (rField != null) {
                rField.updateTheme();
                if (rField.getToolTipText() == null) {
                    styleField(rField, true, "", themeManager.getCurrentTheme());
                }
            }
        }
        
        RoundedPasswordField[] roundedPasswordFields = {passwordField, confirmPasswordField};
        for (RoundedPasswordField rpField : roundedPasswordFields) {
            if (rpField != null) {
                rpField.updateTheme();
                if (rpField.getToolTipText() == null) {
                     styleField(rpField, true, "", themeManager.getCurrentTheme());
                }
            }
        }
        
        if (registerButton != null) {
            registerButton.setFont(themeManager.getCurrentTheme().buttonFont());
            registerButton.setBackground(AppTheme.highlightBlue());
            registerButton.setForeground(Color.WHITE);
        }
        
        if (backToLoginButton != null) {
            backToLoginButton.setFont(themeManager.getCurrentTheme().buttonFont());
            backToLoginButton.setBackground(themeManager.getCurrentTheme().secondaryAccent());
            backToLoginButton.setForeground(themeManager.getCurrentTheme().text());
        }
        
        if (statusLabel != null) {
             statusLabel.setFont(themeManager.getCurrentTheme().labelFont());
             if (statusLabel.getText() == null || !statusLabel.getText().toLowerCase().contains("<html>")) {
                 statusLabel.setForeground(themeManager.getCurrentTheme().textSecondary());
             }
        }
        
        SwingUtilities.updateComponentTreeUI(this);
    }
} 