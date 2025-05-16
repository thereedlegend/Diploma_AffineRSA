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
import javax.swing.JOptionPane;
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
import com.ryumessenger.crypto.KeyManager;

public class RegisterFrame extends JFrame implements ThemedComponent {

    private RoundedTextField usernameField;
    private RoundedTextField tagField;
    private RoundedTextField displayNameField;
    private RoundedPasswordField passwordField;
    private RoundedPasswordField confirmPasswordField;
    private RoundedButton registerButton;
    private RoundedButton backToLoginButton;
    private JLabel statusLabel;
    private final UserService userService;
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
        this.userService = userService;
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
        backToLoginButton.addActionListener(e -> openLoginFrame());
        
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
        KeyManager keyManager = Main.getKeyManager();
        boolean keyActuallySet = keyManager != null && keyManager.getServerRsaPublicKey() != null;

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
                CryptoLogWindow.log("Статус: Ошибка: Неверный формат ключа сервера. Регистрация невозможна.");
            }
            
            JOptionPane.showMessageDialog(this,
                    "Получен недействительный ключ безопасности от сервера. Пожалуйста, свяжитесь с администратором.",
                    "Ошибка ключа сервера", JOptionPane.ERROR_MESSAGE);
        } else {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка: Ключ сервера не получен. Регистрация невозможна.</font></html>");
            setButtonsEnabled(false);
            
            if (showCryptoLog) {
                CryptoLogWindow.log("Статус: Ошибка: Ключ сервера не получен. Регистрация невозможна.");
            }
            
            JOptionPane.showMessageDialog(this,
                "Не удалось получить ключ безопасности сервера. Пожалуйста, проверьте соединение\n" +
                "с сервером и попробуйте перезапустить приложение.",
                "Ошибка безопасности", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void performRegistration(ActionEvent event) {
        KeyManager keyManager = Main.getKeyManager();
        if (!Main.isServerPublicKeyFetched() || keyManager == null || keyManager.getServerRsaPublicKey() == null) {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка: Ключ сервера не доступен. Регистрация невозможна.</font></html>");
            
            if (showCryptoLog) {
                CryptoLogWindow.log("Ошибка: Ключ сервера не доступен. Регистрация невозможна.");
            }
            
            JOptionPane.showMessageDialog(this,
                    "Ключ безопасности сервера недоступен. Попробуйте перезапустить приложение.",
                    "Ошибка безопасности", JOptionPane.ERROR_MESSAGE);
            setButtonsEnabled(false);
            return;
        }

        String username = usernameField.getText().trim();
        String tag = tagField.getText().trim();
        String displayName = displayNameField.getText().trim();
        String password = new String(passwordField.getPassword());
        String confirmPassword = new String(confirmPasswordField.getPassword());

        boolean isUsernameValid = !username.isEmpty() && username.matches("^[a-zA-Z0-9_]{3,20}$");
        boolean isTagValid = !tag.isEmpty() && tag.matches("^[a-zA-Z0-9_]{3,20}$");
        boolean isDisplayNameValid = !displayName.isEmpty() && displayName.length() <= 50;
        boolean isPasswordValid = password.length() >= 6;
        boolean passwordsMatch = password.equals(confirmPassword);

        styleField(usernameField, isUsernameValid, "Логин должен содержать 3-20 англ. букв, цифр или _, и быть уникальным.", themeManager.getCurrentTheme());
        styleField(tagField, isTagValid, "Тег должен содержать 3-20 англ. букв, цифр или _, и быть уникальным.", themeManager.getCurrentTheme());
        styleField(displayNameField, isDisplayNameValid, "Имя не должно быть пустым (до 50 симв.).", themeManager.getCurrentTheme());
        styleField(passwordField, isPasswordValid, "Пароль должен быть не менее 6 символов.", themeManager.getCurrentTheme());
        styleField(confirmPasswordField, passwordsMatch, "Пароли не совпадают.", themeManager.getCurrentTheme());
        
        if (!isUsernameValid || !isPasswordValid || !isTagValid || !isDisplayNameValid || !passwordsMatch) {
            String errorText = "Исправьте ошибки в полях: ";
            if (!isUsernameValid) errorText += "Логин. ";
            else if (!isTagValid) errorText += "Тег. ";
            else if (!isDisplayNameValid) errorText += "Имя. ";
            else if (!isPasswordValid) errorText += "Пароль. ";
            else if (!passwordsMatch) errorText += "Пароли не совпадают. ";
            
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>" + errorText + "</font></html>");
            
            if (showCryptoLog) {
                CryptoLogWindow.log("Ошибка валидации: " + errorText);
            }
            
            return;
        }

        statusLabel.setText("Выполняется регистрация...");
        statusLabel.setForeground(themeManager.getCurrentTheme().textSecondary());
        setButtonsEnabled(false);
        
        if (showCryptoLog) {
            CryptoLogWindow.log("Выполняется регистрация пользователя: " + username + " (" + displayName + ")");
        }

        userService.register(username, tag, displayName, password, (ApiClient.ApiResponse apiResponse) -> {
            SwingUtilities.invokeLater(() -> {
                if (apiResponse.isSuccess()) {
                    statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightGreen()) + "'>Регистрация успешна! Теперь вы можете войти.</font></html>");
                    
                    if (showCryptoLog) {
                        CryptoLogWindow.log("Регистрация успешна! Переход к экрану входа через 2.5 секунды...");
                    }
                    
                    Timer timer = new Timer(2500, e -> openLoginFrame());
                    timer.setRepeats(false);
                    timer.start();
                } else {
                    String errorMessage = "Ошибка регистрации.";
                    if (apiResponse.getJson() != null && apiResponse.getJson().has("message")) {
                        errorMessage = apiResponse.getJson().getString("message");
                    } else if (apiResponse.getStatusCode() == 400) {
                        errorMessage = "Неверные данные или такой пользователь/тег уже существует.";
                    } else if (apiResponse.getStatusCode() == 0 && apiResponse.getBody() != null && apiResponse.getBody().contains("Failed to encrypt")) {
                         errorMessage = "Ошибка шифрования пароля. Проверьте ключ сервера.";
                    } else if (apiResponse.getBody() != null && !apiResponse.getBody().isEmpty()) {
                        errorMessage = "Ошибка сервера: " + apiResponse.getBody().substring(0, Math.min(apiResponse.getBody().length(), 100));
                    } else if (apiResponse.getStatusCode() != 0) {
                         errorMessage = "Ошибка сервера (код: " + apiResponse.getStatusCode() + ")";
                    }
                    statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>" + errorMessage + "</font></html>");
                    
                    if (showCryptoLog) {
                        CryptoLogWindow.log("Ошибка регистрации: " + errorMessage);
                    }
                    
                    setButtonsEnabled(true);
                }
            });
        });
    }
    
    private void setButtonsEnabled(boolean enabled) {
        registerButton.setEnabled(enabled);
        backToLoginButton.setEnabled(enabled);
    }

    private void openLoginFrame() {
        if (showCryptoLog) {
            CryptoLogWindow.log("Переход к экрану входа");
        }
        
        LoginFrame loginFrame = new LoginFrame();
        loginFrame.setVisible(true);
        dispose(); 
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