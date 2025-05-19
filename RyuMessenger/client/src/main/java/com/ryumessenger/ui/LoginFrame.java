package com.ryumessenger.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.Color;

import javax.swing.BorderFactory;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.JCheckBox;

import com.ryumessenger.Main;
import com.ryumessenger.service.UserService;
import com.ryumessenger.crypto.KeyManager;
import com.ryumessenger.ui.theme.AppTheme;
import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.ui.theme.ThemedComponent;

public class LoginFrame extends JFrame implements ThemedComponent {

    private RoundedTextField usernameField;
    private RoundedPasswordField passwordField;
    private RoundedButton loginButton;
    private RoundedButton registerButton;
    private JLabel statusLabel;
    private JCheckBox showCryptoLogCheckbox;
    private final ThemeManager themeManager;
    private final UserService userService;
    private final JPanel inputPanel;
    private final JLabel usernameLabelText;
    private final JLabel passwordLabelText;
    private final JPanel buttonPanel;
    private final JPanel statusPanel;
    private static final int BUTTON_CORNER_RADIUS = 15;
    private KeyManager keyManager;

    public LoginFrame() {
        this(false);
    }

    public LoginFrame(boolean showCryptoLog) {
        setTitle("Ryu Messenger - Вход");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(450, 380);
        setLocationRelativeTo(null);
        setResizable(false);

        themeManager = ThemeManager.getInstance();
        userService = Main.getUserService();
        keyManager = Main.getLegacyKeyManager();

        usernameField = new RoundedTextField(20);
        passwordField = new RoundedPasswordField(20);
        
        AppTheme initialTheme = themeManager.getCurrentTheme();
        loginButton = new RoundedButton("Войти", BUTTON_CORNER_RADIUS, AppTheme.highlightBlue(), Color.WHITE);
        registerButton = new RoundedButton("Регистрация", BUTTON_CORNER_RADIUS, initialTheme.secondaryAccent(), initialTheme.text());
        statusLabel = new JLabel("<html>Инициализация... Ожидание ключа сервера.</html>", JLabel.CENTER);
        
        usernameLabelText = new JLabel("Имя пользователя:");
        passwordLabelText = new JLabel("Пароль:");
        
        showCryptoLogCheckbox = new JCheckBox("Показывать процесс шифрования и обмена данными");
        showCryptoLogCheckbox.setSelected(showCryptoLog);
        showCryptoLogCheckbox.setFont(initialTheme.labelFont());
        showCryptoLogCheckbox.setForeground(initialTheme.text());
        showCryptoLogCheckbox.setBackground(initialTheme.background());

        inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbcInput = new GridBagConstraints();
        gbcInput.insets = new Insets(10, 10, 5, 10);
        gbcInput.anchor = GridBagConstraints.WEST;

        gbcInput.gridx = 0;
        gbcInput.gridy = 0;
        inputPanel.add(usernameLabelText, gbcInput);
        
        gbcInput.gridx = 1;
        gbcInput.gridy = 0;
        gbcInput.weightx = 1.0;
        gbcInput.fill = GridBagConstraints.HORIZONTAL;
        inputPanel.add(usernameField, gbcInput);
        
        gbcInput.gridx = 0;
        gbcInput.gridy = 1;
        gbcInput.weightx = 0;
        gbcInput.fill = GridBagConstraints.NONE;
        inputPanel.add(passwordLabelText, gbcInput);
        
        gbcInput.gridx = 1;
        gbcInput.gridy = 1;
        gbcInput.weightx = 1.0;
        gbcInput.fill = GridBagConstraints.HORIZONTAL;
        inputPanel.add(passwordField, gbcInput);
        
        gbcInput.gridx = 0;
        gbcInput.gridy = 2;
        gbcInput.gridwidth = 2;
        gbcInput.weightx = 1.0;
        inputPanel.add(showCryptoLogCheckbox, gbcInput);

        buttonPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbcButton = new GridBagConstraints();
        gbcButton.insets = new Insets(5, 5, 5, 5);
        gbcButton.fill = GridBagConstraints.HORIZONTAL;
        gbcButton.weightx = 1.0;
        
        gbcButton.gridx = 0;
        gbcButton.gridy = 0;
        buttonPanel.add(loginButton, gbcButton);
        
        gbcButton.gridy = 1;
        buttonPanel.add(registerButton, gbcButton);

        statusPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        statusPanel.add(statusLabel);
        statusPanel.setBorder(BorderFactory.createEmptyBorder(5,0,5,0));

        setLayout(new BorderLayout(0, 10));
        add(statusPanel, BorderLayout.NORTH);
        add(inputPanel, BorderLayout.CENTER);
        JPanel southPanel = new JPanel(new BorderLayout());
        southPanel.add(buttonPanel, BorderLayout.NORTH);
        southPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));
        southPanel.setOpaque(false);
        add(southPanel, BorderLayout.SOUTH);

        loginButton.addActionListener(_ -> performLogin());
        registerButton.addActionListener(_ -> openRegisterFrame());

        getRootPane().setDefaultButton(loginButton);
        themeManager.registerThemedComponent(this);

        checkServerKeyStatusAndUpdateUI();

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                themeManager.unregisterThemedComponent(LoginFrame.this);
            }
        });
    }

    public void checkServerKeyStatusAndUpdateUI() {
        keyManager = Main.getLegacyKeyManager();
        boolean serverKeyReady = false;
        if (keyManager != null && keyManager.getServerRsaPublicKey() != null) {
            serverKeyReady = true;
        }

        if (serverKeyReady) {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightGreen()) + "'>Ключ сервера получен. Готово к входу.</font></html>");
            loginButton.setEnabled(true);
            registerButton.setEnabled(true);
        } else {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка: Ключ сервера не получен. Вход невозможен.</font></html>");
            loginButton.setEnabled(false);
            registerButton.setEnabled(false);
            JOptionPane.showMessageDialog(this, 
                "Не удалось получить ключ безопасности сервера. Пожалуйста, проверьте соединение\\n" +
                "с сервером и попробуйте перезапустить приложение.", 
                "Ошибка безопасности", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void performLogin() {
        String username = usernameField.getText();
        String password = new String(passwordField.getPassword());

        if (username.isEmpty() || password.isEmpty()) {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Имя пользователя и пароль не могут быть пустыми.</font></html>");
            return;
        }

        keyManager = Main.getLegacyKeyManager();
        if (!Main.isServerPublicKeyFetched() || keyManager == null || keyManager.getServerRsaPublicKey() == null) {
            statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка: Ключ сервера не доступен. Вход невозможен.</font></html>");
            return;
        }

        setButtonsEnabled(false);
        statusLabel.setText("Выполняется вход...");

        userService.login(username, password, success -> {
            SwingUtilities.invokeLater(() -> {
                if (success) {
                    statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightGreen()) + "'>Вход успешен! Открываем мессенджер...</font></html>");
                    if (showCryptoLogCheckbox.isSelected()) {
                        CryptoLogWindow.log("Вход успешен для пользователя: " + username);
                    }
                    openMainInterface();
                } else {
                    String errorMessage = "Неверные учетные данные или ошибка сервера.";
                    statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка: " + errorMessage + "</font></html>");
                    if (showCryptoLogCheckbox.isSelected()) {
                        CryptoLogWindow.log("Ошибка входа: " + errorMessage);
                    }
                    setButtonsEnabled(true);
                }
            });
        });
    }

    private void openRegisterFrame() {
        if (!Main.isServerPublicKeyFetched() || keyManager == null || keyManager.getServerRsaPublicKey() == null) {
             statusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Ошибка: Ключ сервера не доступен. Регистрация невозможна.</font></html>");
             JOptionPane.showMessageDialog(this, 
                    "Ключ безопасности сервера недоступен. Попробуйте перезапустить приложение.", 
                    "Ошибка безопасности", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (showCryptoLogCheckbox.isSelected()) {
            CryptoLogWindow.getInstance().setVisible(true);
        }
        
        RegisterFrame registerFrame = new RegisterFrame(Main.getUserService(), showCryptoLogCheckbox.isSelected());
        registerFrame.setVisible(true);
        dispose();
    }

    public boolean isShowCryptoLogSelected() {
        return showCryptoLogCheckbox.isSelected();
    }

    @Override
    public void applyTheme() {
        getContentPane().setBackground(themeManager.getCurrentTheme().background());
        inputPanel.setBackground(themeManager.getCurrentTheme().background());
        
        if (inputPanel != null) {
            inputPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        }
        if (buttonPanel != null) {
            buttonPanel.setBackground(themeManager.getCurrentTheme().background());
        }
        if (statusPanel != null) {
            statusPanel.setBackground(themeManager.getCurrentTheme().background());
        }
        
        Component[] components = getContentPane().getComponents();
        if (components.length > 2 && components[2] instanceof JPanel) {
            JPanel actualSouthPanel = (JPanel) components[2];
            actualSouthPanel.setBackground(themeManager.getCurrentTheme().background());
            if (actualSouthPanel.getComponentCount() > 0 && actualSouthPanel.getComponent(0) instanceof JPanel) {
                 ((JPanel)actualSouthPanel.getComponent(0)).setBackground(themeManager.getCurrentTheme().background());
            }
        }
        
        if (usernameLabelText != null) {
            usernameLabelText.setFont(themeManager.getCurrentTheme().labelFont());
            usernameLabelText.setForeground(themeManager.getCurrentTheme().text());
        }
        if (passwordLabelText != null) {
            passwordLabelText.setFont(themeManager.getCurrentTheme().labelFont());
            passwordLabelText.setForeground(themeManager.getCurrentTheme().text());
        }
        
        if (usernameField != null) {
            usernameField.updateTheme();
        }
        if (passwordField != null) {
            passwordField.updateTheme();
        }
        
        if (showCryptoLogCheckbox != null) {
            showCryptoLogCheckbox.setBackground(themeManager.getCurrentTheme().background());
            showCryptoLogCheckbox.setForeground(themeManager.getCurrentTheme().text());
            showCryptoLogCheckbox.setFont(themeManager.getCurrentTheme().labelFont());
        }
        
        if (loginButton != null) {
            loginButton.setFont(themeManager.getCurrentTheme().buttonFont());
            loginButton.setBackground(AppTheme.highlightBlue());
            loginButton.setForeground(Color.WHITE);
        }
        
        if (registerButton != null) {
            registerButton.setFont(themeManager.getCurrentTheme().buttonFont());
            registerButton.setBackground(themeManager.getCurrentTheme().secondaryAccent());
            registerButton.setForeground(themeManager.getCurrentTheme().text());
        }
        
        if (statusLabel != null) {
            statusLabel.setFont(themeManager.getCurrentTheme().labelFont());
            statusLabel.setForeground(themeManager.getCurrentTheme().text());
        }
        SwingUtilities.updateComponentTreeUI(this);
    }

    private void setButtonsEnabled(boolean enabled) {
        loginButton.setEnabled(enabled);
        registerButton.setEnabled(enabled);
    }

    private void openMainInterface() {
        dispose();
        new MainFrame(showCryptoLogCheckbox.isSelected()).setVisible(true);
    }
} 