package com.ryumessenger.ui;

import javax.swing.*;

import com.ryumessenger.service.UserService;

public class RegisterPanel extends JPanel {

    // Объявления полей-заглушек. Их реальная инициализация должна быть в конструкторе или UI builder.
    // private RoundedTextField usernameField;
    // private RoundedTextField displayNameField;
    // private RoundedTextField tagField;
    // private RoundedPasswordField passwordField;
    // private RoundedPasswordField confirmPasswordField;
    // private JButton registerButton;
    // private JButton loginButton;
    // private JLabel statusLabel;
    // private UserService userService; // Поле не используется
    // private LoginFrame parentFrame; // Поле не используется

    // Конструктор (может потребовать доработки для инициализации UI)
    public RegisterPanel(UserService userService, LoginFrame parentFrame) {
        // this.userService = userService;
        // this.parentFrame = parentFrame;
        // this.themeManager = ThemeManager.getInstance(); // Было добавлено моделью
        // initComponents(); // Метод не используется локально, но может вызываться извне
        // applyTheme(); // Также
    }
    
    // private void initComponents() {
    //     // ...
    // }

    // Метод registerUser(), похоже, действительно не используется и может быть удален
    // private void registerUser() {
    //     String username = usernameField.getText().trim();
    // ... (остальная часть метода закомментирована)
    // }

    // Вспомогательный метод для отображения сообщений
    // private void showMessage(String title, String message, int messageType) {
    //     JOptionPane.showMessageDialog(this, message, title, messageType);
    // }

    // Метод для переключения на панель входа (требует реализации в RegisterFrame)
    // private void showLoginPanel() {
    //     if (parentFrame != null) {
    //         // Логика переключения панелей в LoginFrame или закрытия RegisterPanel
    //         // Например, parentFrame.switchToLoginPanel();
    //         // или просто ((JFrame) SwingUtilities.getWindowAncestor(this)).dispose(); parentFrame.setVisible(true);
    //     }
    // }

    // Если RegisterPanel должен быть ThemedComponent, то нужен метод applyTheme
    /* @Override
    public void applyTheme() {
        if (themeManager == null || themeManager.getCurrentTheme() == null) return;
        AppTheme theme = themeManager.getCurrentTheme();
        setBackground(theme.background());
        if (statusLabel != null) {
            statusLabel.setForeground(theme.text());
            statusLabel.setFont(theme.labelFont());
        }
        // Стилизация других компонентов...
        if (usernameField!=null) usernameField.updateTheme();
        if (displayNameField!=null) displayNameField.updateTheme();
        if (tagField!=null) tagField.updateTheme();
        if (passwordField!=null) passwordField.updateTheme();
        if (confirmPasswordField!=null) confirmPasswordField.updateTheme();
        if (registerButton!=null) {
            registerButton.setFont(theme.buttonFont());
            registerButton.setBackground(theme.buttonBackground());
            registerButton.setForeground(theme.buttonText());
        }
        if (loginButton!=null) {
            loginButton.setFont(theme.buttonFont());
            loginButton.setBackground(theme.buttonBackground());
            loginButton.setForeground(theme.buttonText());
        }
    } */
} 