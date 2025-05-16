package com.ryumessenger.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.WindowEvent;

import javax.swing.BorderFactory;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import com.ryumessenger.Main;
import com.ryumessenger.model.User;
import com.ryumessenger.service.UserService;
import com.ryumessenger.ui.theme.AppTheme;
import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.ui.theme.ThemedComponent;
import com.ryumessenger.crypto.KeyManager;

public class SettingsDialog extends JDialog implements ThemedComponent {

    private RoundedTextField displayNameField;
    private RoundedTextField tagField;
    private RoundedPasswordField currentPasswordField;
    private RoundedPasswordField newPasswordField;
    private RoundedPasswordField confirmNewPasswordField;
    private JComboBox<String> themeComboBox;
    private RoundedButton saveButton;
    private JPanel fieldsPanel;
    private JPanel buttonPanel;
    private JLabel passwordStatusLabel;

    private final UserService userService;
    private User currentUser;
    private final ThemeManager themeManager;
    private static final int BUTTON_CORNER_RADIUS = 15;
    private static final int FIELD_CORNER_RADIUS = 15;

    public SettingsDialog(JFrame parent, UserService userService, User currentUser) {
        super(parent, "Настройки", true);
        this.userService = userService;
        this.currentUser = currentUser;
        this.themeManager = ThemeManager.getInstance();

        initComponents();
        themeManager.registerThemedComponent(this);
        loadUserData();
        checkServerKeyStatusAndUpdateUI();

        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        pack();
        setLocationRelativeTo(parent);
        setResizable(false);
    }

    private void loadUserData() {
        if (currentUser == null) return;
        displayNameField.setText(currentUser.getDisplayName());
        tagField.setText(currentUser.getTag());
        tagField.setEditable(false);
        tagField.setToolTipText("Для смены тега обратитесь в поддержку");

        AppTheme currentTheme = themeManager.getCurrentTheme();
        if (currentTheme.isDarkTheme()) {
            themeComboBox.setSelectedItem("Темная");
        } else {
            themeComboBox.setSelectedItem("Светлая");
        }
    }

    private void initComponents() {
        setLayout(new BorderLayout(10, 10));
        ((JPanel) getContentPane()).setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        fieldsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 5, 8, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0;
        gbc.gridy = 0;
        fieldsPanel.add(new JLabel("Отображаемое имя:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        displayNameField = new RoundedTextField(20);
        displayNameField.setCornerRadius(FIELD_CORNER_RADIUS);
        fieldsPanel.add(displayNameField, gbc);
        gbc.weightx = 0;

        gbc.gridx = 0;
        gbc.gridy = 1;
        fieldsPanel.add(new JLabel("Тег:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        tagField = new RoundedTextField(20);
        tagField.setCornerRadius(FIELD_CORNER_RADIUS);
        fieldsPanel.add(tagField, gbc);
        gbc.weightx = 0;
        
        gbc.gridx = 0;
        gbc.gridy = 2;
        fieldsPanel.add(new JLabel("Текущий пароль (для смены):"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        currentPasswordField = new RoundedPasswordField(20);
        currentPasswordField.setCornerRadius(FIELD_CORNER_RADIUS);
        fieldsPanel.add(currentPasswordField, gbc);
        gbc.weightx = 0;

        gbc.gridx = 0;
        gbc.gridy = 3;
        fieldsPanel.add(new JLabel("Новый пароль:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        newPasswordField = new RoundedPasswordField(20);
        newPasswordField.setCornerRadius(FIELD_CORNER_RADIUS);
        fieldsPanel.add(newPasswordField, gbc);
        gbc.weightx = 0;

        gbc.gridx = 0;
        gbc.gridy = 4;
        fieldsPanel.add(new JLabel("Подтвердите новый пароль:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        confirmNewPasswordField = new RoundedPasswordField(20);
        confirmNewPasswordField.setCornerRadius(FIELD_CORNER_RADIUS);
        fieldsPanel.add(confirmNewPasswordField, gbc);
        gbc.weightx = 0;

        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 2;
        passwordStatusLabel = new JLabel(" ", JLabel.CENTER);
        fieldsPanel.add(passwordStatusLabel, gbc);
        gbc.gridwidth = 1;

        gbc.gridx = 0;
        gbc.gridy = 6;
        fieldsPanel.add(new JLabel("Тема оформления:"), gbc);
        gbc.gridx = 1;
        themeComboBox = new JComboBox<>(new String[]{"Светлая", "Темная"});
        fieldsPanel.add(themeComboBox, gbc);
        gbc.weightx = 0;

        themeComboBox.addActionListener(e -> {
            String selectedThemeName = (String) themeComboBox.getSelectedItem();
            AppTheme currentAppTheme = themeManager.getCurrentTheme();
            AppTheme.ThemeType targetType = "Темная".equals(selectedThemeName) ? AppTheme.ThemeType.DARK : AppTheme.ThemeType.LIGHT;

            if (currentAppTheme.getCurrentThemeType() != targetType) {
                themeManager.setTheme(targetType == AppTheme.ThemeType.DARK ? AppTheme.DARK_THEME : AppTheme.LIGHT_THEME);
            }
        });

        add(fieldsPanel, BorderLayout.CENTER);

        buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        saveButton = new RoundedButton("Сохранить изменения", BUTTON_CORNER_RADIUS, AppTheme.highlightBlue(), Color.WHITE);
        saveButton.addActionListener(e -> saveChanges());
        buttonPanel.add(saveButton);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void checkServerKeyStatusAndUpdateUI() {
        KeyManager keyManager = Main.getKeyManager();
        boolean keyAvailable = Main.isServerPublicKeyFetched() && keyManager != null && keyManager.getServerRsaPublicKey() != null;
        
        if (!keyAvailable) {
            passwordStatusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Смена пароля невозможна: ключ сервера недоступен.</font></html>");
            currentPasswordField.setEnabled(false);
            newPasswordField.setEnabled(false);
            confirmNewPasswordField.setEnabled(false);
        } else {
            passwordStatusLabel.setText(" ");
            currentPasswordField.setEnabled(true);
            newPasswordField.setEnabled(true);
            confirmNewPasswordField.setEnabled(true);
        }
    }

    private void saveChanges() {
        if (currentUser == null) {
            showErrorMessage("Пользователь не загружен.");
            return;
        }
        String newDisplayName = displayNameField.getText().trim();
        String currentPassword = new String(currentPasswordField.getPassword());
        String newPassword = new String(newPasswordField.getPassword());
        String confirmNewPassword = new String(confirmNewPasswordField.getPassword());
        boolean mainChangesMade = false;
        boolean passwordChangeAttempted = !currentPassword.isEmpty() || !newPassword.isEmpty() || !confirmNewPassword.isEmpty();

        if (!newDisplayName.isEmpty() && !newDisplayName.equals(currentUser.getDisplayName())) {
            userService.changeDisplayName(newDisplayName, success -> {
                SwingUtilities.invokeLater(() -> {
                    if (success) {
                        currentUser.setDisplayName(newDisplayName);
                        displayNameField.setBorderColor(AppTheme.highlightGreen());
                        showSuccessMessage("Отображаемое имя успешно изменено.");
                    } else {
                        displayNameField.setBorderColor(AppTheme.highlightRed());
                        showErrorMessage("Ошибка изменения отображаемого имени.");
                    }
                    displayNameField.updateTheme();
                });
            });
            mainChangesMade = true;
        }

        if (passwordChangeAttempted) {
            KeyManager keyManager = Main.getKeyManager();
            if (!Main.isServerPublicKeyFetched() || keyManager == null || keyManager.getServerRsaPublicKey() == null) {
                passwordStatusLabel.setText("<html><font color='" + AppTheme.toHex(AppTheme.highlightRed()) + "'>Смена пароля невозможна: ключ сервера недоступен.</font></html>");
                showErrorMessage("Невозможно сменить пароль: ключ безопасности сервера недоступен. Попробуйте перезапустить приложение.");
                return;
            }

            if (currentPassword.isEmpty()) {
                 currentPasswordField.setBorderColor(AppTheme.highlightRed());
                 currentPasswordField.updateTheme();
                 showWarningMessage("Введите текущий пароль для его изменения.");
                 return;
            }
            if (newPassword.length() < 6) {
                newPasswordField.setBorderColor(AppTheme.highlightRed());
                newPasswordField.updateTheme();
                showWarningMessage("Новый пароль должен быть не менее 6 символов.");
                return;
            }
            if (!newPassword.equals(confirmNewPassword)) {
                newPasswordField.setBorderColor(AppTheme.highlightRed());
                confirmNewPasswordField.setBorderColor(AppTheme.highlightRed());
                newPasswordField.updateTheme();
                confirmNewPasswordField.updateTheme();
                showErrorMessage("Новые пароли не совпадают.");
                return;
            }
            
            currentPasswordField.setBorderColor(themeManager.getCurrentTheme().inputBackground().darker()); currentPasswordField.updateTheme();
            newPasswordField.setBorderColor(themeManager.getCurrentTheme().inputBackground().darker()); newPasswordField.updateTheme();
            confirmNewPasswordField.setBorderColor(themeManager.getCurrentTheme().inputBackground().darker()); confirmNewPasswordField.updateTheme();
            passwordStatusLabel.setText("Выполняется смена пароля...");
            passwordStatusLabel.setForeground(themeManager.getCurrentTheme().textSecondary());

            userService.changePassword(currentPassword, newPassword, success -> {
                SwingUtilities.invokeLater(() -> {
                    if (success) {
                        passwordStatusLabel.setText("<html><font color='"+ AppTheme.toHex(AppTheme.highlightGreen()) +"'>Пароль успешно изменен.</font></html>");
                        currentPasswordField.setText("");
                        newPasswordField.setText("");
                        confirmNewPasswordField.setText("");
                    } else {
                        passwordStatusLabel.setText("<html><font color='"+ AppTheme.toHex(AppTheme.highlightRed()) +"'>Ошибка изменения пароля. Проверьте текущий пароль.</font></html>");
                        currentPasswordField.setBorderColor(AppTheme.highlightRed());
                        currentPasswordField.updateTheme();
                    }
                });
            });
            mainChangesMade = true;
        }
        
        if (!mainChangesMade) {
            showInfoMessage("Нет изменений для сохранения.");
        }
    }

    private void showSuccessMessage(String message) {
        JOptionPane.showMessageDialog(this, message, "Успех", JOptionPane.INFORMATION_MESSAGE);
    }
    private void showErrorMessage(String message) {
        JOptionPane.showMessageDialog(this, message, "Ошибка", JOptionPane.ERROR_MESSAGE);
    }
    private void showWarningMessage(String message) {
        JOptionPane.showMessageDialog(this, message, "Внимание", JOptionPane.WARNING_MESSAGE);
    }
     private void showInfoMessage(String message) {
        JOptionPane.showMessageDialog(this, message, "Информация", JOptionPane.INFORMATION_MESSAGE);
    }

    @Override
    public void applyTheme() {
        getContentPane().setBackground(themeManager.getCurrentTheme().background());
        getRootPane().setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        
        if (fieldsPanel != null) {
            fieldsPanel.setBackground(themeManager.getCurrentTheme().background());
            for (Component comp : fieldsPanel.getComponents()) {
                if (comp instanceof JLabel) {
                    comp.setFont(themeManager.getCurrentTheme().labelFont());
                    comp.setForeground(themeManager.getCurrentTheme().text());
                } else if (comp instanceof RoundedTextField) {
                    ((RoundedTextField) comp).updateTheme();
                } else if (comp instanceof RoundedPasswordField) {
                    ((RoundedPasswordField) comp).updateTheme();
                } else if (comp instanceof JComboBox) {
                    JComboBox<?> comboBox = (JComboBox<?>) comp;
                    comboBox.setBackground(themeManager.getCurrentTheme().inputBackground());
                    comboBox.setForeground(themeManager.getCurrentTheme().text());
                    comboBox.setFont(themeManager.getCurrentTheme().inputFont());
                }
            }
        }
        if (buttonPanel != null) {
            buttonPanel.setBackground(themeManager.getCurrentTheme().background());
        }

        if (saveButton != null) {
            saveButton.setFont(themeManager.getCurrentTheme().buttonFont());
            saveButton.setBackground(AppTheme.highlightBlue());
            saveButton.setForeground(Color.WHITE);
        }

        if (themeComboBox != null) {
            if (themeManager.getCurrentTheme().isDarkTheme()) {
                themeComboBox.setSelectedItem("Темная");
            } else {
                themeComboBox.setSelectedItem("Светлая");
            }
        }
        SwingUtilities.updateComponentTreeUI(this);
    }

    @Override
    protected void processWindowEvent(WindowEvent e) {
        super.processWindowEvent(e);
        if (e.getID() == WindowEvent.WINDOW_CLOSING) {
            themeManager.unregisterThemedComponent(this);
        }
    }
} 