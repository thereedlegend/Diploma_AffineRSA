package com.ryumessenger.ui.components;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import com.ryumessenger.model.Chat;
import com.ryumessenger.service.ChatService;
import com.ryumessenger.ui.ChatListRenderer;
import com.ryumessenger.ui.theme.AppTheme;
import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.ui.theme.ThemedComponent;

public class UserSearchDialog extends JDialog implements ThemedComponent {
    private final JTextField searchField;
    private final JList<Chat> userList;
    private final DefaultListModel<Chat> listModel;
    private final ChatService chatService;
    private final ThemeManager themeManager;
    private JPanel searchPanel;
    private JPanel buttonPanel;
    private JButton searchButton;
    private JButton cancelButton;

    public UserSearchDialog(JFrame parent, ChatService chatService) {
        super(parent, "Поиск пользователей", true);
        this.chatService = chatService;
        this.themeManager = ThemeManager.getInstance();
        this.listModel = new DefaultListModel<>();
        
        setLayout(new BorderLayout());
        setSize(400, 500);
        setLocationRelativeTo(parent);

        // Панель поиска
        searchPanel = new JPanel(new BorderLayout());
        searchField = new JTextField();
        searchPanel.add(searchField, BorderLayout.CENTER);

        // Список пользователей
        userList = new JList<>(listModel);
        userList.setCellRenderer(new ChatListRenderer());

        // Кнопки
        buttonPanel = new JPanel();
        searchButton = new JButton("Поиск");
        cancelButton = new JButton("Отмена");

        buttonPanel.add(searchButton);
        buttonPanel.add(cancelButton);

        // Добавляем компоненты
        add(searchPanel, BorderLayout.NORTH);
        add(userList, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        // Обработчики событий
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    performSearch();
                }
            }
        });

        searchButton.addActionListener(e -> performSearch());
        cancelButton.addActionListener(e -> dispose());

        themeManager.registerThemedComponent(this);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                themeManager.unregisterThemedComponent(UserSearchDialog.this);
            }
        });
    }

    private void performSearch() {
        String query = searchField.getText().trim();
        if (!query.isEmpty()) {
            listModel.clear();
            chatService.searchUsers(query, users -> {
                listModel.clear();
                for (Chat user : users) {
                    listModel.addElement(user);
                }
            });
        }
    }

    @Override
    public void applyTheme() {
        AppTheme theme = themeManager.getCurrentTheme();
        getContentPane().setBackground(theme.background());

        // Theme searchPanel and its contents
        if (searchPanel != null) {
            searchPanel.setBackground(theme.background());
            searchPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0,0,1,0, theme.secondaryAccent()),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)
            ));
        }
        if (searchField != null) {
            searchField.setBackground(theme.inputBackground());
            searchField.setForeground(theme.text());
            searchField.setCaretColor(theme.text());
            searchField.setFont(AppTheme.FONT_GENERAL);
            searchField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(theme.secondaryAccent(), 1),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)
            ));
            searchField.setSelectionColor(AppTheme.highlightBlue());
            searchField.setSelectedTextColor(Color.WHITE);
        }

        // Theme userList
        if (userList != null) {
            userList.setBackground(theme.background());
            userList.setForeground(theme.text());
            userList.setSelectionBackground(theme.primaryAccent());
            userList.setSelectionForeground(theme.text());
            if (userList.getCellRenderer() instanceof ThemedComponent) {
                ((ThemedComponent) userList.getCellRenderer()).applyTheme();
            }
            userList.repaint();
        }
        
        // Theme buttonPanel and its buttons
        if (buttonPanel != null) {
            buttonPanel.setBackground(theme.background());
            buttonPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1,0,0,0, theme.secondaryAccent()),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)
            ));
        }
        if (searchButton != null) {
            searchButton.setBackground(theme.primaryAccent());
            searchButton.setForeground(theme.text());
            searchButton.setFont(AppTheme.FONT_BUTTON);
        }
        if (cancelButton != null) {
            cancelButton.setBackground(theme.secondaryAccent());
            cancelButton.setForeground(theme.text());
            cancelButton.setFont(AppTheme.FONT_BUTTON);
        }
        SwingUtilities.updateComponentTreeUI(this);
    }
} 