package com.ryumessenger.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component; 
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.function.Consumer; // Для двойного клика

import javax.swing.BorderFactory;  // Для двойного клика
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListCellRenderer;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.basic.BasicScrollBarUI;

import com.ryumessenger.model.User;
import com.ryumessenger.service.UserService; 
import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.ui.theme.ThemedComponent;
import com.ryumessenger.ui.theme.AppTheme;

// Заглушка для диалога поиска пользователя
public class UserSearchDialog extends JDialog implements ThemedComponent {

    private RoundedTextField searchField;
    private RoundedButton searchButton;
    private JList<User> resultsList; 
    private DefaultListModel<User> listModel;
    private RoundedButton startChatButton;
    private JLabel statusLabel;
    private JLabel searchLabel;
    private JPanel searchPanel;
    private JPanel bottomPanel;
    private JPanel southWrapper;
    private JScrollPane scrollPane;

    private UserService userService;
    private Consumer<User> onUserSelectedForChat; 

    public UserSearchDialog(Frame owner, UserService userService, Consumer<User> onUserSelectedForChat) {
        super(owner, "Найти пользователя", true); 
        this.userService = userService;
        this.onUserSelectedForChat = onUserSelectedForChat;

        setSize(400, 500);
        setLocationRelativeTo(owner);
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));

        initComponents();
        ThemeManager.getInstance().registerThemedComponent(this);
        SwingUtilities.invokeLater(() -> searchField.requestFocusInWindow());
    }

    private void initComponents() {
        searchPanel = new JPanel(new BorderLayout(5, 0));
        searchPanel.setBorder(new EmptyBorder(10, 10, 5, 10));
        searchLabel = new JLabel("Тег пользователя:");
        searchPanel.add(searchLabel, BorderLayout.WEST);
        searchField = new RoundedTextField();
        searchField.setToolTipText("Введите тег пользователя для поиска");
        searchPanel.add(searchField, BorderLayout.CENTER);
        searchButton = new RoundedButton("Найти", 15, AppTheme.highlightBlue(), Color.WHITE);
        searchPanel.add(searchButton, BorderLayout.EAST);

        listModel = new DefaultListModel<>();
        resultsList = new JList<>(listModel);
        resultsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsList.setCellRenderer(new UserListRenderer()); 
        scrollPane = new JScrollPane(resultsList);

        statusLabel = new JLabel("Введите тег пользователя для поиска.", SwingConstants.CENTER);
        statusLabel.setBorder(new EmptyBorder(5,10,5,10));

        bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        startChatButton = new RoundedButton("Начать чат", 15, AppTheme.highlightGreen(), Color.WHITE);
        startChatButton.setEnabled(false); 
        bottomPanel.add(startChatButton);

        add(searchPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        southWrapper = new JPanel(new BorderLayout());
        southWrapper.add(statusLabel, BorderLayout.CENTER);
        southWrapper.add(bottomPanel, BorderLayout.SOUTH);
        add(southWrapper, BorderLayout.SOUTH);

        searchButton.addActionListener(_ -> performSearch());
        searchField.addActionListener(_ -> performSearch()); 

        resultsList.addListSelectionListener(_ -> {
            if (!resultsList.getValueIsAdjusting()) {
                startChatButton.setEnabled(resultsList.getSelectedValue() != null);
            }
        });

        startChatButton.addActionListener(_ -> {
            User selectedUser = resultsList.getSelectedValue();
            if (selectedUser != null && onUserSelectedForChat != null) {
                onUserSelectedForChat.accept(selectedUser);
                dispose(); 
            }
        });
        
        resultsList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int index = resultsList.locationToIndex(e.getPoint());
                    if (index >= 0) {
                        resultsList.setSelectedIndex(index); 
                        User selectedUser = listModel.getElementAt(index);
                         if (selectedUser != null && onUserSelectedForChat != null) {
                            onUserSelectedForChat.accept(selectedUser);
                            dispose();
                        }
                    }
                }
            }
        });
    }

    private void performSearch() {
        String query = searchField.getText().trim();
        if (query.isEmpty()) {
            statusLabel.setText("Поле поиска не должно быть пустым.");
            listModel.clear();
            startChatButton.setEnabled(false);
            return;
        }

        statusLabel.setText("Поиск...");
        listModel.clear();
        searchButton.setEnabled(false);
        searchField.setEnabled(false);

        this.userService.searchUsers(query, userList -> {
            searchButton.setEnabled(true);
            searchField.setEnabled(true);
            searchField.requestFocusInWindow();

            if (userList == null) {
                statusLabel.setText("Ошибка соединения с сервером или сервер не отвечает.");
                listModel.clear();
                startChatButton.setEnabled(false);
                return;
            }

            if (!userList.isEmpty()) {
                int currentUserId = -1;
                try {
                    String currentUserIdStr = com.ryumessenger.Main.getCurrentUserId();
                    if (currentUserIdStr != null && !currentUserIdStr.isEmpty()) {
                        currentUserId = Integer.parseInt(currentUserIdStr);
                    }
                } catch (NumberFormatException ex) {
                    // Игнорируем ошибку, просто не будем фильтровать
                }
                
                List<User> filteredList = new java.util.ArrayList<>();
                for(User user : userList) {
                    if (currentUserId == -1 || user.getId() != currentUserId) {
                        filteredList.add(user);
                    }
                }

                if (!filteredList.isEmpty()) {
                    for (User user : filteredList) {
                        listModel.addElement(user);
                    }
                    statusLabel.setText("Найдено пользователей: " + filteredList.size());
                } else {
                    statusLabel.setText("Другие пользователи не найдены.");
                    listModel.clear();
                }
            } else {
                statusLabel.setText("Пользователи не найдены.");
                listModel.clear();
            }
            startChatButton.setEnabled(false);
        });
    }


    @Override
    public void applyTheme() {
        AppTheme theme = ThemeManager.getInstance().getCurrentTheme();
        getContentPane().setBackground(theme.background());
        getRootPane().setBorder(BorderFactory.createLineBorder(theme.secondaryAccent().darker(), 1));

        if (searchPanel != null) {
            searchPanel.setBackground(theme.background());
        }
        if (bottomPanel != null) {
            bottomPanel.setBackground(theme.background());
        }
        if (southWrapper != null) {
            southWrapper.setBackground(theme.background());
        }
        
        if (searchLabel != null) {
            searchLabel.setForeground(theme.text());
            searchLabel.setFont(theme.labelFont());
        }
        if (statusLabel != null) {
            statusLabel.setForeground(theme.text());
            statusLabel.setFont(theme.labelFont());
        }

        if (searchField != null) {
            searchField.updateTheme();
        }
        
        if (searchButton != null) {
            searchButton.setFont(theme.buttonFont());
            searchButton.setBackground(AppTheme.highlightBlue());
            searchButton.setForeground(Color.WHITE);
        }
        if (startChatButton != null) {
            startChatButton.setFont(theme.buttonFont());
            startChatButton.setBackground(AppTheme.highlightGreen());
            startChatButton.setForeground(Color.WHITE);
        }


        if (resultsList != null) {
            resultsList.setBackground(theme.inputBackground());
            resultsList.setForeground(theme.text());
            resultsList.setSelectionBackground(AppTheme.highlightBlue());
            resultsList.setSelectionForeground(Color.WHITE);
            ListCellRenderer<? super User> renderer = resultsList.getCellRenderer();
            if (renderer instanceof UserListRenderer) {
                ((UserListRenderer) renderer).applyTheme();
            }
            resultsList.repaint();
        }
        
        if (scrollPane != null) {
            scrollPane.setBackground(theme.inputBackground());
            scrollPane.getViewport().setBackground(theme.inputBackground());
            scrollPane.setBorder(BorderFactory.createLineBorder(theme.secondaryAccent()));
            
            BasicScrollBarUI verticalScrollBarUI = new BasicScrollBarUI() {
                @Override protected void configureScrollBarColors() { this.thumbColor = theme.scrollBar(); this.trackColor = theme.inputBackground(); }
                @Override protected JButton createDecreaseButton(int o) { JButton btn = createZeroButton(); this.decrButton = btn; return btn; }
                @Override protected JButton createIncreaseButton(int o) { JButton btn = createZeroButton(); this.incrButton = btn; return btn; }
                private JButton createZeroButton() { JButton b = new JButton(); b.setPreferredSize(new Dimension(0,0));b.setMinimumSize(new Dimension(0,0));b.setMaximumSize(new Dimension(0,0)); return b;}
            };
            BasicScrollBarUI horizontalScrollBarUI = new BasicScrollBarUI() {
                @Override protected void configureScrollBarColors() { this.thumbColor = theme.scrollBar(); this.trackColor = theme.inputBackground(); }
                @Override protected JButton createDecreaseButton(int o) { JButton btn = createZeroButton(); this.decrButton = btn; return btn; }
                @Override protected JButton createIncreaseButton(int o) { JButton btn = createZeroButton(); this.incrButton = btn; return btn; }
                private JButton createZeroButton() { JButton b = new JButton(); b.setPreferredSize(new Dimension(0,0));b.setMinimumSize(new Dimension(0,0));b.setMaximumSize(new Dimension(0,0)); return b;}
            };
            scrollPane.getVerticalScrollBar().setUI(verticalScrollBarUI);
            scrollPane.getVerticalScrollBar().setBackground(theme.inputBackground());
            scrollPane.getHorizontalScrollBar().setUI(horizontalScrollBarUI);
            scrollPane.getHorizontalScrollBar().setBackground(theme.inputBackground());
        }

        // southWrapper уже обработан выше
        SwingUtilities.updateComponentTreeUI(this);
    }

    @Override
    public void dispose() {
        ThemeManager.getInstance().unregisterThemedComponent(this);
        super.dispose();
    }

    // Внутренний класс-рендерер для списка пользователей
    private static class UserListRenderer extends DefaultListCellRenderer {
        private AppTheme theme; // Храним текущую тему для рендерера

        public UserListRenderer() {
            this.theme = ThemeManager.getInstance().getCurrentTheme();
        }
        
        @Override
        public Component getListCellRendererComponent(
                JList<?> list,
                Object value,
                int index,
                boolean isSelected,
                boolean cellHasFocus) {
            
            JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            
            if (value instanceof User) {
                User user = (User) value;
                
                String displayText = user.getDisplayName();
                if (user.getTag() != null && !user.getTag().isEmpty()) {
                    displayText += " [@" + user.getTag() + "]";
                }
                label.setText(displayText);
                
                if (isSelected) {
                    label.setBackground(theme.secondaryAccent());
                    label.setForeground(Color.WHITE);
                } else {
                    label.setBackground(theme.background());
                    label.setForeground(theme.text());
                }
            }
            
            label.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
            return label;
        }

        public void applyTheme() {
            this.theme = ThemeManager.getInstance().getCurrentTheme();
        }
    }
} 