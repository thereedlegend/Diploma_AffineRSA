package com.ryumessenger.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.Timer;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.plaf.basic.BasicScrollBarUI;
import javax.swing.JFrame;

import com.ryumessenger.Main;
import com.ryumessenger.model.Chat;
import com.ryumessenger.service.ChatService;
import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.ui.theme.ThemedComponent;
import com.ryumessenger.ui.theme.AppTheme;
import java.awt.Color;

public class ChatListPanel extends JPanel implements ThemedComponent {
    private final Consumer<Chat> onChatSelectedCallback;
    private DefaultListModel<Chat> listModel;
    private JList<Chat> chatJList;
    private JLabel titleLabel;
    private JButton newUserButton;
    private final ThemeManager themeManager;
    private final ChatService chatService;
    private final ChatPanel chatPanel;
    private JPanel titleButtonPanel;
    private JPanel buttonContainer;
    private Timer refreshTimer; // Таймер для периодического обновления списка чатов

    public ChatListPanel(Consumer<Chat> onChatSelectedCallback, ChatPanel chatPanel) {
        this.onChatSelectedCallback = onChatSelectedCallback;
        this.themeManager = ThemeManager.getInstance();
        this.chatService = new ChatService(Main.getApiClient());
        this.chatPanel = chatPanel;
        setLayout(new BorderLayout(0, 0));

        JPanel topPanel = new JPanel(new BorderLayout());
        
        titleLabel = new JLabel("Чаты", SwingConstants.CENTER);
        titleLabel.setOpaque(true); 

        newUserButton = new RoundedButton("+", 20, AppTheme.highlightBlue(), Color.WHITE);
        newUserButton.setToolTipText("Найти пользователя и начать новый чат");
        newUserButton.addActionListener(e -> openUserSearchDialog());
        newUserButton.setPreferredSize(new Dimension(40, 40));

        titleButtonPanel = new JPanel(new BorderLayout(0,5));
        titleButtonPanel.add(titleLabel, BorderLayout.CENTER);
        
        topPanel.add(titleButtonPanel, BorderLayout.NORTH);
        add(topPanel, BorderLayout.NORTH);

        listModel = new DefaultListModel<>();
        chatJList = new JList<>(listModel);
        chatJList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        chatJList.setCellRenderer(new ChatListRenderer()); 
        chatJList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                Chat selectedChat = chatJList.getSelectedValue();
                if (selectedChat != null && chatPanel != null) {
                    chatPanel.displayChat(selectedChat);
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(chatJList);
        scrollPane.setOpaque(true);
        scrollPane.setBackground(themeManager.getCurrentTheme().background());
        
        add(scrollPane, BorderLayout.CENTER);
        
        // Создаем панель для нижней части с кнопкой
        buttonContainer = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        buttonContainer.setOpaque(true);
        buttonContainer.setBackground(themeManager.getCurrentTheme().background());
        buttonContainer.add(newUserButton);
        add(buttonContainer, BorderLayout.SOUTH);

        setPreferredSize(new Dimension(300, 0));
        themeManager.registerThemedComponent(this);
        applyTheme();

        loadChats();
        
        // Инициализируем таймер для периодического обновления списка чатов
        // Обновляем каждые 5 секунд
        refreshTimer = new Timer(5000, e -> refreshChatList());
        refreshTimer.start();
    }

    private void openUserSearchDialog() {
        JFrame topFrame = (JFrame) SwingUtilities.getWindowAncestor(this);
        UserSearchDialog userSearchDialog = new UserSearchDialog(
            topFrame, 
            Main.getUserService(), 
            selectedUser -> {
                if (selectedUser != null) {
                    System.out.println("Выбран пользователь для чата: " + selectedUser.toString());
                    
                    // Показываем индикатор загрузки или текст о создании чата
                    if (chatPanel != null) {
                        chatPanel.showLoadingMessage("Создание чата...");
                    }
                    
                    chatService.findOrCreateChatWithUser(selectedUser, newChat -> {
                        SwingUtilities.invokeLater(() -> {
                            if (newChat != null) {
                                // Перезагружаем список чатов с сервера
                                System.out.println("Чат успешно создан, обновляем список чатов");
                                loadChats(() -> {
                                    // После перезагрузки списка находим созданный чат и выбираем его
                                    selectChatById(newChat.getId());
                                });
                            } else {
                                JOptionPane.showMessageDialog(this, "Не удалось создать или найти чат с пользователем.", "Ошибка чата", JOptionPane.ERROR_MESSAGE);
                                // Восстанавливаем интерфейс если была ошибка
                                if (chatPanel != null) {
                                    chatPanel.hideLoadingMessage();
                                }
                            }
                        });
                    });
                }
            }
        );
        userSearchDialog.setVisible(true);
    }
    
    private void selectChatById(String chatId) {
        if (chatId == null || listModel.isEmpty()) return;
        
        // Находим чат по ID в модели и выбираем его
        for (int i = 0; i < listModel.getSize(); i++) {
            Chat chat = listModel.getElementAt(i);
            if (chat.getId().equals(chatId)) {
                chatJList.setSelectedValue(chat, true);
                if (chatPanel != null) {
                    chatPanel.displayChat(chat);
                }
                System.out.println("Выбран чат с ID: " + chatId);
                return;
            }
        }
        
        // Если не нашли чат по ID, выбираем первый в списке
        if (!listModel.isEmpty()) {
            chatJList.setSelectedIndex(0);
            if (chatPanel != null) {
                chatPanel.displayChat(listModel.getElementAt(0));
            }
        }
    }
    
    public void setChatList(List<Chat> chats) {
        Chat selected = chatJList.getSelectedValue(); 
        String selectedId = selected != null ? selected.getId() : null;
        
        listModel.clear();
        if (chats != null) {
            for (Chat chat : chats) {
                listModel.addElement(chat);
            }
        }
        
        // Пытаемся восстановить выбранный чат
        if (selectedId != null) {
            selectChatById(selectedId);
        } else if (!listModel.isEmpty()) {
            chatJList.setSelectedIndex(0);
            if (chatPanel != null) chatPanel.displayChat(listModel.getElementAt(0));
        } else {
            if (onChatSelectedCallback != null) onChatSelectedCallback.accept(null);
            if (chatPanel != null) chatPanel.displayChat(null);
        }
    }

    // Новый метод для загрузки чатов с колбэком завершения
    private void loadChats(Runnable onComplete) {
        if (chatService == null) {
            if (onComplete != null) onComplete.run();
            return;
        }
        
        chatService.getChats(chats -> {
            SwingUtilities.invokeLater(() -> {
                if (chats != null) {
                    setChatList(chats);
                }
                if (onComplete != null) onComplete.run();
            });
        });
    }
    
    // Перегруженный метод без колбэка для обратной совместимости
    private void loadChats() {
        loadChats(null);
    }

    public void updateChatEntry(Chat chat) {
        for (int i = 0; i < listModel.getSize(); i++) {
            if (listModel.getElementAt(i).getId().equals(chat.getId())) {
                listModel.setElementAt(chat, i); 
                if(chat.equals(chatJList.getSelectedValue())){
                     chatJList.repaint(); 
                }
                return;
            }
        }
    }

    @Override
    public void applyTheme() {
        AppTheme theme = themeManager.getCurrentTheme();
        setBackground(theme.background());
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        if (titleButtonPanel != null) titleButtonPanel.setBackground(theme.background());
        if (buttonContainer != null) buttonContainer.setBackground(theme.background());
        Component topPanel = (titleButtonPanel != null && titleButtonPanel.getParent() != null) ? titleButtonPanel.getParent() : null;
        if (topPanel instanceof JPanel) {
            ((JPanel)topPanel).setBackground(theme.background());
        }

        if (titleLabel != null) {
            titleLabel.setFont(AppTheme.FONT_HEADER);
            titleLabel.setBackground(theme.background());
            titleLabel.setForeground(theme.text());
        }
        if (chatJList != null) {
            chatJList.setBackground(theme.background());
            chatJList.setForeground(theme.text());
            if (chatJList.getCellRenderer() instanceof ThemedComponent) {
                ((ThemedComponent) chatJList.getCellRenderer()).applyTheme();
            }
            chatJList.repaint();
        }
        if (newUserButton != null) {
            newUserButton.setFont(theme.buttonFont());
            newUserButton.setBackground(AppTheme.highlightBlue());
            newUserButton.setForeground(Color.WHITE);
        }
        
        Component scrollParent = (chatJList != null) ? chatJList.getParent() : null;
        if (scrollParent instanceof javax.swing.JViewport) {
            scrollParent = scrollParent.getParent();
            if (scrollParent instanceof JScrollPane) {
                JScrollPane scroll = (JScrollPane) scrollParent;
                scroll.setBackground(theme.background());
                scroll.getViewport().setBackground(theme.background());
                scroll.setBorder(BorderFactory.createLineBorder(theme.secondaryAccent(),1));

                BasicScrollBarUI verticalScrollBarUI = new BasicScrollBarUI() {
                    @Override protected void configureScrollBarColors() { 
                        this.thumbColor = theme.scrollBar(); 
                        this.trackColor = theme.background();
                        this.thumbDarkShadowColor = theme.scrollBar().darker();
                        this.thumbHighlightColor = theme.scrollBar().brighter();
                        this.thumbLightShadowColor = theme.scrollBar();
                    }
                    @Override protected JButton createDecreaseButton(int o) { return createZeroButton(); }
                    @Override protected JButton createIncreaseButton(int o) { return createZeroButton(); }
                    private JButton createZeroButton() { 
                        JButton b = new JButton(); 
                        b.setPreferredSize(new Dimension(0,0)); 
                        b.setMinimumSize(new Dimension(0,0)); 
                        b.setMaximumSize(new Dimension(0,0)); 
                        return b;
                    }
                };
                scroll.getVerticalScrollBar().setUI(verticalScrollBarUI);
                scroll.getVerticalScrollBar().setBackground(theme.background());

                BasicScrollBarUI horizontalScrollBarUI = new BasicScrollBarUI() {
                    @Override protected void configureScrollBarColors() { 
                        this.thumbColor = theme.scrollBar(); 
                        this.trackColor = theme.background();
                        this.thumbDarkShadowColor = theme.scrollBar().darker();
                        this.thumbHighlightColor = theme.scrollBar().brighter();
                        this.thumbLightShadowColor = theme.scrollBar();
                    }
                    @Override protected JButton createDecreaseButton(int o) { return createZeroButton(); }
                    @Override protected JButton createIncreaseButton(int o) { return createZeroButton(); }
                    private JButton createZeroButton() { 
                        JButton b = new JButton(); 
                        b.setPreferredSize(new Dimension(0,0)); 
                        b.setMinimumSize(new Dimension(0,0)); 
                        b.setMaximumSize(new Dimension(0,0)); 
                        return b;
                    }
                };
                scroll.getHorizontalScrollBar().setUI(horizontalScrollBarUI);
                scroll.getHorizontalScrollBar().setBackground(theme.background());
            }
        }
        SwingUtilities.updateComponentTreeUI(this);
    }

    @Override
    public void removeNotify() {
        super.removeNotify();
        // Останавливаем таймер при закрытии панели
        if (refreshTimer != null && refreshTimer.isRunning()) {
            refreshTimer.stop();
        }
        themeManager.unregisterThemedComponent(this);
    }

    // Метод для обновления списка чатов
    private void refreshChatList() {
        if (chatService == null) return;
        
        chatService.getChats(chats -> {
            if (chats != null) {
                SwingUtilities.invokeLater(() -> {
                    updateChatListWithMinimalChanges(chats);
                });
            }
        });
    }
    
    // Обновляет список чатов, сохраняя текущий выбор и минимизируя визуальные изменения
    private void updateChatListWithMinimalChanges(List<Chat> chats) {
        if (chats == null) return;
        
        Chat selectedChat = chatJList.getSelectedValue();
        String selectedId = selectedChat != null ? selectedChat.getId() : null;
        
        // Добавляем новые чаты, которых нет в списке
        for (Chat chat : chats) {
            boolean found = false;
            
            for (int i = 0; i < listModel.getSize(); i++) {
                Chat existingChat = listModel.getElementAt(i);
                if (existingChat.getId().equals(chat.getId())) {
                    // Обновляем существующий чат, если изменилось последнее сообщение
                    if (!existingChat.getLastMessage().equals(chat.getLastMessage()) ||
                        existingChat.getUnreadCount() != chat.getUnreadCount()) {
                        listModel.setElementAt(chat, i);
                    }
                    found = true;
                    break;
                }
            }
            
            // Если чат новый, добавляем его в список
            if (!found) {
                listModel.addElement(chat);
            }
        }
        
        // Если был выбран чат, восстанавливаем выбор
        if (selectedId != null) {
            selectChatById(selectedId);
        } else if (!listModel.isEmpty()) {
            chatJList.setSelectedIndex(0);
        }
    }
} 