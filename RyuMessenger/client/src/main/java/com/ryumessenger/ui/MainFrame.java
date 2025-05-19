package com.ryumessenger.ui;

import java.util.ArrayList;

import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.Component;
import javax.swing.BorderFactory;

import com.ryumessenger.Main;
import com.ryumessenger.model.Chat;
import com.ryumessenger.service.ChatService;
import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.ui.theme.ThemedComponent;
import com.ryumessenger.ui.theme.AppTheme;

public class MainFrame extends JFrame implements ThemedComponent {

    private final ChatListPanel chatListPanel;
    private final ChatPanel chatPanel;
    private final JSplitPane splitPane;
    private final ChatService chatService;
    private Timer refreshTimer;
    private Chat currentActiveChat = null;
    private Timer chatListRefreshTimer;
    private Timer chatMessagesRefreshTimer;
    private JMenuBar menuBar;
    private final boolean showCryptoLog;

    public MainFrame() {
        this(false);
    }

    public MainFrame(boolean showCryptoLog) {
        setTitle("Ryu Messenger");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1000, 600);
        setLocationRelativeTo(null);
        this.chatService = new ChatService(Main.getApiClient());
        this.showCryptoLog = showCryptoLog;

        // Создаем панели
        chatPanel = new ChatPanel();
        chatListPanel = new ChatListPanel(this::setActiveChat, chatPanel);

        // Настраиваем разделитель
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, chatListPanel, chatPanel);
        splitPane.setDividerLocation(300);
        splitPane.setResizeWeight(0.3);
        add(splitPane);

        // Создаем меню
        menuBar = createMenuBar();
        setJMenuBar(menuBar);

        // Отображаем журнал шифрования, если нужно
        if (showCryptoLog) {
            CryptoLogWindow.getInstance().setVisible(true);
            CryptoLogWindow.log("Главное окно приложения создано");
        }

        // Регистрируем для управления темами
        ThemeManager.getInstance().registerThemedComponent(this);
        // Применяем начальную тему
        applyTheme();
    }

    public void postInit() {
        startRefreshTimers();
    }

    private JMenuBar createMenuBar() {
        JMenuBar mb = new JMenuBar();
        
        JMenu fileMenu = new JMenu("Файл");
        
        JMenuItem settingsMenuItem = new JMenuItem("Настройки");
        JMenuItem logoutMenuItem = new JMenuItem("Выйти из аккаунта");
        JMenuItem exitMenuItem = new JMenuItem("Выход");
        
        fileMenu.add(settingsMenuItem);
        fileMenu.add(logoutMenuItem);
        fileMenu.addSeparator();
        fileMenu.add(exitMenuItem);
        settingsMenuItem.addActionListener(_ -> openSettings());
        logoutMenuItem.addActionListener(_ -> performLogout());
        exitMenuItem.addActionListener(_ -> System.exit(0));
        
        JMenu helpMenu = new JMenu("Справка");
        
        JMenuItem aboutItem = new JMenuItem("О программе");
        aboutItem.addActionListener(_ -> showAboutDialog());
        
        helpMenu.add(aboutItem);
        mb.add(fileMenu);
        mb.add(helpMenu);

        return mb;
    }

    private void openSettings() {
        // Убедимся, что currentUser загружен перед открытием настроек
        if (Main.getCurrentUser() == null) {
            // Можно показать сообщение или просто не открывать диалог
            Main.getUserService().fetchCurrentUser(user -> {
                if (user != null) {
                    SettingsDialog settingsDialog = new SettingsDialog(this, Main.getUserService(), user);
                    settingsDialog.setVisible(true);
                } else {
                    JOptionPane.showMessageDialog(this, "Не удалось загрузить данные пользователя.", "Ошибка", JOptionPane.ERROR_MESSAGE);
                }
            });
        } else {
            SettingsDialog settingsDialog = new SettingsDialog(this, Main.getUserService(), Main.getCurrentUser());
            settingsDialog.setVisible(true);
        }
    }

    private void showAboutDialog() {
        JOptionPane.showMessageDialog(this,
                "RyuMessenger Client\nВерсия 0.1.0 (Альфа)\nРазработано с использованием Java Swing.",
                "О программе",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void performLogout() {
        System.out.println("Performing logout...");
        stopRefreshTimer();

        if (Main.getApiClient() != null) {
            Main.getApiClient().setAuthToken(null);
            System.out.println("Auth token cleared.");
        }

        if (Main.getUserService() != null) {
            Main.getUserService().clearCurrentUser();
            System.out.println("Current user data cleared from UserService.");
        }
        
        this.currentActiveChat = null;
        if (chatPanel != null) {
            chatPanel.displayChat(null);
        }
        if (chatListPanel != null) {
            chatListPanel.setChatList(new ArrayList<>());
        }

        // Скрываем окно журнала, если оно было открыто
        if (showCryptoLog) {
            CryptoLogWindow.getInstance().setVisible(false);
            CryptoLogWindow.log("Выполнен выход из системы");
        }

        dispose();
        System.out.println("MainFrame disposed.");

        SwingUtilities.invokeLater(() -> {
            LoginFrame loginFrame = new LoginFrame();
            loginFrame.setVisible(true);
            System.out.println("LoginFrame shown.");
        });
    }

    private void setActiveChat(Chat chat) {
        if (currentActiveChat != null && chat != null && currentActiveChat.getId().equals(chat.getId())) {
            return;
        }
        currentActiveChat = chat;
        if (chatPanel != null) {
            chatPanel.displayChat(chat);
            
            // Логирование информации о выбранном чате
            if (showCryptoLog && chat != null) {
                CryptoLogWindow.log("Выбран чат: " + chat.getDisplayName());
            }
        }
    }

    private void loadChatList() {
        if (chatService == null) return;
        
        if (showCryptoLog) {
            CryptoLogWindow.log("Загрузка списка чатов...");
        }
        
        chatService.getChats(chats -> {
            if (chatListPanel != null) {
                chatListPanel.setChatList(chats);
                
                if (showCryptoLog && chats != null) {
                    CryptoLogWindow.log("Загружено чатов: " + chats.size());
                }
            }
            if (currentActiveChat != null && chats != null && !chats.contains(currentActiveChat)) {
                setActiveChat(null);
            } else if (currentActiveChat != null && chats != null && chats.contains(currentActiveChat)) {
                for(Chat updatedChat : chats) {
                    if(updatedChat.equals(currentActiveChat)) {
                        currentActiveChat.setLastMessage(updatedChat.getLastMessage());
                        currentActiveChat.setLastMessageTime(updatedChat.getLastMessageTime());
                        if (currentActiveChat.getUnreadCount() != updatedChat.getUnreadCount()) {
                            currentActiveChat.setUnreadCount(updatedChat.getUnreadCount());
                        }
                        chatListPanel.updateChatEntry(currentActiveChat);
                        break;
                    }
                }
            }
        });
    }

    private void loadMessagesForCurrentChat() {
        if (currentActiveChat != null && chatService != null && chatPanel != null) {
            // Проверяем, отображается ли в панели чата тот же чат, что мы хотим обновить
            // Если нет, то не делаем запрос
            if (!chatPanel.isDisplayingChat(currentActiveChat)) {
                return;
            }
            
            // Получаем ID последнего сообщения из панели чата
            String lastMessageId = chatPanel.getLastMessageId();
            
            // Если нет lastMessageId и уже есть сообщения, не делаем повторный запрос всех сообщений
            if (lastMessageId == null && chatPanel.getDisplayedMessagesCount() > 0) {
                return;
            }
            
            if (showCryptoLog) {
                CryptoLogWindow.log("Загрузка сообщений для чата: " + currentActiveChat.getDisplayName() + 
                                   (lastMessageId != null ? " начиная с ID " + lastMessageId : ""));
            }
            
            // Используем меньшее количество сообщений для обновления (10), чем для начальной загрузки (100)
            int limit = (lastMessageId == null) ? 100 : 10;
            
            chatService.getMessagesForChat(currentActiveChat.getId(), lastMessageId, limit, 0, messages -> {
                // Проверяем, что чат всё еще активен и есть новые сообщения
                if (currentActiveChat != null && messages != null && !messages.isEmpty() && 
                    chatPanel.isDisplayingChat(currentActiveChat)) {
                    
                    // Добавляем только новые сообщения к существующим, а не заменяем весь список
                    chatPanel.addNewMessages(messages);
                    
                    if (showCryptoLog) {
                        CryptoLogWindow.log("Загружено новых сообщений: " + messages.size());
                    }
                    
                    if (messages.size() > 0) {
                        // Появились новые сообщения — обновляем список чатов
                        loadChatList();
                    }
                }
            });
        } else if (chatPanel != null) {
            chatPanel.clearMessages();
        }
    }

    // Метод для доступа к значению showCryptoLog
    public boolean isShowCryptoLog() {
        return showCryptoLog;
    }

    private void startRefreshTimers() {
        if (chatListRefreshTimer != null) chatListRefreshTimer.stop();
        if (chatMessagesRefreshTimer != null) chatMessagesRefreshTimer.stop();
        chatListRefreshTimer = new Timer(5000, _ -> loadChatList());
        chatListRefreshTimer.setRepeats(true);
        chatListRefreshTimer.start();
        chatMessagesRefreshTimer = new Timer(2000, _ -> loadMessagesForCurrentChat());
        chatMessagesRefreshTimer.setRepeats(true);
        chatMessagesRefreshTimer.start();
    }

    private void stopRefreshTimer() {
        if (refreshTimer != null && refreshTimer.isRunning()) {
            refreshTimer.stop();
            System.out.println("Refresh timer stopped.");
        }
    }

    @Override
    public void applyTheme() {
        AppTheme theme = ThemeManager.getInstance().getCurrentTheme();
        setBackground(theme.background());
        getContentPane().setBackground(theme.background());
        
        if (splitPane != null) {
            splitPane.setBackground(theme.background());
            if (splitPane.getUI() instanceof javax.swing.plaf.basic.BasicSplitPaneUI) {
                javax.swing.plaf.basic.BasicSplitPaneDivider divider =
                    ((javax.swing.plaf.basic.BasicSplitPaneUI) splitPane.getUI()).getDivider();
                if (divider != null) {
                    divider.setBackground(theme.secondaryAccent());
                    divider.setBorder(null);
                }
            }
            splitPane.setDividerSize(8);
        }

        if (menuBar != null) {
            menuBar.setBackground(theme.primaryAccent());
            menuBar.setBorder(BorderFactory.createLineBorder(theme.secondaryAccent()));

            for (int i = 0; i < menuBar.getMenuCount(); i++) {
                JMenu menu = menuBar.getMenu(i);
                menu.setFont(theme.labelFont());
                menu.setForeground(theme.text());
                menu.setOpaque(true);
                menu.setBackground(theme.primaryAccent());

                if (menu.getPopupMenu() != null) {
                    menu.getPopupMenu().setBackground(theme.primaryAccent());
                    menu.getPopupMenu().setBorder(BorderFactory.createLineBorder(theme.secondaryAccent()));
                }

                for (Component menuItemComp : menu.getMenuComponents()) {
                    if (menuItemComp instanceof JMenuItem) {
                        JMenuItem menuItem = (JMenuItem) menuItemComp;
                        menuItem.setFont(theme.labelFont());
                        menuItem.setBackground(theme.primaryAccent());
                        menuItem.setForeground(theme.text());
                        menuItem.setOpaque(true);
                    }
                }
            }
        }
        
        if (chatListPanel != null && chatListPanel instanceof ThemedComponent) {
            ((ThemedComponent) chatListPanel).applyTheme();
        }
        if (chatPanel != null && chatPanel instanceof ThemedComponent) {
            ((ThemedComponent) chatPanel).applyTheme();
        }
        
        SwingUtilities.updateComponentTreeUI(this);
    }

    @Override
    public void dispose() {
        System.out.println("MainFrame dispose called.");
        ThemeManager.getInstance().unregisterThemedComponent(this);
        stopRefreshTimer();
        super.dispose();
    }

    @Override
    public void removeNotify() {
        System.out.println("MainFrame removeNotify called.");
        stopRefreshTimer(); 
        super.removeNotify();
    }
} 