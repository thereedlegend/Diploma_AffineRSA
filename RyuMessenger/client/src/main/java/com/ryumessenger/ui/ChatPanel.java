package com.ryumessenger.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.swing.Timer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.plaf.basic.BasicScrollBarUI;

import com.ryumessenger.Main;
import com.ryumessenger.model.Chat;
import com.ryumessenger.model.Message;
import com.ryumessenger.model.Message.MessageStatus;
import com.ryumessenger.service.ChatService;
import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.ui.theme.ThemedComponent;
import com.ryumessenger.ui.theme.AppTheme;

public class ChatPanel extends JPanel implements ThemedComponent {
    private final ChatService chatService;
    private Chat currentChat;
    private JTextPane messageArea; 
    private RoundedTextField messageInput;
    private RoundedButton sendButton;
    private JLabel chatPartnerNameLabel; 
    private List<Message> displayedMessages = new ArrayList<>();
    private final ThemeManager themeManager;
    private JPanel topPanel;
    private JPanel inputPanel;
    private static final int FIELD_CORNER_RADIUS = 15;
    private static final int BUTTON_CORNER_RADIUS = 15;
    private Timer messageRefreshTimer; // Таймер для обновления сообщений
    private String lastMessageId; // ID последнего сообщения для получения только новых сообщений

    public ChatPanel() {
        this.chatService = new ChatService(Main.getApiClient());
        this.themeManager = ThemeManager.getInstance();
        setLayout(new BorderLayout(0, 0)); 
        setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        topPanel = new JPanel(new BorderLayout());
        topPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
        chatPartnerNameLabel = new JLabel("Выберите чат");
        topPanel.add(chatPartnerNameLabel, BorderLayout.CENTER);
        add(topPanel, BorderLayout.NORTH);

        messageArea = new JTextPane();
        messageArea.setEditable(false);
        messageArea.setContentType("text/html"); 
        messageArea.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);

        JScrollPane scrollPane = new JScrollPane(messageArea);
        add(scrollPane, BorderLayout.CENTER);

        inputPanel = new JPanel(new BorderLayout(5, 0));
        inputPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
        messageInput = new RoundedTextField();
        messageInput.setCornerRadius(FIELD_CORNER_RADIUS);
        messageInput.setPreferredSize(new Dimension(messageInput.getPreferredSize().width, 35)); 

        sendButton = new RoundedButton("Отправить", BUTTON_CORNER_RADIUS, AppTheme.highlightBlue(), Color.WHITE);

        inputPanel.add(messageInput, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);
        add(inputPanel, BorderLayout.SOUTH);

        sendButton.addActionListener(this::sendMessageAction);
        messageInput.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER && !e.isShiftDown()) {
                    e.consume();
                    sendMessageAction(null);
                }
            }
        }); 

        displayChat(null);
        
        themeManager.registerThemedComponent(this);
        applyTheme();
        
        // Теперь обновление сообщений полностью управляется из MainFrame
        // Таймер здесь не используется, чтобы избежать дублирования запросов
    }

    public void displayChat(Chat chat) {
        this.currentChat = chat;
        this.displayedMessages.clear();
        this.lastMessageId = null; // Сбрасываем ID последнего сообщения при смене чата
        messageArea.setText(""); 

        AppTheme theme = themeManager.getCurrentTheme();
        String commonBodyStyle = "font-family:'" + AppTheme.FONT_GENERAL.getFamily() + "'; font-size:" + AppTheme.FONT_GENERAL.getSize() + "pt; color:" + AppTheme.toHex(theme.textSecondary()) + ";";
        String centeredStyle = commonBodyStyle + "text-align:center; padding-top: 50px;";

        if (chat == null) {
            chatPartnerNameLabel.setText("Выберите чат");
            messageInput.setEnabled(false);
            sendButton.setEnabled(false);
            messageArea.setText("<html><body style=\"" + centeredStyle + "\">Выберите чат для начала общения.</body></html>");
        } else {
            String displayName = chat.getDisplayName();
            String tag = chat.getTag();
            if (tag != null && !tag.equals(displayName)) {
                displayName += " [@" + tag + "]";
            }
            chatPartnerNameLabel.setText(displayName);
            messageInput.setEnabled(true);
            sendButton.setEnabled(true);
            
            // Загружаем сообщения чата при первом открытии
            chatService.getMessagesForChat(chat.getId(), null, 50, 0, messages -> {
                if (messages != null && isDisplayingChat(chat)) {
                    SwingUtilities.invokeLater(() -> {
                        setMessages(messages);
                        // Обновляем ID последнего сообщения только если есть сообщения
                        if (messages.size() > 0) {
                            // Ищем сообщение с наибольшим ID (или временем отправки)
                            Message newestMessage = null;
                            long newestTimestamp = 0;
                            
                            for (Message msg : messages) {
                                if (msg.getSentAt() > newestTimestamp) {
                                    newestMessage = msg;
                                    newestTimestamp = msg.getSentAt();
                                }
                            }
                            
                            if (newestMessage != null && newestMessage.getId() != null) {
                                lastMessageId = newestMessage.getId();
                            }
                        }
                    });
                }
            });
            
            messageInput.requestFocusInWindow();
        }
    }

    /**
     * Показывает сообщение о загрузке или процессе создания чата
     * @param message Текст сообщения для отображения
     */
    public void showLoadingMessage(String message) {
        AppTheme theme = themeManager.getCurrentTheme();
        String centeredStyle = "font-family:'" + AppTheme.FONT_GENERAL.getFamily() + 
                               "'; font-size:" + AppTheme.FONT_GENERAL.getSize() + 
                               "pt; color:" + AppTheme.toHex(theme.textSecondary()) + 
                               "; text-align:center; padding-top: 50px;";
        
        messageArea.setText("<html><body style=\"" + centeredStyle + "\">" + message + "</body></html>");
        messageInput.setEnabled(false);
        sendButton.setEnabled(false);
    }
    
    /**
     * Скрывает сообщение о загрузке и восстанавливает обычный вид панели
     */
    public void hideLoadingMessage() {
        if (currentChat != null) {
            messageInput.setEnabled(true);
            sendButton.setEnabled(true);
            refreshMessagesDisplay();
        } else {
            displayChat(null); // Восстанавливаем исходное состояние
        }
    }

    public void clearMessages() {
        this.displayedMessages.clear();
        messageArea.setText("");
        AppTheme theme = themeManager.getCurrentTheme();
        String centeredStyle = "font-family:'" + AppTheme.FONT_GENERAL.getFamily() + "'; font-size:" + AppTheme.FONT_GENERAL.getSize() + "pt; color:" + AppTheme.toHex(theme.textSecondary()) + "; text-align:center; padding-top: 50px;";
        if (currentChat == null) { 
            messageArea.setText("<html><body style=\"" + centeredStyle + "\">Выберите чат для начала общения.</body></html>");
        } else {
            refreshMessagesDisplay();
        }
    }

    public boolean isDisplayingChat(Chat chat) {
        if (this.currentChat == null && chat == null) return true; 
        if (this.currentChat == null || chat == null) return false; 
        return this.currentChat.getId().equals(chat.getId());
    }

    public void setMessages(List<Message> messages) {
        displayedMessages.clear();
        if (messages != null) {
            // Сортируем сообщения по времени (от старых к новым)
            messages.sort((m1, m2) -> Long.compare(m1.getSentAt(), m2.getSentAt()));
            displayedMessages.addAll(messages);
            
            // Находим самое новое сообщение для обновления lastMessageId
            if (!messages.isEmpty()) {
                Message newestMessage = null;
                long newestTimestamp = 0;
                
                for (Message msg : messages) {
                    if (msg.getSentAt() > newestTimestamp && msg.getId() != null) {
                        newestMessage = msg;
                        newestTimestamp = msg.getSentAt();
                    }
                }
                
                if (newestMessage != null) {
                    lastMessageId = newestMessage.getId();
                }
            }
        }
        refreshMessagesDisplay();
    }

    public void appendMessage(Message message) {
        if (message == null) return;
        boolean exists = false;
        for (int i = 0; i < displayedMessages.size(); i++) {
            Message m = displayedMessages.get(i);
            if (message.getId() != null && m.getId() != null && m.getId().equals(message.getId())) {
                displayedMessages.set(i, message);
                exists = true;
                break;
            }
            if (m.getTempId() != null && message.getTempId() != null && m.getTempId().equals(message.getTempId()) && message.getId() != null) {
                m.setId(message.getId());
                m.setSentAt(message.getSentAt()); 
                m.setStatus(message.getStatus()); 
                m.setText(message.getText());
                exists = true;
                break;
            }
        }
        if (!exists) {
            displayedMessages.add(message);
        }
        refreshMessagesDisplay();
    }
    
    private void refreshMessagesDisplay() {
        AppTheme theme = themeManager.getCurrentTheme();
        String bodyStyle = "font-family: '" + AppTheme.FONT_MESSAGE.getFamily() + "'; font-size: " + AppTheme.FONT_MESSAGE.getSize() + "pt; color: " + AppTheme.toHex(theme.text()) + "; padding: 10px; margin:0;";
        String baseBubbleStyle = "padding: 8px 12px; margin: 2px 0; border-radius: 15px; max-width: 75%; word-wrap: break-word; display: inline-block; box-shadow: 0 1px 1px rgba(0,0,0,0.1);";
        String myMessageBubbleStyle = baseBubbleStyle + "background-color: " + AppTheme.toHex(theme.myMessageBackground()) + "; color: " + AppTheme.toHex(theme.myMessageText()) + ";";
        String partnerMessageBubbleStyle = baseBubbleStyle + "background-color: " + AppTheme.toHex(theme.partnerMessageBackground()) + "; color: " + AppTheme.toHex(theme.partnerMessageText()) + ";";
        String errorBubbleStyle = baseBubbleStyle + "background-color: #ffcccc; color: #cc0000;";
        String timeStyle = "font-size: 0.75em; color: " + AppTheme.toHex(theme.textSecondary()) + "; margin-top: 3px; display: block; text-align: right;";
        String statusStyle = "font-size: 0.7em; color: " + AppTheme.toHex(theme.textSecondary()) + "; margin-left: 5px; display: inline;";

        StringBuilder html = new StringBuilder("<html><head><style>" +
                "body { margin: 0; }" +
                "div.message-row { overflow: hidden; margin-bottom: 4px; }" +
                "</style></head><body style=\"" + bodyStyle + "\">");

        if (currentChat != null && !displayedMessages.isEmpty()) {
            for (Message msg : displayedMessages) {
                String alignment = msg.isFromCurrentUser() ? "right" : "left";
                // Выбираем стиль сообщения в зависимости от наличия ошибки
                String bubbleStyle;
                if (msg.isError()) {
                    bubbleStyle = errorBubbleStyle;
                } else {
                    bubbleStyle = msg.isFromCurrentUser() ? myMessageBubbleStyle : partnerMessageBubbleStyle;
                }
                String uniqueMessageHtmlId = "msg-" + (msg.getId() != null ? msg.getId() : msg.getTempId());

                html.append("<div class='message-row' style='text-align: ").append(alignment).append(";' id='").append(uniqueMessageHtmlId).append("'>");
                html.append("<div class='bubble' style='").append(bubbleStyle).append("'>");
                html.append(escapeHtml(msg.getText()));
                html.append("</div>");

                if (msg.isFromCurrentUser()) {
                    html.append("<span style='").append(timeStyle).append("'>").append(msg.getFormattedTime());
                    if (msg.getStatus() != null && msg.getStatus() != Message.MessageStatus.NONE) {
                         String statusText = "";
                         switch (msg.getStatus()) {
                             case SENDING: statusText = " (отправка...)"; break;
                             case SENT: statusText = " ✓"; break;
                             case DELIVERED: statusText = " ✓✓"; break;
                             case READ: statusText = " ✓✓"; break;
                             case FAILED: statusText = " (ошибка)"; break;
                             default: break;
                         }
                         html.append("<span style='").append(statusStyle).append("'>").append(statusText).append("</span>");
                    }
                    html.append("</span>");
                } else {
                    html.append("<span style='").append(timeStyle).append("'>").append(msg.getFormattedTime()).append("</span>");
                }
                html.append("</div>");
            }
        } else if (currentChat != null) {
            String emptyChatStyle = "font-family:'" + AppTheme.FONT_GENERAL.getFamily() + "'; font-size:" + AppTheme.FONT_GENERAL.getSize() + "pt; color:" + AppTheme.toHex(theme.textSecondary()) + "; text-align:center; padding-top:30px;";
            html.append("<div style=\"" + emptyChatStyle + "\">Нет сообщений в этом чате. Начните общение!</div>");
        } else {
             String centeredStyleText = "font-family:'" + AppTheme.FONT_GENERAL.getFamily() + "'; font-size:" + AppTheme.FONT_GENERAL.getSize() + "pt; color:" + AppTheme.toHex(theme.textSecondary()) + "; text-align:center; padding-top: 50px;";
             html.append("<div style=\"" + centeredStyleText + "\">Выберите чат для начала общения.</div>");
        }
        html.append("</body></html>");

        final String finalHtml = html.toString();
        SwingUtilities.invokeLater(() -> {
            JScrollPane parentScrollPane = null;
            Component parent = messageArea.getParent();
            if (parent instanceof javax.swing.JViewport) {
                parent = parent.getParent();
                if (parent instanceof JScrollPane) {
                    parentScrollPane = (JScrollPane) parent;
                }
            }

            messageArea.setText(finalHtml);
            
            boolean scrollToBottom = false;
            if (!displayedMessages.isEmpty()) {
                Message lastMessage = displayedMessages.get(displayedMessages.size() - 1);
                if (parentScrollPane != null) {
                    int currentScrollPos = parentScrollPane.getVerticalScrollBar().getValue();
                    int maxScroll = parentScrollPane.getVerticalScrollBar().getMaximum() - parentScrollPane.getVerticalScrollBar().getVisibleAmount();
                    boolean wasAtBottom = (maxScroll <= 0 || currentScrollPos >= maxScroll - 20);

                    if (lastMessage.isFromCurrentUser() && (lastMessage.getStatus() == Message.MessageStatus.SENDING || lastMessage.getStatus() == Message.MessageStatus.SENT)) {
                        scrollToBottom = true; 
                    } else if (wasAtBottom) {
                        scrollToBottom = true;
                    }
                } else {
                    scrollToBottom = true;
                }
            }

            if (scrollToBottom && parentScrollPane != null) {
                 parentScrollPane.getVerticalScrollBar().setValue(parentScrollPane.getVerticalScrollBar().getMaximum());
            }
            if (scrollToBottom) SwingUtilities.invokeLater(() -> messageArea.setCaretPosition(messageArea.getDocument().getLength()));
        });
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\n", "<br>"); 
    }

    private void sendMessageAction(ActionEvent e) {
        if (currentChat == null) return;
        String text = messageInput.getText().trim();
        if (text.isEmpty()) return;

        final String tempId = UUID.randomUUID().toString();
        Message optimisticMessage = new Message(
                tempId,
                text,
                System.currentTimeMillis(),
                true,
                currentChat.getId()
        );
        optimisticMessage.setStatus(MessageStatus.SENDING);
        appendMessage(optimisticMessage);
        messageInput.setText("");

        // Делаем локальную копию объекта currentChat,
        // чтобы избежать проблем при переключении чатов во время отправки
        final Chat targetChat = currentChat;
        
        chatService.sendMessage(targetChat.getId(), text, sentMessage -> {
            if (sentMessage != null && sentMessage.getId() != null) {
                // Обновляем сообщение только если мы все еще в том же чате
                if (isDisplayingChat(targetChat)) {
                    boolean messageFound = false;
                    for (int i = 0; i < displayedMessages.size(); i++) {
                        Message m = displayedMessages.get(i);
                        if (m.getTempId() != null && m.getTempId().equals(optimisticMessage.getTempId())) {
                            displayedMessages.set(i, sentMessage);
                            messageFound = true;
                            
                            // Обновляем lastMessageId, чтобы избежать дублирования в refreshMessages
                            if (sentMessage.getId() != null) {
                                lastMessageId = sentMessage.getId();
                            }
                            break;
                        }
                    }
                    
                    if (!messageFound) {
                        // Если по какой-то причине сообщение не найдено (редкий случай),
                        // добавляем его и обновляем lastMessageId
                        displayedMessages.add(sentMessage);
                        lastMessageId = sentMessage.getId();
                    }
                    
                    refreshMessagesDisplay();
                }
            } else {
                // Если произошла ошибка, но мы все еще в том же чате
                if (isDisplayingChat(targetChat)) {
                    for (int i = 0; i < displayedMessages.size(); i++) {
                        Message m = displayedMessages.get(i);
                        if (m.getTempId() != null && m.getTempId().equals(optimisticMessage.getTempId())) {
                            m.setStatus(MessageStatus.FAILED);
                            break;
                        }
                    }
                    
                    if (sentMessage == null) {
                        JOptionPane.showMessageDialog(this, "Ошибка отправки сообщения", "Ошибка", JOptionPane.ERROR_MESSAGE);
                    }
                    
                    refreshMessagesDisplay();
                }
            }
        });
    }

    /**
     * Возвращает количество отображаемых сообщений в текущем чате.
     */
    public int getDisplayedMessagesCount() {
        return displayedMessages.size();
    }

    @Override
    public void applyTheme() {
        AppTheme theme = themeManager.getCurrentTheme();
        setBackground(theme.background());
        if (topPanel != null) {
            topPanel.setBackground(theme.background());
        }
        if (inputPanel != null) {
            inputPanel.setBackground(theme.background());
        }

        if (chatPartnerNameLabel != null) {
            chatPartnerNameLabel.setFont(AppTheme.FONT_HEADER);
            chatPartnerNameLabel.setForeground(theme.text());
        }

        if (messageArea != null) {
            messageArea.setBackground(theme.chatBackground());
            if (currentChat != null) {
                refreshMessagesDisplay();
            }
        }

        if (messageInput != null) {
            messageInput.updateTheme();
            messageInput.setFont(theme.inputFont());
        }

        if (sendButton != null) {
            sendButton.setFont(theme.buttonFont());
            sendButton.setBackground(AppTheme.highlightBlue());
            sendButton.setForeground(Color.WHITE);
        }

        Component scrollParent = (messageArea != null) ? messageArea.getParent() : null;
        if (scrollParent instanceof javax.swing.JViewport) {
            scrollParent = scrollParent.getParent();
            if (scrollParent instanceof JScrollPane) {
                JScrollPane scroll = (JScrollPane) scrollParent;
                scroll.setBackground(theme.background());
                scroll.getViewport().setBackground(theme.chatBackground());
                scroll.setBorder(BorderFactory.createEmptyBorder());
                
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
                    private JButton createZeroButton() { JButton b = new JButton(); b.setPreferredSize(new Dimension(0,0)); b.setMinimumSize(new Dimension(0,0)); b.setMaximumSize(new Dimension(0,0)); return b;}
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
                    private JButton createZeroButton() { JButton b = new JButton(); b.setPreferredSize(new Dimension(0,0)); b.setMinimumSize(new Dimension(0,0)); b.setMaximumSize(new Dimension(0,0)); return b;}
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
        // Останавливаем таймер при удалении панели, если он был запущен
        if (messageRefreshTimer != null && messageRefreshTimer.isRunning()) {
            messageRefreshTimer.stop();
        }
        themeManager.unregisterThemedComponent(this);
    }

    // Метод для обновления сообщений в текущем чате
    public void refreshMessages() {
        if (currentChat == null) return;
        
        String chatId = currentChat.getId();
        
        // Получаем только новые сообщения, используя ID последнего сообщения
        chatService.getMessagesForChat(chatId, lastMessageId, 50, 0, messages -> {
            if (messages != null && !messages.isEmpty() && isDisplayingChat(currentChat)) {
                // Обрабатываем только если есть новые сообщения и мы все еще в том же чате
                SwingUtilities.invokeLater(() -> {
                    // Обновляем ID последнего сообщения только один раз - для самого последнего сообщения
                    if (!messages.isEmpty()) {
                        // Получаем самое новое сообщение (с наибольшим ID)
                        String newestMessageId = null;
                        long newestTimestamp = 0;
                        
                        // Перебираем полученные сообщения и добавляем только те, которых ещё нет
                        for (Message msg : messages) {
                            // Проверяем, есть ли уже такое сообщение
                            boolean exists = false;
                            for (Message existingMsg : displayedMessages) {
                                if (existingMsg.getId() != null && existingMsg.getId().equals(msg.getId())) {
                                    exists = true;
                                    break;
                                }
                            }
                            
                            // Если сообщения нет в списке, добавляем его
                            if (!exists) {
                                displayedMessages.add(msg);
                                
                                // Проверяем, не является ли это сообщение более новым
                                if (msg.getId() != null && msg.getSentAt() > newestTimestamp) {
                                    newestMessageId = msg.getId();
                                    newestTimestamp = msg.getSentAt();
                                }
                            }
                        }
                        
                        // Обновляем lastMessageId только один раз для самого нового сообщения
                        if (newestMessageId != null) {
                            lastMessageId = newestMessageId;
                        }
                        
                        refreshMessagesDisplay();
                    }
                });
            }
        });
    }

    /**
     * Возвращает ID последнего известного сообщения в чате.
     * @return ID последнего сообщения или null, если сообщений нет
     */
    public String getLastMessageId() {
        return lastMessageId;
    }
    
    /**
     * Добавляет новые сообщения к существующим, избегая дубликатов.
     * @param newMessages Список новых сообщений для добавления
     */
    public void addNewMessages(List<Message> newMessages) {
        if (newMessages == null || newMessages.isEmpty()) {
            return;
        }
        
        // Сортируем новые сообщения по времени
        newMessages.sort((m1, m2) -> Long.compare(m1.getSentAt(), m2.getSentAt()));
        
        // Отслеживаем самое новое сообщение для обновления lastMessageId
        Message newestMessage = null;
        long newestTimestamp = 0;
        boolean hasNewMessages = false;
        
        // Добавляем только те сообщения, которых еще нет
        for (Message newMsg : newMessages) {
            // Пропускаем сообщения с null id, если они не от текущего пользователя
            if (newMsg.getId() == null && !newMsg.isFromCurrentUser()) {
                continue;
            }
            
            boolean exists = false;
            // Проверяем, есть ли такое сообщение уже в списке
            for (Message existingMsg : displayedMessages) {
                // Проверка по ID (если есть)
                if (existingMsg.getId() != null && newMsg.getId() != null && 
                    existingMsg.getId().equals(newMsg.getId())) {
                    exists = true;
                    break;
                }
                
                // Проверка по временному ID (для сообщений отправленных, но еще не получивших ID с сервера)
                if (existingMsg.getTempId() != null && newMsg.getTempId() != null && 
                    existingMsg.getTempId().equals(newMsg.getTempId())) {
                    // Если сообщение уже есть, но получило ID с сервера, обновляем локальное сообщение
                    if (newMsg.getId() != null && existingMsg.getId() == null) {
                        existingMsg.setId(newMsg.getId());
                        existingMsg.setStatus(newMsg.getStatus());
                    }
                    exists = true;
                    break;
                }
                
                // Дополнительная проверка на дубликат по содержимому и времени
                // Если тексты и время отправки близки (в пределах 2 секунд), считаем дубликатом
                if (existingMsg.getText() != null && newMsg.getText() != null && 
                    existingMsg.getText().equals(newMsg.getText()) &&
                    Math.abs(existingMsg.getSentAt() - newMsg.getSentAt()) < 2000) {
                    exists = true;
                    break;
                }
            }
            
            // Если сообщения нет, добавляем его
            if (!exists) {
                displayedMessages.add(newMsg);
                hasNewMessages = true;
                
                // Обновляем информацию о самом новом сообщении
                if (newMsg.getSentAt() > newestTimestamp && newMsg.getId() != null) {
                    newestMessage = newMsg;
                    newestTimestamp = newMsg.getSentAt();
                }
            }
        }
        
        // Обновляем lastMessageId, если найдено новое сообщение
        if (newestMessage != null) {
            lastMessageId = newestMessage.getId();
        }
        
        // Обновляем отображение, только если были добавлены новые сообщения
        if (hasNewMessages) {
            // Сортируем все сообщения для правильного отображения
            displayedMessages.sort((m1, m2) -> Long.compare(m1.getSentAt(), m2.getSentAt()));
            refreshMessagesDisplay();
        }
    }
} 