package com.ryumessenger.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.SwingUtilities;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.ui.theme.ThemedComponent;

/**
 * Окно для отображения процессов шифрования и обмена данными.
 * Реализует паттерн Singleton для обеспечения единственного экземпляра окна.
 */
public class CryptoLogWindow extends JFrame implements ThemedComponent {
    private static CryptoLogWindow instance;
    private JTextPane logArea;
    private DefaultStyledDocument document;
    private final ThemeManager themeManager;
    private static final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    
    // Стили для различных типов сообщений
    private SimpleAttributeSet normalStyle;
    private SimpleAttributeSet errorStyle;
    private SimpleAttributeSet encryptStyle;
    private SimpleAttributeSet decryptStyle;
    private SimpleAttributeSet networkStyle;
    private SimpleAttributeSet timestampStyle;
    
    private CryptoLogWindow() {
        setTitle("Журнал шифрования и обмена данными");
        setSize(850, 600);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
        
        themeManager = ThemeManager.getInstance();
        
        // Инициализация стилей
        normalStyle = new SimpleAttributeSet();
        StyleConstants.setFontFamily(normalStyle, Font.MONOSPACED);
        StyleConstants.setFontSize(normalStyle, 12);
        
        errorStyle = new SimpleAttributeSet(normalStyle);
        StyleConstants.setForeground(errorStyle, new Color(255, 0, 0));
        
        encryptStyle = new SimpleAttributeSet(normalStyle);
        StyleConstants.setForeground(encryptStyle, new Color(0, 128, 0));
        
        decryptStyle = new SimpleAttributeSet(normalStyle);
        StyleConstants.setForeground(decryptStyle, new Color(0, 0, 200));
        
        networkStyle = new SimpleAttributeSet(normalStyle);
        StyleConstants.setForeground(networkStyle, new Color(128, 0, 128));
        
        timestampStyle = new SimpleAttributeSet(normalStyle);
        StyleConstants.setForeground(timestampStyle, new Color(100, 100, 100));
        
        // Создание документа и текстовой области
        document = new DefaultStyledDocument();
        logArea = new JTextPane(document);
        logArea.setEditable(false);
        
        // Автоматическая прокрутка к новым записям
        DefaultCaret caret = (DefaultCaret) logArea.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setPreferredSize(new Dimension(850, 550));
        
        getContentPane().add(scrollPane, BorderLayout.CENTER);
        
        // Панель с кнопками
        JPanel buttonPanel = new JPanel();
        JButton clearButton = new JButton("Очистить");
        clearButton.addActionListener(_ -> clear());
        
        JButton copyButton = new JButton("Копировать");
        copyButton.addActionListener(_ -> {
            logArea.selectAll();
            logArea.copy();
            logArea.setSelectionStart(logArea.getSelectionEnd());
            JOptionPane.showMessageDialog(this, "Журнал скопирован в буфер обмена", "Копирование", JOptionPane.INFORMATION_MESSAGE);
        });
        
        buttonPanel.add(clearButton);
        buttonPanel.add(copyButton);
        getContentPane().add(buttonPanel, BorderLayout.SOUTH);
        
        themeManager.registerThemedComponent(this);
        applyTheme();
        
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                // Только скрываем окно, но не уничтожаем его
                setVisible(false);
            }
        });
        
        CryptoLogWindow.log("Журнал шифрования и обмена данными инициализирован.");
    }
    
    public static synchronized CryptoLogWindow getInstance() {
        if (instance == null) {
            instance = new CryptoLogWindow();
        }
        return instance;
    }
    
    /**
     * Добавляет запись в журнал
     * @param message текст сообщения для записи
     */
    public static void log(String message) {
        SwingUtilities.invokeLater(() -> {
            CryptoLogWindow window = getInstance();
            String timestamp = LocalDateTime.now().format(timeFormatter);
            
            try {
                window.document.insertString(window.document.getLength(), 
                                           "[" + timestamp + "] ", 
                                           window.timestampStyle);
                
                window.document.insertString(window.document.getLength(), 
                                           message + "\n", 
                                           window.normalStyle);
            } catch (BadLocationException e) {
                e.printStackTrace();
            }
        });
    }
    
    /**
     * Добавляет запись в журнал с заголовком операции и соответствующим стилем
     * @param operation название операции (напр. "Шифрование", "Отправка на сервер")
     * @param details детали операции
     */
    public static void logOperation(String operation, String details) {
        SwingUtilities.invokeLater(() -> {
            CryptoLogWindow window = getInstance();
            String timestamp = LocalDateTime.now().format(timeFormatter);
            
            try {
                // Вставка временной метки
                window.document.insertString(window.document.getLength(), 
                                           "[" + timestamp + "] ", 
                                           window.timestampStyle);
                
                // Определение стиля на основе типа операции
                AttributeSet style = window.normalStyle;
                
                if (operation.toLowerCase().contains("ошибка")) {
                    style = window.errorStyle;
                } else if (operation.toLowerCase().contains("шифр")) {
                    style = window.encryptStyle;
                } else if (operation.toLowerCase().contains("расшифр")) {
                    style = window.decryptStyle;
                } else if (operation.toLowerCase().contains("сет") || 
                          operation.toLowerCase().contains("запрос") ||
                          operation.toLowerCase().contains("получ")) {
                    style = window.networkStyle;
                }
                
                // Вставка операции и деталей
                window.document.insertString(window.document.getLength(), 
                                          operation + ": ", 
                                          style);
                
                window.document.insertString(window.document.getLength(), 
                                          details + "\n", 
                                          window.normalStyle);
            } catch (BadLocationException e) {
                e.printStackTrace();
            }
        });
    }
    
    /**
     * Очищает содержимое журнала
     */
    public static void clear() {
        SwingUtilities.invokeLater(() -> {
            CryptoLogWindow window = getInstance();
            window.logArea.setText("");
            CryptoLogWindow.log("Журнал очищен");
        });
    }
    
    @Override
    public void applyTheme() {
        getContentPane().setBackground(themeManager.getCurrentTheme().background());
        logArea.setBackground(themeManager.getCurrentTheme().background());
        logArea.setCaretColor(themeManager.getCurrentTheme().text());
        
        // Обновляем цвета для светлой/тёмной темы
        if (themeManager.getCurrentTheme().isDarkTheme()) {
            // Тёмная тема
            StyleConstants.setForeground(normalStyle, new Color(220, 220, 220));
            StyleConstants.setForeground(errorStyle, new Color(255, 100, 100));
            StyleConstants.setForeground(encryptStyle, new Color(100, 255, 100));
            StyleConstants.setForeground(decryptStyle, new Color(100, 100, 255));
            StyleConstants.setForeground(networkStyle, new Color(200, 100, 200));
            StyleConstants.setForeground(timestampStyle, new Color(150, 150, 150));
        } else {
            // Светлая тема
            StyleConstants.setForeground(normalStyle, new Color(0, 0, 0));
            StyleConstants.setForeground(errorStyle, new Color(200, 0, 0));
            StyleConstants.setForeground(encryptStyle, new Color(0, 120, 0));
            StyleConstants.setForeground(decryptStyle, new Color(0, 0, 180));
            StyleConstants.setForeground(networkStyle, new Color(120, 0, 120));
            StyleConstants.setForeground(timestampStyle, new Color(100, 100, 100));
        }
        
        // Принудительное обновление отображения
        logArea.repaint();
    }
} 