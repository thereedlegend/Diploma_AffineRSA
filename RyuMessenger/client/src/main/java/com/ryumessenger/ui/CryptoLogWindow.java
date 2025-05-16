package com.ryumessenger.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.text.DefaultCaret;

import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.ui.theme.ThemedComponent;

/**
 * Окно для отображения процессов шифрования и обмена данными.
 * Реализует паттерн Singleton для обеспечения единственного экземпляра окна.
 */
public class CryptoLogWindow extends JFrame implements ThemedComponent {
    private static CryptoLogWindow instance;
    private JTextArea logArea;
    private final ThemeManager themeManager;
    private static final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");

    private CryptoLogWindow() {
        setTitle("Журнал шифрования и обмена данными");
        setSize(750, 500);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
        
        themeManager = ThemeManager.getInstance();
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        // Автоматическая прокрутка к новым записям
        DefaultCaret caret = (DefaultCaret) logArea.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setPreferredSize(new Dimension(750, 500));
        
        getContentPane().add(scrollPane, BorderLayout.CENTER);
        
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
            window.logArea.append("[" + timestamp + "] " + message + "\n");
        });
    }
    
    /**
     * Добавляет запись в журнал с заголовком операции
     * @param operation название операции (напр. "Шифрование", "Отправка на сервер")
     * @param details детали операции
     */
    public static void logOperation(String operation, String details) {
        log(operation + ": " + details);
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
        logArea.setForeground(themeManager.getCurrentTheme().text());
        logArea.setCaretColor(themeManager.getCurrentTheme().text());
    }
} 