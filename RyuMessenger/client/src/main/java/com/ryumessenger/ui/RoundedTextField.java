package com.ryumessenger.ui;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Shape;
import java.awt.geom.RoundRectangle2D;

import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;

import com.ryumessenger.ui.theme.AppTheme;
import com.ryumessenger.ui.theme.ThemeManager;

public class RoundedTextField extends JTextField {

    private Shape shape;
    private Color borderColor; // Будет инициализирован в applyCurrentTheme
    private int cornerRadius = 15; // Радиус скругления углов

    public RoundedTextField(int columns) {
        super(columns);
        setOpaque(false); // Делаем поле прозрачным, чтобы отрисовывать свой фон
        setBorder(new EmptyBorder(5, 10, 5, 10)); // Отступы для текста внутри поля
        applyCurrentTheme(); 
    }

    public RoundedTextField() {
        this(0);
    }

    public RoundedTextField(String text) {
        this(0);
        setText(text);
    }

    public RoundedTextField(String text, int columns) {
        this(columns);
        setText(text);
    }
    
    private void applyCurrentTheme() {
        AppTheme theme = ThemeManager.getInstance().getCurrentTheme();
        setBackground(theme.inputBackground());
        setForeground(theme.text());
        setCaretColor(theme.text());
        setSelectionColor(AppTheme.highlightBlue());
        setSelectedTextColor(Color.WHITE);
        // Устанавливаем цвет рамки в зависимости от фокуса
        if (hasFocus()) {
            this.borderColor = AppTheme.highlightBlue();
        } else {
            this.borderColor = theme.secondaryAccent(); 
        }
        repaint();
    }

    public void setBorderColor(Color borderColor) {
        this.borderColor = borderColor;
        repaint();
    }

    public void setCornerRadius(int cornerRadius) {
        this.cornerRadius = cornerRadius;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        // Фон
        g2.setColor(getBackground());
        g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, cornerRadius, cornerRadius);

        // Рамка
        if (borderColor != null) {
            g2.setColor(borderColor);
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, cornerRadius, cornerRadius);
        }
        
        g2.dispose();
        super.paintComponent(g); // Отрисовка текста и каретки
    }

    @Override
    protected void paintBorder(Graphics g) {
        // Не рисуем стандартную рамку, так как мы рисуем свою в paintComponent
    }

    @Override
    public boolean contains(int x, int y) {
        if (shape == null || !shape.getBounds().equals(getBounds())) {
            shape = new RoundRectangle2D.Float(0, 0, getWidth() - 1, getHeight() - 1, cornerRadius, cornerRadius);
        }
        return shape.contains(x, y);
    }

    // Обновление цвета рамки при фокусе
    @Override
    public void processFocusEvent(java.awt.event.FocusEvent e) {
        super.processFocusEvent(e);
        AppTheme theme = ThemeManager.getInstance().getCurrentTheme();
        if (e.getID() == java.awt.event.FocusEvent.FOCUS_GAINED) {
            this.borderColor = AppTheme.highlightBlue();
        } else if (e.getID() == java.awt.event.FocusEvent.FOCUS_LOST) {
            this.borderColor = theme.secondaryAccent();
        }
        repaint();
    }
    
    // Метод для принудительного обновления темы, если понадобится извне
    public void updateTheme() {
        applyCurrentTheme();
    }
} 