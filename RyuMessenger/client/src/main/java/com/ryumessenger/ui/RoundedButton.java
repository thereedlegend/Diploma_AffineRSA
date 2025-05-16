package com.ryumessenger.ui;

import java.awt.Color;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

import javax.swing.JButton;

public class RoundedButton extends JButton {
    private int radius;
    private Color backgroundColor;
    private Color foregroundColor;

    public RoundedButton(String text, int radius, Color backgroundColor, Color foregroundColor) {
        super(text);
        this.radius = radius;
        this.backgroundColor = backgroundColor;
        this.foregroundColor = foregroundColor;
        setContentAreaFilled(false);
        setFocusPainted(false);
        setOpaque(false);
        setForeground(foregroundColor);
        setFont(AppTheme.FONT_BUTTON);
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        // Фон
        if (getModel().isPressed()) {
            g2.setColor(backgroundColor.darker());
        } else if (!isEnabled()) {
            g2.setColor(backgroundColor.darker().darker());
        } else {
            g2.setColor(backgroundColor);
        }
        g2.fillRoundRect(0, 0, getWidth(), getHeight(), radius, radius);
        // Обводка при фокусе
        if (isFocusOwner()) {
            g2.setColor(new Color(255,255,255,60));
            g2.setStroke(new java.awt.BasicStroke(2f));
            g2.drawRoundRect(1, 1, getWidth()-3, getHeight()-3, radius, radius);
        }
        // Текст
        g2.setFont(getFont());
        FontMetrics fm = g2.getFontMetrics();
        String text = getText();
        int textWidth = fm.stringWidth(text);
        int textHeight = fm.getAscent();
        int x = (getWidth() - textWidth) / 2;
        int y = (getHeight() + textHeight) / 2 - 2;
        g2.setColor(foregroundColor);
        g2.drawString(text, x, y);
        g2.dispose();
    }

    @Override
    public void setBackground(Color bg) {
        this.backgroundColor = bg;
        super.setBackground(bg);
    }

    @Override
    public void setForeground(Color fg) {
        this.foregroundColor = fg;
        super.setForeground(fg);
    }

    @Override
    protected void paintBorder(Graphics g) {
        // Не рисуем стандартную границу
    }
} 