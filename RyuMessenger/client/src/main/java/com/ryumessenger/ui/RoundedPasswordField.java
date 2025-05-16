package com.ryumessenger.ui;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Shape;
import java.awt.geom.RoundRectangle2D;

import javax.swing.JPasswordField;
import javax.swing.border.EmptyBorder;

import com.ryumessenger.ui.theme.AppTheme;
import com.ryumessenger.ui.theme.ThemeManager;

public class RoundedPasswordField extends JPasswordField {

    private Shape shape;
    private Color borderColor;
    private int cornerRadius = 15;

    public RoundedPasswordField(int columns) {
        super(columns);
        setOpaque(false);
        setBorder(new EmptyBorder(5, 10, 5, 10));
        applyCurrentTheme();
    }

    public RoundedPasswordField() {
        this(0);
    }

    public RoundedPasswordField(String text) {
        this(0);
        setText(text);
    }

    public RoundedPasswordField(String text, int columns) {
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
        g2.setColor(getBackground());
        g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, cornerRadius, cornerRadius);
        if (borderColor != null) {
            g2.setColor(borderColor);
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, cornerRadius, cornerRadius);
        }
        g2.dispose();
        super.paintComponent(g);
    }

    @Override
    protected void paintBorder(Graphics g) {
        // Custom border painted in paintComponent
    }

    @Override
    public boolean contains(int x, int y) {
        if (shape == null || !shape.getBounds().equals(getBounds())) {
            shape = new RoundRectangle2D.Float(0, 0, getWidth() - 1, getHeight() - 1, cornerRadius, cornerRadius);
        }
        return shape.contains(x, y);
    }

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

    public void updateTheme() {
        applyCurrentTheme();
    }
} 