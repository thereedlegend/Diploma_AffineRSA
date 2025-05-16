package com.ryumessenger.ui.custom;

import javax.swing.JButton;
import java.awt.Color;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.Dimension;
import com.ryumessenger.ui.theme.ThemedComponent;
import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.ui.theme.AppTheme;

public class RoundedButton extends JButton implements ThemedComponent {
    private int cornerRadius;
    private Color customBackgroundColor;
    private Color customForegroundColor;

    public RoundedButton(String text) {
        super(text);
        this.cornerRadius = 15; // Default radius
        setContentAreaFilled(false);
        setFocusPainted(false);
        setBorderPainted(false);
        applyTheme();
        ThemeManager.getInstance().registerThemedComponent(this);
    }

    public RoundedButton(String text, int cornerRadius, Color backgroundColor, Color foregroundColor) {
        super(text);
        this.cornerRadius = cornerRadius;
        this.customBackgroundColor = backgroundColor;
        this.customForegroundColor = foregroundColor;
        setContentAreaFilled(false);
        setFocusPainted(false);
        setBorderPainted(false);
        applyTheme();
        ThemeManager.getInstance().registerThemedComponent(this);
    }

    public void setCornerRadius(int cornerRadius) {
        this.cornerRadius = cornerRadius;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        if (customBackgroundColor != null) {
            g2.setColor(customBackgroundColor);
        } else {
            g2.setColor(getBackground());
        }
        g2.fillRoundRect(0, 0, getWidth(), getHeight(), cornerRadius, cornerRadius);
        
        super.paintComponent(g);
        g2.dispose();
    }

    // This method is needed to make the background transparent for custom painting
    @Override
    public void setContentAreaFilled(boolean b) {
        super.setContentAreaFilled(b);
    }

    @Override
    public void applyTheme() {
        ThemeManager themeManager = ThemeManager.getInstance();
        if (themeManager == null) return;
        AppTheme theme = themeManager.getCurrentTheme();
        if (theme == null) return;

        if (customBackgroundColor == null) {
            setBackground(theme.primaryAccent());
        } else {
             setBackground(customBackgroundColor); // Keep custom if set
        }
        if (customForegroundColor == null) {
            setForeground(theme.text());
        } else {
            setForeground(customForegroundColor); // Keep custom if set
        }
        setFont(theme.buttonFont());
        repaint();
    }

    // Override to ensure preferred size takes border into account for layout if needed
    @Override
    public Dimension getPreferredSize() {
        Dimension size = super.getPreferredSize();
        // Add padding if your border or rounded corners effectively make it larger
        // For now, just default behavior
        return size;
    }
} 