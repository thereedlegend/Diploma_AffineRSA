package com.ryumessenger.ui;

import java.awt.Color;
import java.awt.Font;

public class AppTheme {
    public enum ThemeType {
        LIGHT, DARK
    }

    private static AppTheme instance;
    private static ThemeType currentThemeType = ThemeType.LIGHT;
    
    private Color primaryAccent;
    private Color secondaryAccent;
    private Color text;
    private Color textSecondary;
    private Color highlightBlue;
    private Color highlightGreen;
    private Color highlightRed;
    private Color background;
    private Color inputBackground;
    private Color myMessageBackground;
    private Color myMessageText;
    private Color partnerMessageBackground;
    private Color partnerMessageText;
    private Color scrollBar;

    public static final Font FONT_HEADER = new Font("Arial", Font.BOLD, 16);
    public static final Font FONT_GENERAL = new Font("Arial", Font.PLAIN, 14);
    public static final Font FONT_PRIMARY = new Font("Arial", Font.PLAIN, 14);
    public static final Font FONT_PRIMARY_BOLD = new Font("Arial", Font.BOLD, 14);
    public static final Font FONT_TITLE = new Font("Arial", Font.BOLD, 18);
    public static final Font FONT_MESSAGE = new Font("Arial", Font.PLAIN, 14);
    public static final Font FONT_MESSAGE_INPUT = new Font("Arial", Font.PLAIN, 14);
    public static final Font FONT_BUTTON = new Font("Arial", Font.BOLD, 14);
    public static final Font FONT_CHAT_LIST_ITEM_NAME = new Font("Arial", Font.BOLD, 14);
    public static final Font FONT_CHAT_LIST_ITEM_TAG = new Font("Arial", Font.PLAIN, 12);

    private AppTheme() {
        applyTheme(currentThemeType);
    }

    public static AppTheme getCurrentTheme() {
        if (instance == null) {
            instance = new AppTheme();
        }
        return instance;
    }

    public static void setTheme(ThemeType themeType) {
        currentThemeType = themeType;
        if (instance != null) {
            instance.applyTheme(themeType);
        }
    }

    private void applyTheme(ThemeType themeType) {
        if (themeType == ThemeType.DARK) {
            primaryAccent = new Color(45, 45, 45);
            secondaryAccent = new Color(60, 60, 60);
            text = Color.WHITE;
            textSecondary = new Color(180, 180, 180);
            highlightBlue = new Color(0, 120, 215);
            highlightGreen = new Color(40, 167, 69);
            highlightRed = new Color(220, 53, 69);
            background = new Color(30, 30, 30);
            inputBackground = new Color(45, 45, 45);
            myMessageBackground = new Color(0, 120, 215);
            myMessageText = Color.WHITE;
            partnerMessageBackground = new Color(60, 60, 60);
            partnerMessageText = Color.WHITE;
            scrollBar = new Color(100, 100, 100);
        } else {
            primaryAccent = new Color(240, 240, 240);
            secondaryAccent = new Color(220, 220, 220);
            text = new Color(51, 51, 51);
            textSecondary = new Color(100, 100, 100);
            highlightBlue = new Color(0, 120, 215);
            highlightGreen = new Color(40, 167, 69);
            highlightRed = new Color(220, 53, 69);
            background = Color.WHITE;
            inputBackground = new Color(245, 245, 245);
            myMessageBackground = new Color(0, 120, 215);
            myMessageText = Color.WHITE;
            partnerMessageBackground = new Color(240, 240, 240);
            partnerMessageText = new Color(51, 51, 51);
            scrollBar = new Color(200, 200, 200);
        }
    }

    public static ThemeType getCurrentThemeType() {
        return currentThemeType;
    }

    public static boolean isDarkTheme() {
        return currentThemeType == ThemeType.DARK;
    }

    public Color primaryAccent() { return primaryAccent; }
    public Color secondaryAccent() { return secondaryAccent; }
    public Color text() { return text; }
    public Color textSecondary() { return textSecondary; }
    public Color highlightBlue() { return highlightBlue; }
    public Color highlightGreen() { return highlightGreen; }
    public Color highlightRed() { return highlightRed; }
    public Color background() { return background; }
    public Color inputBackground() { return inputBackground; }
    public Color myMessageBackground() { return myMessageBackground; }
    public Color myMessageText() { return myMessageText; }
    public Color partnerMessageBackground() { return partnerMessageBackground; }
    public Color partnerMessageText() { return partnerMessageText; }
    public Color scrollBar() { return scrollBar; }

    public static String toHex(Color color) {
        return String.format("#%02x%02x%02x", color.getRed(), color.getGreen(), color.getBlue());
    }
} 