package com.ryumessenger.ui.theme;

import java.awt.Color;
import java.awt.Font;

public class AppTheme {

    public enum ThemeType { LIGHT, DARK }

    private final ThemeType currentThemeType;
    private final Color background;
    private final Color primaryAccent;
    private final Color secondaryAccent;
    private final Color text;
    private final Color textSecondary;
    private final Color inputBackground;
    private final Color myMessageBackground;
    private final Color partnerMessageBackground;
    private final Color myMessageText;
    private final Color partnerMessageText;
    private final Color scrollBar;
    private final Color chatBackground;

    private final Font labelFont;
    private final Font inputFont;
    private final Font buttonFont;
    private final Font headerFont;
    private final Font messageFont;
    private final Font messageInputFont;

    // Шрифты
    public static final Font FONT_GENERAL = new Font("Segoe UI", Font.PLAIN, 15);
    public static final Font FONT_MESSAGE_INPUT = new Font("Segoe UI", Font.PLAIN, 16);
    public static final Font FONT_HEADER = new Font("Segoe UI Semibold", Font.BOLD, 20);
    public static final Font FONT_MESSAGE = new Font("Segoe UI", Font.PLAIN, 15);
    public static final Font FONT_BUTTON = new Font("Segoe UI Semibold", Font.PLAIN, 16);

    public AppTheme(ThemeType currentThemeType, Color background, Color primaryAccent, Color secondaryAccent,
                    Color text, Color textSecondary, Color inputBackground, Color myMessageBackground,
                    Color partnerMessageBackground, Color myMessageText, Color partnerMessageText,
                    Color scrollBar, Color chatBackground, Font labelFont, Font inputFont, Font buttonFont,
                    Font headerFont, Font messageFont, Font messageInputFont) {
        this.currentThemeType = currentThemeType;
        this.background = background;
        this.primaryAccent = primaryAccent;
        this.secondaryAccent = secondaryAccent;
        this.text = text;
        this.textSecondary = textSecondary;
        this.inputBackground = inputBackground;
        this.myMessageBackground = myMessageBackground;
        this.partnerMessageBackground = partnerMessageBackground;
        this.myMessageText = myMessageText;
        this.partnerMessageText = partnerMessageText;
        this.scrollBar = scrollBar;
        this.chatBackground = chatBackground;
        this.labelFont = labelFont;
        this.inputFont = inputFont;
        this.buttonFont = buttonFont;
        this.headerFont = headerFont;
        this.messageFont = messageFont;
        this.messageInputFont = messageInputFont;
    }

    // Геттеры
    public ThemeType getCurrentThemeType() { return currentThemeType; }
    public Color background() { return background; }
    public Color primaryAccent() { return primaryAccent; }
    public Color secondaryAccent() { return secondaryAccent; }
    public Color text() { return text; }
    public Color textSecondary() { return textSecondary; }
    public Color inputBackground() { return inputBackground; }
    public Color myMessageBackground() { return myMessageBackground; }
    public Color partnerMessageBackground() { return partnerMessageBackground; }
    public Color myMessageText() { return myMessageText; }
    public Color partnerMessageText() { return partnerMessageText; }
    public Color scrollBar() { return scrollBar; }
    public Color chatBackground() { return chatBackground; }
    public Font labelFont() { return labelFont; } // Используется FONT_GENERAL
    public Font inputFont() { return inputFont; } // Используется FONT_MESSAGE_INPUT для полей ввода
    public Font buttonFont() { return buttonFont; } // Используется FONT_BUTTON
    public Font headerFont() { return headerFont; } // Используется FONT_HEADER
    public Font messageFont() { return messageFont; } // Используется FONT_MESSAGE
    public Font messageInputFont() { return messageInputFont; } // Используется FONT_MESSAGE_INPUT для поля ввода сообщения

    public boolean isDarkTheme() {
        return currentThemeType == ThemeType.DARK;
    }

    // Стандартные цвета для акцентов
    public static Color highlightRed() { return new Color(220, 50, 50); }
    public static Color highlightGreen() { return new Color(60, 170, 60); }
    public static Color highlightBlue() { return new Color(0, 120, 215); } // Уже есть в теме, но пусть будет и тут для удобства

    // Темы
    public static final AppTheme LIGHT_THEME = new AppTheme(
            ThemeType.LIGHT,
            new Color(0xF5F5F5),      // background
            new Color(0xE0E0E0),      // primaryAccent
            new Color(0xBDBDBD),      // secondaryAccent
            new Color(0x212121),      // text
            new Color(0x757575),      // textSecondary
            new Color(0xFFFFFF),      // inputBackground
            new Color(0xDCF8C6),      // myMessageBackground
            new Color(0xFFFFFF),      // partnerMessageBackground
            new Color(0x000000),      // myMessageText
            new Color(0x000000),      // partnerMessageText
            new Color(0xA0A0A0),      // scrollBar
            new Color(0xFFFFFF),      // chatBackground
            FONT_GENERAL, FONT_MESSAGE_INPUT, FONT_BUTTON, FONT_HEADER, FONT_MESSAGE, FONT_MESSAGE_INPUT
    );

    public static final AppTheme DARK_THEME = new AppTheme(
            ThemeType.DARK,
            new Color(0x1E2A3A),      // background
            new Color(0x2C3E50),      // primaryAccent
            new Color(0x34495E),      // secondaryAccent
            new Color(0xEAEAEA),      // text
            new Color(0xB0B8C4),      // textSecondary
            new Color(0x253546),      // inputBackground
            new Color(0x0B61A4),      // myMessageBackground (более насыщенный синий)
            new Color(0x2C3A47),      // partnerMessageBackground
            Color.WHITE,              // myMessageText
            new Color(0xE0E0E0),      // partnerMessageText
            new Color(0x4A5A6A),      // scrollBar
            new Color(0x17212B),      // chatBackground (темнее основного)
            FONT_GENERAL, FONT_MESSAGE_INPUT, FONT_BUTTON, FONT_HEADER, FONT_MESSAGE, FONT_MESSAGE_INPUT
    );

    public static String toHex(Color color) {
        if (color == null) return "#000000"; // Возвращаем черный, если цвет null
        return String.format("#%02x%02x%02x", color.getRed(), color.getGreen(), color.getBlue());
    }
} 