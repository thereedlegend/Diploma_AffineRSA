package com.ryumessenger.ui.theme;

import java.util.ArrayList;
import java.util.List;

public class ThemeManager {
    private static ThemeManager instance;
    private AppTheme currentTheme;
    private final List<ThemedComponent> themedComponents;

    private ThemeManager() {
        this.currentTheme = AppTheme.LIGHT_THEME;
        this.themedComponents = new ArrayList<>();
    }

    public static ThemeManager getInstance() {
        if (instance == null) {
            instance = new ThemeManager();
        }
        return instance;
    }

    public void setTheme(AppTheme theme) {
        this.currentTheme = theme;
        notifyComponents();
    }

    public AppTheme getCurrentTheme() {
        return currentTheme;
    }

    public void registerThemedComponent(ThemedComponent component) {
        if (!themedComponents.contains(component)) {
            themedComponents.add(component);
            component.applyTheme();
        }
    }

    public void unregisterThemedComponent(ThemedComponent component) {
        themedComponents.remove(component);
    }

    private void notifyComponents() {
        for (ThemedComponent component : themedComponents) {
            component.applyTheme();
        }
    }

    // Статические методы для удобства использования
    public static void setThemeStatic(AppTheme theme) {
        getInstance().setTheme(theme);
    }

    public static AppTheme getCurrentThemeStatic() {
        return getInstance().getCurrentTheme();
    }

    public static void registerThemedComponentStatic(ThemedComponent component) {
        getInstance().registerThemedComponent(component);
    }

    public static void unregisterThemedComponentStatic(ThemedComponent component) {
        getInstance().unregisterThemedComponent(component);
    }

    public static AppTheme.ThemeType getCurrentThemeType() {
        return getInstance().getCurrentTheme() == AppTheme.DARK_THEME ? 
               AppTheme.ThemeType.DARK : AppTheme.ThemeType.LIGHT;
    }

    public static boolean isDarkTheme() {
        return getInstance().getCurrentTheme() == AppTheme.DARK_THEME;
    }
} 