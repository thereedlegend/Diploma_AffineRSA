package com.ryumessenger.ui;

import java.awt.Component;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JList;
import com.ryumessenger.model.Chat;
import com.ryumessenger.ui.theme.AppTheme;
import com.ryumessenger.ui.theme.ThemeManager;
import com.ryumessenger.ui.theme.ThemedComponent;
import java.awt.Color;

public class ChatListRenderer extends DefaultListCellRenderer implements ThemedComponent {
    private AppTheme currentTheme;

    public ChatListRenderer() {
        applyTheme();
    }

    @Override
    public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
        super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
        
        if (currentTheme == null) {
            currentTheme = ThemeManager.getInstance().getCurrentTheme(); 
        }

        if (value instanceof Chat) {
            Chat chat = (Chat) value;
            String displayText = "<html><b>" + escapeHtml(chat.getDisplayName()) + "</b>";
            if (chat.getTag() != null && !chat.getTag().isEmpty()) {
                 displayText += " <font color='" + toHex(currentTheme.textSecondary()) + "'>@" + escapeHtml(chat.getTag()) + "</font>";
            }
            if (chat.getLastMessage() != null && !chat.getLastMessage().isEmpty()){
                 displayText += "<br><font size='-1' color='"+toHex(currentTheme.textSecondary())+"'>" + escapeHtml(truncate(chat.getLastMessage(), 30)) + "</font>";
            }
            if (chat.getUnreadCount() > 0) {
                displayText += " <font color='" + toHex(AppTheme.highlightBlue()) + "'><b>(" + chat.getUnreadCount() + ")</b></font>";
            }
            displayText += "</html>";
            setText(displayText);
            setFont(currentTheme.labelFont());
        }

        if (isSelected) {
            setBackground(AppTheme.highlightBlue().darker());
            setForeground(Color.WHITE);
        } else {
            setBackground(currentTheme.background());
            setForeground(currentTheme.text());
        }
        
        setBorder(cellHasFocus ? javax.swing.UIManager.getBorder("List.focusCellHighlightBorder") : javax.swing.BorderFactory.createEmptyBorder(5,5,5,5));

        return this;
    }

    @Override
    public void applyTheme() {
        currentTheme = ThemeManager.getInstance().getCurrentTheme();
        if (currentTheme != null && getParent() instanceof JList) {
            ((JList<?>) getParent()).repaint();
        }
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }
    
    private String toHex(Color color) {
        return String.format("#%02x%02x%02x", color.getRed(), color.getGreen(), color.getBlue());
    }

    private String truncate(String text, int maxLength) {
        if (text == null) return "";
        if (text.length() <= maxLength) return text;
        return text.substring(0, maxLength - 3) + "...";
    }
} 