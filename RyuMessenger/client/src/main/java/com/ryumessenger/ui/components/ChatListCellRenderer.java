package com.ryumessenger.ui.components;

import java.awt.Component;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JList;
import com.ryumessenger.model.Chat;
import com.ryumessenger.ui.ThemedComponent;
import com.ryumessenger.ui.AppTheme;

public class ChatListCellRenderer extends DefaultListCellRenderer implements ThemedComponent {
    @Override
    public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
        super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
        if (value instanceof Chat) {
            Chat chat = (Chat) value;
            setText(chat.getDisplayName() + " [@" + chat.getTag() + "]");
        }
        return this;
    }

    @Override
    public void applyTheme() {
        AppTheme theme = AppTheme.getCurrentTheme();
        setBackground(theme.primaryAccent());
        setForeground(theme.text());
    }
} 