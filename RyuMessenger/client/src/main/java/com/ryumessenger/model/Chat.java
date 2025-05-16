package com.ryumessenger.model;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;
import org.json.JSONArray;
import java.util.List;
import java.util.ArrayList;

// Модель для представления чата в списке чатов
public class Chat {
    private String id;
    private String displayName;
    private String tag;
    private String lastMessage;
    private String lastMessageTime;
    private int unreadCount;
    private boolean lastMessageFromCurrentUser;
    private boolean isGroup;
    private int chatPartnerId;

    public Chat(JSONObject json) {
        this.id = json.getString("id");
        
        // Исправляем обработку display_name/displayName
        if (json.has("display_name")) {
            this.displayName = json.getString("display_name");
        } else if (json.has("displayName")) {
            this.displayName = json.getString("displayName");
        } else if (json.has("user")) {
            // Особый случай для ответа find_or_create_chat
            JSONObject userObj = json.getJSONObject("user");
            if (userObj.has("display_name")) {
                this.displayName = userObj.getString("display_name");
            } else if (userObj.has("displayName")) {
                this.displayName = userObj.getString("displayName");
            } else {
                this.displayName = userObj.optString("username", "Unknown User");
            }
            
            // Установим chatPartnerId из user.id
            this.chatPartnerId = userObj.optInt("id", 0);
            
            // Также возьмем tag из объекта user, если есть
            this.tag = userObj.optString("tag", null);
        } else {
            this.displayName = "Unknown User";
            System.err.println("Chat: Не найдено поле display_name или displayName в JSON: " + json.toString());
        }
        
        // Остальные поля оставляем как есть
        if (this.tag == null) {
            this.tag = json.optString("tag", null);
        }
        this.lastMessage = json.optString("lastMessage", "");
        this.lastMessageTime = json.optString("lastMessageTime", "");
        this.unreadCount = json.optInt("unreadCount", 0);
        this.lastMessageFromCurrentUser = json.optBoolean("lastMessageFromCurrentUser", false);
        this.isGroup = json.optBoolean("isGroup", false);
        
        // Устанавливаем chatPartnerId, если он еще не установлен
        if (this.chatPartnerId == 0) {
            this.chatPartnerId = json.optInt("chatPartnerId", 0);
        }
    }

    public Chat(int chatPartnerId, String displayName, String tag, String lastMessage, int unreadCount, int lastMessageTime, boolean lastMessageFromCurrentUser) {
        this.id = String.valueOf(chatPartnerId);
        this.chatPartnerId = chatPartnerId;
        this.displayName = displayName;
        this.tag = tag;
        this.lastMessage = lastMessage;
        this.lastMessageTime = String.valueOf(lastMessageTime);
        this.unreadCount = unreadCount;
        this.lastMessageFromCurrentUser = lastMessageFromCurrentUser;
        this.isGroup = false;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getTag() {
        return tag;
    }

    public void setTag(String tag) {
        this.tag = tag;
    }

    public String getLastMessage() {
        return lastMessage;
    }

    public void setLastMessage(String lastMessage) {
        this.lastMessage = lastMessage;
    }

    public String getLastMessageTime() {
        return lastMessageTime;
    }

    public void setLastMessageTime(String lastMessageTime) {
        this.lastMessageTime = lastMessageTime;
    }

    public int getUnreadCount() {
        return unreadCount;
    }

    public void setUnreadCount(int unreadCount) {
        this.unreadCount = unreadCount;
    }

    public boolean isLastMessageFromCurrentUser() {
        return lastMessageFromCurrentUser;
    }

    public void setLastMessageFromCurrentUser(boolean lastMessageFromCurrentUser) {
        this.lastMessageFromCurrentUser = lastMessageFromCurrentUser;
    }

    public boolean isGroup() {
        return isGroup;
    }

    public void setGroup(boolean group) {
        isGroup = group;
    }

    public void incrementUnreadCount() {
        this.unreadCount++;
    }

    public void resetUnreadCount() {
        // This method is not provided in the original code or the new constructor
        // It's assumed to exist as it's called in the equals method
    }

    public int getChatPartnerId() {
        return chatPartnerId;
    }

    public void setChatPartnerId(int chatPartnerId) {
        this.chatPartnerId = chatPartnerId;
    }

    // Форматированное время последнего сообщения
    public String getFormattedLastMessageTime() {
        if (lastMessageTime == null || lastMessageTime.isEmpty()) {
            return "";
        }
        long currentTimeMillis = System.currentTimeMillis();
        long messageTimeMillis = Long.parseLong(lastMessageTime) * 1000;

        Calendar messageCal = Calendar.getInstance();
        messageCal.setTimeInMillis(messageTimeMillis);

        Calendar currentCal = Calendar.getInstance();
        currentCal.setTimeInMillis(currentTimeMillis);

        long diffMillis = currentTimeMillis - messageTimeMillis;
        long diffDays = TimeUnit.MILLISECONDS.toDays(diffMillis);

        if (diffDays == 0 && messageCal.get(Calendar.DAY_OF_YEAR) == currentCal.get(Calendar.DAY_OF_YEAR)) {
            // Сегодня
            return new SimpleDateFormat("HH:mm").format(messageCal.getTime());
        } else if (diffDays == 1 && (currentCal.get(Calendar.DAY_OF_YEAR) - messageCal.get(Calendar.DAY_OF_YEAR) == 1 || 
                                     (currentCal.get(Calendar.YEAR) > messageCal.get(Calendar.YEAR) && messageCal.get(Calendar.DAY_OF_YEAR) == messageCal.getActualMaximum(Calendar.DAY_OF_YEAR)))) {
            // Вчера
            return "Вчера"; // Можно добавить время: "Вчера, HH:mm"
        } else if (diffDays < 7 && diffDays > 0) {
            // На этой неделе (показываем день недели)
            return new SimpleDateFormat("EEE").format(messageCal.getTime()); // Напр., "Пн"
        } else {
            // Давно (показываем дату)
            return new SimpleDateFormat("dd.MM.yy").format(messageCal.getTime());
        }
    }

    @Override
    public String toString() {
        String name = displayName;
        if (tag != null && !tag.equals(displayName)) {
            name += " [@" + tag + "]";
        }
        return name + (unreadCount > 0 ? " (" + unreadCount + ")" : "");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Chat chat = (Chat) o;
        return id.equals(chat.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    public static List<Chat> fromJsonArray(JSONArray array) {
        List<Chat> chats = new ArrayList<>();
        if (array == null) return chats;
        for (int i = 0; i < array.length(); i++) {
            chats.add(new Chat(array.getJSONObject(i)));
        }
        return chats;
    }
} 