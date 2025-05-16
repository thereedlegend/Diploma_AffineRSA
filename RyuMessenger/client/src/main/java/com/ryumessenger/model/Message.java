package com.ryumessenger.model;

import org.json.JSONObject;
import org.json.JSONArray;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.ArrayList;

public class Message {
    private String id;
    private String tempId;
    private String text;
    private String senderId;
    private long sentAt;
    private boolean fromCurrentUser;
    private String chatId;
    private MessageStatus status;
    private boolean error;

    public enum MessageStatus {
        NONE, SENDING, SENT, DELIVERED, READ, FAILED
    }

    public Message(JSONObject json) {
        this.id = json.optString("id", null);
        this.text = json.optString("text", "");
        this.senderId = json.optString("senderId", "");
        this.sentAt = json.optLong("sentAt", System.currentTimeMillis());
        this.fromCurrentUser = json.optBoolean("fromCurrentUser", false);
        this.chatId = json.optString("chatId", "");
        
        // Проверяем наличие маркера ошибки
        if (json.has("error") && json.getBoolean("error")) {
            this.error = true;
        }
        
        this.status = MessageStatus.SENT;
    }

    public Message(String tempId, String text, long sentAt, boolean fromCurrentUser, String chatId) {
        this.tempId = tempId;
        this.text = text;
        this.sentAt = sentAt;
        this.fromCurrentUser = fromCurrentUser;
        this.chatId = chatId;
        this.status = MessageStatus.SENDING;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTempId() {
        return tempId;
    }

    public void setTempId(String tempId) {
        this.tempId = tempId;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getSenderId() {
        return senderId;
    }

    public void setSenderId(String senderId) {
        this.senderId = senderId;
    }

    public long getSentAt() {
        return sentAt;
    }

    public void setSentAt(long sentAt) {
        this.sentAt = sentAt;
    }

    public boolean isFromCurrentUser() {
        return fromCurrentUser;
    }

    public void setFromCurrentUser(boolean fromCurrentUser) {
        this.fromCurrentUser = fromCurrentUser;
    }

    public String getChatId() {
        return chatId;
    }

    public void setChatId(String chatId) {
        this.chatId = chatId;
    }

    public MessageStatus getStatus() {
        return status;
    }

    public void setStatus(MessageStatus status) {
        this.status = status;
    }

    public String getFormattedTime() {
        LocalDateTime dateTime = LocalDateTime.ofInstant(Instant.ofEpochMilli(sentAt), ZoneId.systemDefault());
        return dateTime.format(DateTimeFormatter.ofPattern("HH:mm"));
    }

    public boolean isError() {
        return error;
    }

    public void setError(boolean error) {
        this.error = error;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Message message = (Message) o;
        return id != null && id.equals(message.id);
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }

    public static List<Message> fromJsonArray(JSONArray jsonArray) {
        List<Message> messages = new ArrayList<>();
        for (int i = 0; i < jsonArray.length(); i++) {
            try {
                JSONObject jsonMessage = jsonArray.getJSONObject(i);
                Message message = fromJson(jsonMessage);
                messages.add(message);
            } catch (Exception e) {
                System.err.println("Error parsing message at index " + i + ": " + e.getMessage());
                // Добавляем сообщение с ошибкой вместо пропуска
                Message errorMessage = new Message(
                    null, 
                    "[Error: Failed to parse message]",
                    System.currentTimeMillis(),
                    false,
                    ""
                );
                errorMessage.setError(true);
                messages.add(errorMessage);
            }
        }
        return messages;
    }

    public static Message fromJson(JSONObject json) {
        try {
            String id = json.optString("id", null);
            String text = json.optString("text", "");
            boolean fromCurrentUser = json.optBoolean("fromCurrentUser", false);
            String chatId = json.optString("chatId", "");
            long sentAt = json.optLong("sentAt", System.currentTimeMillis());
            String senderId = json.optString("senderId", "");
            
            Message message = new Message(id, text, sentAt, fromCurrentUser, chatId);
            message.setSenderId(senderId);
            
            // Обработка сообщений с ошибками
            if (json.has("error") && json.getBoolean("error")) {
                message.setError(true);
            }
            
            return message;
        } catch (Exception e) {
            System.err.println("Error creating Message from JSON: " + e.getMessage());
            // Возвращаем сообщение с ошибкой вместо null
            Message errorMessage = new Message(
                null, 
                "[Error: Failed to parse message]",
                System.currentTimeMillis(),
                false,
                ""
            );
            errorMessage.setError(true);
            return errorMessage;
        }
    }
} 