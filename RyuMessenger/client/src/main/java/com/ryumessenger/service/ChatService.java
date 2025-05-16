package com.ryumessenger.service;

import java.util.List;
import java.util.function.Consumer;

import com.ryumessenger.model.Chat;
import com.ryumessenger.model.Message;
import com.ryumessenger.network.ApiClient;

public class ChatService {
    private final ApiClient apiClient;

    public ChatService(ApiClient apiClient) {
        this.apiClient = apiClient;
    }

    /**
     * Запрашивает список чатов для текущего пользователя асинхронно.
     * @param callback Функция обратного вызова, принимающая список объектов Chat.
     */
    public void getChats(Consumer<List<Chat>> callback) {
        com.ryumessenger.model.User currentUser = com.ryumessenger.Main.getCurrentUser();
        if (currentUser == null) {
            System.err.println("ChatService: Cannot get chats. No current user logged in.");
            if (callback != null) callback.accept(null);
            return;
        }
        
        // Вместо GET запроса используем POST запрос
        apiClient.post("/chats", "{}", response -> {
            if (response.isSuccess() && response.getJson() != null && response.getJson().has("chats")) {
                // Сервер возвращает {"chats": []}
                org.json.JSONArray chatsJsonArray = response.getJson().getJSONArray("chats");
                List<Chat> chats = Chat.fromJsonArray(chatsJsonArray);
                callback.accept(chats);
            } else {
                System.err.println("ChatService: Failed to get chats. Status: " + response.getStatusCode() + ", Body: " + response.getBody());
                callback.accept(null);
            }
        });
    }

    /**
     * Запрашивает сообщения для указанного чата асинхронно с возможностью получения только новых сообщений.
     * @param chatId ID чата
     * @param lastMessageId ID последнего известного сообщения (null чтобы получить все)
     * @param limit Количество сообщений для получения
     * @param offset Смещение для получения сообщений
     * @param callback Функция обратного вызова, принимающая список объектов Message.
     */
    public void getMessagesForChat(String chatId, String lastMessageId, int limit, int offset, Consumer<List<Message>> callback) {
        String url = "/chats/" + chatId + "/messages";
        
        // Если указан ID последнего сообщения, добавляем его в URL как параметр запроса
        if (lastMessageId != null && !lastMessageId.isEmpty()) {
            url += "?last_message_id=" + lastMessageId;
            
            // Если нужны дополнительные параметры, добавляем их
            if (limit > 0) {
                url += "&limit=" + limit;
            }
            if (offset > 0) {
                url += "&offset=" + offset;
            }
        } else if (limit > 0 || offset > 0) {
            // Если нет lastMessageId, но есть другие параметры
            url += "?";
            if (limit > 0) {
                url += "limit=" + limit;
                if (offset > 0) {
                    url += "&offset=" + offset;
                }
            } else if (offset > 0) {
                url += "offset=" + offset;
            }
        }
        
        apiClient.get(url, response -> {
            if (response.isSuccess() && response.getJson() != null && response.getJson().has("messages")) {
                org.json.JSONArray messagesJsonArray = response.getJson().getJSONArray("messages");
                List<Message> messages = Message.fromJsonArray(messagesJsonArray);
                callback.accept(messages);
            } else {
                System.err.println("ChatService: Failed to get messages for chat " + chatId + 
                    (lastMessageId != null ? " since message " + lastMessageId : "") + 
                    ". Status: " + response.getStatusCode() + ", Body: " + response.getBody());
                callback.accept(null);
            }
        });
    }
    
    /**
     * Отправляет сообщение асинхронно.
     * @param receiverId ID получателя или ID чата
     * @param content Текст сообщения
     * @param callback Функция обратного вызова, принимающая объект Message (успех/ошибка отправки).
     */
    public void sendMessage(String receiverId, String content, Consumer<Message> callback) {
        com.ryumessenger.crypto.EncryptionService encryptionService = com.ryumessenger.Main.getEncryptionService();
        if (encryptionService == null) {
            System.err.println("ChatService: EncryptionService not available for sendMessage.");
            if (callback != null) callback.accept(null);
            return;
        }

        // Проверяем, является ли receiverId идентификатором чата (формат id1-id2)
        String actualReceiverId = receiverId;
        if (receiverId.contains("-")) {
            // Получаем ID партнера из идентификатора чата
            String[] parts = receiverId.split("-");
            int currentUserId = com.ryumessenger.Main.getCurrentUser().getId();
            actualReceiverId = (Integer.parseInt(parts[0]) == currentUserId) ? parts[1] : parts[0];
        }

        String encryptedReceiverIdPayload = encryptionService.encryptUserIdForServerPayload(actualReceiverId);
        if (encryptedReceiverIdPayload == null) {
            System.err.println("ChatService: Failed to encrypt receiver_id for sendMessage.");
            if (callback != null) callback.accept(null);
            return;
        }

        String encryptedMessagePayload = encryptionService.encryptForServer(content);
        if (encryptedMessagePayload == null) {
            System.err.println("ChatService: Failed to encrypt message content for sendMessage.");
            if (callback != null) callback.accept(null);
            return;
        }

        apiClient.sendMessage(encryptedReceiverIdPayload, encryptedMessagePayload, response -> {
            if (response.isSuccess() && response.getJson() != null) {
                Message message = Message.fromJson(response.getJson());
                callback.accept(message);
            } else {
                System.err.println("ChatService: Failed to send message to receiver " + receiverId + ". Status: " + response.getStatusCode() + ", Body: " + response.getBody());
                // Создаем новое сообщение со статусом "ошибка" вместо возврата null
                Message failedMessage = new Message(
                    null,  // id будет null, так как сообщение не сохранено на сервере
                    content,  // текст сообщения сохраняем как есть
                    System.currentTimeMillis(),
                    true,  // отправлено текущим пользователем
                    receiverId  // chatId = receiverId (или может быть ID чата)
                );
                failedMessage.setStatus(Message.MessageStatus.FAILED);
                callback.accept(failedMessage);
            }
        });
    }

    public void deleteMessage(String messageId, Consumer<Boolean> callback) {
        apiClient.deleteMessage(messageId, response -> {
            if (!response.isSuccess()) {
                 System.err.println("ChatService: Failed to delete message " + messageId + ". Status: " + response.getStatusCode() + ", Body: " + response.getBody());
            }
            callback.accept(response.isSuccess());
        });
    }

    public void editMessage(String messageId, String newContent, Consumer<Message> callback) {
        com.ryumessenger.crypto.EncryptionService encryptionService = com.ryumessenger.Main.getEncryptionService();
        if (encryptionService == null) {
            System.err.println("ChatService: EncryptionService not available for editMessage.");
            if (callback != null) callback.accept(null);
            return;
        }

        String encryptedNewContent = encryptionService.encryptForServer(newContent);
        if (encryptedNewContent == null) {
            System.err.println("ChatService: Failed to encrypt new content for editMessage.");
            if (callback != null) callback.accept(null);
            return;
        }

        apiClient.editMessage(messageId, encryptedNewContent, response -> {
            if (response.isSuccess() && response.getJson() != null) {
                Message message = Message.fromJson(response.getJson());
                callback.accept(message);
            } else {
                 System.err.println("ChatService: Failed to edit message " + messageId + ". Status: " + response.getStatusCode() + ", Body: " + response.getBody());
                callback.accept(null);
            }
        });
    }

    public void searchUsers(String query, Consumer<List<Chat>> callback) {
        apiClient.searchUsers(query, response -> {
            if (response.isSuccess() && response.getJsonArray() != null) {
                List<Chat> usersOrChats = Chat.fromJsonArray(response.getJsonArray()); 
                callback.accept(usersOrChats);
            } else {
                System.err.println("ChatService: Failed to search users with query '" + query + "'. Status: " + response.getStatusCode() + ", Body: " + response.getBody());
                callback.accept(null);
            }
        });
    }

    public void findOrCreateChatWithUser(com.ryumessenger.model.User targetUser, Consumer<Chat> callback) {
        if (targetUser == null) {
            System.err.println("ChatService: Invalid user data provided for findOrCreateChatWithUser.");
            if (callback != null) callback.accept(null);
            return;
        }
        String targetUserId = String.valueOf(targetUser.getId());

        com.ryumessenger.model.User currentUser = com.ryumessenger.Main.getCurrentUser();
        if (currentUser == null) {
            System.err.println("ChatService: Current user not logged in, cannot create chat.");
            if (callback != null) callback.accept(null);
            return;
        }
        // String currentUserId = String.valueOf(currentUser.getId()); // ID текущего пользователя, если нужен в payload

        com.ryumessenger.crypto.EncryptionService encryptionService = com.ryumessenger.Main.getEncryptionService();
        if (encryptionService == null) {
            System.err.println("ChatService: EncryptionService not available for findOrCreateChatWithUser.");
            if (callback != null) callback.accept(null);
            return;
        }

        // Шифруем targetUserId с использованием нового Affine+RSA метода
        String encryptedTargetUserIdPayload = encryptionService.encryptTargetUserIdForServerPayload(targetUserId);
        if (encryptedTargetUserIdPayload == null) {
            System.err.println("ChatService: Failed to encrypt target_user_id for findOrCreateChatWithUser.");
            if (callback != null) callback.accept(null);
            return;
        }
        
        org.json.JSONObject finalBody = new org.json.JSONObject();
        try {
            // Сервер ожидает ключ "encrypted_target_user_id_payload"
            finalBody.put("encrypted_target_user_id_payload", encryptedTargetUserIdPayload);
        } catch (org.json.JSONException e) {
            System.err.println("ChatService: Failed to create final JSON body for findOrCreateChatWithUser: " + e.getMessage());
            if (callback != null) callback.accept(null);
            return;
        }

        apiClient.post("/chats/find-or-create", finalBody.toString(), response -> {
            if (response.isSuccess() && response.getJson() != null) {
                Chat chat = new Chat(response.getJson()); // Предполагается, что сервер вернет JSON чата
                callback.accept(chat);
            } else {
                System.err.println("ChatService: Failed to find or create chat with user " + targetUserId + ". Status: " + response.getStatusCode() + ", Body: " + response.getBody());
                callback.accept(null);
            }
        });
    }
} 