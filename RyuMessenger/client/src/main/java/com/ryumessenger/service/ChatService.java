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

                com.ryumessenger.crypto.EncryptionService cryptoService = com.ryumessenger.Main.getEncryptionService();
                com.ryumessenger.security.KeyManager currentUserSecurityKeyManager = com.ryumessenger.Main.getKeyManager();

                if (cryptoService != null && currentUserSecurityKeyManager != null) {
                    for (Message msg : messages) {
                        if (msg.getText() != null && !msg.getText().isEmpty() && !msg.isError()) { // Пытаемся расшифровать, только если есть текст и нет предыдущей ошибки парсинга
                            try {
                                // Содержимое msg.getText() - это e2eEncryptedMessagePayload
                                String decryptedContent = cryptoService.decryptForUser(msg.getText(), currentUserSecurityKeyManager);
                                
                                if (decryptedContent != null) {
                                    msg.setText(decryptedContent); // Обновляем текст сообщения расшифрованным
                                    // Можно добавить флаг msg.setSuccessfullyDecrypted(true); если такой есть
                                } else {
                                    // Не удалось расшифровать (например, ключ не тот, или сообщение не было зашифровано по схеме E2E)
                                    System.err.println("ChatService: Failed to decrypt message ID " + msg.getId() + ". Content might be corrupted, not E2E encrypted, or intended for another recipient.");
                                    msg.setText("[Не удалось расшифровать сообщение: " + msg.getText().substring(0, Math.min(30, msg.getText().length())) + "...]"); // Указываем на ошибку
                                    msg.setError(true); // Устанавливаем флаг ошибки
                                    msg.setStatus(Message.MessageStatus.FAILED); // Можно использовать статус
                                }
                            } catch (Exception e) {
                                System.err.println("ChatService: Exception during decryption of message ID " + msg.getId() + ": " + e.getMessage());
                                e.printStackTrace();
                                msg.setText("[Ошибка при расшифровке сообщения]");
                                msg.setError(true);
                                msg.setStatus(Message.MessageStatus.FAILED);
                            }
                        }
                    }
                } else {
                    System.err.println("ChatService: Cannot decrypt messages. CryptoService or KeyManager not available.");
                    // Сообщения останутся в исходном (возможно, зашифрованном) виде
                    // Можно пометить их как "не расшифровано"
                    for (Message msg : messages) {
                        if (msg.getText() != null && !msg.getText().isEmpty() && !msg.isError()) { // Добавил !msg.isError()
                             msg.setText("[Расшифровка невозможна: сервис не доступен] " + msg.getText().substring(0, Math.min(30, msg.getText().length())) + "...");
                             msg.setError(true);
                        }
                    }
                }
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
     * Отправляет сообщение асинхронно с использованием end-to-end шифрования.
     * @param receiverId ID получателя или ID чата
     * @param content Текст сообщения
     * @param callback Функция обратного вызова, принимающая объект Message (успех/ошибка отправки).
     */
    public void sendMessage(String receiverId, String content, Consumer<Message> callback) {
        com.ryumessenger.crypto.EncryptionService cryptoService = com.ryumessenger.Main.getEncryptionService();
        com.ryumessenger.security.KeyManager currentUserSecurityKeyManager = com.ryumessenger.Main.getKeyManager();

        if (cryptoService == null) {
            System.err.println("ChatService: crypto.EncryptionService not available for sendMessage.");
            handleSendError(null, content, receiverId, "Client configuration error (CryptoService missing)", callback);
            return;
        }
        if (currentUserSecurityKeyManager == null) {
            System.err.println("ChatService: security.KeyManager not available for sendMessage.");
            handleSendError(null, content, receiverId, "Client configuration error (SecurityKeyManager missing)", callback);
            return;
        }

        String actualReceiverIdStr = receiverId;
        if (receiverId.contains("-")) {
            String[] parts = receiverId.split("-");
            // Предполагаем, что ID текущего пользователя - строка
            String currentUserIdStr = String.valueOf(com.ryumessenger.Main.getCurrentUser().getId());
            actualReceiverIdStr = parts[0].equals(currentUserIdStr) ? parts[1] : parts[0];
        }
        final String finalActualReceiverIdStr = actualReceiverIdStr;

        // Шифруем ID получателя для сервера (для маршрутизации)
        String encryptedReceiverIdPayload = cryptoService.encryptUserIdForServerPayload(finalActualReceiverIdStr);
        if (encryptedReceiverIdPayload == null) {
            System.err.println("ChatService: Failed to encrypt receiver_id for sendMessage.");
            handleSendError(null, content, receiverId, "Failed to encrypt receiver ID", callback);
            return;
        }

        // 1. Получаем публичные ключи получателя
        apiClient.fetchUserPublicKeys(finalActualReceiverIdStr, recipientPublicKeys -> {
            if (recipientPublicKeys == null) {
                System.err.println("ChatService: Failed to fetch public keys for receiver " + finalActualReceiverIdStr);
                handleSendError(null, content, receiverId, "Failed to fetch recipient's public keys", callback);
                return;
            }

            // 2. Шифруем сообщение с использованием E2E
            String e2eEncryptedMessagePayload = cryptoService.encryptForUser(content, recipientPublicKeys, currentUserSecurityKeyManager);

            if (e2eEncryptedMessagePayload == null) {
                System.err.println("ChatService: Failed to E2E encrypt message content for sendMessage.");
                handleSendError(null, content, receiverId, "Failed to encrypt message (E2E)", callback);
                return;
            }
            
            System.out.println("ChatService: E2E Encrypted Payload for user " + finalActualReceiverIdStr + ": " + e2eEncryptedMessagePayload.substring(0, Math.min(100, e2eEncryptedMessagePayload.length())) + "...");


            // 3. Отправляем на сервер
            // ApiClient.sendMessage ожидает (encryptedReceiverIdPayload, encryptedMessagePayload, callback)
            // Теперь encryptedMessagePayload - это наш e2eEncryptedMessagePayload
            apiClient.sendMessage(encryptedReceiverIdPayload, e2eEncryptedMessagePayload, response -> {
                if (response.isSuccess() && response.getJson() != null) {
                    Message message = Message.fromJson(response.getJson());
                    // Убедимся, что chatID установлен правильно, если сервер его не возвращает
                    if (message != null && (message.getChatId() == null || message.getChatId().isEmpty())) {
                        message.setChatId(receiverId); // Используем исходный receiverId (может быть ID чата)
                    }
                    if (message != null) {
                        message.setStatus(Message.MessageStatus.SENT); // Устанавливаем статус SENT после успешной отправки
                    }
                    callback.accept(message);
                } else {
                    System.err.println("ChatService: Failed to send message to receiver " + receiverId + ". Status: " + response.getStatusCode() + ", Body: " + response.getBody());
                    handleSendError(null, content, receiverId, response.getErrorMessage(), callback);
                }
            });
        });
    }

    // Вспомогательный метод для обработки ошибок отправки
    private void handleSendError(String messageId, String originalContent, String chatId, String errorMessage, Consumer<Message> callback) {
        if (callback == null) return;
        
        Message failedMessage = new Message(
            messageId, // Может быть null, если ID еще не присвоен
            originalContent,
            System.currentTimeMillis(),
            true, // isFromCurrentUser
            chatId 
        );
        failedMessage.setStatus(Message.MessageStatus.FAILED);
        // Можно добавить поле для текста ошибки в Message, если нужно отображать его в UI
        // failedMessage.setErrorDetails(errorMessage); 
        System.err.println("ChatService Send Error: " + errorMessage);
        callback.accept(failedMessage);
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