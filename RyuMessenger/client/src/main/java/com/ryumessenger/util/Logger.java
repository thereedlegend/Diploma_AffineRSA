package com.ryumessenger.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Logger {

    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    private static void log(String level, String message, Throwable throwable) {
        String timestamp = LocalDateTime.now().format(formatter);
        System.out.printf("[%s] [%s] %s%n", timestamp, level, message);
        if (throwable != null) {
            throwable.printStackTrace(System.out);
        }
    }

    public static void info(String message) {
        log("INFO", message, null);
    }

    public static void warn(String message) {
        log("WARN", message, null);
    }

    public static void error(String message) {
        log("ERROR", message, null);
    }

    public static void error(String message, Throwable throwable) {
        log("ERROR", message, throwable);
    }
} 