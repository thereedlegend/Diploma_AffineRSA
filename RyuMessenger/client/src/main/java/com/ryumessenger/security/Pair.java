package com.ryumessenger.security;

/**
 * Простая реализация пары значений для использования в коллбэках и результатах методов
 */
public class Pair<A, B> {
    private final A first;
    private final B second;
    
    public Pair(A first, B second) {
        this.first = first;
        this.second = second;
    }
    
    public A getFirst() {
        return first;
    }
    
    public B getSecond() {
        return second;
    }
    
    @Override
    public String toString() {
        return "(" + first + ", " + second + ")";
    }
} 