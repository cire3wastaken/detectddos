package me.cire3.hysteria.util;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;

@AllArgsConstructor
public class EvictingList<E> extends LinkedList<E> {
    @Getter
    private int capacity;

    @Override
    public boolean add(E element) {
        if (size() >= capacity)
            removeFirst();
        return super.add(element);
    }

    public boolean isFull() {
        return size() >= capacity;
    }
}
