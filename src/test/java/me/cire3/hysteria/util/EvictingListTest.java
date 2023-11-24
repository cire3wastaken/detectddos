package me.cire3.hysteria.util;

import junit.framework.TestCase;

public class EvictingListTest extends TestCase {
    public void testEvict(){
        EvictingList<Integer> list = new EvictingList<>(3);

        list.add(3);
        list.add(2);
        list.add(1);
        list.add(0);

        assertEquals(3, list.size());
        assertEquals((Integer) 2, list.get(0));
    }
}