package me.cire3.hysteria.util;

import junit.framework.TestCase;

public class TimerUtilTest extends TestCase {
    public void testIncrement(){
        TimerUtil timer = new TimerUtil();
        long instantiatedTime = timer.getTime();
        assertEquals(instantiatedTime + 14, timer.incrementTime(14));
    }

    public void testElapsed(){
        TimerUtil timer = new TimerUtil();
        long beginTime = timer.getTime();
        try {
            Thread.sleep(300);
        } catch (InterruptedException e) {
            while (true){
                if (System.currentTimeMillis() - beginTime >= 300)
                    break;
            }
        }

        assertTrue(timer.elapsed(250));
    }
}