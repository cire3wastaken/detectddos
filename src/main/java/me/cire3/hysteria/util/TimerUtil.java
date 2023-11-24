package me.cire3.hysteria.util;

import lombok.Getter;

public class TimerUtil {
    @Getter
    private long time;

    public TimerUtil(){
        this(System.currentTimeMillis());
    }

    public TimerUtil(long time){
        this.time = time;
    }

    public long incrementTime(long increment){
        if (increment <= 0)
            return this.time;

        return this.time += increment;
    }

    public boolean elapsed(long time){
        return (System.currentTimeMillis() - this.time >= time);
    }

    public long reset(){
        return this.time = System.currentTimeMillis();
    }
}
