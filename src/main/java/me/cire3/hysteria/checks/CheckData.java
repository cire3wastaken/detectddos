package me.cire3.hysteria.checks;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

//@Target(value = ElementType.)
@Retention(RetentionPolicy.RUNTIME)
public @interface CheckData {
    String name();

    String description();

    double bufferDecay();
}
