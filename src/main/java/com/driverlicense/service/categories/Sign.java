package com.driverlicense.service.categories;

import java.util.Map;
import java.util.TreeMap;


public class Sign {
    public static Map<String, Sign> signs = null;


    private final String sign;


    private Sign(String sign) {
        this.sign = sign;
        signs.put(sign, this);
    }


    public String getSign() {
        return this.sign;
    }


    public String toString() {
        return this.sign;
    }


    public boolean equals(Object o) {
        if (o instanceof Sign) {
            return ((Sign) o).sign.equals(this.sign);
        }
        return false;
    }


    static {
        signs = new TreeMap<String, Sign>();
    }
}