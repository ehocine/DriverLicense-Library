package com.driverlicense.service.categories;

import java.util.Map;
import java.util.TreeMap;


public class LimitationCode {
    static boolean domesticNotInternational = false;
    public static Map<String, LimitationCode> limitationCodes = null;


    private final String code;


    private final String description;


    private final boolean domestic;


    private final boolean needSign;


    private final boolean needValue;


    private LimitationCode(String code, String description, boolean domestic, boolean needSign, boolean needValue) {
        this.code = code;
        this.description = description;
        this.domestic = domestic;
        this.needSign = needSign;
        this.needValue = needValue;
        limitationCodes.put(code, this);
    }


    public String getCode() {
        return this.code;
    }


    public String getDescription() {
        return this.description;
    }


    public boolean isDomestic() {
        return this.domestic;
    }


    public boolean needSign() {
        return this.needSign;
    }


    public boolean needValue() {
        return this.needValue;
    }


    public String toString() {
        return this.code;
    }


    public boolean equals(Object o) {
        if (o instanceof LimitationCode) {
            return ((LimitationCode) o).code.equals(this.code);
        }
        return false;
    }


    static {
        limitationCodes = new TreeMap<>();
    }
}