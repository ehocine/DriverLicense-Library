package com.driverlicense.service.categories;

import java.util.Map;
import java.util.TreeMap;

public class DrivingCategory {
    public static final String ALL = "ALL";
    public static Map<String, DrivingCategory> categories = new TreeMap<>();
    private final String category;
    private final String description;

    private DrivingCategory(String str, String str2) {
        this.category = str;
        this.description = str2;
        categories.put(str, this);
    }

    public String getCategory() {
        return this.category;
    }

    public String getDescription() {
        return this.description;
    }

    public boolean isNotSpecific() {
        return ALL.equals(this.category);
    }

    public String toString() {
        return this.category;
    }

    public boolean equals(Object obj) {
        if (obj instanceof DrivingCategory) {
            return ((DrivingCategory) obj).category.equals(this.category);
        }
        return false;
    }

    static {
        new DrivingCategory("a", "Category A vehicles");
        new DrivingCategory("A", "Category A vehicles");
        new DrivingCategory("A1", "Category A1 vehicles");
        new DrivingCategory("A2", "Category A1 vehicles");
        new DrivingCategory("AM", "Category A1 vehicles");
        new DrivingCategory("B", "Category B vehicles");
        new DrivingCategory("B1", "Category B1 vehicles");
        new DrivingCategory("C", "Category C vehicles");
        new DrivingCategory("C1", "Category C1 vehicles");
        new DrivingCategory("D", "Category D vehicles");
        new DrivingCategory("D1", "Category D1 vehicles");
        new DrivingCategory("AE", "Category AE vehicles");
        new DrivingCategory("A1E", "Category A1E vehicles");
        new DrivingCategory("BE", "Category BE vehicles");
        new DrivingCategory("B1E", "Category B1E vehicles");
        new DrivingCategory("CE", "Category CE vehicles");
        new DrivingCategory("C1E", "Category C1E vehicles");
        new DrivingCategory("DE", "Category DE vehicles");
        new DrivingCategory("D1E", "Category D1E vehicles");
        new DrivingCategory("T", "Category T vehicles");
        new DrivingCategory(ALL, "All vehicles");
    }
}