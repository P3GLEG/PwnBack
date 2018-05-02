package com.k4ch0w.wayback_machine;

import java.awt.*;

public class PwnBackTableEntry {
    private final String logMsg;
    private final Color rowColor;


    PwnBackTableEntry(String msg) {
        this.logMsg = msg;
        rowColor = Color.BLACK;
    }

    PwnBackTableEntry(String msg, Color color) {
        this.logMsg = msg;
        rowColor = color;
    }

    String getLogMsg() {
        return logMsg;
    }

    @Override
    public String toString() {
        return logMsg;
    }

    Color getRowColor() {
        return rowColor;
    }
}
