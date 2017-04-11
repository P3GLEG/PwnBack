package com.k4ch0w.pwnback;

import java.awt.*;

/**
 * Created by pganea on 4/7/17.
 */
public class PwnBackTableEntry {
    private final String logMsg;
    private final Color rowColor;

    public PwnBackTableEntry(String msg, PwnBackType logColor) {
        this.logMsg = msg;
        switch (logColor) {
            case LOG_DEBUG:
                this.rowColor = Color.DARK_GRAY;
                break;
            case LOG_INFO:
                this.rowColor = Color.BLUE;
                break;
            case LOG_ERROR:
                this.rowColor = Color.RED;
                break;
            default:
                rowColor = Color.BLACK;
                break;
        }

    }

    public String getLogMsg() {
        return logMsg;
    }

    public Color getRowColor() {
        return rowColor;
    }

    @Override
    public String toString() {
        return logMsg;
    }

}
