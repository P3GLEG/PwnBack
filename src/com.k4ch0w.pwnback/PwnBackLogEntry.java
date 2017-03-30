package com.k4ch0w.pwnback;

/**
 * Created by k4ch0w on 3/29/17.
 */
public class PwnBackLogEntry {
    final int tool;
    final String url;
    public PwnBackLogEntry(String url){
        this.tool = 0;
        this.url = url;
    }

    PwnBackLogEntry(int tool, String url) {
        this.tool = tool;
        this.url = url;
    }
}
