package com.k4ch0w.pwnback;

/**
 * Created by k4ch0w on 3/30/17.
 */
public class PwnBackSettings {
    public static int numOfJSWebDrivers;
    public static int numofHttpResponseParsers;
    public static int startYear;
    public static int endYear;
    public static String phatomjsLocation;
    public static String outputDir;
    public static boolean debug;
    public static String domainToSearch;
    private static PwnBackSettings _instance = instance();

    public PwnBackSettings() {
        numOfJSWebDrivers = 3;
        numofHttpResponseParsers = 10;
        startYear = 2000;
        endYear = 2017;
        phatomjsLocation = "/Applications/phantomjs";
        outputDir = System.getProperty("user.home");
        domainToSearch = "";
        debug = false;
    }

    static public PwnBackSettings instance() {
        if (_instance == null) {
            _instance = new PwnBackSettings();
        }
        return _instance;
    }
}
