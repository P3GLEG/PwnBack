package com.k4ch0w.pwnback;

/**
 * Created by k4ch0w on 3/30/17.
 */
public class PwnBackSettings {
    static int numOfJSWebDrivers;
    static int numofHttpResponseParsers;
    static int startYear;
    static int endYear;
    static String phatomjsLocation;
    static String outputDir;
    static String caBundleLocation;
    static boolean debug;
    static String domainToSearch;
    private static PwnBackSettings _instance = instance();

    public PwnBackSettings() {
        numOfJSWebDrivers = 3;
        numofHttpResponseParsers = 10;
        startYear = 2000;
        endYear = 2017;
        phatomjsLocation = "/Applications/phantomjs";
        outputDir = System.getProperty("user.home");
        caBundleLocation = System.getProperty("user.home") + "/cacert.pem";
        domainToSearch = "";
        debug = false;
    }

    private static PwnBackSettings instance() {
        if (_instance == null) {
            _instance = new PwnBackSettings();
        }
        return _instance;
    }
}
