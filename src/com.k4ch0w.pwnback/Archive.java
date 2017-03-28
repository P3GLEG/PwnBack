package com.k4ch0w.pwnback;

/**
 * Created by k4ch0w on 3/26/17.
 */
public class Archive {
    public final String urlkey;
    public final String timestamp;
    public final String original;
    public final String mimetype;
    public final String statuscode;
    public final String digest;
    public final String length;
    private String robotsTxt = "";
    private String sitemapXML = "";
    private String rootSite = "";

    public Archive(String urlkey, String timestamp, String original, String mimetype, String statuscode, String digest, String length) {
        this.urlkey = urlkey;
        this.timestamp = timestamp;
        this.original = original;
        this.mimetype = mimetype;
        this.statuscode = statuscode;
        this.digest = digest;
        this.length = length;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) return false;
        if (!(obj instanceof Archive)) return false;
        return ((Archive) obj).digest == this.digest;
    }

    public String getRobotsTxt() {
        return robotsTxt;
    }

    public void setRobotsTxt(String robotsTxt) {
        this.robotsTxt = robotsTxt;
    }

    public String getSitemapXML() {
        return sitemapXML;
    }

    public void setSitemapXML(String sitemapXML) {
        this.sitemapXML = sitemapXML;
    }

    public String getRootSite() {
        return rootSite;
    }

    public void setRootSite(String rootSite) {
        this.rootSite = rootSite;
    }
}
