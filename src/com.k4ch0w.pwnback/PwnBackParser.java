package com.k4ch0w.pwnback;

import crawlercommons.sitemaps.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Scanner;

import static org.apache.commons.lang3.CharEncoding.UTF_8;

/**
 * Created by k4ch0w on 3/27/17.
 */
public class PwnBackParser implements Runnable {
    private final PwnBackMediator mediator;

    public PwnBackParser(PwnBackMediator mediator) {
        this.mediator = mediator;
    }

    @Override
    public void run() {
        while (true) {
            PwnBackDocument doc = mediator.getDocument();
            switch (doc.getType()) {
                case WAYBACKAPI:
                    parseWayBackAPI(doc);
                    break;
                case ROBOTS:
                    parseRobotsTxt(doc);
                    break;
                case SITEMAPXML:
                    parseSitemapXML(doc);
                    break;
                case HTML:
                    parseHTML(doc);
                    break;
                default:
                    mediator.addLog("Unable to identify PwnBack DocType " + doc.getType());
            }
        }
    }

    private String removeWaybackToolbar(String html) {
        return html.replaceAll("(?s)<!--.BEGIN.WAYBACK.TOOLBAR.INSERT.-->.*?<!--.END.WAYBACK.TOOLBAR.INSERT.-->",
                "");
    }

    private String stripHTMLTags(String html) {
        return Jsoup.parse(html).text();
    }

    private void parseRobotsTxt(PwnBackDocument doc) {
        String txt = stripHTMLTags(doc.getDocument());
        Scanner scanner = new Scanner(txt);
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine().toLowerCase();
            String[] temp = line.split(" ");
            if (temp.length == 2) {
                switch (temp[0]) {
                    case "disallow:":
                        mediator.addPath(new PwnBackNode(temp[1], doc));
                        break;
                    case "allow:":
                        mediator.addPath(new PwnBackNode(temp[1], doc));
                        break;
                    case "sitemap:":
                        mediator.addURL(new PwnBackURL(temp[1], PwnBackType.SITEMAPXML));
                        break;
                }
            } else {
                mediator.addLog("Fix this? " + Arrays.toString(temp));
            }
        }
        scanner.close();
    }

    private void parseHTML(PwnBackDocument document) {
        String html = removeWaybackToolbar(document.getDocument());
        Document doc = Jsoup.parse(html);
        Elements links = doc.select("a");
        for (Element link :
                links) {
            String relHref = link.attr("href");
            if (relHref.startsWith("mailto:")) {
                mediator.addLog("Found email address " + relHref.replace("mailto:", ""));
            } else if (relHref.startsWith("/web/") && relHref.contains("http")) {
                //Wayback machine uses it's domain to serve content thus things are prepended
                // with http://archive.org/web and why I split them here
                String clean = relHref.substring(relHref.indexOf("http"));
                try {
                    URL temp = new URL(clean);
                    String path = temp.getPath();
                    if (!path.isEmpty() && !path.equals("/") && !path.equals("/web/")
                            && !temp.getHost().contains("archive.org")) {
                        mediator.addPath(new PwnBackNode(path, document));
                    }
                } catch (MalformedURLException e) {
                    mediator.addLog("Error parsing URL : " + clean);
                }
            } else if (relHref.equals("") || relHref.startsWith("#") || relHref.equals("/")) {
                mediator.addLog("Empty or starts with #: " + relHref);
            } else {

                if (checkValidURL(relHref)) {
                    mediator.addPath(new PwnBackNode(relHref, document));
                }
            }
        }
    }

    private boolean checkValidURL(String url) {
        try {
            URL temp = new URL(url);
            String hostname = temp.getHost();
            mediator.addLog("Hostname found " + hostname);
            if (hostname != null && !hostname.contains("archive.org") && !hostname.contains("openlibrary.org")
                    && !hostname.contains("archive-it.org")) {
                return true;
            }
        } catch (MalformedURLException e) {
            return false;
        }
        return false;
    }


    private void parseWayBackAPI(PwnBackDocument doc) {
        String[] waybackUrls = stripHTMLTags(doc.getDocument()).split("\\r?\\n");
        for (String u :
                waybackUrls) {
            String[] archive = u.split(" ");
            if (archive.length == 7 && (!archive[1].equals("http:///") || !archive[1].equals("https:///"))) { //Each archive address has 7 values return
                String waybackRequestString = "http://web.archive.org/web/%s/%s";
                String url = String.format(waybackRequestString, archive[1], archive[2]);
                mediator.addURL(new PwnBackURL(url, PwnBackType.HTML));
                String ROBOTS_TXT = "robots.txt";
                mediator.addURL(new PwnBackURL(url + ROBOTS_TXT, PwnBackType.ROBOTS));
                String SITEMAP_XML = "sitemap.xml";
                mediator.addURL(new PwnBackURL(url + SITEMAP_XML, PwnBackType.SITEMAPXML));
            }
        }
    }

    private void addSiteMapURLS(SiteMap sm, PwnBackDocument doc) {
        for (SiteMapURL url : sm.getSiteMapUrls()) {
            mediator.addPath(new PwnBackNode(url.toString(), doc));
        }
    }

    private void parseSitemapXML(PwnBackDocument doc) {
        try {
            SiteMapParser parser = new SiteMapParser();
            AbstractSiteMap asm = parser.parseSiteMap(doc.getDocument().getBytes(UTF_8), new URL(doc.getUrlFoundAt()));
            if (asm instanceof SiteMap) {
                SiteMap sm = (SiteMap) asm;
                addSiteMapURLS(sm, doc);
            } else if (asm instanceof SiteMapIndex) {
                SiteMapIndex smi = (SiteMapIndex) asm;
                for (AbstractSiteMap asmi : smi.getSitemaps()) {
                    if (asmi instanceof SiteMap) {
                        SiteMap sm = (SiteMap) asmi;
                        addSiteMapURLS(sm, doc);
                    } else {
                        mediator.addLog("Error figuring out ASM type: " + asmi.getClass());
                    }
                }
            } else {
                mediator.addLog("Shouldn't be here");
            }
        } catch (IOException | UnknownFormatException e) {
            e.printStackTrace();
        }

    }

}
