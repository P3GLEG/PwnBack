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
    private static final String ROBOTS_TXT = "robots.txt";
    private static final String SITEMAP_XML = "sitemap.xml";
    private final PwnBackMediator mediator;

    PwnBackParser(PwnBackMediator mediator) {
        this.mediator = mediator;
    }

    @Override
    public void run() {
        try {
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
                        mediator.LOG_ERROR("Unable to identify PwnBack DocType " + doc.getType());
                }
            }
        } catch (InterruptedException e) {
            mediator.LOG_DEBUG("Parser Thread Interrupted by Executor");
        }
    }

    private String removeWaybackToolbar(String html) {
        return html.replaceAll("(?s)<!--.BEGIN.WAYBACK.TOOLBAR.INSERT.-->.*?<!--.END.WAYBACK.TOOLBAR.INSERT.-->",
                "");
    }

    private String stripHTMLTags(String html) {
        return Jsoup.parse(html).text();
    }

    private void parseRobotsTxtLine(String line, PwnBackDocument doc) {
        String[] tokens = line.split(" ");
        if (tokens.length == 2) {
            switch (tokens[0]) {
                case "disallow:":
                    mediator.addPath(new PwnBackNode(tokens[1], doc));
                    break;
                case "allow:":
                    mediator.addPath(new PwnBackNode(tokens[1], doc));
                    break;
                case "sitemap:":
                    mediator.addURL(new PwnBackURL(tokens[1], PwnBackType.SITEMAPXML));
                    break;
            }
        } else {
            mediator.LOG_DEBUG("Fix this? " + Arrays.toString(tokens));
        }
    }

    private void parseRobotsTxt(PwnBackDocument doc) {
        String txt = stripHTMLTags(doc.getDocument());
        Scanner scanner = new Scanner(txt);
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine().toLowerCase();
            parseRobotsTxtLine(line, doc);
        }
        scanner.close();
    }

    private boolean isEmailAddress(String href) {
        return href.startsWith("mailto:");
    }

    private boolean isHttpHref(String href) {
        return href.startsWith("/web/") && href.contains("http");
    }

    private boolean checkValidPath(String path) {
        return !path.isEmpty() && !path.equals("/") && !path.equals("/web/");
    }

    private void parseHrefTag(Element tag, PwnBackDocument document) {
        String relHref = tag.attr("href");
        if (isEmailAddress(relHref)) {
            mediator.LOG_INFO("Found email address " + relHref.replace("mailto:", ""));
        } else if (isHttpHref(relHref)) {
            String sanitizedURL = relHref.substring(relHref.indexOf("http"));
            try {
                URL temp = new URL(sanitizedURL);
                String path = temp.getPath();
                if (checkValidPath(path) && checkValidURL(sanitizedURL)) {
                    mediator.addPath(new PwnBackNode(path, document));
                }
            } catch (MalformedURLException e) {
                mediator.LOG_ERROR("Error parsing URL : " + sanitizedURL);
            }
        } else if (relHref.equals("") || relHref.startsWith("#") || relHref.equals("/")) {
            mediator.LOG_DEBUG("Empty or starts with #: " + relHref);
        } else {
            if (checkValidURL(relHref)) {
                mediator.addPath(new PwnBackNode(relHref, document));
            }
        }
    }

    private void parseHTML(PwnBackDocument document) {
        String html = removeWaybackToolbar(document.getDocument());
        Document doc = Jsoup.parse(html);
        Elements links = doc.select("a");
        for (Element tag :
                links) {
            parseHrefTag(tag, document);
        }
    }

    private boolean checkValidURL(String url) {
        try {
            URL temp = new URL(url);
            String hostname = temp.getHost();
            mediator.LOG_DEBUG("Hostname found " + hostname);
            if (hostname != null && !hostname.contains("archive.org") && !hostname.contains("openlibrary.org")
                    && !hostname.contains("archive-it.org")) {
                return true;
            }
        } catch (MalformedURLException e) {
            return false;
        }
        return false;
    }

    private boolean checkValidWayBackArchive(String[] archive) {
        return archive.length == 7 && (!archive[1].equals("http:///") || !archive[1].equals("https:///"));
    }


    private void parseWayBackAPI(PwnBackDocument doc) {
        String[] waybackUrls = stripHTMLTags(doc.getDocument()).split("\\r?\\n");
        for (String u : waybackUrls) {
            String[] archive = u.split(" ");
            if (checkValidWayBackArchive(archive)) {
                String waybackRequestString = "http://web.archive.org/web/%s/%s";
                String url = String.format(waybackRequestString, archive[1], archive[2]);
                mediator.addURL(new PwnBackURL(url, PwnBackType.HTML));
                mediator.addURL(new PwnBackURL(url + ROBOTS_TXT, PwnBackType.ROBOTS));
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
                        mediator.LOG_ERROR("Error figuring out SiteMap type: " + asmi.getClass());
                    }
                }
            } else {
                mediator.LOG_ERROR("Shouldn't be here");
            }
        } catch (IOException | UnknownFormatException e) {
            mediator.LOG_DEBUG(e.getLocalizedMessage());
        }

    }

}
