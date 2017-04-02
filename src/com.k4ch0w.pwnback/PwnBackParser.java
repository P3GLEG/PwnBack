package com.k4ch0w.pwnback;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Scanner;

/**
 * Created by k4ch0w on 3/27/17.
 */
public class PwnBackParser implements Runnable {
    private final PwnBackMediator mediator;
    private final String waybackRequestString = "http://web.archive.org/web/%s/%s";
    private final String ROBOTS_TXT = "robots.txt";
    private final String SITEMAP_XML = "sitemap.xml";

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
                    System.out.println("fuck if I know");
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
                        mediator.addPath(new PwnBackTableEntry(temp[1], doc.getUrlFoundAt()));
                        break;
                    case "allow:":
                        mediator.addPath(new PwnBackTableEntry(temp[1], doc.getUrlFoundAt()));
                        break;
                    case "sitemap:":
                        mediator.addPath(new PwnBackTableEntry("Sitemap: " + temp[1], doc.getUrlFoundAt()));
                        break;
                }
            } else {
                System.out.println(temp);
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
                System.out.println("Found email address " + relHref.replace("mailto:", ""));
            } else if (relHref.startsWith("/web/") && relHref.contains("http")) {
                //Wayback machine uses it's domain to serve content thus things are prepended
                // with http://archive.org/web and why I split them here
                String clean = relHref.substring(relHref.indexOf("http"));
                try {
                    URL temp = new URL(clean);
                    String path = temp.getPath();
                    if (!path.isEmpty() && !path.equals("/") && !path.equals("/web/")
                            && !temp.getHost().contains("archive.org")) {
                        //TODO: Fix edge case http://*.archive.org and /web/ funky logic in parsing
                        mediator.addPath(new PwnBackTableEntry(path, document.getUrlFoundAt()));
                    }
                } catch (MalformedURLException e) {
                    System.err.println("Error parsing URL : " + clean);
                }
            } else if (relHref.equals("") || relHref.startsWith("#") || relHref.equals("/")) {
                System.out.println("Empty or starts with #: " + relHref);
            } else {
                    mediator.addPath(new PwnBackTableEntry(relHref, document.getUrlFoundAt()));
                }
            }
        }



    private void parseWayBackAPI(PwnBackDocument doc) {
        String[] waybackUrls = stripHTMLTags(doc.getDocument()).split("\\r?\\n");
        for (String u :
                waybackUrls) {
            String[] archive = u.split(" ");
            if (archive.length == 7) { //Each archive address has 7 values return
                String url = String.format(waybackRequestString, archive[1], archive[2]);
                mediator.addURL(new PwnBackURL(url, PwnBackType.HTML));
                mediator.addURL(new PwnBackURL(url + ROBOTS_TXT, PwnBackType.ROBOTS));
                mediator.addURL(new PwnBackURL(url + SITEMAP_XML, PwnBackType.SITEMAPXML));
            }
        }
    }

    private void parseSitemapXML(PwnBackDocument doc) {
        DocumentBuilder newDocumentBuilder;
        try {
            newDocumentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            org.w3c.dom.Document parse = newDocumentBuilder.parse(new ByteArrayInputStream(doc.getDocument().getBytes()));
            NodeList nodeList = parse.getElementsByTagName("loc");
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    mediator.addPath(new PwnBackTableEntry(node.getTextContent(), doc.getUrlFoundAt()));
                }
            }
        } catch (ParserConfigurationException | SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
