package com.k4ch0w.wayback_machine;

import net.miginfocom.swing.MigLayout;
import org.jdesktop.swingx.VerticalLayout;
import org.json.JSONArray;

import javax.swing.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TreeSet;

/**
 * Created by k4ch0w on 3/26/17.
 */

//Wayback documentation located at https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
public class PwnBack {
    private static final String waybackString = "http://web.archive.org/web/timemap/json?" +
            "url=%s/&fl=timestamp:4,original&matchType=prefix" +
            "&filter=statuscode:200&collapse=urlkey&collapse=timestamp:4";
    private JPanel panel = new JPanel();
    private PwnBackTable table = new PwnBackTable();
    private JButton startBtn;
    private JButton exportBtn;
    private JTextField domainTextField;
    private TreeSet<String> paths;


    public JPanel getGui() {
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new VerticalLayout(5));
        JLabel domainLabel = new JLabel("Domain:");
        domainTextField = new JTextField("example.com");
        settingsPanel.add(domainLabel);
        settingsPanel.add(domainTextField);
        startBtn = new JButton();
        startBtn.setText("Go!");
        startBtn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                startBtnMouseClicked(e);
            }
        });
        exportBtn = new JButton();
        exportBtn.setText("Export results");
        exportBtn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                exportBtnMouseClicked(e);
            }
        });
        exportBtn.setEnabled(false);

        panel.setLayout(new MigLayout(
                "fill,insets 0,hidemode 3,align center center,gap 0 0",
                // columns
                "[fill]",
                // rows
                "[301,fill]" +
                        "[grow]" +
                        "[fill]"));

        JScrollPane scrollPane = new JScrollPane(table.getLogTable());
        settingsPanel.add(startBtn);
        settingsPanel.add(exportBtn);
        panel.add(settingsPanel);
        panel.add(scrollPane);
        return panel;
    }

    private void startBtnMouseClicked(MouseEvent e) {
        startBtn.setEnabled(false);
        exportBtn.setEnabled(false);
        table.reset();
        table.log("Starting... this could take about a minute");
        new Thread(() -> {
            go();
            startBtn.setEnabled(true);
            exportBtn.setEnabled(true);
        }).start();
    }

    private void exportBtnMouseClicked(MouseEvent e) {
        exportPathsToFile();
    }


    private void go() {
        URL url;
        paths = new TreeSet<>();
        try {
            url = new URL(String.format(waybackString, domainTextField.getText()));
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.setRequestProperty("robot-id", "k4ch0w");
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();
            JSONArray inputArray = new JSONArray(content.toString());
            inputArray.remove(0);
            for (Object i : inputArray) {
                org.json.JSONArray arr = (org.json.JSONArray) i;
                String path = new URL(arr.get(1).toString()).getPath();
                paths.add(path);
            }
        } catch (IOException e) {
            table.log(new PwnBackTableEntry(e.getMessage()));
            System.out.println(e.getMessage());
        }
        for (String s : paths) {
            table.log(s);
        }
    }

    private void exportPathsToFile() {
        String timeStamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm").format(new Date());
        Path filename = Paths.get(System.getProperty("user.home"), domainTextField.getText() + "_" + timeStamp + ".txt");
        Charset charset = Charset.forName("UTF-8");
        StringBuilder sb = new StringBuilder();
        for (String s : paths) {
            sb.append(s).append("\n");
        }
        boolean ok = true;
        String s = sb.toString();
        try (BufferedWriter writer = Files.newBufferedWriter(filename, charset)) {
            writer.write(s, 0, s.length());
        } catch (IOException x) {
            table.logError(x.getMessage());
            ok = false;
        }
        if (ok) {
            JOptionPane.showMessageDialog(panel,
                    "File written to " + filename);
        } else {
            JOptionPane.showMessageDialog(panel,
                    "Error writing to " + filename);
        }

    }


}



