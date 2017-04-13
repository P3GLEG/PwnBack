/*
 * Created by JFormDesigner on Wed Apr 05 18:40:40 PDT 2017
 */

package com.k4ch0w.pwnback;

import net.miginfocom.swing.MigLayout;
import org.jdesktop.swingx.VerticalLayout;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author Paul Ganea
 */
public class PwnBackGUI extends JPanel {
    private PwnBackMediator mediator;
    private PwnBackTable table;
    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    // Generated using JFormDesigner non-commercial license
    private JPanel panel7;
    private JPanel settingsPanel;
    private JLabel label2;
    private JTextField webDriverTextField;
    private JLabel label3;
    private JTextField httpParserTextField;
    private JLabel label4;
    private JTextField startYearTextField;
    private JLabel label5;
    private JTextField endYearTextField;
    private JLabel label6;
    private JTextField phantomJSTextField;
    private JButton phantomJSLocBtn;
    private JLabel label7;
    private JTextField outputDirectoryTextField;
    private JButton outputBtn;
    private JLabel label8;
    private JTextField caBundleTextField;
    private JButton caBundleBtn;
    private JLabel label1;
    private JTextField domainTextField;
    private JButton cancelBtn;
    private JButton startBtn;
    private PwnBackWebTree webTreePanel;
    private JButton exportBtn;
    private JPanel logTablePanel;

    PwnBackGUI(PwnBackMediator mediator) {
        this.mediator = mediator;
        initComponents();
        table = new PwnBackTable(mediator);
        phantomJSTextField.setText(PwnBackSettings.phatomjsLocation);
        httpParserTextField.setText(Integer.toString(PwnBackSettings.numofHttpResponseParsers));
        startYearTextField.setText(Integer.toString(PwnBackSettings.startYear));
        endYearTextField.setText(Integer.toString(PwnBackSettings.endYear));
        webDriverTextField.setText(Integer.toString(PwnBackSettings.numOfJSWebDrivers));
        outputDirectoryTextField.setText(PwnBackSettings.outputDir);
        //caBundleTextField.setText(PwnBackSettings.caBundleLocation);
        JScrollPane scrollPane = new JScrollPane(table.getLogTable());
        logTablePanel.add(scrollPane);
        cancelBtn.setEnabled(false);
    }

    void notifyUpdate() {
        table.notifyUpdate();
    }

    void addURL(PwnBackNode entry) {
        this.webTreePanel.addTreeNode(entry);
    }

    private void refreshSettings() {
        PwnBackSettings.domainToSearch = domainTextField.getText();
        PwnBackSettings.caBundleLocation = caBundleTextField.getText();
        PwnBackSettings.outputDir = outputDirectoryTextField.getText();
        PwnBackSettings.phatomjsLocation = phantomJSTextField.getText();
        PwnBackSettings.startYear = Integer.parseInt(startYearTextField.getText());
        PwnBackSettings.endYear = Integer.parseInt(endYearTextField.getText());
        PwnBackSettings.numofHttpResponseParsers = Integer.parseInt(httpParserTextField.getText());
        PwnBackSettings.numOfJSWebDrivers = Integer.parseInt(webDriverTextField.getText());
    }

    private void startBtnMouseClicked(MouseEvent e) {
        startBtn.setEnabled(false);
        cancelBtn.setEnabled(true);
        refreshSettings();
        File f = new File(PwnBackSettings.phatomjsLocation);
        if (!f.exists()) {
            JOptionPane.showMessageDialog(this.getParent(),
                    "PhantomJS Binary not found at " + f.getAbsolutePath());
        } else if (domainTextField.getText().isEmpty()) {
            JOptionPane.showMessageDialog(this.getParent(),
                    "No domain put into domainTextField!");
        } else {
            mediator.LOG_INFO("Staring crawl on:" + domainTextField.getText());
            mediator.addDomain(domainTextField.getText());
            mediator.start();
        }


    }

    private void outputBtnMouseClicked(MouseEvent e) {
        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(new java.io.File(System.getProperty("user.home")));
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setAcceptAllFileFilterUsed(false);
        int returnVal = chooser.showOpenDialog(this.getParent());
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            outputDirectoryTextField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void phantomJSLocBtnMouseClicked(MouseEvent e) {
        JFileChooser chooser = new JFileChooser();
        int returnVal = chooser.showOpenDialog(this.getParent());
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            phantomJSTextField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void cancelBtnMouseClicked(MouseEvent e) {
        this.mediator.cancel();
        startBtn.setEnabled(true);
        cancelBtn.setEnabled(false);
    }

    private void exportBtnMouseClicked(MouseEvent e) {
        String timeStamp = new SimpleDateFormat("yyyy-MM-dd-HH-mm").format(new Date());
        Path filename = Paths.get(PwnBackSettings.outputDir, PwnBackSettings.domainToSearch +
                "_" + timeStamp + ".txt");
        if (this.mediator.exportPathsToFile(webTreePanel.getTree(), filename)) {
            JOptionPane.showMessageDialog(this.getParent(),
                    "File written to " + filename);
        } else {
            JOptionPane.showMessageDialog(this.getParent(),
                    "Unable to write to folder " + PwnBackSettings.outputDir + "!");
        }

    }

    private void caBundleBtnMouseClicked(MouseEvent e) {
        JFileChooser chooser = new JFileChooser();
        int returnVal = chooser.showOpenDialog(this.getParent());
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            caBundleTextField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void initComponents() {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        // Generated using JFormDesigner non-commercial license
        panel7 = new JPanel();
        settingsPanel = new JPanel();
        label2 = new JLabel();
        webDriverTextField = new JTextField();
        label3 = new JLabel();
        httpParserTextField = new JTextField();
        label4 = new JLabel();
        startYearTextField = new JTextField();
        label5 = new JLabel();
        endYearTextField = new JTextField();
        label6 = new JLabel();
        phantomJSTextField = new JTextField();
        phantomJSLocBtn = new JButton();
        label7 = new JLabel();
        outputDirectoryTextField = new JTextField();
        outputBtn = new JButton();
        label8 = new JLabel();
        caBundleTextField = new JTextField();
        caBundleBtn = new JButton();
        label1 = new JLabel();
        domainTextField = new JTextField();
        cancelBtn = new JButton();
        startBtn = new JButton();
        webTreePanel = new PwnBackWebTree();
        exportBtn = new JButton();
        logTablePanel = new JPanel();

        //======== this ========
        setLayout(new MigLayout(
                "insets 0,hidemode 3,gap 0 0",
                // columns
                "[300,fill]" +
                        "[grow]",
                // rows
                "[grow,fill]" +
                        "[]" +
                        "[grow]"));

        //======== panel7 ========
        {
            panel7.setLayout(new MigLayout(
                    "fill,insets 0,hidemode 3,align center center,gap 0 0",
                    // columns
                    "[fill]",
                    // rows
                    "[301,fill]" +
                            "[grow]" +
                            "[fill]"));

            //======== settingsPanel ========
            {
                settingsPanel.setLayout(new VerticalLayout(5));

                //---- label2 ----
                label2.setText("# of PhantomJS WebDrivers");
                label2.setHorizontalAlignment(SwingConstants.CENTER);
                settingsPanel.add(label2);
                settingsPanel.add(webDriverTextField);

                //---- label3 ----
                label3.setText("# of HTTP Response Parsers");
                label3.setHorizontalAlignment(SwingConstants.CENTER);
                settingsPanel.add(label3);
                settingsPanel.add(httpParserTextField);

                //---- label4 ----
                label4.setText("Start Year");
                label4.setHorizontalAlignment(SwingConstants.CENTER);
                settingsPanel.add(label4);
                settingsPanel.add(startYearTextField);

                //---- label5 ----
                label5.setText("End Year");
                label5.setHorizontalAlignment(SwingConstants.CENTER);
                settingsPanel.add(label5);
                settingsPanel.add(endYearTextField);

                //---- label6 ----
                label6.setText("PhantomJS Location");
                label6.setHorizontalAlignment(SwingConstants.CENTER);
                settingsPanel.add(label6);
                settingsPanel.add(phantomJSTextField);

                //---- phantomJSLocBtn ----
                phantomJSLocBtn.setText("Select file...");
                phantomJSLocBtn.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        phantomJSLocBtnMouseClicked(e);
                    }
                });
                settingsPanel.add(phantomJSLocBtn);

                //---- label7 ----
                label7.setText("Output Folder");
                label7.setHorizontalAlignment(SwingConstants.CENTER);
                settingsPanel.add(label7);
                settingsPanel.add(outputDirectoryTextField);

                //---- outputBtn ----
                outputBtn.setText("Select folder...");
                outputBtn.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        outputBtnMouseClicked(e);
                    }
                });
                settingsPanel.add(outputBtn);

                //---- label8 ----
                label8.setText("CA-Bundle location");
                label8.setHorizontalAlignment(SwingConstants.CENTER);
                settingsPanel.add(label8);
                settingsPanel.add(caBundleTextField);

                //---- caBundleBtn ----
                caBundleBtn.setText("Select file...");
                caBundleBtn.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        caBundleBtnMouseClicked(e);
                    }
                });
                settingsPanel.add(caBundleBtn);
            }
            panel7.add(settingsPanel, "cell 0 0,alignx center,grow 0 100");

            //---- label1 ----
            label1.setText("Domain: ");
            panel7.add(label1, "cell 0 1,alignx center,growx 0");
            panel7.add(domainTextField, "cell 0 1");

            //---- cancelBtn ----
            cancelBtn.setText("Cancel");
            cancelBtn.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    cancelBtnMouseClicked(e);
                }
            });
            panel7.add(cancelBtn, "cell 0 2");

            //---- startBtn ----
            startBtn.setText("Start");
            startBtn.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    startBtnMouseClicked(e);
                }
            });
            panel7.add(startBtn, "cell 0 2");
        }
        add(panel7, "cell 0 0");

        //======== webTreePanel ========
        {
            webTreePanel.setLayout(new GridLayout());
        }
        add(webTreePanel, "cell 1 0,growx");

        //---- exportBtn ----
        exportBtn.setText("Export Results to File");
        exportBtn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                exportBtnMouseClicked(e);
            }
        });
        add(exportBtn, "cell 1 1,alignx center,growx 0");

        //======== logTablePanel ========
        {
            logTablePanel.setLayout(new GridLayout());
        }
        add(logTablePanel, "cell 0 2 2 1");
        // JFormDesigner - End of component initialization  //GEN-END:initComponents
    }
    // JFormDesigner - End of variables declaration  //GEN-END:variables
}

