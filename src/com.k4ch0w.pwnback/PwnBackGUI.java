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

/**
 * @author Paul Ganea
 */
public class PwnBackGUI extends JPanel {
    private PwnBackMediator mediator;
    private PwnBackTable table;

    public PwnBackGUI(PwnBackMediator mediator) {
        this.mediator = mediator;
        initComponents();
        table = new PwnBackTable(mediator);
        phantomJSTextField.setText(PwnBackSettings.phatomjsLocation);
        httpParserTextField.setText(Integer.toString(PwnBackSettings.numofHttpResponseParsers));
        startYearTextField.setText(Integer.toString(PwnBackSettings.startYear));
        endYearTextField.setText(Integer.toString(PwnBackSettings.endYear));
        webDriverTextField.setText(Integer.toString(PwnBackSettings.numOfJSWebDrivers));
        outputDirectoryTextField.setText(PwnBackSettings.outputDir);
        JScrollPane scrollPane = new JScrollPane(table.getLogTable());
        logTablePanel.add(scrollPane);
        cancelBtn.setEnabled(false);
    }

    public void notifyUpdate() {
        table.notifyUpdate();
    }

    public void addURL(PwnBackNode entry) {
        this.webTreePanel.addTreeNode(entry);
    }

    private void startBtnMouseClicked(MouseEvent e) {
        File f = new File(PwnBackSettings.phatomjsLocation);
        if (!f.exists()) {
            JOptionPane.showMessageDialog(this.getParent(),
                    "PhantomJS Binary not found at " + f.getAbsolutePath());
        } else if (domainTextField.getText().isEmpty()) {
            JOptionPane.showMessageDialog(this.getParent(),
                    "No domain put into domainTextField!");
        } else {
            mediator.addLog("Staring crawl on:" + domainTextField.getText());
            mediator.addDomain(domainTextField.getText());
            mediator.start();
        }
        startBtn.setEnabled(false);
        cancelBtn.setEnabled(true);
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
        label1 = new JLabel();
        domainTextField = new JTextField();
        cancelBtn = new JButton();
        startBtn = new JButton();
        webTreePanel = new PwnBackWebTree();
        logTablePanel = new JPanel();

        //======== this ========
        setLayout(new MigLayout(
                "insets 0,hidemode 3,gap 0 0",
                // columns
                "[300,fill]" +
                        "[grow]",
                // rows
                "[fill,grow]" +
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

        //======== logTablePanel ========
        {
            logTablePanel.setLayout(new GridLayout());
        }
        add(logTablePanel, "cell 0 1 2 1");
        // JFormDesigner - End of component initialization  //GEN-END:initComponents
    }

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
    private JLabel label1;
    private JTextField domainTextField;
    private JButton cancelBtn;
    private JButton startBtn;
    private PwnBackWebTree webTreePanel;
    private JPanel logTablePanel;
    // JFormDesigner - End of variables declaration  //GEN-END:variables
}

