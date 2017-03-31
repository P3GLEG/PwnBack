/*
 * Created by JFormDesigner on Thu Mar 30 17:58:59 PDT 2017
 */

package com.k4ch0w.pwnback;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;

/**
 * @author Paul Ganea
 */
public class MainPanel extends JPanel {
    private final PwnBackMediator mediator;
    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    // Generated using JFormDesigner Evaluation license - Paul Ganea
    private JPanel optionsPanel;
    private JLabel jsDriverLabel;
    private JTextField jsDriverTextField;
    private JLabel label2;
    private JLabel httpRespLabel;
    private JTextField httpRespTextField;
    private JLabel label3;
    private JLabel startYearLabel;
    private JTextField starYearTextField;
    private JLabel label4;
    private JLabel endYearLabel;
    private JTextField endYearTextField;
    private JLabel label5;
    private JLabel phantomJSLabel;
    private JTextField phantomJSTextField;
    private JButton phantomJSLocBtn;
    private JLabel outputLabel;
    private JTextField outputTextField;
    private JButton outputLocationBtn;
    private JLabel domainLabel;
    private JTextField domainTextField;
    private JLabel label1;
    private JPanel btnPanel;
    private JButton startBtn;
    private JButton button1;
    private JButton exportResultsBtn;

    public MainPanel(PwnBackMediator mediator) {
        this.mediator = mediator;
        initComponents();
        phantomJSTextField.setText(PwnBackSettings.phatomjsLocation);
        httpRespTextField.setText(Integer.toString(PwnBackSettings.numofHttpResponseParsers));
        starYearTextField.setText(Integer.toString(PwnBackSettings.startYear));
        endYearTextField.setText(Integer.toString(PwnBackSettings.endYear));
        jsDriverTextField.setText(Integer.toString(PwnBackSettings.numOfJSWebDrivers));
        outputTextField.setText(PwnBackSettings.outputDir);
    }

    private void startBtnMouseClicked(MouseEvent e) {
        File f = new File(PwnBackSettings.phatomjsLocation);
        if(!f.exists()) {
            JOptionPane.showMessageDialog(this.getParent(),
                "PhantomJS Binary not found at " + f.getAbsolutePath());
        } else{
            mediator.addDomain(domainTextField.getText());
            mediator.start();
        }

    }

    private void exportResultsBtnMouseClicked(MouseEvent e) {
        mediator.exportPathsToFile();
        JOptionPane.showMessageDialog(this.getParent(),
                "Exported data to " + PwnBackSettings.outputDir + "/output.txt");
    }

    private void outputLocationBtnMouseClicked(MouseEvent e) {
        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(new java.io.File(System.getProperty("user.home")));
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setAcceptAllFileFilterUsed(false);
        int returnVal = chooser.showOpenDialog(this.getParent());
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            outputTextField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void phantomJSLocBtnMouseClicked(MouseEvent e) {
        JFileChooser chooser = new JFileChooser();
        int returnVal = chooser.showOpenDialog(this.getParent());
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            phantomJSTextField.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private void initComponents() {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        // Generated using JFormDesigner Evaluation license - Paul Ganea
        optionsPanel = new JPanel();
        jsDriverLabel = new JLabel();
        jsDriverTextField = new JTextField();
        label2 = new JLabel();
        httpRespLabel = new JLabel();
        httpRespTextField = new JTextField();
        label3 = new JLabel();
        startYearLabel = new JLabel();
        starYearTextField = new JTextField();
        label4 = new JLabel();
        endYearLabel = new JLabel();
        endYearTextField = new JTextField();
        label5 = new JLabel();
        phantomJSLabel = new JLabel();
        phantomJSTextField = new JTextField();
        phantomJSLocBtn = new JButton();
        outputLabel = new JLabel();
        outputTextField = new JTextField();
        outputLocationBtn = new JButton();
        domainLabel = new JLabel();
        domainTextField = new JTextField();
        label1 = new JLabel();
        btnPanel = new JPanel();
        startBtn = new JButton();
        button1 = new JButton();
        exportResultsBtn = new JButton();

        //======== this ========
        setMinimumSize(null);
        setMaximumSize(null);
        setPreferredSize(null);



        setLayout(new GridLayout(2, 1));

        //======== optionsPanel ========
        {
            optionsPanel.setMinimumSize(null);
            optionsPanel.setMaximumSize(null);
            optionsPanel.setLayout(new GridLayout(7, 3));

            //---- jsDriverLabel ----
            jsDriverLabel.setText("Number of PhantomJS Drivers");
            jsDriverLabel.setHorizontalAlignment(SwingConstants.CENTER);
            jsDriverLabel.setMaximumSize(null);
            jsDriverLabel.setMinimumSize(null);
            optionsPanel.add(jsDriverLabel);

            //---- jsDriverTextField ----
            jsDriverTextField.setHorizontalAlignment(SwingConstants.CENTER);
            jsDriverTextField.setMaximumSize(null);
            jsDriverTextField.setMinimumSize(null);
            optionsPanel.add(jsDriverTextField);

            //---- label2 ----
            label2.setMaximumSize(null);
            label2.setMinimumSize(null);
            optionsPanel.add(label2);

            //---- httpRespLabel ----
            httpRespLabel.setText("# of HTTP Response Parsers");
            httpRespLabel.setHorizontalAlignment(SwingConstants.CENTER);
            httpRespLabel.setMaximumSize(null);
            httpRespLabel.setMinimumSize(null);
            optionsPanel.add(httpRespLabel);

            //---- httpRespTextField ----
            httpRespTextField.setHorizontalAlignment(SwingConstants.CENTER);
            httpRespTextField.setMaximumSize(null);
            httpRespTextField.setMinimumSize(null);
            optionsPanel.add(httpRespTextField);
            optionsPanel.add(label3);

            //---- startYearLabel ----
            startYearLabel.setText("Start Year");
            startYearLabel.setHorizontalAlignment(SwingConstants.CENTER);
            optionsPanel.add(startYearLabel);

            //---- starYearTextField ----
            starYearTextField.setHorizontalAlignment(SwingConstants.CENTER);
            starYearTextField.setMaximumSize(new Dimension(0, 0));
            starYearTextField.setMinimumSize(new Dimension(0, 0));
            optionsPanel.add(starYearTextField);
            optionsPanel.add(label4);

            //---- endYearLabel ----
            endYearLabel.setText("End Year");
            endYearLabel.setHorizontalAlignment(SwingConstants.CENTER);
            optionsPanel.add(endYearLabel);

            //---- endYearTextField ----
            endYearTextField.setHorizontalAlignment(SwingConstants.CENTER);
            endYearTextField.setMaximumSize(new Dimension(0, 0));
            endYearTextField.setMinimumSize(new Dimension(0, 0));
            optionsPanel.add(endYearTextField);
            optionsPanel.add(label5);

            //---- phantomJSLabel ----
            phantomJSLabel.setText("PhantomJS Location");
            phantomJSLabel.setHorizontalAlignment(SwingConstants.CENTER);
            optionsPanel.add(phantomJSLabel);

            //---- phantomJSTextField ----
            phantomJSTextField.setHorizontalAlignment(SwingConstants.CENTER);
            phantomJSTextField.setMaximumSize(new Dimension(0, 0));
            phantomJSTextField.setMinimumSize(new Dimension(0, 0));
            optionsPanel.add(phantomJSTextField);

            //---- phantomJSLocBtn ----
            phantomJSLocBtn.setText("Select");
            phantomJSLocBtn.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    phantomJSLocBtnMouseClicked(e);
                }
            });
            optionsPanel.add(phantomJSLocBtn);

            //---- outputLabel ----
            outputLabel.setText("Output Directory");
            outputLabel.setHorizontalAlignment(SwingConstants.CENTER);
            optionsPanel.add(outputLabel);

            //---- outputTextField ----
            outputTextField.setHorizontalAlignment(SwingConstants.CENTER);
            outputTextField.setMaximumSize(new Dimension(0, 0));
            outputTextField.setMinimumSize(new Dimension(0, 0));
            optionsPanel.add(outputTextField);

            //---- outputLocationBtn ----
            outputLocationBtn.setText("Select");
            outputLocationBtn.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    outputLocationBtnMouseClicked(e);
                }
            });
            optionsPanel.add(outputLocationBtn);

            //---- domainLabel ----
            domainLabel.setText("Domain to Crawl");
            domainLabel.setHorizontalAlignment(SwingConstants.CENTER);
            optionsPanel.add(domainLabel);

            //---- domainTextField ----
            domainTextField.setHorizontalAlignment(SwingConstants.CENTER);
            domainTextField.setMaximumSize(new Dimension(0, 0));
            domainTextField.setMinimumSize(new Dimension(0, 0));
            domainTextField.setText("something.com");
            optionsPanel.add(domainTextField);
            optionsPanel.add(label1);
        }
        add(optionsPanel);

        //======== btnPanel ========
        {
            btnPanel.setMaximumSize(new Dimension(500, 500));
            btnPanel.setLayout(new FlowLayout());

            //---- startBtn ----
            startBtn.setText("Start");
            startBtn.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    startBtnMouseClicked(e);
                }
            });
            btnPanel.add(startBtn);

            //---- button1 ----
            button1.setText("Cancel");
            btnPanel.add(button1);

            //---- exportResultsBtn ----
            exportResultsBtn.setText("Export results to File");
            exportResultsBtn.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    exportResultsBtnMouseClicked(e);
                }
            });
            btnPanel.add(exportResultsBtn);
        }
        add(btnPanel);
        // JFormDesigner - End of component initialization  //GEN-END:initComponents
    }
    // JFormDesigner - End of variables declaration  //GEN-END:variables
}
