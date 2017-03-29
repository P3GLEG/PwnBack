/*
 * Created by JFormDesigner on Tue Mar 28 14:58:28 PDT 2017
 */

package com.k4ch0w.pwnback;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * @author unknown
 */
public class PwnBackGui extends JPanel {

    private DefaultListModel<String> files = new DefaultListModel<>();
    public PwnBackGui(){
        initComponents();
        files.addElement("test");
        fileList = new JList<String>(files);
        files.addElement("FML WTF");
    }



    private void startButtonMouseClicked(MouseEvent e) {
        // TODO add your code here
    }

    private void initComponents() {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        // Generated using JFormDesigner Evaluation license - Paul Ganea
        tabbedPane1 = new JTabbedPane();
        panel2 = new JPanel();
        fileList = new JList();
        panel1 = new JPanel();
        domainLabel = new JLabel();
        domainTextField = new JTextField();
        startButton = new JButton();

        //======== this ========

        // JFormDesigner evaluation mark
        setBorder(new javax.swing.border.CompoundBorder(
            new javax.swing.border.TitledBorder(new javax.swing.border.EmptyBorder(0, 0, 0, 0),
                "JFormDesigner Evaluation", javax.swing.border.TitledBorder.CENTER,
                javax.swing.border.TitledBorder.BOTTOM, new java.awt.Font("Dialog", java.awt.Font.BOLD, 12),
                java.awt.Color.red), getBorder())); addPropertyChangeListener(new java.beans.PropertyChangeListener(){public void propertyChange(java.beans.PropertyChangeEvent e){if("border".equals(e.getPropertyName()))throw new RuntimeException();}});

        setLayout(new BorderLayout());

        //======== tabbedPane1 ========
        {

            //======== panel2 ========
            {
                panel2.setLayout(new GridLayout());

                //---- fileList ----
                fileList.setVisibleRowCount(10);
                panel2.add(fileList);
            }
            tabbedPane1.addTab("Files", panel2);
        }
        add(tabbedPane1, BorderLayout.CENTER);

        //======== panel1 ========
        {
            panel1.setLayout(new FlowLayout(FlowLayout.LEFT));

            //---- domainLabel ----
            domainLabel.setText("Domain: ");
            panel1.add(domainLabel);

            //---- domainTextField ----
            domainTextField.setMinimumSize(new Dimension(200, 24));
            domainTextField.setPreferredSize(new Dimension(200, 24));
            panel1.add(domainTextField);

            //---- startButton ----
            startButton.setText("Start");
            startButton.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    startButtonMouseClicked(e);
                }
            });
            panel1.add(startButton);
        }
        add(panel1, BorderLayout.NORTH);
        // JFormDesigner - End of component initialization  //GEN-END:initComponents
    }

    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    // Generated using JFormDesigner Evaluation license - Paul Ganea
    private JTabbedPane tabbedPane1;
    private JPanel panel2;
    private JList fileList;
    private JPanel panel1;
    private JLabel domainLabel;
    private JTextField domainTextField;
    private JButton startButton;
    // JFormDesigner - End of variables declaration  //GEN-END:variables
}
