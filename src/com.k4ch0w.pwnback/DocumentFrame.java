/*
 * Created by JFormDesigner on Mon Apr 10 14:57:16 PDT 2017
 */

package com.k4ch0w.pwnback;

import net.miginfocom.swing.MigLayout;
import org.xml.sax.SAXException;

import javax.swing.*;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.io.IOException;
import java.util.ArrayList;

/**
 * @author Paul Ganea
 */
class DocumentFrame extends JFrame {
    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    // Generated using JFormDesigner commercial license
    private JScrollPane scrollPane1;
    private JList<PwnBackDocument> list1;
    private JPanel panel1;
    private JScrollPane scrollPane2;
    private JTextPane textPane1;

    DocumentFrame(ArrayList<PwnBackDocument> docs) throws IOException, SAXException {
        initComponents();
        DefaultListModel<PwnBackDocument> listModel;
        listModel = new DefaultListModel<>();
        for (PwnBackDocument doc : docs) {
            listModel.addElement(doc);
        }
        list1.setModel(listModel);
        ListSelectionListener listSelectionListener = listSelectionEvent -> {
            if (!listSelectionEvent.getValueIsAdjusting()) {
                textPane1.setText(listModel.get(list1.getSelectedIndex()).getDocument());
            }
        };
        list1.addListSelectionListener(listSelectionListener);
        textPane1.setText(docs.get(0).getDocument());
        textPane1.setEditable(false);
    }

    private void initComponents() {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        // Generated using JFormDesigner non-commercial license
        scrollPane1 = new JScrollPane();
        list1 = new JList<>();
        panel1 = new JPanel();
        scrollPane2 = new JScrollPane();
        textPane1 = new JTextPane();

        //======== this ========
        setMinimumSize(new Dimension(1000, 700));
        Container contentPane = getContentPane();
        contentPane.setLayout(new MigLayout(
                "insets 0,hidemode 3",
                // columns
                "[fill]" +
                        "[grow]",
                // rows
                "[grow,fill]"));

        //======== scrollPane1 ========
        {
            scrollPane1.setMinimumSize(new Dimension(250, 148));
            scrollPane1.setPreferredSize(new Dimension(250, 148));
            scrollPane1.setViewportView(list1);
        }
        contentPane.add(scrollPane1, "cell 0 0");

        //======== panel1 ========
        {
            panel1.setLayout(new GridLayout());

            //======== scrollPane2 ========
            {
                scrollPane2.setViewportView(textPane1);
            }
            panel1.add(scrollPane2);
        }
        contentPane.add(panel1, "cell 1 0,growx");
        pack();
        setLocationRelativeTo(getOwner());
        // JFormDesigner - End of component initialization  //GEN-END:initComponents
    }
    // JFormDesigner - End of variables declaration  //GEN-END:variables
}
