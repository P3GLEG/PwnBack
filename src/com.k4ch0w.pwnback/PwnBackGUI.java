package com.k4ch0w.pwnback;

import javax.swing.*;

/**
 * Created by k4ch0w on 3/30/17.
 */
public class PwnBackGUI extends JPanel {
    private final PwnBackMediator mediator;
    private final PwnBackTable table;
    private final MainPanel panel;

    public PwnBackGUI(PwnBackMediator mediator) {
        super();
        this.mediator = mediator;
        table = new PwnBackTable(this.mediator);
        panel = new MainPanel(this.mediator);
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        JScrollPane scrollPane = new JScrollPane(table.getLogTable());
        splitPane.setLeftComponent(scrollPane);
        splitPane.setRightComponent(panel);
        this.add(splitPane);
    }

    public void notifyUpdate() {
        table.notifyUpdate();
    }


}
