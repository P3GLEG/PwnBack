/*
 * Created by JFormDesigner on Tue Mar 28 14:58:28 PDT 2017
 */

package com.k4ch0w.pwnback;


import org.jdesktop.swingx.table.TableUtilities;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * @author unknown
 */
public class PwnBackTable extends AbstractTableModel {

    private final PwnBackMediator mediator;
    private final int columnCount = 1;
    private final JTable logTable = new JTable(this);

    public PwnBackTable(PwnBackMediator mediator) {
        this.mediator = mediator;
        logTable.getModel().addTableModelListener(e -> {
            if (TableUtilities.isInsert(e)) {
                int viewRow = logTable.convertRowIndexToView(e.getFirstRow());
                logTable.scrollRectToVisible(logTable.getCellRect(viewRow, 0, true));
            }
        });
        logTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                final Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                c.setForeground(mediator.getLog().get(row).getRowColor());
                return c;
            }
        });


    }

    public JTable getLogTable() {
        return logTable;
    }

    public void notifyUpdate() {
        int row = mediator.getLog().size();
        fireTableRowsInserted(row, row);
    }

    @Override
    public int getRowCount() {
        return mediator.getLog().size();
    }

    @Override
    public int getColumnCount() {
        return columnCount;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return String.class;
            case 1:
                return Color.class;
        }
        return null;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        switch (columnIndex) {
            case 0:
                return mediator.getLog().get(rowIndex).getLogMsg();
            case 1:
                return mediator.getLog().get(rowIndex).getRowColor();
            default:
                return "";
        }
    }

}
