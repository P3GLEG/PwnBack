package com.k4ch0w.wayback_machine;

import org.jdesktop.swingx.table.TableUtilities;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * @author k4ch0w
 */
public class PwnBackTable extends AbstractTableModel {

    private final int columnCount = 1;
    private final JTable logTable = new JTable(this);
    private final List<PwnBackTableEntry> tableEntries = new ArrayList<>();


    PwnBackTable() {
        logTable.getModel().addTableModelListener(e -> {
            if (TableUtilities.isInsert(e)) {
                int viewRow = logTable.convertRowIndexToView(e.getFirstRow());
                logTable.scrollRectToVisible(logTable.getCellRect(viewRow, 0, true));
            }
        });
        logTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                return super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            }
        });


    }

    JTable getLogTable() {
        return logTable;
    }

    private void notifyUpdate() {
        int row = tableEntries.size();
        fireTableRowsInserted(row, row);
    }

    @Override
    public int getRowCount() {
        return tableEntries.size();
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
                return tableEntries.get(rowIndex).getLogMsg();
            case 1:
                return tableEntries.get(rowIndex).getRowColor();
            default:
                return "";
        }
    }

    void reset() {
        tableEntries.clear();
        this.notifyUpdate();

    }

    void log(String msg) {
        log(new PwnBackTableEntry(msg));
    }

    void log(PwnBackTableEntry entry) {
        tableEntries.add(entry);
        this.notifyUpdate();
    }

    void logError(String msg) {
        log(new PwnBackTableEntry(msg, Color.red));
    }


}
