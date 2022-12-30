package burp.ui;

import burp.bean.Drop;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.net.URL;
import java.util.Vector;

public class DropPacketTable extends JTable {

    private static final Vector<String> columnName = new Vector<>();

    static {
        columnName.addElement("编号(ID)");
        columnName.addElement("地址(URL)");
        columnName.addElement("备注(Comment)");
    }

    protected Vector<Drop> data = new Vector<>();

    protected DefaultTableModel model = new DefaultTableModel() {

        @Override
        public int getRowCount() {
            return data.size();
        }

        @Override
        public String getColumnName(int column) {
            return columnName.get(column);
        }

        @Override
        public int getColumnCount() {
            return columnName.size();
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Drop item = data.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return item.getId();
                case 1:
                    return item.getUrl();
                case 2:
                    return item.getComment();
            }
            return null;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 5) {
                return Boolean.class;
            } else {
                return super.getColumnClass(columnIndex);
            }
        }
    };

    protected DefaultTableCellRenderer tableCellRenderer = new DefaultTableCellRenderer();

    DropPacketTable() {
        tableCellRenderer.setHorizontalAlignment(JLabel.CENTER);

        setModel(model);
        setShowGrid(true);
        setRowHeight(30);
        setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        setDefaultRenderer(Object.class, tableCellRenderer);
        getTableHeader().setDefaultRenderer(tableCellRenderer);
    }

    public void addRow(Drop item) {
        data.add(item);
        updateUI();
    }

    public void addRows(Vector<Drop> items) {
        data.addAll(items);
        updateUI();
    }

    public void removeRow(int rowIndex) {
        data.remove(rowIndex);
        updateUI();
    }

    public void removeAll() {
        int dataSize = data.size();
        if (dataSize > 0) {
            data.clear();
            updateUI();
        }
    }

    public Drop getSelectedItem() {
        int index = getSelectedRow();
        if (index != -1) {
            return data.get(index);
        } else {
            return null;
        }
    }

    public void removeSelectedItem() {
        int index = getSelectedRow();
        if (index != -1) {
            data.remove(index);
            updateUI();
        }
    }

    public Vector<Drop> getDropPacketData() {
        return data;
    }
}