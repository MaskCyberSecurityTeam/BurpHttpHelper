package burp.ui.component;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.util.Vector;

public abstract class BeanTable<T> extends JTable {

    protected Vector<String> columnName;

    protected final Vector<T> data = new Vector<>();

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
            return BeanTable.this.initializeGetValueAt(rowIndex, columnIndex);
        }

        @Override
        public void setValueAt(Object aValue, int row, int column) {
            BeanTable.this.initializeSetValueAt(aValue, row, column);
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

    public BeanTable() {
        this.columnName = initializeColumnName();
        this.tableCellRenderer.setHorizontalAlignment(JLabel.CENTER);

        setModel(model);
        setShowGrid(true);
        setRowHeight(30);
        setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        setDefaultRenderer(Object.class, tableCellRenderer);
        getTableHeader().setDefaultRenderer(tableCellRenderer);
    }

    public abstract Object initializeGetValueAt(int rowIndex, int columnIndex);

    public abstract Vector<String> initializeColumnName();

    public void initializeSetValueAt(Object aValue, int row, int column) {
        T valueAt = (T) getValueAt(row, column);
        data.setElementAt(valueAt, column);
        model.fireTableCellUpdated(row, column);
    }

    public void addRow(T item) {
        data.add(item);
        updateUI();
    }

    public void addRows(Vector<T> items) {
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

    public T getSelectedItem() {
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

    public Vector<T> getTableData() {
        return data;
    }

    public int getDataSize() {
        return data.size();
    }
}