package burp.ui.component;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.util.Vector;

/**
 * JavaBean方式的表格
 *
 * @param <T> JavaBean
 * @author RichardTangß
 */
public abstract class BeanTable<T> extends JTable {

    // 存储表头的集合
    protected Vector<String> columnName;

    // 存储表格数据的集合
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

    /**
     * 自定义根据行号列号获取数据的逻辑
     *
     * @param rowIndex    行号
     * @param columnIndex 列号
     * @return 数据
     */
    public abstract Object initializeGetValueAt(int rowIndex, int columnIndex);

    /**
     * 自定义初始化表头
     *
     * @return 表头集合
     */
    public abstract Vector<String> initializeColumnName();

    /**
     * 自定义根据行号列号存储数据
     *
     * @param aValue      数据
     * @param rowIndex    行号
     * @param columnIndex 列号
     */
    public void initializeSetValueAt(Object aValue, int rowIndex, int columnIndex) {
        T valueAt = (T) getValueAt(rowIndex, columnIndex);
        data.setElementAt(valueAt, columnIndex);
        model.fireTableCellUpdated(rowIndex, columnIndex);
    }

    /**
     * 添加一行数据
     *
     * @param item 需要添加的JavaBean实例
     */
    public void addRow(T item) {
        data.add(item);
        updateUI();
    }

    /**
     * 添加多行数据
     *
     * @param items 需要添加的JavaBean实例集合
     */
    public void addRows(Vector<T> items) {
        data.addAll(items);
        updateUI();
    }

    /**
     * 根据行号删除数据
     *
     * @param rowIndex 行号
     */
    public void removeRow(int rowIndex) {
        data.remove(rowIndex);
        updateUI();
    }

    /**
     * 删除全部数据
     */
    public void removeAll() {
        int dataSize = data.size();
        if (dataSize > 0) {
            data.clear();
            updateUI();
        }
    }

    /**
     * 获取选中的行数据
     *
     * @return 选中的行数据
     */
    public T getSelectedItem() {
        int index = getSelectedRow();
        if (index != -1) {
            return data.get(index);
        } else {
            return null;
        }
    }

    /**
     * 删除选中的行数据
     */
    public void removeSelectedItem() {
        int index = getSelectedRow();
        if (index != -1) {
            data.remove(index);
            updateUI();
        }
    }

    /**
     * 获取存储表格数据的集合
     *
     * @return 数据集合
     */
    public Vector<T> getTableData() {
        return data;
    }

    /**
     * 获取表格行数量
     *
     * @return 表格行数量
     */
    public int getDataSize() {
        return data.size();
    }
}