package burp.ui;

import burp.bean.Rule;
import burp.core.RuleCore;
import sun.swing.table.DefaultTableCellHeaderRenderer;

import javax.swing.*;
import javax.swing.table.*;
import java.util.Vector;

public class RuleTable extends JTable {

    private static final Vector<String> columnName = new Vector<>();

    static {
        columnName.addElement("编号(ID)");
        columnName.addElement("地址(URL)");
        columnName.addElement("协议头(HeaderName)");
        columnName.addElement("协议值(HeaderValue)");
        columnName.addElement("动作(Action)");
        columnName.addElement("状态(State)");
    }

    protected Vector<Rule> data = new Vector<>();

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
            Rule item = data.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return item.getId();
                case 1:
                    return item.getUrl();
                case 2:
                    return item.getHeaderName();
                case 3:
                    return item.getHeaderValue();
                case 4:
                    return item.getAction();
                case 5:
                    return item.getActive();
            }
            return null;
        }

        @Override
        public void setValueAt(Object aValue, int row, int column) {
            if (column == 5) {
                Boolean isActive = (Boolean) aValue;
                Rule rule = data.get(row);
                rule.setActive(isActive);
                if (isActive) {
                    RuleCore.activeRuleData.add(row, rule);
                } else {
                    RuleCore.activeRuleData.remove(row);
                }
            }
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

    protected DefaultTableCellHeaderRenderer tableHeaderRenderer = new DefaultTableCellHeaderRenderer();

    RuleTable() {
        model.setDataVector(data, columnName);

        tableCellRenderer.setHorizontalAlignment(JLabel.CENTER);
        tableHeaderRenderer.setHorizontalAlignment(JLabel.CENTER);

        setModel(model);
        setShowGrid(true);
        setRowHeight(30);
        setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        setDefaultRenderer(Object.class, tableCellRenderer);
        getTableHeader().setDefaultRenderer(tableHeaderRenderer);
    }

    public void addRow(Rule item) {
        data.add(item);
        updateUI();
    }

    public void addRows(Vector<Rule> items) {
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

    public Rule getSelectedItem() {
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

    public Vector<Rule> getRuleData() {
        return data;
    }
}