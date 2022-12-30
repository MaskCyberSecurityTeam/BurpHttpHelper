package burp.ui.main;

import burp.bean.Rule;
import burp.core.RuleCore;
import burp.ui.component.BeanTable;

import java.util.Vector;

public class RuleTable extends BeanTable<Rule> {

    RuleTable() {
        super();
    }

    @Override
    public Object initializeGetValueAt(int rowIndex, int columnIndex) {
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
    public Vector<String> initializeColumnName() {
        final Vector<String> columnName = new Vector<>();
        columnName.addElement("编号(ID)");
        columnName.addElement("地址(URL)");
        columnName.addElement("协议头(HeaderName)");
        columnName.addElement("协议值(HeaderValue)");
        columnName.addElement("动作(Action)");
        columnName.addElement("状态(State)");
        return columnName;
    }

    @Override
    public void initializeSetValueAt(Object aValue, int row, int column) {
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
}