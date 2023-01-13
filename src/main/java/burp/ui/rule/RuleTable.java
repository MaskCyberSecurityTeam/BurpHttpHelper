package burp.ui.rule;

import burp.bean.Rule;
import burp.core.RuleCore;
import burp.ui.component.BeanTable;

import java.util.Vector;

/**
 * 规则表格
 *
 * @author RichardTang
 */
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
                return item.getKeyName();
            case 3:
                return item.getKeyValue();
            case 4:
                return item.getType();
            case 5:
                return item.getAction();
            case 6:
                return item.getActive();
        }
        return null;
    }

    @Override
    public Vector<String> initializeColumnName() {
        final Vector<String> columnName = new Vector<>();
        columnName.addElement("编号(ID)");
        columnName.addElement("地址(URL)");
        columnName.addElement("键名(KeyName)");
        columnName.addElement("键值(KeyValue)");
        columnName.addElement("类型(Type)");
        columnName.addElement("动作(Action)");
        columnName.addElement("状态(State)");
        return columnName;
    }

    @Override
    public void initializeSetValueAt(Object aValue, int row, int column) {
        // 最后一个column，在当前项目中是固定的组件为CheckBox，需要特殊处理。
        if (column == 6) {
            Boolean isActive = (Boolean) aValue;
            Rule rule = data.get(row);
            rule.setActive(isActive);
            if (isActive) {
                RuleCore.activeRuleData.addElement(rule);
            } else {
                RuleCore.activeRuleData.removeElement(rule);
            }
        }
    }
}