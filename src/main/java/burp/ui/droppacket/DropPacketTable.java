package burp.ui.droppacket;

import burp.bean.Drop;
import burp.ui.component.BeanTable;

import java.util.Vector;

/**
 * 丢弃数据包表格
 *
 * @author RichardTang
 */
public class DropPacketTable extends BeanTable<Drop> {

    DropPacketTable() {
        super();
    }

    @Override
    public Object initializeGetValueAt(int rowIndex, int columnIndex) {
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
    public Vector<String> initializeColumnName() {
        final Vector<String> columnName = new Vector<>();
        columnName.addElement("编号(ID)");
        columnName.addElement("地址(URL)");
        columnName.addElement("备注(Comment)");
        return columnName;
    }
}