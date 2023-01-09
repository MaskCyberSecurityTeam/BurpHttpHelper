package burp.bean;

import burp.constant.RuleActionOption;
import burp.constant.RuleTypeOption;
import lombok.Builder;
import lombok.Data;

/**
 * 规则
 *
 * @author RichardTang
 */
@Data
@Builder
public class Rule {

    // 编号
    private Integer id;

    // 地址
    private String url;

    // 键名
    private String keyName;

    // 键值
    private String keyValue;

    // 类型
    private RuleTypeOption type;

    // 动作
    private RuleActionOption action;

    // 状态
    private Boolean active;

    public void setKeyName(String keyName) {
        // 全部小写方式存储
        this.keyName = keyName.toLowerCase();
    }
}