package burp.bean;

import burp.constant.RuleActionOption;
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

    // 协议头
    private String headerName;

    // 协议值
    private String headerValue;

    // 动作
    private RuleActionOption action;

    // 状态
    private Boolean active;

    public void setHeaderName(String headerName) {
        // 全部小写方式存储
        this.headerName = headerName.toLowerCase();
    }
}