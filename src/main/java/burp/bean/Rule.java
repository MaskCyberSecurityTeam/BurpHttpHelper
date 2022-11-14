package burp.bean;

import burp.constant.RuleActionOption;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Rule {

    private Integer id;

    private String url;

    private String headerName;

    private String headerValue;

    private RuleActionOption action;

    private Boolean active;
}