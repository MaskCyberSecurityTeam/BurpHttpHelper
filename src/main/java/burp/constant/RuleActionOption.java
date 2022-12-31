package burp.constant;

/**
 * 主面板规则 - 动作常量
 *
 * @author RichardTang
 */
public enum RuleActionOption {

    ADD("add"), MODIFY("modify"), REMOVE("remove");

    private String text;

    RuleActionOption(String text) {
        this.text = text;
    }
}
