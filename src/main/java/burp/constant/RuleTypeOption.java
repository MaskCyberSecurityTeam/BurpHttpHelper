package burp.constant;

/**
 * 规则类型<br>
 * 用于描述规则适用的操作是HttpHeader还是HttpCookie
 *
 * @author RichardTang
 */
public enum RuleTypeOption {

    HEADER("header"), COOKIE("cookie");

    private String text;

    RuleTypeOption(String text) {
        this.text = text;
    }
}