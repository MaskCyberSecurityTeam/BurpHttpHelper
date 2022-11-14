package burp.constant;

public enum RuleActionOption {

    ADD("add"), MODIFY("modify"), REMOVE("remove");

    private String text;

    RuleActionOption(String text) {
        this.text = text;
    }
}
