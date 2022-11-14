package burp.core;

import burp.bean.Rule;

import java.net.URL;
import java.util.List;
import java.util.Vector;
import java.util.regex.Pattern;

public class RuleCore {

    public static final String ANY = "*";

    public static final String ANY_REGEXP = "(.*)";

    public static final Vector<Rule> activeRuleData = new Vector<>();

    public static void assembly(final List<String> metaDataHeaders, final URL url) {
        for (Rule rule : activeRuleData) {

            boolean flag = Pattern.compile(rule.getUrl().replace(ANY, ANY_REGEXP))
                    .matcher(url.toExternalForm())
                    .find();

            if (!flag) {
                break;
            }

            String headerName = rule.getHeaderName();
            switch (rule.getAction()) {
                case ADD:
                    addOptionAssembly(metaDataHeaders, headerName, rule.getHeaderValue());
                    break;
                case MODIFY:
                    modifyOptionAssembly(metaDataHeaders, headerName, rule.getHeaderValue());
                    break;
                case REMOVE:
                    removeOptionAssembly(metaDataHeaders, headerName);
                    break;
            }
        }
    }

    public static void addOptionAssembly(final List<String> metaDataHeaders, final String headerName, final String headerValue) {
        metaDataHeaders.add(String.format("%s: %s", headerName, headerValue));
    }

    public static void modifyOptionAssembly(final List<String> metaDataHeaders, final String headerName, final String headerValue) {
        int index = 0;
        for (String header : metaDataHeaders) {
            if (header.contains(headerName)) {
                metaDataHeaders.set(index, String.format("%s: %s", headerName, headerValue));
                break;
            }
            index++;
        }
    }

    public static void removeOptionAssembly(final List<String> metaDataHeaders, final String headerName) {
        metaDataHeaders.removeIf(header -> header.contains(headerName));
    }

}