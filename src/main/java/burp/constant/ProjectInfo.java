package burp.constant;

import java.io.IOException;
import java.util.Properties;

public class ProjectInfo {

    public static String VERSION;

    static {
        try {
            Properties properties = new Properties();
            properties.load(ProjectInfo.class.getClassLoader().getResourceAsStream("info.properties"));
            VERSION = properties.getProperty("version");
        } catch (IOException e) {
            VERSION = "None";
        }
    }

    public static final String EXT_NAME = String.format("BurpHeaderHelper - %s - Http Protocol Helper", VERSION);

    public static final String VERSION_BANNER = String.format("Version: %s", VERSION);

    public static final String TEAM = "Team: MaskSec";

    public static final String AUTHOR = "Author: RichardTang";

    public static final String GITHUB = "GitHub: https://github.com/MaskCyberSecurityTeam/BurpHeaderHelper";


}
