package burp.constant;

import java.io.IOException;
import java.util.Properties;

/**
 * 项目信息
 *
 * @author RichardTang
 */
public class ProjectInfo {

    // 当前版本号
    public static String VERSION;

    static {
        try {
            // 启动时通过读取配置文件获取版本号
            Properties properties = new Properties();
            properties.load(ProjectInfo.class.getClassLoader().getResourceAsStream("info.properties"));
            VERSION = properties.getProperty("version");
        } catch (IOException e) {
            VERSION = "None";
        }
    }

    // Burpsuite上的Tab页显示的标题
    public static final String TAB_TITLE = "BurpHeaderHelper";

    // 信息
    public static final String EXT_NAME       = String.format("BurpHeaderHelper - %s - Http Protocol Helper", VERSION);
    public static final String VERSION_BANNER = String.format("Version: %s", VERSION);
    public static final String TEAM           = "Team: MaskSec";
    public static final String AUTHOR         = "Author: RichardTang";
    public static final String GITHUB         = "GitHub: https://github.com/MaskCyberSecurityTeam/BurpHeaderHelper";
}