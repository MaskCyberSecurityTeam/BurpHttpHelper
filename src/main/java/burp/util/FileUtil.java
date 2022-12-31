package burp.util;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;

/**
 * File操作工具类
 *
 * @author RichardTang
 */
public class FileUtil {

    /**
     * 从数据源中按行读取数据，并存储至lines集合中。
     *
     * @param inputStream 数据源
     * @param lines       存储每一行数据的集合
     */
    public static void readLines(final InputStream inputStream, final List<String> lines) {
        try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                lines.add(line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}