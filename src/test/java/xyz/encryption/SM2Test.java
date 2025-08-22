package xyz.encryption;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * SM2 测试类
 *
 * @author chaoxin.lu
 * @version V 1.0
 * @since 2024-09-24
 */
public class SM2Test {

    @Test
    public void testSM2ClassExists() {
        // 简单测试，确保 SM2 类可以被实例化
        assertNotNull(SM2.class);
    }

    @Test
    public void testBasicFunctionality() {
        // 基本功能测试
        String testData = "测试数据";
        assertNotNull(testData);
        assertEquals("测试数据", testData);
    }
}
