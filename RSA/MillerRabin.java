package RSA;

import java.math.BigInteger;
import java.util.Random;

public class MillerRabin {
    private static final int ORDER = 10000;// 随机数的数量级
    private static final int MIN = 1000; // 选择的随机数的最小值
    /**
     * 整数转为二进制
     * @param m 整数
     * @return 字节数组
     */
    public static byte[] getByte(int m){
        String sb = "";
        while (m > 0){
            sb = (m % 2) + sb;
            m = m / 2;
        }
        return sb.getBytes();
    }
    /**
     * 平方-乘法计算指数模运算 a^m % n
     * @param a 底数
     * @param m 指数
     * @param n 被mod数
     * @return
     */
    public static int Square_and_Mutiply(int a, int m, int n){
        int d = 1;
        byte[] bm = getByte(m);// 把m转化为二进制数
        for (int i = 0; i < bm.length; i++){
            d = (d * d) % n;
            if (bm[i] == 49)// 二进制1等于asciI码的49
                d = (d * a) % n;
        }
        return d;
    }
    /**
     * 随机选择一个奇数
     */
    public static int getRandom(){
        int x = 3;
        Random rd = new Random();
        do	{
            x = rd.nextInt(ORDER);
        } while (x < MIN || x % 2 == 0);
        return x;
    }
    /**
     * 验证一个数是否为素数，将n-1改写为2^k * m的形式，其中m是奇数，在{2,...,n-1}中随机选取一个整数a;
     * @param n
     * @return 如果是素数返回true,否则返回false
     */
    public static boolean isPrime(int n){
        int[] arr = intTOIndex(n - 1);// n-1 用2的幂表示
        int k = arr[0];
        int m = arr[1];
        Random r = new Random();// 在{2,...,n-1}随机选择一个整数a
        int a = 0;
        do {
            a = r.nextInt(n - 1);
        } while (a < 2);
        int b = Square_and_Mutiply(a, m, n);
        if (b == 1)
            return true;
        for (int i = 0; i < k; i++)  {
            if (b == (n - 1)) return true;
            else b = (b * b) % n;
        }		 return false;
    }
    /**
     * 将一个数改为2^k * m的形式，其中m是奇数
     * @param n
     * @return arr[0]=k,arr[1]=m
     */
    public static int[] intTOIndex(int n){
        int[] arr = new int[2];
        int k = 0;
        int x;
        // 当n为奇数是停止循环
        do {
            k++;
            n >>= 1;
            x = n & 1;
        } while (x == 0);
        arr[0] = k;
        arr[1] = n;
        return arr;
    }
    /**
     * 获取一个随机数为并且检查其为素数
     * @return
     */
    public  static int getPrime(){
        int x = 0;
        while (x % 2 == 0 || !isPrime(x)){
            x = getRandom();
        }
        return x;
    }
}
