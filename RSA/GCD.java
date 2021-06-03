package RSA;

import java.math.BigInteger;

public class GCD {
    /**
     * 辗转相除法求最大公约数
     */
    public BigInteger gcd(BigInteger a, BigInteger b){
        if(b.equals(BigInteger.ZERO)){
            return a ;
        }else{
            return gcd(b, a.mod(b)) ;
        }
    }
    /**
     * 扩展欧几里得算法：
     * 求ax + by = 1中的x与y的整数解（a，b互素）
     */
    public BigInteger[] extGcd(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            BigInteger x1 = BigInteger.ONE;
            BigInteger y1 = BigInteger.ZERO;
            BigInteger x = x1;
            BigInteger y = y1;
            BigInteger r = a;
            BigInteger[] result = {r, x, y};
            return result;
        } else {
            BigInteger[] temp = extGcd(b, a.mod(b));
            BigInteger r = temp[0];
            BigInteger x1 = temp[1];
            BigInteger y1 = temp[2];

            BigInteger x = y1;
            BigInteger y = x1.subtract(a.divide(b).multiply(y1));     //y=x1-a/b*y1
            BigInteger[] result = {r, x, y};
            return result;
        }
    }
}
