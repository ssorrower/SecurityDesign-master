package RSA;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class RSA {

    private static int P_length = 1024-6;
    private static int Q_length = 1024+6;
    private static int N = P_length+Q_length;

    private static BigInteger p;
    private static BigInteger q;

    private static BigInteger[][] keys;
    private static BigInteger[] pubkey;
    private static BigInteger[] selfkey;


    public RSA(){
        Random random = new Random();
        BigInteger pp= BigInteger.probablePrime(P_length,random);
        BigInteger qq= BigInteger.probablePrime(Q_length,random);
        int count=0;
        BigInteger[] bigIntegers = new BigInteger[2];

        while(count<1){
            if(pp.isProbablePrime(100)){
                BigInteger p1 = BigInteger.ZERO;
                p1 = p1.add(pp);
                p1 = (p1.subtract(BigInteger.ONE)).divide(BigInteger.valueOf(2));
                if((p1.isProbablePrime(100))){
                    bigIntegers[count] = pp;
                    count++;
                }
            }
            pp= BigInteger.probablePrime(P_length,random);
        }
        while(count<2){
            if(qq.isProbablePrime(100)){
                BigInteger q1 = BigInteger.ZERO;
                q1 = q1.add(qq);
                q1 = (q1.subtract(BigInteger.ONE)).divide(BigInteger.valueOf(2));
                if((q1.isProbablePrime(100))){
                    bigIntegers[count] = qq;
                    count++;
                }
            }
            qq= BigInteger.probablePrime(Q_length,random);
        }
        // 公钥私钥中用到的两个大质数p,q
        p = bigIntegers[0];
        q = bigIntegers[1];
        keys = genKey() ;
        pubkey  = keys[0] ;
        selfkey = keys[1] ;
        System.out.println("p:"+p);
        System.out.println("q:"+q);
    }

    public RSA(String p, String q){
        this.p = new BigInteger(p);
        this.q = new BigInteger(q);
        keys = genKey() ;
        pubkey  = keys[0] ;
        selfkey = keys[1] ;
        /*
        System.out.println("pubkey n:"+pubkey[0]);
        System.out.println("e:"+pubkey[1]);
        System.out.println("selfkey n:"+selfkey[0]);
        System.out.println("d:"+selfkey[1]);*/
    }

	/**
	*@pubkey pubkey[0]=n,pubkey[1]=e
	*@selfkey selfkey[0]=n,selfkey[1]=d
	*/
    public RSA(BigInteger[] pubkey, BigInteger[]selfkey){
        this.pubkey = pubkey;
        this.selfkey = selfkey;
    }

    public BigInteger[][] genKey(){
        BigInteger n = p.multiply(q) ;
        //fy为欧拉函数=(p-1)(q-1)
        BigInteger fy = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)) ;
        BigInteger e = new BigInteger("65537") ;
        BigInteger a = e ;
        BigInteger b = fy ;
        BigInteger[] rxy = new GCD().extGcd(a, b) ;
        BigInteger r = rxy[0] ;
        BigInteger x = rxy[1] ;
        BigInteger y = rxy[2] ;
        BigInteger d = x ;
        if(d.compareTo(BigInteger.ZERO) == -1){
            d = d.add(fy);
        }
        // 公钥  私钥
        return new BigInteger[][]{{n , e}, {n , d}} ;
    }

    /**
     * 加密
     * @param m 被加密的信息转化成为大整数，再分割为数组m
     * @param pubkey 公钥
     */
    public String encrypt(BigInteger[] m, BigInteger[] pubkey){
        BigInteger n = pubkey[0] ;
        BigInteger e = pubkey[1] ;
        Exponentiation exponentiation = new Exponentiation();
        BigInteger[] c = new BigInteger[m.length];
        for(int i=0; i<m.length; i++){
            c[i] = exponentiation.expMode(m[i], e, n) ;
        }
        return Convert.BigToStringWithoutAscll(c);
    }

    /**
     * 解密
     * @param c
     * @param selfkey 私钥
     */
    public String decrypt(BigInteger[] c, BigInteger[] selfkey){
        BigInteger n = selfkey[0] ;
        BigInteger d = selfkey[1] ;
        Exponentiation exponentiation = new Exponentiation();
        BigInteger[] m = new BigInteger[c.length];
        for(int i=0; i<m.length; i++){
            m[i] = exponentiation.expMode(c[i], d, n) ;
        }
        return Convert.BigToString(m);
    }

    /**
     * 签名
     * @param hm 消息经过hash后的值
     * @param selfkey 私钥
     */
    public BigInteger sign(BigInteger hm, BigInteger[] selfkey){
        BigInteger n = selfkey[0] ;
        BigInteger d = selfkey[1] ;
        Exponentiation exponentiation = new Exponentiation();
        BigInteger s = exponentiation.expMode(hm, d, n) ;
        return s ;
    }

    /**
     * 验证
     * @param s 签名
     * @param pubkey 公钥
     */
    public BigInteger verify(BigInteger s, BigInteger[] pubkey){
        BigInteger n = pubkey[0] ;
        BigInteger e = pubkey[1] ;
        Exponentiation exponentiation = new Exponentiation();
        BigInteger v = exponentiation.expMode(s, e, n) ;
        return v ;
    }


    /**
     * 加密
     * @param message 原文
     */
    public String encrypt_string(String message){
        BigInteger[] m = Convert.StringToBig(message,N/8-55);     //num = N/8-11   ，那么每次能够加密的数据为num个字符
        // 加密
        String result = encrypt(m, pubkey);
        return result;
    }

    /**
     * 解密
     * @param message 密文
     */
    public String decrypt_string(String message){
        BigInteger[] info = Convert.StringToBigWithoutAscll(message);
        String result = decrypt(info, selfkey);
        return result;
    }

    /**
     * 签名
     * @param message 消息
     */
    public String sign_string(String message){
        BigInteger hm;
        if(message.hashCode() < 0){   //1代表原hash为负数 2代表正数
            hm = new BigInteger("1"+ (message.hashCode() & Integer.MAX_VALUE));
        }else {
            hm = new BigInteger("2"+ message.hashCode());
        }
        hm = sign(hm,selfkey);
        BigInteger[] bigIntegers = new BigInteger[1];
        bigIntegers[0] = hm;
        return Convert.BigToStringWithoutAscll(bigIntegers);
    }

    /**
     * 验证
     * @param message 签名
     */
    public String verify_string(String message){
        BigInteger[] s = Convert.StringToBigWithoutAscll(message);
        BigInteger v = verify(s[0],pubkey);
        BigInteger[] bigIntegers = new BigInteger[1];
        bigIntegers[0] = v;
        String result = Convert.BigToStringWithoutAscll(bigIntegers);

        if(result.charAt(0) == '2'){
            result = result.substring(1,result.length());
        }else {
            result = result.substring(1,result.length());
            result = "-"+ result;
            int temp = Integer.parseInt(result);
            temp = temp&Integer.MAX_VALUE;
            result = String.valueOf(-temp);
        }
        return result;
    }
}
