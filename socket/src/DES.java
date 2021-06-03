package socket.src;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import sun.security.util.BitArray;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.BitSet;

public class DES {

    private int[] IP;       //8*8

    private int[] IP_1;     //8*8

    private int[][][] S;      //8*4*16

    private int[] E;        //8*8

    private int[] PC_1;     //8*7   行数*列数

    private int[] PC_2;     //6*8

    private int[] P;        //2*16

    private int[] LFT={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1}; //密钥偏移次数

    private int[][] sub_key = new int[16][48];

    private static BitSet key_bitset;

    private static final int BITSET_SIZE = 64;

    private static final int KEYBITSET_SIZE = 56;

    public DES(String key){
        IP = new int[]{
                58,50,42,34,26,18,10,2,
                60,52,44,36,28,20,12,4,
                62,54,46,38,30,22,14,6,
                64,56,48,40,32,24,16,8,
                57,49,41,33,25,17,9,1,
                59,51,43,35,27,19,11,3,
                61,53,45,37,29,21,13,5,
                63,55,47,39,31,23,15,7
        };
        IP_1 = new int[]{
                40,8,48,16,56,24,64,32,
                39,7,47,15,55,23,63,31,
                38,6,46,14,54,22,62,30,
                37,5,45,13,53,21,61,29,
                36,4,44,12,52,20,60,28,
                35,3,43,11,51,19,59,27,
                34,2,42,10,50,18,58,26,
                33,1,41,9,49,17,57,25
        };
        S = new int[][][]{
                {
                        { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                        { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                        { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                        { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },
                {
                        { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                        { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                        { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                        { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },
                {
                        { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                        { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                        { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                        { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },
                {
                        { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                        { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                        { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                        { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },
                {
                        { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                        { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                        { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                        { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },
                {
                        { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                        { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                        { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                        { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },
                {
                        { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                        { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                        { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                        { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },
                {
                        { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                        { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                        { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                        { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } }
        };
        E = new int[]{
                32,1,2,3,4,5,
                4,5,6,7,8,9,
                8,9,10,11,12,13,
                12,13,14,15,16,17,
                16,17,18,19,20,21,
                20,21,22,23,24,25,
                24,25,26,27,28,29,
                28,29,30,31,32,1
        };

        PC_1 = new int[]{
                57,49,41,33,25,17,9,
                1,58,50,42,34,26,18,
                10,2,59,51,43,35,27,
                19,11,3,60,52,44,36,
                63,55,47,39,31,23,15,
                7,62,54,46,38,30,22,
                14,6,61,53,45,37,29,
                21,13,5,28,20,12,4
        };
        PC_2 = new int[]{
                14,17,11,24,1,5,3,28,
                15,6,21,10,23,19,12,4,
                26,8,16,7,27,20,13,2,
                41,52,31,37,47,55,30,40,
                51,45,33,48,44,49,39,56,
                34,53,46,42,50,36,29,32
        };
        P = new int[]{
                16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
                2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
        };

        key_bitset = key_to_bitset(key);
        generateKey(key_bitset);

        /*  //用于读取文件获取数据时初始化数组
        IP = new int[64];
        IP_1 = new int[64];
        S = new int[8][][];
        E = new int[64];
        PC_1 = new int[56];
        PC_2 = new int[48];
        P = new int[32];*/
    }

    public BitSet Encrypt(BitSet M_bitSet, int flag){ //flag=0 加密   flag=1 解密
        //进行IP置换
        BitSet temp = new BitSet(BITSET_SIZE);
        for(int i=0; i<BITSET_SIZE; i++){
            if(M_bitSet.get(IP[i]-1)){
                temp.set(i);
            }
        }
        //加密解密过程
        if(flag == 0){//加密
            for(int i=0; i<16; i++){
                L(temp,i,flag,sub_key[i]);
            }
        }else if (flag == 1){//解密
            for(int j=15; j>=0; j--){
                L(temp,j,flag,sub_key[j]);
            }
        }
        //结果处理
        BitSet C = new BitSet();
        for(int i=0; i<IP_1.length; i++){
            if(temp.get(IP_1[i]-1)){
                C.set(i);
            }
        }
        return C;
    }

    public void L(BitSet M, int nums, int flag, int[] key){

        BitSet L0 = new BitSet(BITSET_SIZE/2);
        BitSet R0 = new BitSet(BITSET_SIZE/2);
        BitSet L1;
        BitSet R1;
        BitSet f;
        //64bit M分割为 32bit L   32bit R 两半部分
        for(int i=0; i<BITSET_SIZE/2; i++){
            if(M.get(i)){
                L0.set(i);
            }
            if(M.get(i+BITSET_SIZE/2)){
                R0.set(i);
            }
        }
        L1 = R0;
        R1 = L0;
        f=F_function(R0,key);
        M.clear();   //注意，BitSet要先clear再赋值，否则会有前面的1干扰
        R1.xor(f);   //f是轮函数结果，与L0异或 得到R1
        for(int i=0; i<BITSET_SIZE/2; i++){
            if(((flag == 0) && (nums == 15)) || ((flag == 1)&&(nums == 0))){
                //不交换L R
                if(R1.get(i)){
                    M.set(i);
                }
                if(L1.get(i)){
                    M.set(i+BITSET_SIZE/2);
                }
            }else {
                // 把L R交换送到下一轮
                if(L1.get(i)){
                    M.set(i);
                }
                if(R1.get(i)){
                    M.set(i+BITSET_SIZE/2);
                }
            }
        }
    }

    public BitSet F_function(BitSet r_content, int[] key){
        BitSet result = new BitSet(BITSET_SIZE/2);  //作为一轮轮函数的输出
        int[] temp = new int[48];
        //将32-->48 进行E扩展置换
        for(int i=0; i<48; i++){
            if(r_content.get(E[i]-1)){
                temp[i] = 1;
            }else {
                temp[i] = 0;
            }
        }
        //明文和密钥异或
        for(int i=0; i<48; i++){
            temp[i] = temp[i] ^ key[i];
        }
        int[][] s = new int[8][6];
        int[] s_after = new int[32];
        //开始S盒替换: 48-->32 先分割后替换
        for(int i=0; i<8; i++){
            //分割为6bit的S盒输入
            System.arraycopy(temp,i*6,s[i],0,6);
            int row = (s[i][0]<<1) + s[i][5];
            int column = (s[i][1]<<3) + (s[i][2]<<2)+(s[i][3]<<1)+(s[i][4]);
            String str = Integer.toBinaryString(S[i][row][column]);  //把s盒输出变成2进制字符串
            while(str.length()<4){  //补足0
                str = "0" + str;
            }
            for(int j=0; j<4; j++){
                int num = Integer.valueOf(str.charAt(j));
                if(num == 48){
                    num = 0;
                }else if(num == 49){
                    num = 1;
                }else {
                    System.out.println("To bit error");
                }
                s_after[4*i+j] = num;
            }
        }
        //S盒替换结束
        //开始P置换
        for(int i=0; i<P.length; i++){
            if(s_after[P[i]-1] == 1){
                result.set(i);
            }
        }
        return result;
    }


    public void generateKey(BitSet key){
        BitSet c0 = new BitSet(KEYBITSET_SIZE/2);
        BitSet d0 = new BitSet(KEYBITSET_SIZE/2);
        for(int i=0; i<KEYBITSET_SIZE/2; i++){ //因为不需要PC-1来将64-->56，所以直接等分成两部分
            if(key.get(i)){ //左半部分 <28
                c0.set(i);
            }
            if(key.get(i+KEYBITSET_SIZE/2)){//右半部分 >=28
                d0.set(i);
            }
        }
        for(int i=0; i<16; i++){
            BitSet c1 = new BitSet(KEYBITSET_SIZE/2);
            BitSet d1 = new BitSet(KEYBITSET_SIZE/2);
            if(LFT[i] == 1){
                for(int j=0; j<KEYBITSET_SIZE/2; j++){ //c0向左偏移成为c1
                    if(c0.get(j) && j==0){
                        c1.set(KEYBITSET_SIZE/2-1);
                    }else if(c0.get(j)){
                        c1.set(j-1);
                    }
                    if(d0.get(j) && j==0){//d0向左偏移成为d1
                        d1.set(KEYBITSET_SIZE/2-1);
                    }else if(d0.get(j)){
                        d1.set(j-1);
                    }
                }
            }else if(LFT[i] == 2){
                for(int j=0; j<KEYBITSET_SIZE/2; j++){ //c0向左偏移成为c1
                    if(c0.get(j) && j==0){
                        c1.set(KEYBITSET_SIZE/2-2);
                    }else if(c0.get(j) && j==1){
                        c1.set(KEYBITSET_SIZE/2-1);
                    }else if(c0.get(j)){
                        c1.set(j-2);
                    }
                    if(d0.get(j) && j==0){//d0向左偏移成为d1
                        d1.set(KEYBITSET_SIZE/2-2);
                    }else if(d0.get(j) && j==1){
                        d1.set(KEYBITSET_SIZE/2-1);
                    }else if(d0.get(j)){
                        d1.set(j-2);
                    }
                }
            }//偏移完成，开始置换缩减至48bit
            BitSet temp = new BitSet(KEYBITSET_SIZE);
            for(int k=0; k<KEYBITSET_SIZE/2; k++){ //把c1 d1合并至56 bit 的temp
                if(c1.get(k)){
                    temp.set(k);
                }
                if(d1.get(k)){
                    temp.set(k+KEYBITSET_SIZE/2);
                }
            }
            //PC-2压缩置换
            for(int k=0; k<PC_2.length; k++){//subkey数组存放16个子密钥，每个子密钥为48bit
                if(temp.get(PC_2[k]-1)){
                    sub_key[i][k] = 1;
                }else {
                    sub_key[i][k] = 0;
                }
            }
            c0 = c1;
            d0 = d1;
        }
    }

    public static String[] split(String text){
        int size = text.length()/8;
        String[] result;
        if(size>0){
            if(size*8 == text.length()){
                result = new String[size];
            }else {
                result = new String[size+1];
            }
        }else {//size == 0
            result = new String[1];
            result[0] = text;
            return result;
        }
        int i=0;
        while (size>0){
            result[i] = text.substring(i*8,(i+1)*8);
            i++;
            size--;
        }
        if(i*8 < text.length()){//如果多出一组大小小于N，就把这最后一组补上
            result[i] = text.substring(i*8,text.length());
        }
        return result;
    }

    public static BitSet[] strings_to_bitsets(String[] message_array){
        BitSet[] bitSets = new BitSet[message_array.length];
        BitArray[] bitArrays = new BitArray[message_array.length];
        for(int i=0; i<bitArrays.length; i++){
            bitArrays[i] = new BitArray(message_array[i].length()*8,message_array[i].getBytes());
            bitSets[i] = new BitSet(BITSET_SIZE);
            for(int j=0; j<bitArrays[i].length(); j++){
                if (bitArrays[i].get(j)){
                    bitSets[i].set(j);
                }
            }
        }
        return bitSets;
    }

    public static BitSet[] base64strings_to_bitsets(String message){
        if(message.indexOf(0) >=0){
            message = message.substring(0,message.indexOf(0));    //这一步很重要，由于在result中含有ascll码为0的值，导致转换为byte[]时出错，所以要先剔除掉0
        }
        byte[] message_bytes = Base64.decode(message);
        if(message_bytes == null){
            return null;
        }
        int size = message_bytes.length/8;
        byte[][] result_bytes;
        if(size>0){
            if(size*8 == message_bytes.length){
                result_bytes = new byte[size][8];
            }else {
                result_bytes = new byte[size+1][8];
            }
            int i=0;
            int k=0;
            while (size>0){
                for(int j=0; j<8; j++){   //按照每8个byte分组
                    result_bytes[i][j] = message_bytes[k];
                    k++;
                }
                i++;
                size--;
            }
            if(i*8 < message_bytes.length){//如果多出一组大小小于N，就把这最后一组补上
                for(int j=0; j<message_bytes.length-i*8; j++){
                    result_bytes[i][j] = message_bytes[k];
                    k++;
                }
            }
        }else {
            result_bytes  = new byte[1][message_bytes.length];
            for(int i=0; i<message_bytes.length; i++){
                result_bytes[1][i] = message_bytes[i];
            }
        }//至此，已经把传入的密文通过base64解码为byte数组，然后byte数组按照8个byte进行分割成二维byte数组-->result_bytes[][]
        BitSet[] bitSets = new BitSet[result_bytes.length];
        BitArray[] bitArrays = new BitArray[result_bytes.length];
        for(int i=0; i<bitArrays.length; i++){
            bitArrays[i] = new BitArray(result_bytes[i].length*8,result_bytes[i]);
            bitSets[i] = new BitSet(BITSET_SIZE);
            for(int j=0; j<bitArrays[i].length(); j++){
                if (bitArrays[i].get(j)){
                    bitSets[i].set(j);
                }
            }
        }
        return bitSets;
    }

    public static String bitsets_to_base64string(BitSet[] bitSets){
        //System.out.println(bitSets[0].length());//64
        //System.out.println(bitSets[1].length());//62
        BitArray[] result_bitArrays = new BitArray[bitSets.length];
        for(int i=0; i<result_bitArrays.length; i++){
            //所以还是不能用bitset.length，直接64--> BITSET_SIZE
            result_bitArrays[i] = new BitArray(BITSET_SIZE);
            for(int j=0; j<BITSET_SIZE; j++){
                if (bitSets[i].get(j)){
                    result_bitArrays[i].set(j,true);
                }else {
                    result_bitArrays[i].set(j,false);
                }
            }
        }
        byte[][] result_bytes = new byte[result_bitArrays.length][];
        for(int i=0; i<result_bitArrays.length; i++){
            result_bytes[i] = result_bitArrays[i].toByteArray();
        }
        byte[] bytes = new byte[result_bytes.length*8];
        int t = 0;
        for(int i=0; i<result_bytes.length; i++){
            for(int j=0; j<result_bytes[i].length; j++){
                bytes[t] = result_bytes[i][j];
                t++;
            }
        }
        String base64 = Base64.encode(bytes);
        return base64;
    }

    public static String bitsets_to_string(BitSet[] bitSets){
        //System.out.println(bitSets[0].length());//64
        //System.out.println(bitSets[1].length());//62
        BitArray[] result_bitArrays = new BitArray[bitSets.length];
        for(int i=0; i<result_bitArrays.length; i++){
            //所以还是不能用bitset.length，直接64--> BITSET_SIZE
            result_bitArrays[i] = new BitArray(BITSET_SIZE);
            for(int j=0; j<BITSET_SIZE; j++){
                if (bitSets[i].get(j)){
                    result_bitArrays[i].set(j,true);
                }else {
                    result_bitArrays[i].set(j,false);
                }
            }
        }
        byte[][] result_bytes = new byte[result_bitArrays.length][];
        StringBuilder stringBuilder = new StringBuilder();
        for(int i=0; i<result_bitArrays.length; i++){
            result_bytes[i] = result_bitArrays[i].toByteArray();
            for(int j=0; j<result_bytes[i].length; j++){
                stringBuilder.append((char)result_bytes[i][j]);
            }
        }
        return stringBuilder.toString();
    }

    public static BitSet key_to_bitset(String key){
        BitArray bitArraykey = new BitArray(KEYBITSET_SIZE,key.getBytes());
        BitSet key_bit = new BitSet(KEYBITSET_SIZE);
        for(int i=0; i<KEYBITSET_SIZE; i++){
            if (bitArraykey.get(i)){
                key_bit.set(i);
            }
        }
        return key_bit;
    }

    public String encrypt_string(String message){
        message = Base64.encode(message.getBytes());
        //System.out.println("原文经过base64编码："+message);
        //System.out.println("原文经过base64编码再转回："+ new String(Base64.decode(message)));
        //String[] message_array = DES.split(message);     //因为已经不使用Stirng_to_bitset(String[] array)，所以也不需要此split函数了
        //把String[] 转换成 2进制 的BitSet数组

        BitSet[] M_bitSets = base64strings_to_bitsets(message);
        if(M_bitSets == null){
            return null;
        }
        BitSet[] C_bitSets = new BitSet[M_bitSets.length];
        for(int i=0; i<C_bitSets.length; i++){
            C_bitSets[i] = Encrypt(M_bitSets[i],0);
            //System.out.println(C_bitSets[i]);
        }
        return bitsets_to_base64string(C_bitSets);
    }

    public String decrypt_string(String message){
        BitSet[] C_bitSets = base64strings_to_bitsets(message);
        if(C_bitSets == null){
            return null;
        }
        BitSet[] M_bitSets = new BitSet[C_bitSets.length];
        for(int i=0; i<C_bitSets.length; i++){
            M_bitSets[i] = Encrypt(C_bitSets[i],1);
        }
        String result = bitsets_to_base64string(M_bitSets);
        if(result.indexOf(0) >=0){
            result = result.substring(0,result.indexOf(0));    //这一步很重要，由于在result中含有ascll码为0的值，导致转换为byte[]时出错，所以要先剔除掉0
        }
        String base64result = new String(Base64.decode(result));
        if(base64result.indexOf(0) >=0){
            base64result = base64result.substring(0,base64result.indexOf(0));    //这一步很重要，因为base64解码后可能存在ascll = 0的值，所以要剔除掉0
        }
        return base64result;
    }

    public int[] getIP() {
        return IP;
    }

    public int[][][] getS() {
        return S;
    }

    public int[] getE() {
        return E;
    }

    public int[] getIP_1() {
        return IP_1;
    }

    public int[] getP() {
        return P;
    }

    public int[] getPC_1() {
        return PC_1;
    }

    public int[] getPC_2() {
        return PC_2;
    }

    public void setIP() {
        /*
        try{  //为了快，不从文件读取，直接在构造函数用数据初始化数组
            File fileIP = new File("E:/eclipse文件/Security/src/com/company/des/IP");
            BufferedReader br = new BufferedReader(new FileReader(fileIP));//构造一个BufferedReader类来读取文件
            String s = null;
            int i=0;
            while((s = br.readLine())!=null){//使用readLine方法，一次读一行
                String[] data = s.split(" ");
                for (int j=0;j<8;i++,j++){
                    IP[i] = Integer.parseInt(data[j]);
                }
            }
            br.close();
        }catch(Exception e){
            e.printStackTrace();
        }*/

    }

    public void setIP_1() {
        try{
            File fileIP_1 = new File("E:/eclipse文件/Security/src/com/company/des/IP-1");
            BufferedReader br = new BufferedReader(new FileReader(fileIP_1));//构造一个BufferedReader类来读取文件
            String s = null;
            int i=0;
            while((s = br.readLine())!=null){//使用readLine方法，一次读一行
                String[] data = s.split(" ");
                for (int j=0;j<8;i++,j++){
                    IP_1[i] = Integer.parseInt(data[j]);
                }
            }
            br.close();
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public void setS() {
        for (int i=0; i<8; i++){
            for(int j=0; j<4; j++){
                S[i][j] = new int[16];
            }
        }
        try{
            File fileS = new File("E:/eclipse文件/Security/src/com/company/des/S");
            BufferedReader br = new BufferedReader(new FileReader(fileS));//构造一个BufferedReader类来读取文件
            String s = null;
            int m=0,n=0,x=0;
            while((s = br.readLine())!=null){//使用readLine方法，一次读一行
                String[] data = s.split(" ");
                if(x == 4){
                    m++;
                    x=0;
                }
                for (int j=0;j<16;n++,j++){
                    S[m][x][n] = Integer.parseInt(data[j]);
                }
                x++;
                n=0;
            }
            br.close();
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public void setE() {
        try{
            File fileE = new File("E:/eclipse文件/Security/src/com/company/des/E");
            BufferedReader br = new BufferedReader(new FileReader(fileE));//构造一个BufferedReader类来读取文件
            String s = null;
            int i=0;
            while((s = br.readLine())!=null){//使用readLine方法，一次读一行
                String[] data = s.split(" ");
                for (int j=0;j<6;i++,j++){
                    E[i] = Integer.parseInt(data[j]);
                }
            }
            br.close();
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public void setPC_1() {
        try{
            File filePC_1 = new File("E:/eclipse文件/Security/src/com/company/des/PC-1");
            BufferedReader br = new BufferedReader(new FileReader(filePC_1));//构造一个BufferedReader类来读取文件
            String s = null;
            int i=0;
            while((s = br.readLine())!=null){//使用readLine方法，一次读一行
                String[] data = s.split(" ");
                for (int j=0;j<7;i++,j++){
                    PC_1[i] = Integer.parseInt(data[j]);
                }
            }
            br.close();
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public void setPC_2() {
        try{
            File filePC_2 = new File("E:/eclipse文件/Security/src/com/company/des/PC-2");

            BufferedReader br = new BufferedReader(new FileReader(filePC_2));//构造一个BufferedReader类来读取文件
            String s = null;
            int i=0;
            while((s = br.readLine())!=null){//使用readLine方法，一次读一行
                String[] data = s.split(" ");
                for (int j=0;j<8;i++,j++){
                    PC_2[i] = Integer.parseInt(data[j]);
                }
            }
            br.close();
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public void setP() {
        try{
            File fileP = new File("E:/eclipse文件/Security/src/com/company/des/P");
            BufferedReader br = new BufferedReader(new FileReader(fileP));//构造一个BufferedReader类来读取文件
            String s = null;
            int i=0;
            while((s = br.readLine())!=null){//使用readLine方法，一次读一行
                String[] data = s.split(" ");
                for (int j=0;j<16;i++,j++){
                    P[i] = Integer.parseInt(data[j]);
                }
            }
            br.close();
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
