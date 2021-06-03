package socket.src;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Date;

public class client {
    private static final String AS_IP = "192.168.43.93";
    private static final String TGS_IP = "192.168.43.49";
    private static final String SERVER_IP = "192.168.43.94";
//    private static final String AS_IP = "192.168.43.168";
//    private static final String TGS_IP = "192.168.43.168";
//    private static final String SERVER_IP = "192.168.43.168";
    private static final int AS_PORT = 8888;
    private static final int TGS_PORT = 8889;
    private static final int SERVER_PORT = 8890;
    static Socket socket = null;
    static DataOutputStream output = null;
    static DataInputStream input = null;
    private static final Logger log = LogManager.getLogger(client.class);

    public static void connect() {
        try {
            socket = new Socket(AS_IP, AS_PORT);
            output = new DataOutputStream(socket.getOutputStream());
            input = new DataInputStream(socket.getInputStream());

            String ID_c = "0001";//从ui界面获取
            String AD_c = "172000000001";  //应该用个函数获取地址
            String K_c = "1234567";
            Kerberos kerberos = new Kerberos();
            //AS
            Date TS1 = new Date();
            String message = kerberos.client_to_as(ID_c,kerberos.ID_tgs,TS1);  //调用Kerberos类函数生成消息字符串
            output.writeUTF(message);//发送信息
            //System.out.println(message.length());  //检验数据长度
            String receive = input.readUTF();  //接受信息

            System.out.println("Client收到AS的加密报文："+ receive);  //输出接受信息->在ui界面显示
            log.info("Client收到AS的加密报文：" + receive);
            String[] result1 = kerberos.client_parse_as(K_c, receive);  //调用Kerberos类中解析函数
            if(result1.length == 1){
                System.out.println("Client 访问 AS失败，错误代码：" + result1[0]);
                log.error(" Client 访问 AS失败，错误代码：" + result1[0]);
                if(result1[0].equals("0000")){
                    log.error(" Client 访问 AS失败，错误原因：找不到当前的ID_C + " + ID_c);
                }
                return;
            }
            String k_c_tgs = result1[0];
            String Ticket_tgs = result1[4];  //未解密的ticket_tgs  只有TGS可以解开


            //TGS
            Socket socket2 = new Socket(TGS_IP, TGS_PORT);
            DataOutputStream output2 = new DataOutputStream(socket2.getOutputStream());
            DataInputStream input2 = new DataInputStream(socket2.getInputStream());
            Date TS3 = new Date();
            String message2 = kerberos.client_to_tgs(kerberos.ID_v,Ticket_tgs,kerberos.get_Authenticator_c(k_c_tgs,ID_c,AD_c,TS3));  //调用Kerberos类函数生成消息字符串
            output2.writeUTF(message2);//发送信息
            String receive2 = input2.readUTF();  //接受信息
            System.out.println("Client收到TGS的加密报文："+ receive2);  //输出接受信息->在ui界面显示
            log.info("Client收到TGS的加密报文：" + receive2);
            String[] result2 = null;
            result2 = kerberos.client_parse_tgs(k_c_tgs, receive2);  //调用Kerberos类中解析函数
            String k_c_v = result2[0];
            String Ticket_v = result2[3];  //未解密的ticket_v  只有Server V可以解开

             //V
            Socket socket3 = new Socket(SERVER_IP, SERVER_PORT);
            DataOutputStream output3 = new DataOutputStream(socket3.getOutputStream());
            DataInputStream input3 = new DataInputStream(socket3.getInputStream());
            Date TS5 = new Date();
            String message3 = kerberos.client_to_v(Ticket_v,kerberos.get_Authenticator_c(k_c_v,ID_c,AD_c,TS5));  //调用Kerberos类函数生成消息字符串
            output3.writeUTF("1007" + message3);//发送信息给Server V，表示要认证
            String receive3 = input3.readUTF();  //接受信息
            System.out.println("Client收到Server V的加密报文："+ receive3);  //输出接受信息->在ui界面显示
            log.info("Client收到Server V的加密报文："+ receive3);
            String[] result3 = null;
            result3 = kerberos.client_parse_v(k_c_v, receive3);  //调用Kerberos类中解析函数
            String TS6 = result3[0];
            /*   //已经在client_parse_v中用同样的办法处理了返回值
            if(TS6.indexOf(0) >=0){
                TS6 = TS6.substring(0,TS6.indexOf(0));    //这一步很重要，由于在result中含有ascll码为0的值  导致TS6 和 TS5+1 虽然数值相等，但是由于有\u00000导致看上去一样实际上不一样
            }*/
            System.out.println("TS6:" + TS6);
            if(TS6.equals(String.valueOf(TS5.getTime()+1))){
                System.out.println("Client 与 Server V 认证成功，开始提供聊天室服务......");
                log.info("Client 与 Server V 认证成功，开始提供聊天室服务");
            }else {
                System.out.println("认证失败: TS5 不符合 ，Log时间:" + new Date());
                log.error("认证失败: TS5 不符合");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            try {
                input.close();
                output.close();
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args){
        connect();
    }
}
