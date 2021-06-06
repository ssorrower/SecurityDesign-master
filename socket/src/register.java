package socket.src;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class register {
    private static final String SERVER_IP = "192.168.43.93";
    private static final int SERVER_PORT = 8888;
    static Socket socket = null;
    static DataOutputStream output = null;
    static DataInputStream input = null;
    private static final Logger log = LogManager.getLogger(register.class);


    public static void connect() {
        try {
            socket = new Socket(SERVER_IP, SERVER_PORT);
            output = new DataOutputStream(socket.getOutputStream());
            input = new DataInputStream(socket.getInputStream());
            Kerberos kerberos = new Kerberos();
            String message = kerberos.register;  //Kerberos类请求注册字符串
            output.writeUTF(message);//发送注册请求
            //System.out.println(message.length());  //检验数据长度
            String receive = input.readUTF();  //接受证书
            if(receive.equals("0002")){
                log.error(" 注册失败，错误原因: 已存在此用户ID");
            }
            System.out.println(receive);
            //调用Kerberos类中解析函数,解析证书
            String pk = kerberos.parse_Certification(receive);

            if(!pk.equals(null)){
                output.writeUTF(kerberos.client_id_key("0001","abcdefg",pk));
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

    /*public static void main(String[] args){
        connect();
    }*/
}
