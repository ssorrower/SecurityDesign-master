package socket.src;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Date;

public class V {
    /*public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(8890);
        System.out.println("V server start at:" + new Date());
        Vthread a = new Vthread();
        while (true) {
            Socket socket = serverSocket.accept();
            a.setSocket(socket);
            new Thread(a).start();
        }
    }*/
}

class Vthread  implements Runnable{
    Socket socket;
    private static final Logger log = LogManager.getLogger(V.class);
    public void setSocket(Socket socket){
        this.socket = socket;
    }
    @Override
    public void run(){
        //System.out.println(1);
        try {
            InetAddress address = socket.getInetAddress();
            System.out.println("connected with address:"+address.getHostAddress());
            log.info("Server V connected with address:"+address.getHostAddress());
            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());
            String receive = input.readUTF(); //接收数据

            Kerberos kerberos = new Kerberos();
            String []result = kerberos.v_parse_client(receive);   //要在这里解析出数据Authenticator_c中的TS5
            System.out.println("Server V 接收到 Client的报文: "+ receive);
            log.info("Server V 接收到 Client的报文: "+ receive);
            String Ticket_v = result[1];
            DES des = new DES("vvvmima"); //K_V
            String Ticket_v_decrypt = des.decrypt_string(Ticket_v);
            String k_c_v = Ticket_v_decrypt.substring(0,7);
            DES des2 = new DES(k_c_v); //K_c_v
            String Authenticatorc = des2.decrypt_string(result[2]);
            String TS5_string = Authenticatorc.substring(16,29);
            System.out.println("Server V 接收到的TS_5_to_time:" + TS5_string);
            log.info("Server V 接收到的TS_5_to_time:" + TS5_string);
            output.writeUTF(kerberos.v_to_client(k_c_v,TS5_string));
            output.flush();
            socket.shutdownOutput();
            socket.close();
        } catch (
                IOException e) {
            e.printStackTrace();
        }
    }
}


