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

public class TGS {
    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(8889);
        System.out.println("TGS server start at:" + new Date());
        while (true) {
            Socket socket = serverSocket.accept();
            TGSthread a = new TGSthread();
            a.setSocket(socket);
            new Thread(a).start();
        }
    }

}
class TGSthread implements Runnable{
    Socket socket;
    private static final Logger log = LogManager.getLogger(TGS.class);
    public void setSocket(Socket socket){
        this.socket = socket;
    }
    @Override
    public void run(){
        try {
            InetAddress address = socket.getInetAddress();
            System.out.println("connected with address:"+address.getHostAddress());
            log.info("TGS connected with address:"+address.getHostAddress());
            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());
            String receive = input.readUTF(); //接收数据

            Kerberos kerberos = new Kerberos();
            String []result = kerberos.tgs_parse_client(receive);
            System.out.println("TGS 接收到 Client的报文: "+ receive);
            log.info("TGS 接收到 Client的报文: "+ receive);
            String k_c_v = kerberos.create_sessionkey();//当生命周期过后要换密钥 K_c_v————> 每次认证都随机生成，由客户端判断生命周期

            String Ticket_tgs = result[1];
            DES des = new DES("tgsmima"); //K_TGS
            String Ticket_tgs_decrypt = des.decrypt_string(Ticket_tgs);
            String k_c_tgs = Ticket_tgs_decrypt.substring(0,7);
            String ID_C = Ticket_tgs_decrypt.substring(7,11);
            String AD_C = Ticket_tgs_decrypt.substring(11,23);
            Date TS4 = new Date();
            output.writeUTF(kerberos.tgs_to_client(k_c_tgs,k_c_v,kerberos.ID_v,TS4,kerberos.
                    get_Ticket_v("",k_c_v,ID_C,AD_C,kerberos.ID_v,TS4,kerberos.Lifetime)));
            output.flush();
            socket.shutdownOutput();
            socket.close();
        } catch (
                IOException e) {
            e.printStackTrace();
        }
    }
}


