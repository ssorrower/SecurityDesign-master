import RSA.RSA;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import socket.src.DES;
import socket.src.Kerberos;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
/**
 * 网络多客户端聊天室
 * 功能1： 客户端通过Java NIO连接到服务端，支持多客户端的连接
 * 功能2：客户端初次连接时，服务端提示输入昵称，如果昵称已经有人使用，提示重新输入，如果昵称唯一，则登录成功，之后发送消息都需要按照规定格式带着昵称发送消息
 * 功能3：客户端登录后，发送已经设置好的欢迎信息和在线人数给客户端，并且通知其他客户端该客户端上线
 * 功能4：服务器收到已登录客户端输入内容，转发至其他登录客户端。
 *
 * TODO 客户端下线检测
 */
public class ChatRoomServer {

    private static final Logger log = LogManager.getLogger(ChatRoomServer.class);
    private static Selector selector = null;
    static final int port = 9999;
    private static Charset charset = Charset.forName("UTF-8");
    //用来记录在线人数，以及昵称
    private static HashSet<String> users = new HashSet<String>();

    //相当于自定义协议格式，与客户端协商好
    private static int USER_EXIST = 1003;
    private static int USER_LIST=1004;
    private static int USER_REGIST_SUCC = 1005;
    private static int USER_REQUIRE = 1006;
    private static int USER_EXIT = 1000;
    private static int USER_SEND = 1001;
    private static int USER_LOGIN = 1002;
    private static String USER_VERIFY = "1007";
    private static BigInteger[] selfkey = new BigInteger[2];//的私钥server

    private static String USER_CONTENT_SPILIT = "#@#";
    private SocketChannel sc0;

    public static HashMap<SocketChannel,String[]> map = new HashMap<>();//数据字典,通道与sessionkey

    private static boolean flag = false;

    public void init() throws IOException
    {
        selector = Selector.open();
        ServerSocketChannel server = ServerSocketChannel.open();
        server.bind(new InetSocketAddress(port));
        //非阻塞的方式
        server.configureBlocking(false);
        //注册到选择器上，设置为监听状态
        server.register(selector, SelectionKey.OP_ACCEPT);
        selfkey[0]=new BigInteger("13001106526213460135508574438840026795234423504475048394574507593825609303940972968641240068077643512099754665285310307761434798867852929898156665888139980391508044898214140863780027477940340938052795780670631144808803015806046739377393676757840926487115296689326934732127307465606187070590942866873828652644747198161955492870684564271203405791512164665860264154930957132317401123147585992330684664625062722742170140920105831476904564832667101943244060923092249831560742328940893107943174268255288128745656481042601161876880862066173174282190546980044281034081128934074579100081681010910010248617335049232458523680621");
        selfkey[1]=new BigInteger("5439329536631931023017678601989024439607132735236604542942741103729257999370699571649208255285119969761557183994658335421376943561006141338138114683108932699921557029832514889970315599091295118489854700554008199330341179644872294230568338847112934118897940398929691981936900428757130220921510939878442831174746219191444366146520185770293651513065881337073020694268006091552298717545117918401985236054144766429626803652100609542344298298566770250441286836147256806667334663886757135622190258178220092732310647591548452806037735659793600006601342570157978583135821331001790890256098422489671528280433453376749772318901");
        System.out.println("Server is listening now...");

        while(true) {
            int readyChannels = selector.select();
            if(readyChannels == 0) continue;
            Set selectedKeys = selector.selectedKeys();  //可以通过这个方法，知道可用通道的集合
            Iterator keyIterator = selectedKeys.iterator();
            while(keyIterator.hasNext()) {
                SelectionKey sk = (SelectionKey) keyIterator.next();
                keyIterator.remove();
                dealWithSelectionKey(server,sk);
            }
        }
    }

    public void dealWithSelectionKey(ServerSocketChannel server,SelectionKey sk) throws IOException {
        if(sk.isAcceptable())
        {
            SocketChannel sc = server.accept();

            //非阻塞模式
            sc.configureBlocking(false);
            //注册选择器，并设置为读取模式，收到一个连接请求，然后起一个SocketChannel，并注册到selector上，之后这个连接的数据，就由这个SocketChannel处理
            sc.register(selector, SelectionKey.OP_READ);

            //将此对应的channel设置为准备接受其他客户端请求
            sk.interestOps(SelectionKey.OP_ACCEPT);
            System.out.println("Server is listening from client :" + sc.getRemoteAddress());

        }
        //处理来自客户端的数据读取请求
        if(sk.isReadable())
        {
            //返回该SelectionKey对应的 Channel，其中有数据需要读取
            SocketChannel sc = (SocketChannel)sk.channel();
            ByteBuffer buff = ByteBuffer.allocate(1024);
            StringBuilder content = new StringBuilder();
            try
            {
                while(sc.read(buff) > 0)
                {
                    buff.flip();
                    content.append(charset.decode(buff));
                }
                System.out.println("Server is listening from client " + sc.getRemoteAddress() + " data rev is: " + content);
                //将此对应的channel设置为准备下一次接受数据
                sk.interestOps(SelectionKey.OP_READ);
            }
            catch (IOException io)
            {
                sk.cancel();
                if(sk.channel() != null)
                {
                    sk.channel().close();
                }
            }
            if(content.length() > 0)
            {
                sc0=sc;
                unPackage(content.toString());
            }
        }
    }
    /*
     *将当前在线的用户列表返回
     */
    public static void SendList(SocketChannel sc) throws IOException {
        Iterator<String> iterator = users.iterator();
        String message ="";
        while (iterator.hasNext()) {
            String next = iterator.next();
            message+=next;
            message+=USER_CONTENT_SPILIT;
            System.out.println(message);
        }
        DES des = new DES(map.get(sc)[0]);
        sc.write(charset.encode(des.encrypt_string(PackageMessage(message,USER_LIST))));
    }
    //TODO 要是能检测下线，就不用这么统计了
    public static int OnlineNum(Selector selector) {
        int res = 0;
        for(SelectionKey key : selector.keys())
        {
            Channel targetchannel = key.channel();

            if(targetchannel instanceof SocketChannel)
            {
                res++;
            }
        }
        return res;
    }

    public void BroadCast(Selector selector, SocketChannel except, String content,int type) throws IOException {
        //广播数据到所有的SocketChannel中
        int i=0;
        int j=0;

        for(SelectionKey key : selector.keys())
        {
            i++;
            //System.out.println("i: "+i);
            Channel targetchannel = key.channel();
            //如果except不为空，不回发给发送此内容的客户端
            if(targetchannel instanceof SocketChannel && targetchannel!=except)
            {
                j++;
                //System.out.println("j: "+j);
                SocketChannel dest = (SocketChannel)targetchannel;

                //String name =
                if(map.get(dest)==null){
                    System.out.println("map size:   "+map.size()+"   ************************************");
                    continue;
                }
                DES des = new DES(map.get(dest)[0]);
                if(type==USER_SEND)
                    content=PutSign(content,dest);
                dest.write(charset.encode(des.encrypt_string(content)));
            }
        }
    }


    /*
     *将消息解封
     */
    public boolean unPackage(String message) throws IOException {
        if(message == null){
            System.out.println("message is null!!!!!!!!!!!!!");
            return false;
        }
        String typ=message.substring(0,4);
        String content="";
        if(typ.equals(USER_VERIFY)){
            String receive = message.substring(4);
            Kerberos kerberos = new Kerberos();
            String []result = kerberos.v_parse_client(receive);   //要在这里解析出数据Authenticator_c中的TS5
            System.out.println("Server V 接收到 Client的报文: "+ receive);
            log.info("Server V 接收到 Client的报文: "+ receive);
            String Ticket_v = result[1];
            DES des = new DES("vvvmima"); //K_V
            String Ticket_v_decrypt = des.decrypt_string(Ticket_v);
            String k_c_v = Ticket_v_decrypt.substring(0,7);//session_key
            DES des2 = new DES(k_c_v); //K_c_v
            String Authenticatorc = des2.decrypt_string(result[2]);
            String TS5_string = Authenticatorc.substring(16,29);
            String client_N = Authenticatorc.substring(29).split(" ")[0];
            String client_PK = Authenticatorc.substring(29).split(" ")[1];
            System.out.println("Server V 接收到的TS_5_to_time:" + TS5_string);
            log.info("Server V 接收到的TS_5_to_time:" + TS5_string);

            System.out.println("k_c_v:"+k_c_v);
            System.out.println("注册用户map添加前大小："+map.size());

            String map_client_value[] = new String[3];
            map_client_value[0] = k_c_v;
            map_client_value[1] = client_N;
            map_client_value[2] = client_PK;
            map.put(sc0,map_client_value);//将通道与sessionkey对应
            System.out.println("注册用户map添加后大小："+map.size());
            sc0.write(charset.encode(kerberos.v_to_client(k_c_v,TS5_string)));
            return false;
        }
        DES d=new DES(map.get(sc0)[0]);
        message=d.decrypt_string(message);
        if(message == null){
            return false;
        }
        String type0=message.substring(0,4);
        int type=Integer.parseInt(type0);
        if(type == USER_SEND){
            String len=message.substring(4,12);
            int length=Integer.parseInt(len);
            String info=message.substring(12,12+length);
            content=message.substring(0,12+length);
            int signlen=Integer.parseInt(message.substring(12+length,12+length+8));
            String hash=VertifySign(message.substring(12+length+8,12+length+8+signlen),sc0);
            if(!String.valueOf(content.hashCode()).equals(hash)) {
                System.out.println("对比1:" + content.hashCode());
                System.out.println("对比2:"+hash);
                System.out.println("warning!!!!!!!!!!!!!!!!!!!!!!!!!!someone distort the message!");
            }BroadCast(selector, null, PackageMessage(info,USER_SEND),USER_SEND);
        }
        else if(type == USER_EXIT){
            String len=message.substring(4,12);
            int length=Integer.parseInt(len);
            String info=message.substring(12,12+length);
            users.remove(info);

            System.out.println("用户退出map移除前大小："+map.size());
            map.remove(sc0);//将信道弹出
            System.out.println("用户退出map移除后大小："+map.size());

            int num = OnlineNum(selector);
            info=info+" exit the chat room! Online numbers:"+(num-1);
            BroadCast(selector, sc0, PackageMessage(info,USER_EXIT),USER_EXIT);
        }
        else if(type == USER_LIST){
            String len=message.substring(4,12);
            int length=Integer.parseInt(len);
            String info=message.substring(12,12+length);
            SendList(sc0);
        }
        else if(type == USER_REQUIRE){
            String len=message.substring(4,12);
            int length=Integer.parseInt(len);
            String info=message.substring(12,12+length);
            if(users.contains(info)) {
                DES des = new DES(map.get(sc0)[0]);
                sc0.write(charset.encode(des.encrypt_string(PackageMessage("the name exist",USER_EXIST))));
            }
            else{
                users.add(info);
                DES des = new DES(map.get(sc0)[0]);
                sc0.write(charset.encode(des.encrypt_string(PackageMessage(info,USER_REGIST_SUCC))));
                System.out.println("name:"+info);
                int num = OnlineNum(selector);
                String mess = "welcome "+info+" to chat room! Online numbers:"+num;
                BroadCast(selector, sc0, PackageMessage(mess,USER_LOGIN),USER_REQUIRE);
            }
        }
        else{
            return false;
        }
        return false;
    }

    /*
     *将消息封装
     */
    public static String PackageMessage(String message,int type)
    {
        String str=""+message;
        int len=message.length();
        if(type==USER_EXIT) {
            str=IntToString(len)+str;
            str="1000"+str;
            return str;
        }
        else if(type==USER_LOGIN) {
            str=IntToString(len)+str;
            str="1002"+str;
            return str;
        }
        else if(type==USER_SEND){
            str=IntToString(len)+str;
            str="1001"+str;
            return str;
        }else if(type==USER_LIST){
            str=IntToString(len)+str;
            str="1004"+str;
            return str;
        }else if(type==USER_REQUIRE){
            str=IntToString(len)+str;
            str="1006"+str;
            return str;
        }else if(type==USER_REGIST_SUCC){
            str=IntToString(len)+str;
            str="1005"+str;
            return str;
        }else if(type==USER_EXIST){
            str=IntToString(len)+str;
            str="1003"+str;
            return str;
        }
        else{
            return str;
        }

    }

    public static String IntToString(int num)
    {
        String str=String.valueOf(num);
        int len=str.length();
        for(;len<8;len++)
        {
            str="0"+str;
        }
        return str;
    }

    /*
     * 将传入的字符串进行hash后进行加密并返回加密后的字符串
     * */
    private static String PutSign(String plaintext, SocketChannel sc)
    {
        BigInteger[] pubkey = new BigInteger[2];
        pubkey[0]=new BigInteger(map.get(sc)[1]);
        pubkey[1]=new BigInteger(map.get(sc)[2]);
        RSA rsa=new RSA(pubkey,selfkey);
        String signature=rsa.sign_string(plaintext);
        String signlen=IntToString(signature.length());
        plaintext=plaintext+signlen+signature;
        return plaintext;
    }
    /*
     * 将传入的字符串进行rsa解密并返回解密后的字符串
     * */
    private String VertifySign(String cyphertext,SocketChannel sc)
    {
        BigInteger[] pubkey = new BigInteger[2];
        pubkey[0]=new BigInteger(map.get(sc)[1]);
        pubkey[1]=new BigInteger(map.get(sc)[2]);
        RSA rsa=new RSA(pubkey,selfkey);
        System.out.println("cyphertext:  "+cyphertext);
        String hashnum=rsa.verify_string(cyphertext);
        return hashnum;
    }



    public static void main(String[] args) throws IOException
    {
        new ChatRoomServer().init();
    }
}