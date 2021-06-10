package javaui.src;

import javaui.src.BackgroundClient;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.channels.SocketChannel;
import java.util.regex.Pattern;

import static java.lang.Thread.sleep;

public class AntChatUi {
    public JFrame frame = new JFrame("物联网安全课程设计"); // 声明窗口对象
    public static final int roomwidth=700;//认证过程的窗口宽高
    public static final int roomheight=630;
    private static final Logger log = LogManager.getLogger(AntChatUi.class);

    /*
     * 判断是否为整数
     * @param str 传入的字符串
     * @return 是整数返回true,否则返回false
     */
    public boolean isInteger(String str) {
        Pattern pattern = Pattern.compile("^[-\\+]?[\\d]*$");
        return pattern.matcher(str).matches();
    }

    /*
     * 设置窗口生成大小位置
     * @param panel 传入的界面
     * @return 返回定位以后的界面
     */
    public void resetFrame(int curWidth, int curHeight)
    {
        // 设置窗口的长和宽
        frame.setSize(roomwidth, roomheight);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        //窗口在屏幕中间显示
        Toolkit tk = Toolkit.getDefaultToolkit();
        Dimension dimension = tk.getScreenSize();//获取屏幕大小
        int width=dimension.width;
        int height=dimension.height;
        int x=(width-curWidth)/2;
        int y=(height-curHeight)/2;
        frame.setLocation(x, y);//登陆界面在屏幕的位置坐标x,y



    }


    public void chatroom() {
        // 创建 JFrame 实例

        resetFrame(roomwidth,roomheight);
        /* 创建面板，这个类似于 HTML 的 div 标签
         * 我们可以创建多个面板并在 JFrame 中指定位置
         * 面板中我们可以添加文本字段，按钮及其他组件。
         */
        //创建一个JLayeredPane用于分层的。
        JLayeredPane layeredPane=new JLayeredPane();

        JPanel panel = new JPanel();

        frame.add(panel);
        /*
         * 调用用户定义的方法并添加组件到面板
         */
        placeComponents(frame,panel);


        // 设置界面可见
        frame.setVisible(true);

    }


    /*
     *生成本次匿名聊天界面
     * @param frame框架
     * @panel 面板
     * @jl1 显示kerberos数据框
     * @jl2 显示数据交流数据框
     */
    public void Anonymousroom(JPanel panel,JTextArea textarea0, JTextArea jl1, JTextArea jl2, JLabel OnlineLabel, JList<String> list, String name, BackgroundClient client)
    {
        //监听关闭窗口的事件
        frame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                super.windowClosing(e);
                try {
                    client.UserExit();
                } catch (IOException e1) {
                    System.out.println("发送退出报文出错");
                }
            }
        });

        try {
            client.AquireList(list);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        //创建显示文字的区域
        textarea0.setVisible(true);
        //将后台与前台ui连接
        client.update(textarea0,jl1,jl2);
        JScrollPane jsp0 = new JScrollPane(textarea0);
        textarea0.setEditable(false);
        //设置矩形大小.参数依次为(矩形左上角横坐标x,矩形左上角纵坐标y，矩形长度，矩形宽度)
        jsp0.setBounds(100, 20, 500, 150);//聊天内容显示框位置大小
        //默认的设置是超过文本框才会显示滚动条，以下设置让滚动条一直显示
        jsp0.setVerticalScrollBarPolicy( JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        panel.add(jsp0);
        /*
         * 创建文本域用于用户输入
         */
        JTextField userText = new JTextField(20);
        userText.setBounds(100,175,165,25);//聊天内容输入框位置大小
        panel.add(userText);

        // 创建发送按钮
        JButton sendButton = new JButton("发送");
        // 实现"重置"按钮功能

        sendButton.setBounds(275, 175, 80, 25);
        panel.add(sendButton);
        //jl2.setForeground(Color.red);
        jl2.setEditable(false);
        //jl2.setText(jl2.getText()+"haha\n");
        //jl2.setForeground(Color.blue);
        //jl2.setText(jl2.getText()+"haha\n");
        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                // TODO Auto-generated method stub
                if(userText.getText().length()==0) {
                    JOptionPane.showMessageDialog(null, "发送消息不能为空!");
                }
                else{
                    try {
                        client.SendMessage(userText.getText());
                        userText.setText("");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        });

    }


    /*
     *生成注册本次匿名聊天昵称界面
     * @param frame框架
     * @panel 面板
     * @jl1 显示kerberos数据框
     * @jl2 显示数据交流数据框
     */
    public void inputFunname(JFrame frame, JPanel panel, JTextArea textarea1, JTextArea textarea2, JLabel OnlineLabel, JList<String> list, BackgroundClient client) throws IOException {
        client.update(textarea1,textarea2);
        client.StartThread();
        try {
            client.AquireList(list);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        /*
         * 创建文本域用于用户输入
         */
        JLabel jl0 = new JLabel("输入本次聊天昵称\n");
        JTextField userText = new JTextField(20);
        userText.setBounds(260,90,180,25);
        jl0.setBounds(260, 50, 500, 40);
        panel.add(userText);
        panel.add(jl0);

        // 创建确认按钮
        JButton confirmButton = new JButton("确认");
        confirmButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                // TODO Auto-generated method stub
                try {
                    if(userText.getText().equals("")){
                        JOptionPane.showMessageDialog(null, "不能为空!");
                    }
                    else if(client.RequestAnonymous(userText.getText())==true)
                    {
                        JOptionPane.showMessageDialog(null, "OK!");
                        String name=userText.getText();
                        frame.setTitle(name);
                        jl0.setVisible(false);
                        userText.setVisible(false);
                        confirmButton.setVisible(false);
                        JTextArea communicateText = new JTextArea();
                        communicateText.setVisible(false);
                        Anonymousroom(panel,communicateText,textarea1,textarea2,OnlineLabel,list,name,client);
                    }
                    else{
                        JOptionPane.showMessageDialog(null, "昵称重复!");
                        userText.setText("");
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

            }
        });
        confirmButton.setBounds(310, 150, 80, 25);
        panel.add(confirmButton);
    }

    /*
     *生成认证注册身份界面
     */
    private void placeComponents(JFrame frame,JPanel panel) {
        /*
         * 这边设置布局为 null
         */
        panel.setLayout(null);
        // 绝对布局
        // 定义一个容器
        // 文本域
        JLabel OnlineLabel = new JLabel("当前在线群友");
        OnlineLabel.setBounds(550,215,80,25);
        panel.add(OnlineLabel);

        //显示在线人员
        JList<String> list = new JList<String>();
        list.setBounds(550, 245, 120, 300);
        panel.add(list);

        JLabel jl01 = new JLabel("账号(4位数字)：");
        final JTextField jtf01 = new JTextField();
        JLabel jl02 = new JLabel("密码(6-12字符串):");
        final JPasswordField jpf01 = new JPasswordField();
        // 设置密码字符为*
        jpf01.setEchoChar('*');
        // 创建"认证"按钮
        JButton jb01 = new JButton("认证");
        // 创建"重置"按钮
        JButton jb02 = new JButton("重置");
        // 创建"注册"按钮
        JButton jb03 = new JButton("注册");
        //kerberos数据
        JLabel jl1 = new JLabel("Kerberos认证过程:\n");

        JTextArea textarea1=new JTextArea(" ");
        textarea1.setEditable(false);
        //数据交流部分
        JLabel jl2 = new JLabel("数据交流部分:");

        JTextArea textarea2=new JTextArea(" ");
        textarea2.setEditable(false);
        //添加监听

        BackgroundClient client=new BackgroundClient();
        client.kerberostextarea = textarea1;
        client.datatextarea = textarea2;
        client.userId = jtf01;
        client.userPass =jpf01;
        try {
            client.init();
        } catch (IOException e1) {
            e1.printStackTrace();
        }

        jb01.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // TODO Auto-generated method stub
                if (jtf01.getText().trim().length()==4 &&
                        isInteger(jtf01.getText().trim())&&
                        new String(jpf01.getPassword()).trim().length()>=6&&
                        new String(jpf01.getPassword()).trim().length()<12) {

                    boolean verify_result = false;
                    try {
                        verify_result = client.Verify();
                    } catch (Exception e3) {
                        e3.printStackTrace();
                    }
                    if(verify_result){
                        //认证成功
                    }else {
                        //认证失败
                        log.error("Kerberos 认证失败, 无法提供聊天室服务!!!!!!");
                        JOptionPane.showMessageDialog(null, "认证失败！");
                        return;
                    }
                    JOptionPane.showMessageDialog(null, "认证成功！");
                    frame.setTitle("输入匿名昵称");
                    jl01.setVisible(false);
                    jl02.setVisible(false);
                    jb01.setVisible(false);
                    jb02.setVisible(false);
                    jb03.setVisible(false);
                    jtf01.setVisible(false);
                    jpf01.setVisible(false);
                    try {
                        inputFunname(frame,panel,textarea1,textarea2,OnlineLabel,list,client);
                    } catch (Exception e1) {
                        e1.printStackTrace();
                    }

                } else if (jtf01.getText().trim().length() == 0){
                    JOptionPane.showMessageDialog(null, "用户ID不能为空!");
                }
                else if (new String(jpf01.getPassword()).trim().length() == 0){
                    JOptionPane.showMessageDialog(null, "用户口令不能为空!");
                } else {
                    JOptionPane.showMessageDialog(null, "格式错误");
                    // 清零
                    jtf01.setText("");
                    jpf01.setText("");
                }
            }
        });
        // 实现"重置"按钮功能
        jb02.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                // TODO Auto-generated method stub
                jtf01.setText("");
                jpf01.setText("");
            }
        });
        jb03.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                BackgroundClient client=new BackgroundClient();
                client.userId = jtf01;
                client.userPass =jpf01;
                String result = client.Register();
                JOptionPane.showMessageDialog(null, result);
            }
        });
        // 将各组件添加到容器中
        panel.add(jl01);
        panel.add(jtf01);
        panel.add(jl02);
        panel.add(jpf01);
        panel.add(jb01);
        panel.add(jb02);
        panel.add(jb03);
        // 设置各组件的位置以及大小

        int jb_begin = 210;
        int jb_distanse = 110;
        int height = 30;
        jl01.setBounds(150, 50, 100, height);//账号label
        jtf01.setBounds(250, 50, 210, height);//账号框
        jl02.setBounds(150, 100, 100, height);//密码label
        jpf01.setBounds(250, 100, 210, height);//密码框
        jb01.setBounds(jb_begin, 180, 70, height);//认证按钮
        jb02.setBounds(jb_begin + jb_distanse, 180, 70, height);//重置按钮
        jb03.setBounds(jb_begin + 2*jb_distanse, 180, 70, height);//注册按钮
        jb01.setBackground(Color.orange);
        jb02.setBackground(Color.orange);
        jb03.setBackground(Color.orange);

        //创建显示文字的区域
        JScrollPane jsp1 = new JScrollPane(textarea1);
        //设置矩形大小.参数依次为(矩形左上角横坐标x,矩形左上角纵坐标y，矩形长度，矩形宽度)
        jl1.setBounds(10, 215, 250, 30);//label位置
        jsp1.setBounds(10, 245, 250, 300);//滚动条
        //默认的设置是超过文本框才会显示滚动条，以下设置让滚动条一直显示
        jsp1.setVerticalScrollBarPolicy( JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        //把滚动条添加到容器里面
        panel.add(jsp1);
        panel.add(jl1);
        panel.setBackground(Color.PINK);
        //创建显示文字的区域
        JScrollPane jsp2 = new JScrollPane(textarea2);
        //设置矩形大小.参数依次为(矩形左上角横坐标x,矩形左上角纵坐标y，矩形长度，矩形宽度)
        jl2.setBounds(280, 215, 250, 30);
        jsp2.setBounds(280, 245, 250, 300);
        //默认的设置是超过文本框才会显示滚动条，以下设置让滚动条一直显示
        jsp2.setVerticalScrollBarPolicy( JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        //把滚动条添加到容器里面
        panel.add(jsp2);
        panel.add(jl2);

    }

    public static void main(String[]argc)
    {
        AntChatUi mainui=new AntChatUi();
        mainui.chatroom();
    }
}
