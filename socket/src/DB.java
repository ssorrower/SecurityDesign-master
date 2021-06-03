package socket.src;

import java.sql.*;
import java.util.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;


public class DB { //创建 HandleSql 类
    static Connection con; //声明 Connection 对象
    static PreparedStatement pStmt;//声明预处理 PreparedStatement 对象
    static ResultSet res;//声明结果 ResultSet 对象
    static String url = "jdbc:mysql://localhost:3306/mydatabase_tb_user?serverTimezone=UTC";
    static String user = "root";
    static String password = "sk15972177210...";


    public Connection getConnection() {//建立返回值为 Connection 的方法
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            System.out.println("数据库驱动加载成功");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        try {
            con = DriverManager.getConnection(url,user,password);
            System.out.println("数据库连接成功");
            //con.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return con;
    }


    public String chazhao(String zh){

        try {
            Statement state = con.createStatement();
            String sql="select usercom from tb_user where userid='"+zh+"'";
            ResultSet re=state.executeQuery(sql);
            if(re.next()){
                //con.close();
                return re.getString(1);
            }
            else{
                //con.close();
                System.out.println("false");
                return null;
            }
        }catch (SQLException e) {
            e.printStackTrace();
            return null;
        }
    }


    public boolean tianjia(String zh,String mm){
        try {
            Statement state=con.createStatement();
            if(mm.length()>=6&&mm.length()<=12&&zh.length()==4)
            {
                String sql="insert into tb_user values('"+zh+"','"+mm+"')";   //SQL语句
                state.executeUpdate(sql);         //将sql语句上传至数据库执行
                //con.close();
                System.out.println("true");
                return true;
            }
            else{
                System.out.println("false");
                return false;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }


    /*public static void main(String[] args) {//主方法
        Main h = new Main();//创建本类对象
        con=h.getConnection();
        Scanner sc=new Scanner(System.in);
        boolean x,y;
        String zh1,zh2;
        String mm1,mm2;
        String a;
        String b="A";
        char[] ch = b.toCharArray();
        while(ch[0]=='A')
        {
            System.out.println("请选择你的操作：A:查找 B:添加");
            a=sc.next();
            switch(a)
            {
                case"A":
                    System.out.println("请输入用户名");
                    zh1=sc.next();
                    System.out.println("请输入密码 ");
                    mm1=sc.next();
                    x = h.chazhao(zh1,mm1);
                    break;
                case"B":
                    System.out.println("请输入用户名");
                    zh2=sc.next();
                    System.out.println("请输入密码 ");
                    mm2=sc.next();
                    y = h.tianjia(zh2,mm2);
                    break;
            }
            System.out.println("是否继续查找或添加：A:是 B:否");
            b=sc.next();
            ch = b.toCharArray();
        }
    }*/
}



