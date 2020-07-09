
	
	import org.apache.commons.codec.binary.Hex;

	import javax.crypto.Cipher;
	import java.io.ByteArrayOutputStream;
	import java.io.DataOutputStream;
	import java.io.FileInputStream;
	import java.security.KeyStore;
	import java.security.PrivateKey;
	import java.security.PublicKey;
	import java.security.Signature;
	import java.security.cert.Certificate;
	import java.security.cert.X509Certificate;
	import java.security.interfaces.RSAPrivateKey;
	import java.security.interfaces.RSAPublicKey;
import java.util.Scanner;
		
public class zs {
	
		private static boolean result1;
		private static String result2;
	    //֤������
	    private static final String PASSWORD = "87654321";
	    private static final String PASSWORD1 = "87654321";
	    //֤�����
	    private static final String ALIAS = "hty";
	    private static final String ALIAS1 = "hty";
	    private static String message2;
	    public static void main(String[] args) throws Exception {
	    	
	    	Scanner input1 = new Scanner(System.in);
	    	System.out.println("��������Ҫ���ܵ�����");
	    	message2 = input1.nextLine();    //��Ҫ���ܵ���Ϣ����
	        KeyStore keyStore = KeyStore.getInstance("jks");       
	        KeyStore keyStore1 = KeyStore.getInstance("jks");
	        
	        keyStore.load(new FileInputStream(".\\keystore_test.jks"), PASSWORD.toCharArray());
	        keyStore1.load(new FileInputStream(".\\keystore_test.jks"), PASSWORD1.toCharArray());
	        
	        Certificate x509Certificate = keyStore.getCertificate(ALIAS);
	        Certificate x509Certificate1 = keyStore1.getCertificate(ALIAS1);
	        sign(keyStore , keyStore1);
	         			
	        	encrypt2(x509Certificate.getPublicKey(), (PrivateKey) keyStore.getKey(ALIAS, PASSWORD.toCharArray()));
	       // 	encrypt2(x509Certificate1.getPublicKey(), (PrivateKey) keyStore1.getKey(ALIAS1, PASSWORD1.toCharArray()));

	        System.out.println("==============================================================================");
	        System.out.println("");System.out.println("");System.out.println("");
	        if(result1 == true)
	        	System.out.println("���ܺ���" +result2);
	        else {
	        	System.out.println("�������");
	        	String continue2 = input1.nextLine();
	        }
	        System.out.println("");System.out.println("");System.out.println("");
	        System.out.println("==============================================================================");
	        System.out.println("�밴���������..........");
	        String continue1 = input1.nextLine();
	        
	    }

	    /**
	     * ǩ������֤ǩ��
	     *
	     * @throws Exception
	     */
	    public static void sign(KeyStore keyStore,KeyStore keyStore1) throws Exception {
	    	
	        X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(ALIAS);
	        X509Certificate x509Certificate1 = (X509Certificate) keyStore1.getCertificate(ALIAS1);
	        //��Ҫǩ������Ϣ������
	        String message = "����ʦ����ѧ��Ϣ��ѧ�빤��ѧԺ";
	        //��ȡCA֤��˽Կ
	        PrivateKey priKey = (PrivateKey) keyStore.getKey(ALIAS, PASSWORD.toCharArray());
	//        System.out.println("˽Կ:" + Hex.encodeHexString(priKey.getEncoded()));

	        //��˽Կǩ��
	        Signature signature = Signature.getInstance("SHA256withRSA");
	        signature.initSign(priKey);
	        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
	        DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
	        dataOutputStream.writeUTF(message);
	        signature.update(byteArrayOutputStream.toByteArray());
	        String result = Hex.encodeHexString(signature.sign());
	        System.out.println("ǩ��֮�������:" + result);
 

	        //�ù�Կ����֤ǩ��
	        Signature signature1 = Signature.getInstance("SHA256withRSA");
	        signature1.initVerify(x509Certificate1.getPublicKey());
//	        System.out.println("��Կ:" + Hex.encodeHexString(x509Certificate1.getPublicKey().getEncoded()));
	        ByteArrayOutputStream byteArrayOutputStream1 = new ByteArrayOutputStream();
	        DataOutputStream dataOutputStream1 = new DataOutputStream(byteArrayOutputStream1);
	        dataOutputStream1.writeUTF(message);
	        signature1.update(byteArrayOutputStream1.toByteArray());
	        result1 = signature1.verify(Hex.decodeHex(result.toCharArray()));
	        System.out.println("��֤���:   " + result1);
	      
	     
	    }

	    /**
	     * ���ܺͽ���
	     *
	     * @param publicKey
	     * @param privateKey
	     * @throws Exception
	     */
	    public static void encrypt(PublicKey publicKey, PrivateKey privateKey) throws Exception {

	        String input = message2;
	        Cipher cipher = Cipher.getInstance("RSA");
	        RSAPublicKey pubKey = (RSAPublicKey) publicKey;
	        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
	        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
	        byte[] cipherText = cipher.doFinal(input.getBytes());
	
	        System.out.println("����֮�������:" + Hex.encodeHexString(cipherText));
	    
	}
	    public static void encrypt2(PublicKey publicKey, PrivateKey privateKey) throws Exception {
	    	
	        String input = message2;
	        Cipher cipher = Cipher.getInstance("RSA");
	        RSAPublicKey pubKey = (RSAPublicKey) publicKey;
	        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
	        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
	        byte[] cipherText = cipher.doFinal(input.getBytes());
	        
	        
	        //����
	       
	        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
	        byte [] plainText = cipher.doFinal(cipherText);
	        result2 = new String(plainText);
	  
      
	}
	    
}
	