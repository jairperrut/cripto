package senai.sc.seg;

/**
 * Classe de trabalho que implementa os métodos criptográficos necessários para
 * o funcionamento do processo de criptografia entre um Cliente e o Servidor.
 * Esta classe atende somente ao servidor de comunicação. * 
 * 
 */
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

    /**
     KeyStore de criptografia gerado com prazo de vida de 10 anos.
     Utilizado apenas para armazenar as chaves Pública e Privada,
     necessárias ao processo de criptografia. Utiliza algorítmo RSA.
     Comando para geração do certificado:
     keytool -genkey -alias autentica -keyalg RSA -keypass seg2012 -storepass seg2012 -keystore env_digital.jks -validity 3650
    */

public class Cripto_Server {
       public static File certFile = new File("c:/CTAI/Tecnica_Seguranca_Redes/Ferramentas_e_Programas/assdigital_v3/certificados.jks");
       private static final String alias = "cert_1"; 
       private static final String pwd = "senha";
       private PrivateKey privKey = null;
       private PublicKey pubKey = null;
       public Cripto_Server(){
     }
    
	/**
     Método que decripta dados, encriptados pela chave Pública
     contida no Keystore.
     Após decriptado, retorna um array de bytes dos dados.
    * @param dados, chavePriv
    * @return 
    */

     public static byte[] decripta (byte[] dados, PrivateKey chavePriv){
        try {
        Cipher cifra = Cipher.getInstance("RSA");
        cifra.init(Cipher.DECRYPT_MODE, chavePriv);
        System.out.println("Crypto_Server: Tam bytes decriptados: " + dados.length);
        return cifra.doFinal(dados);
        }
        catch ( Exception e ) {
		System.out.println("Classe Crypto_Server - Erro na decriptação..." + e.getMessage());
                return null; //"Erro decriptação!".getBytes();
        }
       }
     
    
        /**
         Método para ler a chave Privada do Keystore
         Retorna um objeto chave Privada PrivateKey
        * @return
        * @throws Exception 
        */
        public static PrivateKey getPrivateKeyFromFile() throws Exception {
        KeyStore ks = KeyStore.getInstance ( "JKS" );
        InputStream is = new FileInputStream( certFile );
        ks.load( is, pwd.toCharArray());
        is.close();
        Key key = ks.getKey( alias, pwd.toCharArray() );
        if( key instanceof PrivateKey ) {
            return (PrivateKey) key;
        }
        return null;
    }
        /**
         Método para ler a chave Pública do Keystore
         Retorna um objeto chave Pública PublicKey
        * @return
        * @throws Exception 
        */
    
    public static PublicKey getPublicKeyFromFile() throws Exception {
        KeyStore ks = KeyStore.getInstance ( "JKS" );
        InputStream is = new FileInputStream( certFile );
        ks.load( is, pwd.toCharArray() );
        Certificate c = ks.getCertificate( alias );
        PublicKey p = c.getPublicKey();
        System.out.println("Chave Pública: " + p.toString());
        return p;
	}
    
    public void gerarChaveRSA(){
    	try{
	    	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    	keyGen.initialize(2048);
	    	KeyPair pair = KeyGen.genKeyPair();
	    	privKey = pair.getPrivate();
	    	pubKey = pair.getPublic();
	    	
    	}catch (NoSuchAlgorithmException e){
    		
    	}
    	
    	
    }
    
    /**
     * Método para encriptar dados com a chave Simétrica.
     * @param textoP
     * @param chaveS
     * @return bytes encriptados
     */
    public static byte[] encriptaSim(byte[] textoP, byte[] chaveS){
         try {
             Cipher cifra = Cipher.getInstance("AES/CBC/PKCS5Padding");
             IvParameterSpec ivspec = new IvParameterSpec (new byte[16]);
             cifra.init(Cipher.ENCRYPT_MODE, new SecretKeySpec (chaveS,"AES"),ivspec);
             return cifra.doFinal(textoP);
         } 
         catch (Exception ex){
           System.out.println("Erro de encriptação simétrica, Verifique! " + ex.getMessage());
              return null;
         }
     }
    /**
     * Método para decriptar dados com uma chave Simétrica.
     * @param textoC
     * @param chaveSeg
     * @return bytes decriptados.
     */
    public static byte[] decriptaSim(byte[] textoC, byte[] chaveSeg){
         try {
             Cipher cifra = Cipher.getInstance("AES/CBC/PKCS5Padding");
             IvParameterSpec ivspec = new IvParameterSpec (new byte[16]);             
             cifra.init(Cipher.DECRYPT_MODE, new SecretKeySpec (chaveSeg,"AES"),ivspec);
             return cifra.doFinal(textoC);             
         } 
         catch (Exception ex){
           System.out.println("Erro na decriptação simétrica, Verifique! " + ex.getMessage());
              return null;
         }
     }

	public PrivateKey getPrivKeyRSA() {
		return privKey;
	}

	public PublicKey getPubKeyRSA() {
		return pubKey;
	}
    
}