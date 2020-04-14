/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JKSinjector;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Scanner;

/**
 *
 * @author e10934a
 */


public class JKSinjectorDAS {
    
    static final String KESTOREPATH = "javax.net.ssl.keyStore";
    static final String KEYSTOREPASS = "javax.net.ssl.keyStorePassword";
    static final String TRUSTSTOREPATH = "javax.net.ssl.trustStore";
    static final String TRUSTSTOREPASS = "javax.net.ssl.trustStorePassword";
    
    private static final org.apache.log4j.Logger log = org.apache.log4j.Logger.getLogger(JKSinjectorDAS.class.getName());
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args){
      String nomAliasJOB = "";
      String nomAliasREPO = "";
      //---Manipulacion archivos config del DAS
      Archivo arch_confJOB = new Archivo("C:/test/DAS/Job Server v1.15/conf/com.eda.crypto.cfg");
      Archivo arch_confREPO = new Archivo("C:/test/DAS/Repository Server v1.15/conf/com.eda.crypto.cfg");
 
      
    Path ruta_keystoreJOB = null;
        try {
            ruta_keystoreJOB = arch_confJOB.getPath(arch_confJOB.getParam(KESTOREPATH));
            log.info("Path Keystore JOB: " + ruta_keystoreJOB.toString());
        } catch (IOException ex) {
            log.error("Error IO",ex);
        }
    String pwd_keystoreJOB = null;
        try {
            pwd_keystoreJOB = arch_confJOB.getParam(KEYSTOREPASS);
            log.info("Clave JOB: " +pwd_keystoreJOB);
        } catch (IOException ex) {
            log.error("Error IO", ex);
        }
      
    Path ruta_keystoreREPO = null;
        try {
            ruta_keystoreREPO = arch_confREPO.getPath(arch_confREPO.getParam(KESTOREPATH));
            log.info("Path Keystore REPO: " + ruta_keystoreREPO.toString());
        } catch (IOException ex) {
            log.error("Error IO",ex);
        }
        
      String pwd_keystoreREPO = null;
        try {
            pwd_keystoreREPO = arch_confREPO.getParam(KEYSTOREPASS);
            log.info("Clave REPO: " +pwd_keystoreREPO);
        } catch (IOException ex) {
            log.error("Error IO", ex);
        }
        
      Path ruta_TrustStore = null;
        try {
            ruta_TrustStore = arch_confREPO.getPath(arch_confREPO.getParam(TRUSTSTOREPATH));
            log.info("Path TrustStore : " + ruta_TrustStore.toString());
        } catch (IOException ex) {
            log.error("Error IO",ex);
        }
        
      String pwd_TrustStore = null;
        try {
            pwd_TrustStore = arch_confREPO.getParam(TRUSTSTOREPASS);
            log.info("Clave REPO: " +pwd_TrustStore);
        } catch (IOException ex) {
            log.error("Error IO", ex);
        }
      /* Abrir keystore*/
      Certificado certJOB = new Certificado(pwd_keystoreJOB, ruta_keystoreJOB.toString());
      certJOB.mostrarAlias();
      nomAliasJOB = certJOB.getNom1Alias();
      System.out.println(nomAliasJOB);
      
      /*
      Certificado certREPO = new Certificado(pwd_keystoreREPO, ruta_keystoreREPO.toString());
      nomAliasREPO = certREPO.getNom1Alias();
      System.out.println(nomAliasJOB);
      //certREPO.mostrarAlias();
      //TrustStore
      Certificado truststore = new Certificado(pwd_TrustStore, ruta_TrustStore.toString());
     // truststore.mostrarAlias();
     */
      
      
      /*
      //---Utilizacion del certificado desde la carpeta de proyecto
      FileSystem sistemaFicheros = FileSystems.getDefault();
      //System.out.println(sistemaFicheros.toString());
      //configuracion para terminal de windwos
      //Path rutaFichero = sistemaFicheros.getPath("./Certificado");
      
      //#prueba interna en carpeta de proyecto
      Path rutaFichero = sistemaFicheros.getPath("./src/Certificado");
      
      //Carpeta c = new Carpeta(rutaFichero);
      //c.listarArchivos();
      //c.convertirCertificado();
      */
      
      
      //pressAnyKeyToContinue();
      
       
}//end main
   
    //metodo para pausar ventana esperando interaccion con usuario
    static public void pressAnyKeyToContinue()
      { 
          String seguir;
          Scanner teclado = new Scanner(System.in);
          System.out.println("Pulsar una tecla para continuar...");
          try
            {
             seguir = teclado.nextLine();
            }   
         catch(Exception e)
          {}  
     }  
}