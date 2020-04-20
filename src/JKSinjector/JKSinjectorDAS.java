/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JKSinjector;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;



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
      String pathCA = "";
      Archivo arch_confJOB = null;
      Archivo arch_confREPO = null;
      
      //---Manipulacion archivos config del DAS
      Carpeta root = new Carpeta();
      String rutaConfigJob = root.getServiceConfig("Job Server");
      log.info("Path configuracion JOB Service: " + rutaConfigJob);
      String rutaConfigRepo = root.getServiceConfig("Repository Server");
      log.info("Path configuracion REPO Service: " + rutaConfigRepo);
   
      arch_confJOB = new Archivo(rutaConfigJob);       
      //Archivo arch_confJOB = new Archivo("C:/test/DAS/Job Server v1.15/conf/com.eda.crypto.cfg"); testlocal
      arch_confREPO = new Archivo(rutaConfigRepo);
      //Archivo arch_confREPO = new Archivo("C:/test/DAS/Repository Server v1.15/conf/com.eda.crypto.cfg");
      
    //---Recuperacion rutas y claves de los KeyStores, TrustStore 
      Path ruta_keystoreJOB = null;
      ruta_keystoreJOB = arch_confJOB.getPath(arch_confJOB.getParam(KESTOREPATH));
      log.info("Path Keystore JOB: " + ruta_keystoreJOB.toString());
      
      String pwd_keystoreJOB = null;
      pwd_keystoreJOB = arch_confJOB.getParam(KEYSTOREPASS);
      log.info("Clave JOB: " +pwd_keystoreJOB);
      
      Path ruta_keystoreREPO = null;
      ruta_keystoreREPO = arch_confREPO.getPath(arch_confREPO.getParam(KESTOREPATH));
      log.info("Path Keystore REPO: " + ruta_keystoreREPO.toString());
        
      String pwd_keystoreREPO = null;
      pwd_keystoreREPO = arch_confREPO.getParam(KEYSTOREPASS);
      log.info("Clave REPO: " +pwd_keystoreREPO);
        
      Path ruta_TrustStore = null;
      ruta_TrustStore = arch_confREPO.getPath(arch_confREPO.getParam(TRUSTSTOREPATH));
      log.info("Path TrustStore : " + ruta_TrustStore.toString());
        
      String pwd_TrustStore = null;
      pwd_TrustStore = arch_confREPO.getParam(TRUSTSTOREPASS);
      log.info("Clave REPO: " +pwd_TrustStore);
      
      //---Obtengo ruta de le certificado aportado por el cliente
      Carpeta input = new Carpeta();
      File ca = input.getCertFile();
        if (ca != null) {
            pathCA = ca.getAbsolutePath();
        }
      
      //---Abrir KeyStore
      //1) JOBSERVER
      Certificado certJOB = new Certificado(pwd_keystoreJOB, ruta_keystoreJOB.toString());
      certJOB.mostrarAliases();
      nomAliasJOB = certJOB.getNom1Alias();
      Certificate certJ = certJOB.abrirX509(pathCA);
      //log.info("certificado: "+certJ.toString()); muestra la signature del certificado
      certJOB.borrarCert(nomAliasJOB);
      certJOB.setKeystore(nomAliasJOB, (X509Certificate) certJ);
      //2) REPOSITORYSERVER
      Certificado certREPO = new Certificado(pwd_keystoreREPO, ruta_keystoreREPO.toString());
      certREPO.mostrarAliases();
      nomAliasREPO = certREPO.getNom1Alias();
      Certificate certR = certREPO.abrirX509(pathCA);      
      //log.info("certificado: "+certR.toString()); muestra la signature del certificado
      certREPO.borrarCert(nomAliasREPO);
      certREPO.setKeystore(nomAliasREPO, (X509Certificate) certR);
    
      //certJOB.getDatosCertificado(nomAliasJOB);
      //Certificado test = new Certificado(); //creo keystore nuevo con certificado autofirmado
      
   
   
      //---TrustStore
      Certificado truststore = new Certificado(pwd_TrustStore, ruta_TrustStore.toString());
      truststore.mostrarAliases();
        if (truststore.existeAlias(nomAliasJOB)) {
          try {
              truststore.borrarAlias(nomAliasJOB);
          } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
              log.error("Error con el KeyStore", ex);
          }
            truststore.setKeystore(nomAliasJOB, (X509Certificate)certJ);
        }
        if (truststore.existeAlias(nomAliasREPO)) {
          try {
              truststore.borrarAlias(nomAliasREPO);
          } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
              log.error("Error con el KeyStore", ex);
          }
            truststore.setKeystore(nomAliasREPO, (X509Certificate)certJ);
        }
      
      
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