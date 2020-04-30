/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DasKey;

import java.io.File;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/**
 *
 * @author e10934a
 */


public class Principal {
    
    static final String KESTOREPATH = "javax.net.ssl.keyStore";
    static final String KEYSTOREPASS = "javax.net.ssl.keyStorePassword";
    static final String TRUSTSTOREPATH = "javax.net.ssl.trustStore";
    static final String TRUSTSTOREPASS = "javax.net.ssl.trustStorePassword";
    private static final org.apache.log4j.Logger log = org.apache.log4j.Logger.getLogger(Principal.class.getName());
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
     // arch_confJOB = new Archivo("C:/test/DAS/Job Server v1.15/conf/com.eda.crypto.cfg"); /*testlocal*/
      arch_confREPO = new Archivo(rutaConfigRepo);
     // arch_confREPO = new Archivo("C:/test/DAS/Repository Server v1.15/conf/com.eda.crypto.cfg"); /*testlocal*/
      
    //--------------------------------------------------------------//
    //   Recuperacion rutas y claves de los KeyStores, TrustStore   //
    //--------------------------------------------------------------//
    //#JOB
      Path ruta_keystoreJOB = null;
      ruta_keystoreJOB = arch_confJOB.getPath(arch_confJOB.getParam(KESTOREPATH));
      log.info("Path Keystore JOB: " + ruta_keystoreJOB.toString());
      
      String pwd_keystoreJOB = null;
      pwd_keystoreJOB = arch_confJOB.getParam(KEYSTOREPASS);
      log.info("Clave JOB: " +pwd_keystoreJOB);
      estaEncriptado(pwd_keystoreJOB);
      
    //#REPOSITORY  
      Path ruta_keystoreREPO = null;
      ruta_keystoreREPO = arch_confREPO.getPath(arch_confREPO.getParam(KESTOREPATH));
      log.info("Path Keystore REPO: " + ruta_keystoreREPO.toString());
        
      String pwd_keystoreREPO = null;
      pwd_keystoreREPO = arch_confREPO.getParam(KEYSTOREPASS);
      log.info("Clave REPO: " +pwd_keystoreREPO);
      estaEncriptado(pwd_keystoreREPO);
      
     //#TRUSTSTORE
      Path ruta_TrustStore = null;
      ruta_TrustStore = arch_confREPO.getPath(arch_confREPO.getParam(TRUSTSTOREPATH));
      log.info("Path TrustStore : " + ruta_TrustStore.toString());
        
      String pwd_TrustStore = null;
      pwd_TrustStore = arch_confREPO.getParam(TRUSTSTOREPASS);
      log.info("Clave REPO: " +pwd_TrustStore);
      estaEncriptado(pwd_TrustStore);
      
      //-----------------------------//  
      //      keystore con CA        //
      //-----------------------------// 
      
      //---Obtengo ruta de le certificado aportado por el cliente
      Carpeta input = new Carpeta();
      File ca = input.getCertFile();
        if (ca != null) {
            pathCA = ca.getAbsolutePath();
        }
        
      String pwdCA = "Miclave.1";
      StrongBox caStore = new StrongBox(pwdCA, pathCA.toString());
      //-----------------------------// 
        
      //---Abrir KeyStore
      //1) JOBSERVER
      log.info("#Modificando Job JKS...");
      StrongBox ksJOB = new StrongBox(pwd_keystoreJOB, ruta_keystoreJOB.toString());
      ksJOB.mostrarAliases();
      nomAliasJOB = ksJOB.getNomFirstAlias();
      //Certificate extCertJob = ksJOB.abrirX509(pathCA); #abrir certificado
      ksJOB.borrarCert(nomAliasJOB);
      ksJOB.setKey(caStore.getKey(caStore.getNomFirstAlias(), pwdCA), nomAliasJOB, pwd_keystoreJOB);
      //ksJOB.setKeystore(nomAliasJOB, (X509Certificate) extCertJob); #borrar
      
      //2) REPOSITORYSERVER
      log.info("#Modificando Repo JKS...");
      StrongBox ksREPO = new StrongBox(pwd_keystoreREPO, ruta_keystoreREPO.toString());
      ksREPO.mostrarAliases();
      nomAliasREPO = ksREPO.getNomFirstAlias();
      //Certificate extCertRepo = ksREPO.abrirX509(pathCA); #abrir certificado
      ksREPO.borrarCert(nomAliasREPO);
      ksREPO.setKey(caStore.getKey(caStore.getNomFirstAlias(), pwdCA), nomAliasREPO, pwd_keystoreREPO);
      //ksREPO.setKeystore(nomAliasREPO, (X509Certificate) extCertRepo);#borrar
    
   
      //---TrustStore
      log.info("#Modificando TrustStore...");
      StrongBox truststore = new StrongBox(pwd_TrustStore, ruta_TrustStore.toString());
      truststore.mostrarAliases();
        if (truststore.existeAlias(nomAliasJOB)) {
            truststore.borrarAlias(nomAliasJOB); 
        }  
        if (truststore.existeAlias(nomAliasREPO)) {
            truststore.borrarAlias(nomAliasREPO);
        }
 
      //Certificate cerTrusted = caStore.getTurstStoreCert(caStore.getNomFirstAlias(), pwdCA);
      truststore.setKeystore(nomAliasREPO, (X509Certificate) caStore.getTurstStoreCert(caStore.getNomFirstAlias(), pwdCA));    
      log.info("Importe TrustStore [OK]");
      log.info(truststore.getNomFirstAlias());
      
      pressAnyKeyToContinue();
      
       
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
    
    static public void estaEncriptado(String clave){
        if (clave.contains("ENC(")) {
            log.info("La clave: " + clave + " esta encriptada, no se puede seguir con el proceso");
            System.exit(0);
        }
    }
    
  
}