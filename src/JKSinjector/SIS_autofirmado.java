/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JKSinjector;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Scanner;

import org.apache.log4j.Logger;

/**
 *
 * @author e10934a
 */


public class SIS_autofirmado {
    
   //ubicacion "sensible data" en system.properties
    private static final String KEYSTOREPATH = "jetty.keyStore.file";
    private static final String KEYSTOREPASS = "jetty.keyStore.password";
    //ubicacion archivo de configuracion -> despues debe ir el classpath donde va ir el jar
    private static final String PATHSYSTEMPROP = "C:/test/system.properties";
    
    private static final Logger log = Logger.getLogger(SIS_autofirmado.class.getName());

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args){
        String rutaK ="";
        FileSystem sistemaFicheros = FileSystems.getDefault();
        
        try {
            
            //---Manipulacion archivo config del SIS
            Archivo arch_conf = new Archivo(PATHSYSTEMPROP);
            try {
                /*EJECUCION SOFT DEPLOYADO
                Path rootApp = sistemaFicheros.getPath("./");
                Path ruta_keystore = arch_conf.getPath(arch_conf.getParamExt(KEYSTOREPATH));
                rutaK =rootApp.toString() + ruta_keystore.toString();
                log.info("ruta JKS: "+rutaK);
                */
                
                //test local
                Path ruta_keystore = arch_conf.getPath(arch_conf.getParam(KEYSTOREPATH));
                rutaK = ruta_keystore.toString();
                log.info("ruta JKS: "+rutaK);
            } catch (IOException ex) {
                log.error("error IO", ex);
            }
            String pwd_keystore = arch_conf.getParam(KEYSTOREPASS);
            //log.debug(rutaK);
            //log.debug(pwd_keystore);
            
            
            Certificado cert = new Certificado(pwd_keystore,rutaK); 
            cert.borrarAlias(cert.getAlias());
            cert.setKeystore("lalala",cert.getCertAutofirmados("CN= EXPERIAN_Java,O=Experian,OU=Experian,L=CABA,ST=CABA,C=AR"));
            
            
            pressAnyKeyToContinue();
            
           
            
        }//end main
 catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            log.error("error Keystore", ex);
        }
}
   
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