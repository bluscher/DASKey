/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DasKey;

import java.io.File;
import java.io.IOException;
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

public class Carpeta {
    private static final Logger log = Logger.getLogger(Carpeta.class.getName());
    //static final String pwd_keystore = "Miclave.1";
    private String rutaDAS;
    private Path path;
    private static final String NOMAPP = File.separator +"DASKey";
    private static final String PATHSYSTEM = System.getProperty("user.dir");
  
    public Carpeta(Path ruta){
        this.path = ruta;
        if(!ruta.toFile().isDirectory()) {
            System.out.println("No existe la carpeta");
            System.exit(1);
        }
        else
           {
            this.rutaDAS = ruta.toString();
            // System.out.println(rutaDAS);
           }
    }
    
    public Carpeta(){
        rutaDAS = PATHSYSTEM.replaceAll(NOMAPP,"");
    }
    
    //Verifica si en la carpeta Input tiene un certificado y lo obtiene el primero.
    public File getCertFile(){
        File carpeta = new File(PATHSYSTEM + File.separator +"input"+File.separator);
        File[] listaf = carpeta.listFiles();
        
        if (carpeta.exists() && listaf.length <= 1) {
            File aux = listaf[0];
            log.info("Ruta archivo Certificado a agregar: "+aux.getPath());
            log.info("Nombre Certificado: " + aux.getName());
            return aux;
        }else
            log.info("No hay certificado en la carpeta.");
            return null;       
    }
    
    public void listarArchivos(){    
        String[] lista = path.toFile().list();
        for(int i=0; i<lista.length; i++){
            System.out.println(lista[i]);
        }
    }
    
    public String getNombreFile(){
        String[] lista = path.toFile().list();
        return lista[0];
    }
    
    public Path getPath(){
        return this.path;
    }
    
    public String getServiceConfig(String nom){
        //rutaProyecto = "c://test/DAS"; // ####para pruebas local###
        File f = new File(rutaDAS);
        log.debug("#######ruta DAS: "+rutaDAS);
        String[] listarArchivos = f.list(new FiltroContenido(nom));
        if (listarArchivos.length == 0) {
            log.info("No se encontro el Archivo de configuracion");
            return "";
        }else
        return rutaDAS + "/"+ listarArchivos[0] + File.separator + "conf" + File.separator + "com.eda.crypto.cfg";
    }
    
    
    /*#viejo#*/
    public void convertirCertificado() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException{
        //Certificado ca = new Certificado(pwd_keystore, p.toString()+this.getNombreFile());  
        File f = this.path.toFile();
        String[] listaArchivos = f.list(new FiltroExtension(".jks"));
        System.out.println("Archivo: "+listaArchivos[0]);
        System.out.println("Ingresar la clave del certificado seguido de la tecla -ENTER-");
        Scanner teclado = new Scanner(System.in);
        String pwd_keystore = teclado.nextLine();
        String nameExt = listaArchivos[0];
        //quitar todos los caracteres incluido el punto y lo que sigue
        String nameCorto = nameExt.split("\\.",2)[0];
        Certificado ca = new Certificado(pwd_keystore,f.getAbsolutePath()+"/"+listaArchivos[0]);
        ca.toPKCS12(nameCorto); 
        log.info(" Conversion [Exitosa]");
        
    }
}
