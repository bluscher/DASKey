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
    private String rutaProyecto;
    private Path p;

  
    public Carpeta(Path ruta){
        this.p = ruta;
        if(!ruta.toFile().isDirectory()) {
            System.out.println("No existe la carpeta");
            System.exit(1);
        }
        else
           {
            this.rutaProyecto = ruta.toString();
            // System.out.println(rutaProyecto);
           }
    }
    
    public void listarArchivos(){    
        String[] lista = p.toFile().list();
        for(int i=0; i<lista.length; i++){
            System.out.println(lista[i]);
        }
    }
    
    public String getNombreFile(){
        String[] lista = p.toFile().list();
        return lista[0];
    }
    
    public Path getPath(){
        return this.p;
    }
    
    public void convertirCertificado() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException{
        //Certificado ca = new Certificado(pwd_keystore, p.toString()+this.getNombreFile());  
        File f = this.p.toFile();
        String[] listaArchivos = f.list(new Filtro(".jks"));
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
