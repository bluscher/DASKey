/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DasKey;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.logging.Level;
import org.apache.log4j.Logger;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/*import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;*/


/**
 *
 * @author e10934a
 */
public final class StrongBox {
  
     //Medida de las claves
    public static final int KEY_LEN = 2048;
    //Fecha de expiración
    private static final int EXPIRATION = 365;
    //Algoritmo de firma a usar
    private static final String ALGORITHM = "SHA1withRSA";
    private static final String OUTPUT_PATH = System.getProperty("user.dir") + File.separator + "output"+ File.separator + "certificado.crt";
    
    private static final Logger log = Logger.getLogger(StrongBox.class.getName());
    
    private String password;
    private String archivo;
    private KeyStore ks;
    private InputStream ksData;
    private char[] ksPass;
    private File Keystorefile; 
    
    
    public StrongBox(String pwd, String arch){
    //constructor
        password = pwd;
        archivo = arch;
        //  Keystorefile = new File(arch); borrar
        cargarKeystore();
    }
     public StrongBox(String pwd, File f){
    //constructor
        password = pwd;
        archivo = "";
        Keystorefile = f;
        cargarKeystore(pwd,f);
    }
    public KeyStore getKeystore(){
        return this.ks;
    }
    
    public StrongBox(){
      cargarKeystoreNEW();
    }
            
    public void mostrarAliases(){
     System.out.println("#Listar Alias " + this.archivo + ": [BEGIN]");
     Enumeration aliases = null ;
        try {
            aliases = ks.aliases();
        } catch (KeyStoreException ex) {
            log.error("Error conn el Keystore: ",ex);
        }
      while (aliases.hasMoreElements()){
         System.out.println(aliases.nextElement());
     }
     System.out.println("#Listar Alias: [END]");
    } 
    
    public String getNomFirstAlias(){
        String result = "Ningun Alias";
        Enumeration aliases = null;
        try {
          log.info("El numero de alias es : " + ks.size());
          aliases = ks.aliases();
        } catch (KeyStoreException ex) {
            log.error("No existe ningun Alias",ex);
        }
            if (aliases.hasMoreElements()){
            result = (String)aliases.nextElement();
            log.info("Nombre alias: " +result);
            }
            return result;
   
    }
    
    public int cantAlias(){
        try {
            return this.ks.size();
        } catch (KeyStoreException ex) {
            log.error("Error con cargar el Keystore", ex);
        }
        return 0;
    }
    
    public void borrarAlias(String aliasToDell){
        try {
            if(ks.containsAlias(aliasToDell)){
                try (FileOutputStream resul = new FileOutputStream(this.archivo)) {
                    ks.deleteEntry(aliasToDell);
                    ks.store(resul, ksPass);
                }
                log.info("[Borrado exitoso] "+aliasToDell);
            }else
                log.info("No hubo Borrado:" + aliasToDell);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
           log.error(ex);
        }
    } 
    
    public KeyStore cargarKeystore(String pwd, File pathKS){
        try{
            KeyStore ks = KeyStore.getInstance("JKS");
            char[] ksPass = pwd.toCharArray();
            try(InputStream ksData = new FileInputStream(pathKS)){
                try {
                    //antes que un keystore se pueda ser accedido debe ser cargado "load"
                    ks.load(ksData,ksPass);
                    ksData.close();
                } catch (NoSuchAlgorithmException ex) {
                } catch (CertificateException ex) {
                    log.error("error certificado", ex);
                }
            } catch (FileNotFoundException ex) {
                log.error("error archivo no encontrado", ex);
            } catch (IOException ex) {
                log.error("error IO", ex);
            }
            return ks;
            
        }//cargarKeystore sobrecargado
        catch (KeyStoreException ex) {
            log.error("error keystore", ex);
        }
        return null;
        
    }
    
    public void cargarKeystore() {
        try {
            this.ks = KeyStore.getInstance("JKS");
            this.ksPass = this.password.toCharArray();
            try {
                this.ksData = new FileInputStream(this.archivo);
            } catch (FileNotFoundException ex) {
                log.error("error FileNotFound", ex);
            }
            try {
                ks.load(ksData,ksPass);
            } catch (IOException ex) {
                log.error("Error con el KeyStore: ", ex);
            } catch (NoSuchAlgorithmException ex) {
                log.error("error Algoritmo", ex);
            } catch (CertificateException ex) {
                log.error("error certificado", ex);
            }
            ksData.close();
        } //cargarKeystore
        catch (KeyStoreException ex) {
            log.error("error keystore", ex);
        } catch (IOException ex) {
           log.error("error IO", ex);
        }
    }
    
    public void cargarKeystoreNEW() {
        try {
            this.ks = KeyStore.getInstance("JKS");
            this.ksPass = "test".toCharArray();
            FileOutputStream newkeystore = new FileOutputStream(OUTPUT_PATH);
            try {
                ks.load(null,ksPass);
                ks.setCertificateEntry("Test_certDesde0",this.newCertAutofirmados("CN= EXPERIAN_Java,O=Experian,OU=Experian,L=CABA,ST=CABA,C=AR"));
                log.info("keystore [CREADO]");
                ks.store(newkeystore, ksPass);
            } catch (IOException ex) {
                log.error("error el kestore no tiene certificado", ex);
            } catch (NoSuchAlgorithmException ex) {
                log.error("error Algoritmo", ex);
            } catch (CertificateException ex) {
                log.error("error certificado", ex);
            }
            newkeystore.close();
        } //cargarKeystore
        catch (KeyStoreException ex) {
            log.error("error keystore", ex);
        } catch (IOException ex) {
           log.error("error IO", ex);
        }
    }
    
    public void setKeystore(String Alias, X509Certificate clientCertificate){
        try {
            ks.setCertificateEntry(Alias, clientCertificate);
            FileOutputStream keyStoreOutputStream = new FileOutputStream(archivo);
            ks.store(keyStoreOutputStream, ksPass);
            log.info("Guardado nuevo Certificado en Keystore: " + archivo +" [OK] ");
        } catch (KeyStoreException ex) {
            log.error("Error con el KeyStore",ex);
        } catch (FileNotFoundException ex) {
            log.error("Error no se encuetra el archivo",ex);
        } catch (IOException ex) {
            log.error("Error de IO",ex);
        } catch (NoSuchAlgorithmException ex) {
            log.error("Error con el Algoritmo",ex);
        } catch (CertificateException ex) {
            log.error("Error con el Certificado",ex);
        }
    }
    /*
     public void setKeystore2(String Alias, Certificate clientCertificate){
        try {
          
            Certificate[] vectorCert = new Certificate[1];
            vectorCert[0]=clientCertificate;
            ks.setKeyEntry(Alias, clientCertificate.getPublicKey(), ksPass, vectorCert);
            FileOutputStream keyStoreOutputStream = new FileOutputStream(archivo);
            ks.store(keyStoreOutputStream, ksPass);
            log.info("Guardado nuevo Certificado en Keystore: " + archivo +" [OK] ");
        } catch (KeyStoreException ex) {
            log.error("Error con el KeyStore",ex);
        } catch (FileNotFoundException ex) {
            log.error("Error no se encuetra el archivo",ex);
        } catch (IOException ex) {
            log.error("Error de IO",ex);
        } catch (NoSuchAlgorithmException ex) {
            log.error("Error con el Algoritmo",ex);
        } catch (CertificateException ex) {
            log.error("Error con el Certificado",ex);
        }
    }*/
    public KeyStore.Entry getKey(String alias, String password){
        char[] keyPassowrd = password.toCharArray();
        KeyStore.ProtectionParameter claveEntrada = new KeyStore.PasswordProtection(keyPassowrd);
        try {
            KeyStore.Entry keyEntry = ks.getEntry(alias, claveEntrada);
            log.info("Recuperar entrada Keystore alias : "+alias+" [OK]");
            return keyEntry;
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException ex) {
            log.error(ex);
        }
        return null;
    }
    
    public Certificate getTurstStoreCert (String alias, String password){
        char[] keyPassowrd = password.toCharArray();
        KeyStore.ProtectionParameter claveEntrada = new KeyStore.PasswordProtection(keyPassowrd);
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, claveEntrada);
            return privateKeyEntry.getCertificate();
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException ex) {
            log.error(ex);
        }
        return null;
    }
    
    public void setKey(KeyStore.Entry keyEntry,String alias, String password){
        char[] keyPassowrd = password.toCharArray();
        KeyStore.ProtectionParameter claveEntrada = new KeyStore.PasswordProtection(keyPassowrd);
        try {
            FileOutputStream newkeystore = new FileOutputStream(archivo);
            ks.setEntry(alias, keyEntry, claveEntrada);
            log.info("Cargar clave del alias :"+alias +" [OK]");
            ks.store(newkeystore, keyPassowrd);
        } catch (KeyStoreException ex) {
            log.error(ex);
        } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
            log.error(ex);
        }
    
    }
    
    public void getDatosCertificado(String alias){    
        try {
            System.out.println( this.ks.getCertificate(alias).toString());
        } catch (KeyStoreException ex) {
            log.error("Error certificado", ex);
        }
    }
    
    /** 
     * Create a self-signed X.509 Certificate ##metodo 1 de prueb##
     * @param dn the X.509 Distinguished Name, eg "CN=EXPERIAN_Java, L=CABA, C=AR"
     * @param pair the KeyPair
     * @param days how many days from now the Certificate is valid for
     * @param algorithm the signing algorithm, eg "SHA1withRSA"
     */ 
    public X509Certificate crearX509(String dn, KeyPair pair, int days, String algorithm)throws GeneralSecurityException, IOException{
      PrivateKey privkey = pair.getPrivate();
      X509CertInfo info = new X509CertInfo();
      Date from = new Date();
      Date to = new Date(from.getTime() + days * 86400000l);
      CertificateValidity interval = new CertificateValidity(from, to);
      BigInteger sn = new BigInteger(64, new SecureRandom());
      X500Name owner = new X500Name(dn);

      info.set(X509CertInfo.VALIDITY, interval);
      info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
      info.set(X509CertInfo.SUBJECT, owner);
      info.set(X509CertInfo.ISSUER, owner);
      info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
      info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
      AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
      info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

      // Sign the cert to identify the algorithm that's used.
      X509CertImpl cert = new X509CertImpl(info);
      cert.sign(privkey, algorithm);

      // Update the algorith, and resign.
      algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
      info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
      cert = new X509CertImpl(info);
      cert.sign(privkey, algorithm);
      return cert;
    } //end X509
    
    public X509Certificate newCertAutofirmados(String subject){
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException ex) {
            log.error("Error en algoritmo ", ex);
        }
        keyGen.initialize(KEY_LEN);  
        KeyPair kPair = keyGen.generateKeyPair();
        log.info("llave publicar: " + kPair.getPublic().toString());
        log.info("llave privada: " + kPair.getPrivate().toString());
        
        X509Certificate cert = null;
        try {
            cert = crearX509(subject, kPair, KEY_LEN, ALGORITHM);
            log.info("creacion certificado X509 [OK]");
        } catch (GeneralSecurityException | IOException ex) {
            log.error("error gral. ", ex);
        }

        return cert;
    }
    
    public void saveCertAutoSign(String cuerpo){
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException ex) {
            log.error("Error en algoritmo ", ex);
        }
        keyGen.initialize(KEY_LEN);
        KeyPair kPair = keyGen.generateKeyPair();
        log.info("llave publicar: " + kPair.getPublic().toString());
        log.info("llave privada: " + kPair.getPrivate().toString());
        
        X509Certificate cert = null;
        try {
            cert = crearX509(cuerpo, kPair, KEY_LEN, ALGORITHM);
            log.info("creacion certificado X509 [OK]");
        } catch (GeneralSecurityException | IOException ex) {
            log.error("error gral. ", ex);
        }

        try (FileOutputStream certFile = new FileOutputStream(OUTPUT_PATH)) {
            try {
                certFile.write(cert.getEncoded());
                log.info("nuevo certificado creado en path [ok]");
            } catch (CertificateEncodingException ex) {
                log.error("error de Certificado ", ex);
            }
        } catch (FileNotFoundException ex) {
            log.error("error de archivo ", ex);
        } catch (IOException ex) {
            log.error("error IO ", ex);
        }
    }
    
    public void toPKCS12(String nameCert) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
        pkcs12.load(null, ksPass);
        Enumeration aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
           String alias = (String) aliases.nextElement();
           pkcs12.setCertificateEntry(alias,ks.getCertificate(alias));
        }
        //###MODIFICAR LA UBICACION FINAL DONDE SE GUARDA EL CERTIFICADO###
        FileOutputStream out = new FileOutputStream(System.getProperty("user.dir") + File.separator + "output"+ File.separator +nameCert+".p12");
        pkcs12.store(out, ksPass);
        out.close();
    
    }

    public Certificate abrirX509(String path){
        Certificate cert = null;
        FileInputStream fcert = null;
        try {
            fcert = new FileInputStream(path);
            log.info("ruta certificado a abrir: "+path);
        } catch (FileNotFoundException ex) {
            log.error("No se puede abrir el archivo", ex);
        }
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
           // log.info("StrongBox: "+cf.toString());
        } catch (CertificateException ex) {
            log.error("Error Certificado", ex);
        }
        
        try {
            cert = cf.generateCertificate(fcert);
            log.info("certificago cargado [OK]");
          
        } catch (CertificateException ex) {
            log.error("Error en certificado", ex);
        }
        return cert;
    }

    public CertPath getCertPathX509(String path){
        CertPath cert = null;
        FileInputStream fcert = null;
        try {
            fcert = new FileInputStream(path);
            log.info("ruta certificado a abrir: "+path);
        } catch (FileNotFoundException ex) {
            log.error("No se puede abrir el archivo", ex);
        }
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
           // log.info("StrongBox: "+cf.toString());
        } catch (CertificateException ex) {
            log.error("Error Certificado", ex);
        }
        
        try {
            cert = cf.generateCertPath(fcert);
            log.info("certificago cargado [OK]");
          
        } catch (CertificateException ex) {
            log.error("Error en certificado", ex);
        }
        return cert;
    }
    
    void borrarCert(String nomAliasJOB) {
        try {
            ks.deleteEntry(nomAliasJOB);
        } catch (KeyStoreException ex) {
            log.error("Error KeyStore", ex);
        }
    }
   
    public boolean existeAlias(String alias){
        try {
            return ks.containsAlias(alias);
        } catch (KeyStoreException ex) {
            log.error("No existe el Alias en el Keystore", ex);
        }
        return false; 
    }
    
    public Certificate getCertificado(String alias){
        try {
            return ks.getCertificate(alias);
        } catch (KeyStoreException ex) {
            log.error(ex);
        }
        return null;
    }
    
}//end certificado
