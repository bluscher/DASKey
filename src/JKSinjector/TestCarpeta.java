package JKSinjector;


import JKSinjector.Carpeta;
import org.apache.log4j.Logger;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author e10934a
 */
public class TestCarpeta {
    
    
     private static final Logger log = Logger.getLogger(TestCarpeta.class.getName());
    
    
    
    
     public static void main(String[] args){
     
         Carpeta folder = new Carpeta();
         folder.getCertFile();
     
     }
}
