/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JKSinjector;

import java.io.File;
import java.io.FilenameFilter;

/**
 *
 * @author e10934a
 */
public class Filtro implements FilenameFilter{
    String extension;

    public Filtro(String ext) {
        this.extension = ext;
    }
      
    @Override
    public boolean accept(File dir, String name) {
        return name.endsWith(extension);
    }
    
}
