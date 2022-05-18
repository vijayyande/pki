/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkcs11;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 *
 * @author vijay
 */
public class Pkcs11 {

    
    public static String providerName = "";
    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws KeyStoreException, IOException, CertificateException, GeneralSecurityException, InterruptedException, Exception {
        
        
        System.out.println(" command line parameter: java -jar pkcs11 AlgorithmName HSMLoginPassword EntryName  Y/N");
        System.out.println("      Last parameter Y if you want to save on pkcs11 store. ");
        System.out.println(" e.g.: java -jar pkcs11 RSA Pass@1234 EntryName Y");
        System.out.println(" e.g.: java -jar pkcs11 AES 1234 EntryName Y/N");
   
        if ( args.length < 4 )
        {
            System.err.println("\nPlease provide all command line prameters");
            return ;
        }
        System.out.println("Starting...");
        System.out.println("Adding security provider...");
  
        
        Provider prov = AddSecurityProvider();
        KeyStore keystor = null;
        KeyPairGenerator gen = null;
        RSAKeyGenParameterSpec keyGenparm = null;
        

            
        keystor = KeyStore.getInstance("PKCS11", prov);
        //keystor = KeyStore.getInstance(providerName);
        System.out.println("Login into keystore(hsm)...");
        //keystor.load(null, "1234".toCharArray());
        keystor.load(null, args[1].toCharArray());
        
        
        /// symmetric key -  generation
        //KeyGenerator symmetric = KeyGenerator.getInstance("AES", prov);
        KeyGenerator symmetric = KeyGenerator.getInstance(args[0], prov);
        symmetric.init(128);    ////// key size 
        symmetric.init(new SecureRandom());
        SecretKey symmetricKey =  symmetric.generateKey();   ///// generate symmetric key
        byte[] keyEncoded =  symmetricKey.getEncoded();
        System.out.println("Symmetric key: " + keyEncoded.toString());
        

        
        String encodedKey = Base64.getEncoder().encodeToString(symmetricKey.getEncoded());
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey.getBytes());
        System.out.println("Base64 enkey: " + encodedKey);
        System.out.println("Base64 dekey: " + new String(decodedKey)  );
        System.out.println("=======================");
        

        
        //KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection("1234".toCharArray());
        KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(args[1].toCharArray());
        
        KeyStore.SecretKeyEntry ske = new KeyStore.SecretKeyEntry(symmetricKey); /// entry name for storing key on HSM
        //keystor.setEntry("symmetric2", ske, protectionParam);
        
        if( args[3].compareToIgnoreCase("Y") == 1 )
        {
            keystor.setEntry(args[2], ske, protectionParam);  ///// finally store key on HSM, use pin to encrypt
        }
               
        
                
        ///// key wrap - unwrap example

        Cipher c = Cipher.getInstance("AESWrap", "SunJCE");
        SecretKey cipherKey = new SecretKeySpec(keyEncoded, "AES");
        c.init(Cipher.WRAP_MODE, cipherKey);

        
        //// wrap 
        //byte[] wrapped = c.wrap(toBeWrappedKey);
        byte[] wrapped = c.wrap(symmetricKey);
        System.out.println("UnWrapped Byte: " + new String(symmetricKey.getEncoded()) );
        System.out.println("Wrapped Byte: " + new String(wrapped) );
        
        /// unwrap
        c.init(Cipher.UNWRAP_MODE, cipherKey);
        Key unwrapped = c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        System.out.println("Unwrapped: " +  new String(unwrapped.getEncoded()) );
        

        
       
        
        ////// GCM - demo
        byte[] IV = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
        byte[] cipherText = encrypt("Hello World".getBytes(), symmetricKey, IV);
        String decryptedText = decrypt(cipherText, symmetricKey, IV);
        System.out.println("Decrypted GCM :" + decryptedText);
         
        
        System.out.println("Storing on hsm...");
        keystor.store(null);
        

        System.out.println("done!");

       
        
    }
    
    
public static byte[] encrypt(byte[] plaintext, SecretKey key, byte[] IV) throws Exception
    {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        
        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
        
        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        
        // Perform Encryption
        byte[] cipherText = cipher.doFinal(plaintext);
        
        return cipherText;
    }

    public static String decrypt(byte[] cipherText, SecretKey key, byte[] IV) throws Exception
    {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        
        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        
        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
        
        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        
        // Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);
        
        return new String(decryptedText);
    }


    
    private static Provider AddSecurityProvider()
    {
        
        Provider prov = null;
        //// add security provider - PKCS#11  dll path must be provided
        //String tokenConf = String.format("name=nexusPKCS\nlibrary=%s\nshowInfo=true", "C:/SoftHSM2/lib/softhsm2-x64.dll");
        //InputStream is = new ByteArrayInputStream(tokenConf.getBytes());
        //prov = new sun.security.pkcs11.SunPKCS11(is);
        
        //Security.getProvider(name)
     
        if( providerName.isEmpty()  )
        {
            Provider tmp = Security.getProvider(providerName);
            if( tmp == null )
            {
                String pkcs11ConfigSettings = "name = nexus " + "\n" + "library = C:/SoftHSM2/lib/softhsm2-x64.dll" ;
                byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
                ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);

                
                //String cfgFile = "library = C:\\SoftHSM2\\lib\\softhsm2-x64.dll" ;
                //String cfgFilePath = "C:\\neXus\\NetbeansProject\\pkcs11-symmetrickey\\hsm1.cfg";
                //String cfgFilePath = "C:\\neXus\\NetbeansProject\\pkcs11-symmetrickey\\opensc.cfg";
                
                String cfgFilePath = "hsm.cfg";

                
                //prov = new sun.security.pkcs11.SunPKCS11("hsm.cfg");
                prov =  new sun.security.pkcs11.SunPKCS11();
                prov = prov.configure(cfgFilePath);
                
              
        
                int pos = Security.addProvider(prov);
                if( pos == -1 )
                {
                    System.err.println("ERROR: Adding of security provider failed.");
                }
            }
        }
//        else
//        {
//            Provider tmp = Security.getProvider(providerName);
//            if( tmp == null )
//            {
//                prov = new sun.security.pkcs11.SunPKCS11("hsm.cfg");
//        
//                int pos = Security.addProvider(prov);
//                if( pos == -1 )
//                {
//                    System.err.println("Adding of security provider failed.");
//                }
//            }
//            else
//            {
//                prov = tmp;
//            }
//        }        
 
        providerName = prov.getName();
        System.out.println("=====> Security provider added: " + prov.getName());
        return prov;
        
        
        
    }
    
      
    
}
