/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package rsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Gitu
 */
public class Bob {
    private BigInteger publicKey = null;
    private BigInteger totient = null;
    public String encrypt(String plainText) {
        BigInteger msg = new BigInteger(plainText.getBytes());
        //uses BigInteger function that performs operation similar to equation C=M^e mod n
        byte[] encrypted = msg.modPow(publicKey, totient).toByteArray();
        return toHex(encrypted);
    }

    private String toHex(byte[] bytes) {
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "X", bi);
    }
    
    public void encryption() {
        try {
            Socket clientSocket;
            ObjectOutputStream oos = null;
            ObjectInputStream ois = null;

            clientSocket = new Socket("127.0.0.1", 4444);
            //write to socket using ObjectOutputStream
            oos = new ObjectOutputStream(clientSocket.getOutputStream());
            System.out.println("[+] Sending request to Socket Server");
            oos.writeObject("Hello Alice. Requesting Public Key...");
            oos.flush();
            
            //read the server response message
            //Bob receives public key
            ois = new ObjectInputStream(clientSocket.getInputStream());
            try {
                publicKey = (BigInteger) ois.readObject();
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(Bob.class.getName()).log(Level.SEVERE, null, ex);
            }
            System.out.println("\t[-] Public Key: " + publicKey);
            
            //receipt message
            oos.reset();
            oos.writeObject("Public Key Received.");
            oos.flush();
            
            //Bob receives totient
            ois = new ObjectInputStream(clientSocket.getInputStream());
            try {
                totient = (BigInteger) ois.readObject();
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(Bob.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            
            //encrypt message to cypher text
            System.out.println("[+] Encrypting...");
            String message = "APT3090 Cryptograhy and Network Security. Group 5.";
            String cypherText = encrypt(message);
            System.out.println("[+] Secret Message: " + message);
            System.out.println("[+] Cypher text: " + cypherText);
            
            //send cypher text to Alice 
            oos.writeObject(cypherText);
            oos.flush();
            
            oos.close();
            ois.close();
            clientSocket.close();
        } catch (IOException ex) {
            Logger.getLogger(Bob.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    
    public static void main(String[] args) {
        Bob client = new Bob();
        client.encryption();
    }
}
