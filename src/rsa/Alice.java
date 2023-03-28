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
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Gitu
 */

public class Alice {
    private BigInteger phiN, p, q, N, e, d;
    private ServerSocket serverSocket;
    private Socket clientSocket;
    private ObjectInputStream ois;
    private ObjectOutputStream oos;


    private void init(int keySize) {
        if (keySize < 512)
            throw new IllegalArgumentException("Key size too small.");
        SecureRandom rand = new SecureRandom();
        generatePQ(keySize / 2, rand);
        N = (p.multiply(q));
        phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        generateExponents(invertibleSet());
    }
    
    private void displayValues() {
        System.out.println("[+] Generated values: ");
        System.out.println("\tp: " + p);
        System.out.println("\tq: " + q);
        System.out.println("\tphi: " + phiN);
        System.out.println("\tModulus (N): " + N);        
        System.out.println("\tPrivate Key (d): " + d);        
    }
    
    //generates values for p and q using odd prime numbers (bit length == half of key value) 
    private void generatePQ(int bitLength, Random rand) {
        while (true) {
            p = generatePrime(bitLength, rand);
            q = generatePrime(bitLength, rand);
            if (!p.equals(q))
                return;
        }
    }
    
    //generates prime numbers of specified bit length and a random number
    private BigInteger generatePrime(int bitLength, Random rand) {
        BigInteger two = new BigInteger("2");
        while (true) {
            BigInteger prime = BigInteger.probablePrime(bitLength, rand);
            if (!prime.mod(two).equals(BigInteger.ZERO))
                return prime;
        }
    }

    //generates values for e and d
    private void generateExponents(BigInteger[] invertibleSet) {
        Random rand = new Random();
        while (true) {
            BigInteger invertible = invertibleSet[rand
                    .nextInt(invertibleSet.length)];
            BigInteger inverse = invertible.modInverse(phiN);
            if (invertible.multiply(inverse).mod(phiN)
                    .equals(BigInteger.ONE.mod(phiN)))
            {
                e = invertible;
                d = inverse;
                return;
            }
        }
    }

    private BigInteger[] invertibleSet() {
        final int maxSize = 100000;
        Set<BigInteger> invertibles = new HashSet<>();
        BigInteger end = N.subtract(BigInteger.ONE);
        for (BigInteger i = new BigInteger("5"); i.compareTo(end) < 0; i = i
                .add(BigInteger.ONE))
        {
            if (i.gcd(phiN).equals(BigInteger.ONE))
            {
                invertibles.add(i);
                if (invertibles.size() == maxSize)
                    break;
            }
        }
        return invertibles.toArray(new BigInteger[invertibles.size()]);
    }

    public String decrypt(String cipherText) {
        BigInteger encrypted = new BigInteger(cipherText, 16);
        //uses BigInteger function that performs operation similar to equation M=C^d mod n
        return new String(encrypted.modPow(d, N).toByteArray());
    }

    public BigInteger getModulus()
    {
        return N;
    }

    public BigInteger getPublicKeyExponent()
    {
        return e;
    }

    public BigInteger getPrivateKeyExponent()
    {
        return d;
    }
    
    public void startServer(int port) {
        try {
            serverSocket = new ServerSocket(port);
            System.out.println("[+] Server Started.");
            displayValues();
            System.out.println("[+] Waiting for client...");
            
            clientSocket = serverSocket.accept();
            System.out.println("[+] Bob Connected.");
            
            //receive message from Bob
            ois = new ObjectInputStream(clientSocket.getInputStream());
            String message = null;
            try {
                message = (String) ois.readObject();
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(Alice.class.getName()).log(Level.SEVERE, null, ex);
            }
            System.out.println("\t[-] " + message);
            
            //write object to Socket 
            //sending public key to Bob
            System.out.println("[+] Sending public key...");
            oos = new ObjectOutputStream(clientSocket.getOutputStream());
            oos.writeObject(e);
            oos.flush();

            //receipt from Bob
            try {
                message = (String) ois.readObject();
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(Alice.class.getName()).log(Level.SEVERE, null, ex);
            }
            System.out.println("\t[-] " + message);
            
            //write object to Socket 
            //sending totient to Bob
            oos = new ObjectOutputStream(clientSocket.getOutputStream());
            oos.writeObject(N);
            oos.flush();
            
            System.out.println("[+] Waiting for cypher text... ");
            //receive cypher text from Bob
            String cypherText = null;
            try {
                cypherText = (String) ois.readObject();
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(Alice.class.getName()).log(Level.SEVERE, null, ex);
            }
            System.out.println("\t[-] " + cypherText);
            
            //decrypt cypher text
            System.out.println("[+] Decrypting...");
            String decrypted = decrypt(cypherText);
            System.out.println("[+] Decrypted message: " + decrypted);

            oos.close();
            ois.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException ex) {
            Logger.getLogger(Alice.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static void main(String[] args) {
        Alice server = new Alice();
        server.init(1024);
        server.startServer(4444);
    }
}