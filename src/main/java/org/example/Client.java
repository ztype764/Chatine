package org.example;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client {
    private static final Logger logger = Logger.getLogger(Client.class.getName());
    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private BufferedReader stdIn;
    private String baseKey = "your-secure-base-key";

    public Client(String hostname, int port, String client) {
        try {
            socket = new Socket(hostname, port);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            stdIn = new BufferedReader(new InputStreamReader(System.in));

            // Send the client's name to the server without encryption
            out.println(client);

            new Thread(new ReadThread(in, baseKey)).start();
            String userInput;
            while ((userInput = stdIn.readLine()) != null) {
                try {
                    long ntpTime = CryptoUtils.getNTPTime() / 1000;
                    SecretKey key = CryptoUtils.deriveKey(baseKey, ntpTime);
                    String encryptedMessage = CryptoUtils.encrypt(userInput, key);
                    System.out.print("\n" + client + " : ");
                    out.println(encryptedMessage);
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Error encrypting message", e);
                }
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error connecting to server", e);
        }
    }

    public static void main(String[] args) {
        String hostname = "localhost";
        int port = 30023;
        Scanner scanner = new Scanner(System.in);
        System.out.print("Write your name: ");
        String client = scanner.nextLine(); // Use nextLine() to capture full name
        new Client(hostname, port, client);
    }
}

class ReadThread implements Runnable {
    private static final Logger logger = Logger.getLogger(ReadThread.class.getName());
    private final BufferedReader in;
    private final String baseKey;

    public ReadThread(BufferedReader in, String baseKey) {
        this.in = in;
        this.baseKey = baseKey;
    }

    @Override
    public void run() {
        String serverMessage;
        try {
            while ((serverMessage = in.readLine()) != null) {
                try {
                    long ntpTime = CryptoUtils.getNTPTime() / 1000;
                    SecretKey key = CryptoUtils.deriveKey(baseKey, ntpTime);
                    String decryptedMessage = CryptoUtils.decrypt(serverMessage, key);
                    System.out.println(decryptedMessage);
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Error decrypting message", e);
                }
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error in read thread", e);
        }
    }
}
