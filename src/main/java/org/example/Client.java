package org.example;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.util.Properties;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client {
    private static final Logger logger = Logger.getLogger(Client.class.getName());

    public Client(String hostname, int port, String client) {
        try {
            Socket socket = new Socket(hostname, port);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

            // Check if the name is available
            out.println(client);
            String serverResponse = in.readLine();
            while (!"OK".equals(serverResponse)) {
                System.out.println(serverResponse);
                client = stdIn.readLine();
                out.println(client);
                serverResponse = in.readLine();
            }

            new Thread(new ReadThread(in)).start();
            String userInput;
            while ((userInput = stdIn.readLine()) != null) {
                try {
                    long ntpTime = CryptoUtils.getNTPTime() / 1000;
                    SecretKey key = CryptoUtils.deriveKey(ntpTime);
                    String encryptedMessage = CryptoUtils.encrypt(userInput, key);
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
        Properties properties = new Properties();
        try (InputStream input = new FileInputStream("system.properties")) {
            properties.load(input);
            String hostname = properties.getProperty("server.hostname", "localhost");
            int port = Integer.parseInt(properties.getProperty("server.port", "30023"));

            Scanner scanner = new Scanner(System.in);
            System.out.print("Write your name: ");
            String client = scanner.nextLine();
            new Client(hostname, port, client);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error loading system.properties", e);
        }
    }
}

class ReadThread implements Runnable {
    private static final Logger logger = Logger.getLogger(ReadThread.class.getName());
    private final BufferedReader in;

    public ReadThread(BufferedReader in) {
        this.in = in;
    }

    @Override
    public void run() {
        String serverMessage;
        try {
            while ((serverMessage = in.readLine()) != null) {
                try {
                    long ntpTime = CryptoUtils.getNTPTime() / 1000;
                    SecretKey key = CryptoUtils.deriveKey(ntpTime);
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
