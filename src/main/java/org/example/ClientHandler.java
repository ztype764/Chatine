package org.example;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ClientHandler implements Runnable {
        private static final Logger logger = Logger.getLogger(ClientHandler.class.getName());
        private final Socket socket;
        private PrintWriter out;
        private String clientName;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public String getClientName() {
            return clientName;
        }

        @Override
        public void run() {
            try {
                out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                while (true) {
                    clientName = in.readLine();
                    if (ChatServer.isNameAvailable(clientName)) {
                        ChatServer.addClientName(clientName);
                        out.println("OK");
                        break;
                    } else {
                        out.println("Name already taken");
                    }
                }

                logger.info(clientName + " has joined the chat");
                ChatServer.broadcastMessage(clientName + " has joined the chat", this);

                String message;
                while ((message = in.readLine()) != null) {
                    try {
                        long ntpTime = CryptoUtils.getNTPTime() / 1000;
                        SecretKey key = CryptoUtils.deriveKey(ntpTime);
                        String decryptedMessage = CryptoUtils.decrypt(message, key);
                        ChatServer.broadcastMessage("[" + clientName + "]: " + decryptedMessage, this);
                        System.out.println("[" + clientName + "]: " + decryptedMessage);
                    } catch (Exception e) {
                        logger.log(Level.SEVERE, "Error decrypting message", e);
                    }
                }
            } catch (IOException e) {
                logger.log(Level.SEVERE, "Error in client handler", e);
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    logger.log(Level.INFO, "Error closing socket", e);
                }
                ChatServer.removeClient(this);
                logger.info(clientName + " has left the chat");
                ChatServer.broadcastMessage(clientName + " has left the chat", this);
            }
        }

        public void sendMessage(String message) {
            try {
                long ntpTime = CryptoUtils.getNTPTime() / 1000;
                SecretKey key = CryptoUtils.deriveKey(ntpTime);
                String encryptedMessage = CryptoUtils.encrypt(message, key);
                out.println(encryptedMessage);
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error encrypting message", e);
            }
        }
    }
