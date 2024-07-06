package org.example;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;

public class ChatServer {
    private static final Logger logger = Logger.getLogger(ChatServer.class.getName());
    static Set<ClientHandler> clientHandlers = new HashSet<>();
    private static final String BASE_KEY = "your-secure-base-key";
    private static final Set<String> clientNames = new HashSet<>();

    public static void main(String[] args) {
        int port = 30023;
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logger.info("Server started on port " + port);

            new Thread(new ServerInputHandler()).start();

            while (true) {
                Socket clientSocket = serverSocket.accept();
                ClientHandler clientHandler = new ClientHandler(clientSocket);
                clientHandlers.add(clientHandler);
                new Thread(clientHandler).start();
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error starting the server", e);
        }
    }

    public static void broadcastMessage(String message, ClientHandler sender) {
        for (ClientHandler clientHandler : clientHandlers) {
            if (clientHandler != sender) {
                clientHandler.sendMessage(message);
            }
        }
    }

    public static void broadcastMessageFromServer(String message) {
        String upperCaseMessage = message.toUpperCase();
        String redMessage = "\u001B[31m" + upperCaseMessage + "\u001B[0m";
        for (ClientHandler clientHandler : clientHandlers) {
            clientHandler.sendMessage("Server: " + redMessage);
        }
    }

    public static void removeClient(ClientHandler clientHandler) {
        clientHandlers.remove(clientHandler);
    }
    public static boolean isNameAvailable(String name) {
        return !clientNames.contains(name);
    }

    public static void addClientName(String name) {
        clientNames.add(name);
    }
}

class ClientHandler implements Runnable {
    private static final Logger logger = Logger.getLogger(ClientHandler.class.getName());
    private final Socket socket;
    private PrintWriter out;
    private String clientName;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Read the client's name and check if it's available
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
            ChatServer.clientHandlers.add(this);

            String message;
            while ((message = in.readLine()) != null) {
                try {
                    long ntpTime = CryptoUtils.getNTPTime() / 1000;
                    SecretKey key = CryptoUtils.deriveKey( ntpTime);
                    String decryptedMessage = CryptoUtils.decrypt(message, key);
                    ChatServer.broadcastMessage("[" + clientName + "]" + ": " + decryptedMessage, this);
                    System.out.println("[" + clientName + "]" + ": " + decryptedMessage);
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

    public String getClientName() {
        return clientName;
    }
}

class ServerInputHandler implements Runnable {
    private static final Logger logger = Logger.getLogger(ServerInputHandler.class.getName());
    private final BufferedReader stdIn;

    public ServerInputHandler() {
        stdIn = new BufferedReader(new InputStreamReader(System.in));
    }

    @Override
    public void run() {
        String serverInput;
        try {
            while ((serverInput = stdIn.readLine()) != null) {
                ChatServer.broadcastMessageFromServer(serverInput);
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error reading from server console", e);
        }
    }
}

