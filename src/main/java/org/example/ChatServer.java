package org.example;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;

public class ChatServer {
    private static final Logger logger = Logger.getLogger(ChatServer.class.getName());
    static Set<ClientHandler> clientHandlers = new HashSet<>();
    private static final Set<String> clientNames = new HashSet<>();
    private static final Set<String> bannedClients = new HashSet<>();

    public static void main(String[] args) {
        Scanner s = new Scanner(System.in);
        System.out.print("Input Port for Server: ");
        int port = s.nextInt();
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

    public static void banUser(String name) {
        for (ClientHandler clientHandler : clientHandlers) {
            if (clientHandler.getName().equals(name)) {
                clientHandler.sendBanMessage();
                clientHandlers.remove(clientHandler);
                clientNames.remove(name);
                bannedClients.add(name);
                logger.info(name + " has been banned from the server.");
                return;
            }
        }
        logger.info("User " + name + " not found.");
    }

    public static void unbanUser(String name) {
        if (bannedClients.remove(name)) {
            logger.info(name + " has been unbanned.");
        } else {
            logger.info(name + " was not banned.");
        }
    }

    public static void removeClient(String client) {
        clientNames.remove(client);
    }

    public static boolean isNameAvailable(String name) {
        return !clientNames.contains(name);
    }

    public static void addClientName(String name) {
        clientNames.add(name);
    }

    public static boolean isClientBanned(String name) {
        return bannedClients.contains(name);
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
                if (serverInput.startsWith(".kick ")) {
                    String userToKick = serverInput.split(" ")[1];
                    ChatServer.broadcastMessageFromServer(userToKick+" was banned from server");
                    ChatServer.removeClient(userToKick);
                } else if (serverInput.startsWith(".ban ")) {
                    String userToBan = serverInput.split(" ")[1];
                    ChatServer.banUser(userToBan);
                } else if (serverInput.startsWith(".unban ")) {
                    String userToUnban = serverInput.split(" ")[1];
                    ChatServer.unbanUser(userToUnban);
                } else {
                    ChatServer.broadcastMessageFromServer(serverInput);
                }
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error reading from server console", e);
        }
    }
}
