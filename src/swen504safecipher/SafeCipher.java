package swen504safecipher;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.sql.Connection;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class SafeCipher extends Application {
	
	private Key desKey; // Variable to store the DES key
	private Key aesKey; // Variable to store the AES key
	private Stage primaryStage;
	private static final String DB_URL = "jdbc:mysql://securecipher.cg3i8aewd36j.ap-southeast-2.rds.amazonaws.com:3306/secure1?user=admin";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "BennettM.10311031";
    final Label message = new Label("");
    final boolean finalLoginSuccess = false;
    private TextField usernameField = new TextField();
    private PasswordField passwordField = new PasswordField();
    private String userNameCurrent = "";
    private SecretKey masterKey;
	
	
    private Scene createLoginScene(Stage primaryStage) {
    	
    	    VBox loginLayout = new VBox(10);
    	    loginLayout.setAlignment(Pos.CENTER);
    	    loginLayout.setPadding(new Insets(10));
    	    
    	    // Create HBox for username
	        HBox usernameBox = new HBox(10);
	        usernameBox.setAlignment(Pos.CENTER);
	        Label usernameLabel = new Label("Username: ");
	       
	        usernameField.setPromptText("Username");
	        usernameBox.getChildren().addAll(usernameLabel, usernameField);

	        // Create HBox for password
	        HBox passwordBox = new HBox(10);
	        passwordBox.setAlignment(Pos.CENTER);
	        Label passwordLabel = new Label("Password: ");
	        
	        passwordField.setPromptText("Password");
	        passwordBox.getChildren().addAll(passwordLabel, passwordField);
    	        	    
    	    Button loginButton = new Button("Login");
    	    loginButton.setOnAction(e -> {
    	        handleLogin(usernameField.getText(), passwordField.getText());	      
    	    });
    	    Button signUpButton = new Button("Sign Up");
    	    signUpButton.setOnAction(e -> {
    	        // TODO: 验证用户名和密码
    	        // 如果验证成功，显示主界面
    	        primaryStage.setScene(createMainScene());
    	    });
    	    HBox buttonsLS = new HBox();
    	    buttonsLS.setSpacing(10);
    	    buttonsLS.setAlignment(Pos.CENTER);
    	    buttonsLS.getChildren().addAll(loginButton,signUpButton);

    	    loginLayout.getChildren().addAll(usernameBox, passwordBox, buttonsLS,message);

    	    return new Scene(loginLayout, 1500, 600);
    }
    
    private Scene createMainScene() {
        HBox root = new HBox();
        root.setAlignment(Pos.CENTER);

        VBox left = new VBox(10);
        left.setPadding(new Insets(15));
        Label titleLeft = new Label("Text:");
        TextArea textLeft = new TextArea();
        textLeft.setPrefWidth(400); 
        textLeft.setPrefHeight(500); 
        left.getChildren().addAll(titleLeft, textLeft);

        VBox middle = new VBox(10);
        middle.setPadding(new Insets(50, 15, 15, 15));
        HBox enDeBtnBox = new HBox(10);
        Button encoButton = new Button("ENCRYPT");
        Button decoButton = new Button("DECRYPT");
        enDeBtnBox.getChildren().addAll(encoButton, decoButton);
        // ComboBox for selecting the encryption method
        ComboBox<String> methodComboBox = new ComboBox<>();
        methodComboBox.getItems().addAll("Caesar Cipher", "DES", "AES");
        HBox keyBox = new HBox(20);
        Label keyLabel = new Label("Key:");
        TextField keyInput = new TextField();
        keyInput.setPrefWidth(50); 
        keyBox.getChildren().addAll(keyLabel, keyInput);
        HBox saveLoadLocalButtons = new HBox(20);
        Button saveKeyButton = new Button("Save Key to Local");
        Button loadKeyButton = new Button("Load Key from Local");
        saveLoadLocalButtons.getChildren().addAll(saveKeyButton,loadKeyButton);
        VBox saveLoadCloudButtons = new VBox(20);
        HBox saveCloud = new HBox(20);
        Label saveLabel = new Label("Tag:");
        TextField saveTextField = new TextField();
        Button saveKeyCloudButton = new Button("Save Key to Cloud");
        saveCloud.getChildren().addAll(saveLabel,saveTextField,saveKeyCloudButton);
        HBox loadCloud = new HBox(20);
        Label loadLabel = new Label("Tag:");
        TextField loadTextField = new TextField();
        Button loadKeyCloudButton = new Button("Load Key from Cloud");
        loadCloud.getChildren().addAll(loadLabel,loadTextField,loadKeyCloudButton);
        saveLoadCloudButtons.getChildren().addAll(saveCloud,loadCloud);
        middle.getChildren().addAll( methodComboBox,keyBox,enDeBtnBox,saveLoadLocalButtons,saveLoadCloudButtons);

        VBox right = new VBox(10);
        right.setPadding(new Insets(15));
        Label titleRight = new Label("Result:");
        TextArea textRight = new TextArea();
        textRight.setPrefWidth(400); 
        textRight.setPrefHeight(500); 
        right.getChildren().addAll(titleRight, textRight);

        root.getChildren().addAll(left, middle, right);

     // ComboBox event handler
        methodComboBox.setOnAction(e -> {
            String selectedMethod = methodComboBox.getValue();
            System.out.println("Selected encryption method: " + selectedMethod);
            if ("Caesar Cipher".equals(selectedMethod)) {
                keyLabel.setVisible(true);
                keyInput.setVisible(true);
            } else {
                keyLabel.setVisible(false);
                keyInput.setVisible(false);
            }
        });

        // ENCRYPT button event handler
        encoButton.setOnAction(e -> {
            String selectedMethod = methodComboBox.getValue();
            if ("Caesar Cipher".equals(selectedMethod)) {
                try {
                    int key = Integer.parseInt(keyInput.getText());
                    CaesarCipher cipher = new CaesarCipher(key);
                    String encodedText = cipher.encrypt(textLeft.getText());
                    textRight.setText(encodedText);
                    System.out.println("originaltext: "+ textLeft.getText());
                    System.out.println("key: "+ key);
                    System.out.println("encoded text: "+ encodedText);
                } catch (NumberFormatException e1) {
                    textRight.setText("Error: Invalid key. Please enter a number.");
                }
            } else if ("DES".equals(selectedMethod)) {
                try {
                    DES des = new DES();
                    desKey = des.getSecretKey(); // Store the key
                    String encryptedText = des.encrypt(textLeft.getText());
                    textRight.setText(encryptedText);
                    
                    System.out.println("originaltext: " + textLeft.getText());
                    System.out.println(desKey);
                    System.out.println("key: " + Base64.getEncoder().encodeToString(desKey.getEncoded()) );
                    System.out.println("encryptedText: " + encryptedText);
                } catch (Exception ex) {
                    textRight.setText("Error during DES encryption: " + ex.getMessage());
                }
             } else if ("AES".equals(selectedMethod)) {
                try {
                    AES aes = new AES();
                    aesKey = aes.getSecretKey(); // Store the key
                    String encryptedText = aes.encrypt(textLeft.getText());
                    textRight.setText(encryptedText);
                    
                    System.out.println("originaltext: " + textLeft.getText());
                    System.out.println(aesKey);
                    System.out.println("key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()) );
                    System.out.println("encryptedText: " + encryptedText);
                } catch (Exception ex) {
                    textRight.setText("Error during AES encryption: " + ex.getMessage());
                }
            }else {
                // Handle other encryption methods or display a message
                textRight.setText("Please select a valid encryption method.");
            }
        });

        // DECRYPT button event handler
        decoButton.setOnAction(e -> {
            String selectedMethod = methodComboBox.getValue();
            if ("Caesar Cipher".equals(selectedMethod)) {
                try {
                    int key = Integer.parseInt(keyInput.getText());
                    CaesarCipher cipher = new CaesarCipher(key);
                    String decodedText = cipher.decrypt(textLeft.getText());
                    textRight.setText(decodedText);
                    System.out.println("originaltext: "+ textLeft.getText());
                    System.out.println("key: "+ key);
                    System.out.println("decoded text:" + decodedText);
                } catch (NumberFormatException e1) {
                    textRight.setText("Error: Invalid key. Please enter a number.");
                }
            } else if ("DES".equals(selectedMethod)) {
                try {
                	 DES des = new DES();
                     String decryptedText = des.decrypt(textLeft.getText(), desKey); // 使用存储的密钥进行解密
                     textRight.setText(decryptedText);
                     System.out.println("originaltext: " + textLeft.getText());
                     System.out.println("key: " + Base64.getEncoder().encodeToString(desKey.getEncoded()) );
                     System.out.println("encryptedText: " + decryptedText);
                     
                } catch (Exception ex) {
                    textRight.setText("Error during DES decryption: " + ex.getMessage());
                }    
            }else if ("AES".equals(selectedMethod)) {
                try {
               	    AES aes = new AES();
                    String decryptedText = aes.decrypt(textLeft.getText(), aesKey); // 使用存储的密钥进行解密
                    textRight.setText(decryptedText);
                    System.out.println("originaltext: " + textLeft.getText());
                    System.out.println("key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()) );
                    System.out.println("encryptedText: " + decryptedText);                   
                } catch (Exception ex) {
                   textRight.setText("Error during AES decryption: " + ex.getMessage());
                }
            } else {
                // Handle other decryption methods or display a message
                textRight.setText("Please select a valid decryption method.");
            }
        });
       
        // 在createMainScene方法中添加以下代码
        saveKeyButton.setOnAction(e -> {
            String selectedMethod = methodComboBox.getValue();
            if ("DES".equals(selectedMethod)) {
                saveKeyUsingFileChooser(desKey, "DES");
            } else if ("AES".equals(selectedMethod)) {
                saveKeyUsingFileChooser(aesKey, "AES");
            }
        });

        loadKeyButton.setOnAction(e -> {
            String selectedMethod = methodComboBox.getValue();
            if ("DES".equals(selectedMethod)) {
                loadKeyUsingFileChooser("DES");
            } else if ("AES".equals(selectedMethod)) {
                loadKeyUsingFileChooser("AES");
            }
        });
        
        saveKeyCloudButton.setOnAction(e ->{
        	String selectedMethod = methodComboBox.getValue();
            if ("DES".equals(selectedMethod)) {
                try {
					saveKeytoCloud(desKey, userNameCurrent, saveTextField.getText());
				} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException
						| IllegalBlockSizeException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
            } else if ("AES".equals(selectedMethod)) {
                saveKeyUsingFileChooser(aesKey, "AES");
            }
        });
        
        
        return new  Scene(root, 1500, 600);
    }
    
    
    
    private void saveKeyUsingFileChooser(Key key, String algorithm) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save " + algorithm + " Key");
        File file = fileChooser.showSaveDialog(primaryStage);
        if (file != null) {
            saveKeyToFile(key, file.getPath());
        }
    }

    private void loadKeyUsingFileChooser(String algorithm) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Load " + algorithm + " Key");
        File file = fileChooser.showOpenDialog(primaryStage);
        if (file != null) {
            try {
                Key loadedKey = loadKeyFromFile(file.getPath(), algorithm);
                if ("DES".equals(algorithm)) {
                    desKey = loadedKey;
                } else if ("AES".equals(algorithm)) {
                    aesKey = loadedKey;
                }
            } catch (Exception e) {
                e.printStackTrace(); // 此处应有更好的错误处理
            }
        }
    }
    
    private void saveKeyToFile(Key key, String filePath ) {
    	//Convert key to a byte array
    	byte[] keyBytes = key.getEncoded();
    	
    	//Convert byte array to Base64 string for easy storage
    	String base64Key = Base64.getEncoder().encodeToString(keyBytes);
    	
    	//Write the Base64 string to a file
    	try {
			Files.write(Paths.get(filePath), base64Key.getBytes());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

    private Key loadKeyFromFile(String filePath, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        // Read the Base64 encoded string from the file
        byte[] encodedKey = Base64.getDecoder().decode(Files.readAllBytes(Paths.get(filePath)));

        if ("DES".equals(algorithm)) {
            // Create DES key spec and generate the key
            KeySpec keySpec = new DESKeySpec(encodedKey);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            return keyFactory.generateSecret(keySpec);
        } else if ("AES".equals(algorithm)) {
            // For AES, use SecretKeySpec to generate the key
            return new SecretKeySpec(encodedKey, "AES");
        }

        throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
    }
    
    private void handleLogin(String username, String password) {
        // Perform database login logic here
        System.out.println("Username: " + username);
        System.out.println("Password: " + password);

        // TODO: Add your database login logic here
        // Use Platform.runLater() or a background thread for database operations
        new Thread(() -> {
            boolean loginSuccess = false;
            try {
                Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

                String sql = "SELECT * FROM user WHERE secure1.user.Username = ? AND secure1.user.Password = ? ";
                try (PreparedStatement statement = connection.prepareStatement(sql)) {
                    statement.setString(1, username);
                    statement.setString(2, User.hashPassword(password));

                    ResultSet resultSet = statement.executeQuery();
                    loginSuccess = resultSet.next(); // 处理数据
                } // 自动关闭 PreparedStatement 和 ResultSet

                connection.close();
            } catch (Exception e) {
                e.printStackTrace();
            }

            // 在 FX 线程中处理 UI 更新
            final boolean finalLoginSuccess = loginSuccess;
            Platform.runLater(() -> {
                if (finalLoginSuccess) {
                	primaryStage.setScene(createMainScene());
                    message.setText("Successfully log in.");
                    System.out.println("Successfully log in.");
                    userNameCurrent = username;
                } else {
                    message.setText("Unsuccessfully log in.");
                    System.out.println("Unsuccessful login");
                }
            });
        }).start();
    }
    
    public void insertUser(User user) {

        try {
            Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            String sql = "INSERT INTO 'user' (username, password) VALUES (?, ?)";
            PreparedStatement statement = connection.prepareStatement(sql);
            statement.setString(1, user.getUsername());
            statement.setString(2, user.getPassword());

            statement.executeUpdate();
            statement.close();
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
            // Handle SQL exceptions
        }
    }
    
    public void saveKeytoCloud(Key key,String userNameCurrent, String keyLabel) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
    	//Convert key to a byte array   	
    	byte[] keyBytes = key.getEncoded();
    	
    	//Convert byte array to Base64 string for easy storage
    	String base64Key = Base64.getEncoder().encodeToString(keyBytes);
    	
    	DES des = new DES();
        keyforDesKey  = des.getSecretKey(); // Store the key
        String encryptedKey = des.encrypt(base64Key);
        
        try {
            Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            String sql = "INSERT INTO `keys` (Username, KeyLabel, KeyValue) VALUES (?,?,?)";
            PreparedStatement statement = connection.prepareStatement(sql);
            statement.setString(1, userNameCurrent);
            statement.setString(2, keyLabel);
            statement.setString(3, encryptedKey);
            
            statement.executeUpdate();
            statement.close();
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
            // Handle SQL exceptions
        }
		
    }
    
    public Key loadKeyfromCloud(String userNameCurrent, String keyLabel) {
        String encryptedKey = null;

        try {
            Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            String sql = "SELECT KeyValue FROM `keys` WHERE Username = ? AND KeyLabel = ?";
            PreparedStatement statement = connection.prepareStatement(sql);
            statement.setString(1, userNameCurrent);
            statement.setString(2, keyLabel);

            ResultSet resultSet = statement.executeQuery();
            if (resultSet.next()) {
                encryptedKey = resultSet.getString("KeyValue");
            }

            resultSet.close();
            statement.close();
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
            // Handle SQL exceptions
            return null;
        }

        if (encryptedKey == null) {
            // Key not found
            return null;
        }

        try {
            // Assuming you have a DES class for decryption
            DES des = new DES();
            String decryptedBase64Key = des.decrypt(encryptedKey,keyforDesKey);
            byte[] decodedKey = Base64.getDecoder().decode(decryptedBase64Key);
            
            // If key is a DES key, use DESKeySpec to convert byte[] back to Key
            // For AES, you would use SecretKeySpec
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            KeySpec keySpec = new DESKeySpec(decodedKey);
            return keyFactory.generateSecret(keySpec);

        } catch (Exception e) {
            e.printStackTrace();
            // Handle decryption exceptions
            return null;
        }
    }

    
    public void start(Stage primaryStage) {
    	
    	masterKey = new SecretKeySpec(Base64.getDecoder().decode("1nPsGt/3uv4="), "DES");
    	this.primaryStage = primaryStage;
    	primaryStage.show();
    	insertUser(new User("Michael","123"));
        Scene loginScene = createLoginScene(primaryStage);
        primaryStage.setScene(loginScene);
        primaryStage.setTitle("SafeCipher Login");     
    }

    
    public static void main(String[] args) {
        launch(args);
    }
}
