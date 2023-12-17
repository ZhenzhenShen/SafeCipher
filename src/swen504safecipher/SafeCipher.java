package swen504safecipher;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.geometry.Rectangle2D;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ColorPicker;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.layout.Background;
import javafx.scene.layout.BackgroundImage;
import javafx.scene.layout.BackgroundPosition;
import javafx.scene.layout.BackgroundRepeat;
import javafx.scene.layout.BackgroundSize;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.stage.FileChooser;
import javafx.stage.Screen;
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
    private Label hintLabel = new Label("");
    private String selectedMethod;
    private ComboBox<String> methodComboBox = new ComboBox<>(); 
    private ComboBox<String> saveComboBox;
    private ComboBox<String> loadComboBox;

    private Scene createLoginScene(Stage primaryStage) {
    	
    	    VBox loginLayout = new VBox(10);
    	    loginLayout.setAlignment(Pos.CENTER);
    	    loginLayout.setPadding(new Insets(10));
    	    
    	    Label titleLabel = new Label("Safe Cipher");
    	    titleLabel.setFont(new Font("Comic Sans MS", 50)); 
    	    titleLabel.setTextFill(Color.DARKBLUE); // 这会将颜色设置为红色
    	    titleLabel.setAlignment(Pos.CENTER);
    	    titleLabel.setPadding(new Insets(0, 0, 40, 0)); 


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
    	    	String username = usernameField.getText(); // 假设 usernameField 是用户名输入字段
    	        String password = passwordField.getText(); // 假设 passwordField 是密码输入字段

    	        // 调用 signUpUser 方法并获取结果
    	        String resultMessage = signUpUser(username, password);

    	        // 显示结果消息
    	        message.setText(resultMessage); // 假设 message 是用来显示消息的 Label
    	       
    	    });
    	    HBox buttonsLS = new HBox();
    	    buttonsLS.setSpacing(10);
    	    buttonsLS.setAlignment(Pos.CENTER);
    	    buttonsLS.getChildren().addAll(loginButton,signUpButton);
    	    
    	    Image lockImage = null;
    	    try {
    	        lockImage = new Image("lock3.jpg");
    	    } catch (Exception e) {
    	        e.printStackTrace();
    	    }

    	    // Create a BackgroundSize object
    	    BackgroundSize backgroundSize = new BackgroundSize(100.0, 100.0, true, true, false, true);

    	    // Create a BackgroundImage with the new BackgroundSize
    	    BackgroundImage backgroundImage = new BackgroundImage(lockImage,
    	                    BackgroundRepeat.NO_REPEAT, 
    	                    BackgroundRepeat.NO_REPEAT, 
    	                    BackgroundPosition.CENTER, 
    	                    backgroundSize);

    	    // Set the background to loginLayout
    	    loginLayout.setBackground(new Background(backgroundImage));


    	    loginLayout.getChildren().addAll(titleLabel, usernameBox, passwordBox, buttonsLS,message);
    	 //   loginLayout.setStyle("-fx-background-color: #d6d6cd;"); 
    	    return new Scene(loginLayout, 1300, 600);
    }
    
    private Scene createMainScene() {
       	
    	hintLabel.setStyle("-fx-text-fill: red;");
    	hintLabel.setFont(new Font(20));

        HBox root = new HBox();
        
        saveComboBox = new ComboBox<>();
        loadComboBox = new ComboBox<>();
        // 确保这些组件在添加项目之前已经初始化
        
        root.setAlignment(Pos.CENTER);
        
        hintLabel.setPrefHeight(50);
        Label backgroundLabel = new Label("Choose background color");
     // 创建ColorPicker组件
        ColorPicker colorPicker = new ColorPicker();

        // 设置默认颜色（可选）
     //   colorPicker.setValue(Color.web("#d6d6cd")); // 默认背景色
        try {
            if (Files.exists(Paths.get("color.txt"))) {
                List<String> lines = Files.readAllLines(Paths.get("color.txt"));
                if (!lines.isEmpty()) {
                    String savedColor = lines.get(0);
                    root.setStyle("-fx-background-color: " + savedColor + ";");
                    colorPicker.setValue(Color.web(savedColor));
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    
        // 为ColorPicker添加事件处理器
        colorPicker.setOnAction(e -> {
            Color newColor = colorPicker.getValue();
            String colorHex = String.format("#%02X%02X%02X",
                (int) (newColor.getRed() * 255),
                (int) (newColor.getGreen() * 255),
                (int) (newColor.getBlue() * 255));
            root.setStyle("-fx-background-color: " + colorHex + ";");
            
            // Save the color to a file
            try (PrintWriter out = new PrintWriter("color.txt")) {
                out.println(colorHex);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
                    
        });
        
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
        methodComboBox.getItems().addAll("Caesar Cipher", "DES", "AES");
        HBox keyBox = new HBox(20);
        Label keyLabel = new Label("Key:");
        TextField keyInput = new TextField();
        keyInput.setPrefWidth(50); 
        keyBox.getChildren().addAll(keyLabel, keyInput);
        HBox saveLoadLocalButtons = new HBox(20);
        Button saveKeyLocalButton = new Button("Save Key to Local");
        Button loadKeyLocalButton = new Button("Load Key from Local");
        saveLoadLocalButtons.getChildren().addAll(saveKeyLocalButton,loadKeyLocalButton);
        VBox saveLoadCloudButtons = new VBox(20);
        
        HBox saveCloud = new HBox(20);
        Label saveLabel = new Label("Tag:");
        saveComboBox.setPrefWidth(190);
        saveComboBox.setEditable(true);
        Button saveKeyCloudButton = new Button("Save Key to Cloud");
        saveCloud.getChildren().addAll(saveLabel,saveComboBox,saveKeyCloudButton);
        HBox loadCloud = new HBox(20);
        Label loadLabel = new Label("Tag:");
        loadComboBox.setPrefWidth(190);
        Button loadKeyCloudButton = new Button("Load Key from Cloud");
        loadCloud.getChildren().addAll(loadLabel,loadComboBox,loadKeyCloudButton);
        saveLoadCloudButtons.getChildren().addAll(saveCloud,loadCloud);
        middle.getChildren().addAll( methodComboBox,keyBox,enDeBtnBox,saveLoadLocalButtons,saveLoadCloudButtons,hintLabel,backgroundLabel,colorPicker);

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
            selectedMethod = methodComboBox.getValue();
           
            System.out.println("Selected encryption method: " + selectedMethod);
            if ("Caesar Cipher".equals(selectedMethod)) {
                keyLabel.setVisible(true);
                keyInput.setVisible(true);
                saveLoadLocalButtons.setVisible(false);
                saveLoadCloudButtons.setVisible(false);
            } else {
                keyLabel.setVisible(false);
                keyInput.setVisible(false);
                saveLoadLocalButtons.setVisible(true);
                saveLoadCloudButtons.setVisible(true);
                populateComboBoxes();
            }
        });

        // ENCRYPT button event handler
        encoButton.setOnAction(e -> {
           selectedMethod = methodComboBox.getValue();
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
            selectedMethod = methodComboBox.getValue();
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
        saveKeyLocalButton.setOnAction(e -> {
            selectedMethod = methodComboBox.getValue();
            if ("DES".equals(selectedMethod)) {
                saveKeyUsingFileChooser(desKey, "DES");
            } else if ("AES".equals(selectedMethod)) {
                saveKeyUsingFileChooser(aesKey, "AES");
            }
        });

        loadKeyLocalButton.setOnAction(e -> {
            selectedMethod = methodComboBox.getValue();
            if ("DES".equals(selectedMethod)) {
                loadKeyUsingFileChooser("DES");
            } else if ("AES".equals(selectedMethod)) {
                loadKeyUsingFileChooser("AES");
            } else {
                textRight.setText("Only \"DES\" OR \"AES\" provided save key method");
            }
        });
        
        saveKeyCloudButton.setOnAction(e ->{
        	
        	hintLabel.setText("");       
            selectedMethod = methodComboBox.getValue();
            if (selectedMethod == null) {
                hintLabel.setText("Select \"DES\" OR \"AES\" Method");
                return;
            }
            
            Key currentKey = "DES".equals(selectedMethod) ? desKey : aesKey;
            if (currentKey == null) {
                hintLabel.setText("Please press \"ENCRYPT\" button first!");
                return;
            }

            String enteredTag = saveComboBox.getValue(); // 获取ComboBox的当前值
            if (enteredTag == null || enteredTag.trim().isEmpty()) {
                hintLabel.setText("Please enter a tag!");
                return;
            }

            try {
                handleTagEntry(enteredTag, currentKey); // 处理标签条目
            } catch (Exception ex) {
                ex.printStackTrace(); // 更好的异常处理
            }
                
            populateComboBoxes();
        });
        
        loadKeyCloudButton.setOnAction(e->{
        	hintLabel.setText("");
        	selectedMethod = methodComboBox.getValue();
        	  if ("DES".equals(selectedMethod)||"AES".equals(selectedMethod)) {
        		  loadKeyfromCloud(userNameCurrent, loadComboBox.getValue(),methodComboBox.getValue());
              } else {
            	  hintLabel.setText("Select \"DES\" OR \"AES\" Method");
              }
        });
        
        return new  Scene(root, 1300, 600);
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
    	
    	//Convert key to a byte array， and convert byte array to Base64 string for easy storage
    	String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());
    	
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
    
    public String signUpUser(String newUsername, String newPassword) {
        String checkUserSql = "SELECT COUNT(*) FROM user WHERE username = ?";

        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement checkUserStmt = connection.prepareStatement(checkUserSql)) {
            
            checkUserStmt.setString(1, newUsername);
            try (ResultSet resultSet = checkUserStmt.executeQuery()) {
                if (resultSet.next() && resultSet.getInt(1) > 0) {
                    return "Username already exists. Please choose a different username."; // 用户名已存在
                }
            }

            insertUser(new User(newUsername, newPassword));
            
            return "User registered successfully, you could now log in."; // 用户注册成功
        } catch (SQLException e) {
            e.printStackTrace();
            return "Database error occurred. Please try again."; // 数据库错误
        }
    }

    
    public void insertUser(User user) {

        try {
            Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            String sql = "INSERT INTO `user` (username, password) VALUES (?, ?)";
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

    public void loadKeyfromCloud(String userNameCurrent, String keyLabel,String keyType) {
    	
	    // Check if keyLabel is null or empty
	    if (keyLabel == null || keyLabel.trim().isEmpty()) {
	        hintLabel.setText("Please enter a tag!");
	        return;
	    }
    	   	
        String encryptedKey = null;
        try {
            Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            String sql = "SELECT KeyValue FROM `keys` WHERE Username = ? AND KeyLabel = ? AND KeyType = ?";
            PreparedStatement statement = connection.prepareStatement(sql);
            statement.setString(1, userNameCurrent);
            statement.setString(2, keyLabel);
            statement.setString(3, keyType);

            ResultSet resultSet = statement.executeQuery();
            if (resultSet.next()) {
            	encryptedKey = resultSet.getString("KeyValue");
                System.out.println("encrypted key in database: " + encryptedKey);
            }

            resultSet.close();
            statement.close();
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
            // Handle SQL exception
        }

        try {
            // A DES for decrypting the encryptedKey
            DES des = new DES();
            String decryptEncryptedKey = des.decrypt(encryptedKey,masterKey);
            byte[] decryptedKey = Base64.getDecoder().decode(decryptEncryptedKey);
            
            switch (keyType) {
            case "DES":
                SecretKeyFactory desFactory = SecretKeyFactory.getInstance("DES");
                KeySpec desKeySpec = new DESKeySpec(decryptedKey);
                desKey = desFactory.generateSecret(desKeySpec);
                break;

            case "AES":
                aesKey = new SecretKeySpec(decryptedKey, "AES");
                break;

            default:
                hintLabel.setText("Invalid key type!");
                return;
            }     

        } catch (Exception e) {
            e.printStackTrace();
            // Handle decryption exception
        }
        hintLabel.setText("Successfully loaded the key!");
    }
    
    public boolean checkTagExists(String userNameCurrent, String keyLabel, String keyType) {
    	String sql = "SELECT COUNT(*) FROM `keys` WHERE KeyLabel = ? AND KeyType = ? AND Username = ?";
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, keyLabel);
            statement.setString(2, keyType);
            statement.setString(3, userNameCurrent);

            ResultSet resultSet = statement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt(1) > 0; // 如果计数大于0，则表示存在
            }
        } catch (SQLException e) {
            e.printStackTrace();
            // 处理异常
        }
        return false; // 如果出现异常或未找到记录
    }
    
   public List<String> getAllTags(String userNameCurrent, String keyType){
	   ArrayList<String> tags = new ArrayList<String>();
	   String sql = "SELECT KeyLabel FROM `keys` WHERE Username = ? AND KeyType = ?";
       
       try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            PreparedStatement statement = connection.prepareStatement(sql)) {
           
           statement.setString(1, userNameCurrent);
           statement.setString(2, keyType);

           try (ResultSet resultSet = statement.executeQuery()) {
        	   String tag;
        	   while(resultSet.next()) {
        		   tag = resultSet.getString("KeyLabel");
        		   tags.add(tag);
        	   }
           }
       } catch (SQLException e) {
           e.printStackTrace();
           // Consider more robust exception handling strategy here
       }
	   return tags;
   }
   
   void populateComboBoxes() {
	    selectedMethod = methodComboBox.getValue();
	    List<String> tags = getAllTags(userNameCurrent,selectedMethod);
	    setTagsInSaveComboBox(tags);
	    setTagsInLoadComboBox(tags);
	}
   
   void setTagsInSaveComboBox(List<String> tags) {
	    saveComboBox.getItems().clear(); // Clear existing items
	    saveComboBox.getItems().addAll(tags); // Add new tags
	}
   
   void setTagsInLoadComboBox(List<String> tags) {
	    loadComboBox.getItems().clear(); // Clear existing items
	    loadComboBox.getItems().addAll(tags); // Add new tags
	}
   
   private void handleTagEntry(String enteredTag, Key key) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
	   
	   String encryptedKey = encryptKeyWithMasterKey(key);
	    if (checkTagExists(userNameCurrent, enteredTag, methodComboBox.getValue())) {
	        // 如果标签已存在，询问用户是否覆盖
	        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
	        alert.setTitle("Tag Exists");
	        alert.setHeaderText("The tag '" + enteredTag + "' already exists.");
	        alert.setContentText("Do you want to overwrite the existing key?");

	        Optional<ButtonType> result = alert.showAndWait();
	        if (result.isPresent() && result.get() == ButtonType.OK) {
	            updateKeyValueInCloud(userNameCurrent, enteredTag, encryptedKey, methodComboBox.getValue());  
	        } else {
	            saveComboBox.getEditor().clear();
	        }
	    } else {
	        insertKeyValueInCloud(userNameCurrent, enteredTag, encryptedKey, methodComboBox.getValue());
	    }
	}
   
   public String encryptKeyWithMasterKey(Key keyToEncrypt) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
	    //Convert key to a byte array and convert byte array to Base64 string for easy storage
	    String base64Key = Base64.getEncoder().encodeToString(keyToEncrypt.getEncoded());
	    // 使用DES算法和masterKey对base64Key进行加密
	    DES des = new DES();
	    return des.encrypt(base64Key, masterKey);
	}

   
   public void updateKeyValueInCloud(String username, String keyLabel, String newKeyValue, String keyType) {
	    // 使用数据库连接更新 keyValue
	    try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
	        String sql = "UPDATE `keys` SET KeyValue = ? WHERE Username = ? AND KeyLabel = ? AND KeyType = ?";
	        try (PreparedStatement statement = connection.prepareStatement(sql)) {
	            statement.setString(1, newKeyValue);
	            statement.setString(2, username);
	            statement.setString(3, keyLabel);
	            statement.setString(4, keyType);

	            statement.executeUpdate();
	        }
	    } catch (SQLException e) {
	        e.printStackTrace();
	        // 更详细的错误处理
	    }
	}
   
   public void insertKeyValueInCloud(String username, String keyLabel, String newKeyValue, String keyType) {
	     
       try {
           Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
           String sql = "INSERT INTO `keys` (Username, KeyLabel, KeyValue,KeyType) VALUES (?,?,?,?)";
           PreparedStatement statement = connection.prepareStatement(sql);
           statement.setString(1, userNameCurrent);
           statement.setString(2, keyLabel);
           statement.setString(3, newKeyValue);
           statement.setString(4, keyType);
           
           statement.executeUpdate();
           statement.close();
           connection.close();
       } catch (SQLException e) {
           e.printStackTrace();
           // Handle SQL exceptions
       }
       System.out.println("successfully save to cloud");
       hintLabel.setText("Successfully save key to cloud!");
   }


    
    public void start(Stage primaryStage) {
    	   	
    	masterKey = new SecretKeySpec(Base64.getDecoder().decode("1nPsGt/3uv4="), "DES");
    	this.primaryStage = primaryStage;
    	primaryStage.show();
   // 	insertUser(new User("Michael","123"));
        Scene loginScene = createLoginScene(primaryStage);
        primaryStage.setScene(loginScene);
        primaryStage.setTitle("SafeCipher Login");     
        Rectangle2D screenBounds = Screen.getPrimary().getVisualBounds();
        primaryStage.setX((screenBounds.getWidth() - loginScene.getWidth()) / 2);
        primaryStage.setY((screenBounds.getHeight() - loginScene.getHeight()) / 2);
    }

    
    public static void main(String[] args) {
        launch(args);
    }
}
