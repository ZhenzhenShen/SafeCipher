The link to the vedio domo is below.
https://youtu.be/5XJdaN8ZOOI
1. Implement encryption and decryption using shift cipher (i.e. Caesar cipher). Allow users to
input plain text and key, apply the Caesar cipher encryption, and display the encrypted text. The
user should also be able to decrypt the text.
2. Allow users to choose between algorithms.Provide an option to save/load AES/DES keys
to/from a file by using filechooser locally. The user could also save and load keys from cloud. The
keys on cloud are encrypted.
3. For saving and loading on cloud, the UI gave clues for selecting methods, encrypting to get a
key and choose a tag. If a tag already exists, the UI will let the user know and choose to overwrite
existing key or enter a new tag. The loadTagComboBox are timely updated with the change of
saveTagComboBox.
4. As to the login, the password “123” is securely saved using SHA-256.
5. As to the sign up, if a username already exists, the UI will let the user to enter another
username.
6. Implement advanced GUI features for better user experience by giving user messages when
login or save keys to cloud. Because “AES””DES” and ”Caesar cipher” got different contents with
data, so I set corresponding content visible or invisible accordingly.
