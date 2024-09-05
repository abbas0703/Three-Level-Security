# Three-Level-Security With GO-LANG

This project is a user registration and login system built with Go, MongoDB, and HTML templates. It includes features like password hashing, CAPTCHA validation, and email notifications.

## Features

### 1. Password Hashing
- User passwords are securely hashed using the SHA-256 algorithm before being stored in the MongoDB database. This ensures that passwords are not stored in plain text.

### 2. CAPTCHA Validation
- A CAPTCHA code is generated and validated during user registration and login processes to enhance security and prevent bots from accessing the system.

### 3. Email Notifications
- Upon successful login, the system sends an email notification to the user, confirming the login. This is done using the SMTP protocol, with the sender's credentials securely stored in environment variables.

### 4. Secure User Registration
- Users can register with a unique username and password. The system checks for the existence of the username before creating a new account, ensuring no duplicates.

### 5. Environment Variables
- Sensitive information like MongoDB URI, SMTP credentials, and email addresses are managed through environment variables, keeping them secure and separate from the codebase.

### 6. Session Management
- The system uses cookies to manage CAPTCHA codes, ensuring that the codes are only valid for a limited time, adding an extra layer of security.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/yourrepository.git
   ```

2. Navigate to the project directory:
   ```bash
   cd yourrepository
   ```
3. Install the required dependencies:
   ```bash
   go get
   ```
4. Create a .env file in the root directory and add your environment variables:
   ```plaintext
   MONGODB_URI=your_mongodb_uri
   FROM_EMAIL=your_email@example.com
   FROM_EMAIL_PASSWORD=your_email_password
   SMTP_ADDR=smtp.your-email-provider.com
   ```
5. Run the application:
  ```bash
  go run main.go
  ```
6. Access the application at http://localhost:8080.

### Usage

- **Registration**: Visit /register to create a new account. Enter your desired username, password, and the CAPTCHA code displayed.

- **Login**: Visit /login to log into your account. After entering your username, password, and CAPTCHA code, an email notification will be sent to your registered email address upon successful login.

- **Main Page**: After logging in, you will be redirected to the main page, where you can see a welcome message.

## Output:

![Screenshot 2024-08-21 230837](https://github.com/user-attachments/assets/22e40461-807a-4e98-a69e-a9999dd38ec3)

![Screenshot 2024-08-21 231248](https://github.com/user-attachments/assets/bfcb8a65-d9f4-4265-b746-1cbff7f7a2cb)

MongoDB
![Screenshot 2024-08-21 231011](https://github.com/user-attachments/assets/12399258-c9c3-4260-b4cb-d43be23946ae)

## Contributing

Feel free to fork this repository, create a branch, and submit a pull request with your enhancements or bug fixes.















