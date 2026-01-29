import sys
from PyQt5.QtWidgets import *
from chat_client import ChatClient
from admin_panel import AdminLogin, AdminPanel

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Secure Chat System")
        self.setFixedSize(400, 200)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Secure Chat System")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold; margin: 20px;")
        layout.addWidget(title)
        
        # Buttons
        client_btn = QPushButton("Launch Chat Client")
        client_btn.clicked.connect(self.launch_client)
        layout.addWidget(client_btn)
        
        admin_btn = QPushButton("Launch Admin Panel")
        admin_btn.clicked.connect(self.launch_admin)
        layout.addWidget(admin_btn)
        
        exit_btn = QPushButton("Exit")
        exit_btn.clicked.connect(self.close)
        layout.addWidget(exit_btn)
        
        self.setLayout(layout)
    
    def launch_client(self):
        self.chat_client = ChatClient()
        self.chat_client.show()
    
    def launch_admin(self):
        from admin_panel import AdminLogin, AdminPanel
        
        login = AdminLogin()
        if login.exec_() == QDialog.Accepted:
            self.admin_panel = AdminPanel()
            self.admin_panel.show()

def main():
    app = QApplication(sys.argv)
    
    # Check if we should start server or client
    if len(sys.argv) > 1 and sys.argv[1] == "--server":
        from chat_server import ChatServer
        print("Starting chat server...")
        server = ChatServer()
        server.start()
    else:
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())

if __name__ == "__main__":
    main()