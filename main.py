from datetime import datetime
from email.header import Header
from enum import Enum
import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
import socket as sk
import ssl as ssl
from email.base64mime import body_encode
import xml.sax as sax
import logging
from email.mime.text import MIMEText

class WidgetLogger(logging.Handler):
    def __init__(self, widget):
        logging.Handler.__init__(self)
        self.setLevel(logging.DEBUG)
        self.widget = widget
        self.widget.config(state='disabled')
        self.widget.tag_config("INFO", foreground="black")
        self.widget.tag_config("DEBUG", foreground="grey")
        self.widget.tag_config("WARNING", foreground="orange")
        self.widget.tag_config("ERROR", foreground="red")
        self.widget.tag_config("CRITICAL", foreground="red", underline=1)

        self.red = self.widget.tag_configure("red", foreground="red")
    def emit(self, record):
        self.widget.config(state='normal')
        # Append message (record) to the widget
        self.widget.insert(tk.END, self.format(record) + '\n', record.levelname)
        self.widget.see(tk.END)  # Scroll to the bottom
        self.widget.config(state='disabled') 
        self.widget.update() # Refresh the widget




class xml_handler(sax.ContentHandler):
    def __init__(self):
        self.CurrentData = ""
        self.SMTP_server = ""
        self.username = ""
        self.password = ""
        self.remember = False

 
   # 元素开始事件处理
    def startElement(self, tag, attributes):
        self.CurrentData = tag
        if tag == "info":
            print("*****Info*****")
    def characters(self, content):
        if self.CurrentData == "server":
            self.SMTP_server = content
        elif self.CurrentData == "username":
            self.username = content
        elif self.CurrentData == "password":
            self.password = content
        elif self.CurrentData == "remember":
            if content == "True":
                self.remember = True
            else :
                self.remember = False
    def endElement(self, tag):
        if self.CurrentData == "server":
            print("SMTP_server:", self.SMTP_server)
        elif self.CurrentData == "username":
            print("username:", self.username)
        elif self.CurrentData == "password":
            print("password:", self.password)
        elif self.CurrentData == "remember":
            print("remember:", self.remember)
        self.CurrentData = ""



class State(Enum):
    Choose_SMTP_Server=0
    Input_Info=1
    Connect_SMTP=2
    Input_Dst=3
    Process=4

class App(ttk.Frame):
    __state = State.Choose_SMTP_Server
    __mail_server_list = ["smtp.qq.com", "smtp.sina.com","smtp.gmail.com", "smtp.163.com"]
    __mail_server = None
    __frame = None
    __srcaddr = None
    __password = None
    __dstaddr = None
    __ccaddr = None
    __date = None
    __remember = None
    __mail_server_choice = None
    __ssl_port = 465
    __tls_port = 587
    __logger=None
    __subject = None
    __content = None
    def __init__(self, master=None):
        super().__init__(master)
        self.pack()
        self.master.title("SMTP Client")
        self.master.geometry("1080x500")
        self.master.iconbitmap("e_mail.ico")
        self.__frame = ttk.Frame(self,padding=(20,20))
        self.__frame.grid(row=0, column=0)
        self.__subject=tk.StringVar(None)
        self.__ccaddr=tk.StringVar(None)
        self.__dstaddr=tk.StringVar(value="someone@example.com")
        self.__content = tk.StringVar(None)
        # 创建一个 XMLReader
        self.__parser = sax.make_parser()
        # turn off namepsaces
        self.__parser.setFeature(sax.handler.feature_namespaces, 0)
        
        # 重写 ContextHandler
        self.__parser.setContentHandler(xml_handler())
        
        self.__parser.parse("info.xml")
        server=xml_handler.SMTP_server
        username=xml_handler.username
        password=xml_handler.password
        if(server!=None and username!=None and password!=None):
            self.__mail_server=tk.StringVar(value=server)
            self.__srcaddr=tk.StringVar(value=username)
            self.__password=tk.StringVar(value=password)
            self.__remember=tk.BooleanVar(value=True)
        else:
            self.__remember=tk.BooleanVar(value=False)
            
            
        console = scrolledtext.ScrolledText(self, width=70, height=30)
        console.grid(row=0, column=9, sticky='w')
        self.__logger=logging.getLogger()
        self.__logger.addHandler(WidgetLogger(console))
        self.__logger.setLevel(logging.DEBUG)
        logging.info("Welcome to SMTP Client\n")
        
        

    
    def __clear(self):
        for i in self.__frame.winfo_children():
            i.destroy()
    
    def __goto_state(self, state):
        self.__clear()
        self.__state = state
        if self.__state == State.Choose_SMTP_Server:
            self.__choose_mail_server()
        elif self.__state == State.Input_Info:
            self.__info_input()
        elif self.__state == State.Input_Dst:
            self.__input_dsraddr()
        elif self.__state == State.Process:
            self.__process()
        else:
            pass

    def __choose_mail_server(self):
        self.__mail_server_choice =tk.IntVar(value=1)
        
        def __naccheck(entry):
            if self.__mail_server_choice.get()!=6:
                entry.configure(state='disabled')
            else:
                entry.configure(state='normal')
                
        def __set_mail_server():
            if self.__mail_server_choice.get() == 6:
                self.__mail_server = tk.StringVar(value=entry.get())
            else:
                self.__mail_server = tk.StringVar(value=self.__mail_server_list[self.__mail_server_choice.get()-1])
            if self.__remember.get():
                pass
            self.__goto_state(State.Input_Info)
        
        
        tk.Label(self.__frame, text="Choose:").grid(row=1, column=1, sticky='w')
        
        entry = tk.Entry(self.__frame,  width="30")
        entry.insert(20, 'smtp.yourserver.com')
        entry.grid(row=6, column=4, sticky='w')
        entry.configure(state='disabled')
        i=1
        for server in self.__mail_server_list:
            radio_button = ttk.Radiobutton(self.__frame, text=server, variable=self.__mail_server_choice, value=i,command=lambda e=entry: __naccheck(e))
            radio_button.grid(row=i, column=2, sticky='w')
            i+=1
        radio_button = ttk.Radiobutton(self.__frame, text="else", variable=self.__mail_server_choice, value=6,command=lambda e=entry: __naccheck(e))    
        radio_button.grid(row=6, column=2, sticky='w')
        
        button=ttk.Button(self.__frame, text="Next", command=__set_mail_server).grid(row=7, column=5, sticky='w')
        cb = ttk.Checkbutton(self.__frame, text='Remember',variable=self.__remember).grid(row=7, column=4, sticky='w')
        if self.__remember.get():
            self.__mail_server_choice.set(6)
            entry.configure(state='normal')
            entry.delete(0,tk.END)
            entry.insert(0,self.__mail_server.get())


      
      
    def __info_input(self):
        if not self.__remember.get():
            self.__srcaddr=tk.StringVar(None)
            self.__password=tk.StringVar(None)
            
        label_text=tk.StringVar()
        label_text.set("Your Email Address:")
        label=tk.Label(self.__frame, textvariable=label_text, height=4).grid(row=1, column=1, sticky='w')
        entry=ttk.Entry(self.__frame,textvariable=self.__srcaddr,width=50)
        entry.grid(row=1, column=2, sticky='w')


        label_text=tk.StringVar()
        label_text.set("Password:")
        label=tk.Label(self.__frame, textvariable=label_text, height=4).grid(row=2, column=1, sticky='w')
        entry=ttk.Entry(self.__frame,textvariable=self.__password,width=50,show="*")
        entry.grid(row=2, column=2, sticky='w')
        
        button=ttk.Button(self.__frame, text="Previous", command=lambda p=State.Choose_SMTP_Server: self.__goto_state(p)).grid(row=4, column=1, sticky='w')
        button=ttk.Button(self.__frame, text="Test Connection", command=lambda :logging.debug("Connection Success") if self.__login()!= False else logging.warning("Connection Failed")).grid(row=4, column=2, sticky='w')
        button=ttk.Button(self.__frame, text="Next", command=lambda p=State.Input_Dst: self.__goto_state(p)).grid(row=4, column=3, sticky='e')

    def __login(self)->bool:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            
            raw_sock = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
            logging.info(f"Connecting to {self.__mail_server.get()}:{self.__tls_port} ...\n")
            raw_sock.connect((self.__mail_server.get(), self.__tls_port)) 
            clientSocket = context.wrap_socket(raw_sock, server_hostname=self.__mail_server.get())
        except ssl.SSLError:
            logging.warning("SSL Error\n")
            
            logging.info("STARTTLS not supported, using SSL instead")
            context=ssl.create_default_context()
            raw_sock = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
            logging.info(f"Connecting to {self.__mail_server.get()}:{self.__ssl_port} ...\n")
            raw_sock.connect((self.__mail_server.get(), self.__ssl_port)) 
            clientSocket = context.wrap_socket(raw_sock, server_hostname=self.__mail_server.get())
        recv = clientSocket.recv(1024).decode()
        logging.info("SERVER: \n"+recv)
        if '220' != recv[:3]:
            logging.error('220 reply not received from server.')
            return False
        logging.debug("Socket Connected\n")
        

        heloCommand = 'EHLO '+self.__mail_server.get()+'\r\n'
        clientSocket.send(heloCommand.encode()) 
        logging.info("CLIENT: \n"+heloCommand)
        
        recv1 = clientSocket.recv(1024).decode()
        logging.info("SERVER: \n"+recv1)
        if '250' != recv1[:3]:
            logging.error('250 reply not received from server.')
            return False
        logging.debug("EHLO Success\n")
        
        # heloCommand = 'HELO MyName\r\n'
        # clientSocket.send(heloCommand.encode())
        # logging.info("CLIENT:\n"+heloCommand)
        
        # recv1 = clientSocket.recv(1024).decode()
        # logging.info("SERVER: \n"+recv1)
        # if '250' != recv1[:3]:
        #     logging.error('250 reply not received from server.') 
        #     return False
            

        logging.info(f"CLIENT: \nAUTH PLAIN username = {self.__srcaddr.get()} password = {self.__password.get()}\n")
        user_pass_encode64 = body_encode(f"\0{self.__srcaddr.get()}\0{self.__password.get()}".encode('ascii'), eol='')
        clientSocket.sendall(f'AUTH PLAIN {user_pass_encode64}\r\n'.encode())
        recv2 = clientSocket.recv(1024).decode()
        logging.info("SERVER: \n"+recv2)
        if '235' != recv2[:3]:
            logging.error('235 reply not received from server.')
            return False
        return clientSocket
        
    
    def __input_dsraddr(self):
        def next():
            self.__content=tk.StringVar(None)
            value=text_area.get("1.0",tk.END)
            self.__content.set(value)
            self.__goto_state(State.Process)
        
        label_text=tk.StringVar()
        label_text.set("Send To:")
        label=tk.Label(self.__frame, textvariable=label_text, height=4).grid(row=0, column=0, sticky='w')
        entry=ttk.Entry(self.__frame,textvariable=self.__dstaddr,width=50).grid(row=0, column=1, sticky='w')
        
        label_text=tk.StringVar()
        label_text.set("Cc:")
        label=tk.Label(self.__frame, textvariable=label_text, height=4).grid(row=1, column=0, sticky='w')
        entry=ttk.Entry(self.__frame,textvariable=self.__ccaddr,width=50).grid(row=1, column=1, sticky='w')
        
        label_text=tk.StringVar()
        label_text.set("Subject:")
        label=tk.Label(self.__frame, textvariable=label_text, height=4).grid(row=2, column=0, sticky='w')
        entry=ttk.Entry(self.__frame,textvariable=self.__subject,width=50).grid(row=2, column=1, sticky='w')
        
        label_text=tk.StringVar()
        label_text.set("Content:")  
        label=tk.Label(self.__frame, textvariable=label_text, height=4).grid(row=3, column=0, sticky='w')
        text_area = scrolledtext.ScrolledText(self.__frame, wrap=tk.WORD,width=40, height=8,font=("Times New Roman", 15))
        text_area.grid(row=3, column=1, sticky='w')
        
        button=ttk.Button(self.__frame, text="Previous", command=lambda p=State.Input_Info: self.__goto_state(p)).grid(row=4, column=0, sticky='w')
        button=ttk.Button(self.__frame, text="Send", command=next).grid(row=4, column=1, sticky='e')
    
    def __process(self):
        sock=self.__login()

        for i in range(1,4):
            if sock==False:
                logging.error("Connection Failed")
                logging.info(f"Retry Attempt {i}")
                ret=self.__login()

        if sock==False:
            logging.error("Connection Failed")
            logging.warning("Please Check Your Internet Connection And Your Account")
            self.__goto_state(State.Choose_SMTP_Server)
        
        From_mail=self.__srcaddr.get()
        To_mail=self.__dstaddr.get()
        Cc_mail_list=[]
        for i in self.__ccaddr.get().strip().split(','):
            if(i.strip()!=''):
                Cc_mail_list.append(i.strip())
        Date=datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
        Data=MIMEText(self.__content.get(), 'plain', 'utf-8')
        Data['Subject']=Header(self.__subject.get(), 'utf-8')
        Data['From']=From_mail
        Data['To']=To_mail
        Data['Cc']=','.join(Cc_mail_list)
        Data['Date']=Date
        
        command = "MAIL FROM: <"+From_mail+">\r\n"
        sock.send(command.encode()) 
        logging.info("CLIENT: \n"+command)
        recv = sock.recv(1024).decode()
        logging.info("SERVER: \n"+recv)
        if '250' != recv[:3]:
            logging.error('250 reply not received from server.')
            return False
        logging.debug("MAIL FROM Success\n")
        
        command = "RCPT TO: <"+To_mail+">\r\n"
        sock.send(command.encode()) 
        logging.info("CLIENT: \n"+command)
        recv = sock.recv(1024).decode()
        logging.info("SERVER: \n"+recv)
        if '250' != recv[:3]:
            logging.error('250 reply not received from server.')
            return False
        logging.debug("RCPT TO Success\n")
        
        for i in Cc_mail_list:
            if i=='':
                continue
            command = "RCPT TO: <"+i+">\r\n"
            sock.send(command.encode()) 
            logging.info("CLIENT: \n"+command)
            recv = sock.recv(1024).decode()
            logging.info("SERVER: \n"+recv)
            if '250' != recv[:3]:
                logging.error('250 reply not received from server.')
                return False
            logging.debug("RCPT TO Success\n")
        
        command="DATA\r\n"
        sock.send(command.encode())
        logging.info("CLIENT: \n"+command)
        recv = sock.recv(1024).decode()
        logging.info("SERVER: \n"+recv)
        if '354' != recv[:3]:
            logging.error('354 reply not received from server.')
            return False
        logging.debug("Data Start Success\n")
        
        command=Data.as_string()
        sock.send(command.encode()) 
        logging.info("CLIENT: \n"+"To: "+To_mail+"\nCc: "+','.join(Cc_mail_list)+"\nSubject: "+self.__subject.get()+"\n"+self.__content.get())
        
        
        command="\r\n.\r\n"
        sock.send(command.encode()) 
        logging.info(command)
        recv = sock.recv(1024).decode()
        logging.info("SERVER: \n"+recv)
        if '250' != recv[:3]:
            logging.error('250 reply not received from server.')
            return False
        logging.debug("Data End Success\n")
        
        command="QUIT\r\n"
        sock.send(command.encode()) 
        logging.info("CLIENT: \n"+command)
        recv = sock.recv(1024).decode()
        logging.info("SERVER: \n"+recv)
        if '221' != recv[:3]:
            logging.error('221 reply not received from server.')
            return False
        logging.debug("Quit Success\n")

    def launch(self):
        self.__goto_state(State.Choose_SMTP_Server)
        self.mainloop()






def main():
    app=App()
    app.launch()



if __name__ == "__main__":
    main()
