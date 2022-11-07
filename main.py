from datetime import datetime
from enum import Enum
import os
import tkinter as tk
from tkinter import filedialog
from tkinter import scrolledtext
from tkinter import ttk
import tkinterweb as tkweb
import socket as sk
import ssl as ssl
from email.base64mime import body_encode
import xml.sax as sax
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
import logging
from email.mime.text import MIMEText
import imaplib as imaplib
from email import message_from_string
from email import header
from email import utils
from email.mime.multipart import MIMEMultipart


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
    Choose_User = 0
    Choose_SMTP_Server=1
    Input_Info=2
    Connect_SMTP=3
    Input_Dst=4
    Process=5
    Inbox=6
    Process_Done=7

class App(ttk.Frame):
    __state = State.Choose_SMTP_Server
    __mail_server_list = ["qq.com", "sina.com","gmail.com", "163.com"]
    __mail_server = None
    __frame = None
    __account_name = None
    __srcaddr = None
    __password = None
    __dstaddr = None
    __ccaddr = None
    __remember = None
    __mail_server_choice = None
    __ssl_port = 465
    __tls_port = 587
    __logger=None
    __subject = None
    __content = None
    __webview=None
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
        self.__srcaddr=tk.StringVar(None)
        self.__dstaddr=tk.StringVar(None)
        self.__content = tk.StringVar(None)
        self.__password = tk.StringVar(None)
        self.__account_name = tk.StringVar(None) 
        self.__mail_server_choice =tk.IntVar(value=1)
        self.__mail_server=tk.StringVar(None)
        self.__userlist=[]
        self.__tree=ET.parse('info.xml')
        self.__tree_root=self.__tree.getroot()
        self.__webview = tkweb.HtmlFrame(self.master)
        self.__mail_list = []
        self.__file_list = []
        self.__console = scrolledtext.ScrolledText(self, width=70, height=30)
        
        self.__logger=logging.getLogger()
        self.__logger.addHandler(WidgetLogger(self.__console))
        self.__logger.setLevel(logging.DEBUG)
        logging.info("Welcome to SMTP Client\n")
        
        
    def __show_console(self,show):
        if show:
            self.__console.grid(row=0, column=9, sticky='w')
        else:
            self.__console.grid_forget()
        
    
    def __clear(self):
        self.__show_console(False)
        self.__webview.pack_forget()
        for i in self.__frame.winfo_children():
            i.destroy()
    
    def __goto_state(self, state):
        self.__clear()
        self.__state = state
        print(state)
        if self.__state == State.Choose_User:
            self.__choose_user()
        elif self.__state == State.Choose_SMTP_Server:
            self.__choose_mail_server()
        elif self.__state == State.Input_Info:
            self.__info_input()
        elif self.__state == State.Input_Dst:
            self.__input_dsraddr()
        elif self.__state == State.Process:
            self.__process()
        elif self.__state == State.Inbox:
            self.__inbox()
        elif self.__state == State.Process_Done:
            self.__process_done()
        else:
            pass

    def __choose_user(self):
        tk.Label(self.__frame, text="Choose User",height=4).grid(row=0, column=0, sticky='w')
        self.__userlist.clear()
        for user in self.__tree_root:
            userinfo={"name":user.attrib["name"],"username":user.find("username").text,"password":user.find("password").text,"server":user.find("server").text}
            self.__userlist.append(userinfo)
        i=1
        def next(skip):
            if skip:
                self.__srcaddr=tk.StringVar(value= user["username"])
                self.__mail_server=tk.StringVar(value=user["server"])
                self.__password=tk.StringVar(value=user["password"])
                self.__goto_state(State.Inbox)
            else:
                self.__goto_state(State.Choose_SMTP_Server)
        for user in self.__userlist:
            ttk.Button(self.__frame,text=user["name"]+"\n"+user["username"],command=lambda p=True:next(p)).grid(row=i,column=0,sticky="w")
            ttk.Button(self.__frame,text="Delete",command=lambda p=user["name"]: self.__delete_user(p)).grid(row=i,column=1,sticky="w")
            i+=1
        ttk.Button(self.__frame,text="Add User",command=lambda p=False: next(p)).grid(row=i,column=0,sticky="w")
    def __choose_mail_server(self):
        def __naccheck(entry):
            if self.__mail_server_choice.get()!=6:
                entry.configure(state='disabled')
            else:
                entry.configure(state='normal')
                
        def __set_mail_server():
            if self.__mail_server_choice.get() == 6:
                self.__mail_server = tk.StringVar(value=entry.get().strip())
            else:
                self.__mail_server = tk.StringVar(value=self.__mail_server_list[self.__mail_server_choice.get()-1].strip())
            self.__goto_state(State.Input_Info)
        
        
        tk.Label(self.__frame, text="Choose:").grid(row=1, column=1, sticky='w')
        
        entry = tk.Entry(self.__frame,  width="30")
        entry.grid(row=6, column=4, sticky='w')
        if(self.__mail_server_choice.get()==6):
            entry.configure(state='normal')
            entry.insert(20, self.__mail_server.get())
        else:
            entry.insert(20, 'smtp.yourserver.com')
            entry.configure(state='disabled')
        i=1
        for server in self.__mail_server_list:
            radio_button = ttk.Radiobutton(self.__frame, text=server, variable=self.__mail_server_choice, value=i,command=lambda e=entry: __naccheck(e))
            radio_button.grid(row=i, column=2, sticky='w')
            i+=1
        radio_button = ttk.Radiobutton(self.__frame, text="else", variable=self.__mail_server_choice, value=6,command=lambda e=entry: __naccheck(e))    
        radio_button.grid(row=6, column=2, sticky='w')
        ttk.Button(self.__frame, text="Previous", command=lambda p=State.Choose_User:self.__goto_state(p)).grid(row=7, column=2, sticky='w')
        ttk.Button(self.__frame, text="Next", command=__set_mail_server).grid(row=7, column=5, sticky='w')

      
      
    def __info_input(self):
        def next():
            self.__update_info(self.__account_name.get(),self.__mail_server.get(),self.__srcaddr.get(),self.__password.get())
            self.__goto_state(State.Inbox)
        
        label_text=tk.StringVar()
        label_text.set("Account Name:")
        label=tk.Label(self.__frame, textvariable=label_text, height=4).grid(row=0, column=1, sticky='w')
        entry=ttk.Entry(self.__frame,textvariable=self.__account_name,width=50)
        entry.grid(row=0, column=2, sticky='w')
        
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
        button=ttk.Button(self.__frame, text="Create", command=next).grid(row=4, column=3, sticky='e')

    def __update_info(self,name,server,username,password):
        for child in self.__tree_root:
            if child.attrib["name"]==name:
                child.find("server").text=server
                child.find("username").text=username
                child.find("password").text=password
                return
        new_user=ET.Element("user")
        new_user.attrib["name"]=name
        new_user.append(ET.Element("server"))
        new_user.append(ET.Element("username"))
        new_user.append(ET.Element("password"))
        new_user.find("server").text=server
        new_user.find("username").text=username
        new_user.find("password").text=password
        self.__tree_root.append(new_user)
        ET.dump(new_user)
        
        self.__tree.write('info.xml')
    def __delete_user(self,name):
        for child in self.__tree_root:
            if child.attrib["name"]==name:
                self.__tree_root.remove(child)
                self.__tree.write('info.xml')
                self.__goto_state(State.Choose_User)
                return
    def __login(self):
        self.__show_console(True)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            
            raw_sock = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
            logging.info(f"Connecting to smtp.{self.__mail_server.get()}:{self.__tls_port} ...\n")
            raw_sock.connect(("smtp."+self.__mail_server.get(), self.__tls_port)) 
            clientSocket = context.wrap_socket(raw_sock, server_hostname="smtp."+self.__mail_server.get())
        except ssl.SSLError:
            logging.warning("SSL Error\n")
            
            logging.info("STARTTLS not supported, using SSL instead")
            context=ssl.create_default_context()
            raw_sock = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
            logging.info(f"Connecting to smtp.{self.__mail_server.get()}:{self.__ssl_port} ...\n")
            raw_sock.connect(("smtp."+self.__mail_server.get(), self.__ssl_port)) 
            clientSocket = context.wrap_socket(raw_sock, server_hostname="smtp."+self.__mail_server.get())
        recv = clientSocket.recv(1024).decode()
        logging.info("SERVER: \n"+recv)
        if '220' != recv[:3]:
            logging.error('220 reply not received from server.')
            return False
        logging.debug("Socket Connected\n")
        

        heloCommand = 'EHLO '+"smtp."+self.__mail_server.get()+'\r\n'
        clientSocket.send(heloCommand.encode()) 
        logging.info("CLIENT: \n"+heloCommand)
        
        recv1 = clientSocket.recv(1024).decode()
        logging.info("SERVER: \n"+recv1)
        if '250' != recv1[:3]:
            logging.error('250 reply not received from server.')
            return False
        logging.debug("EHLO Success\n")
            

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
            value=text.get("1.0",tk.END)
            for file in value.splitlines():
                if file!="":
                    self.__file_list.append(file)
            self.__goto_state(State.Process)
        def open_file(text):
            filename=filedialog.askopenfilename(title="Open file")
            text.config(state=tk.NORMAL)
            text.insert(tk.END,filename+"\n")
            text.config(state=tk.DISABLED)
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
        
        text=scrolledtext.ScrolledText(self.__frame, wrap=tk.WORD,width=40, height=4,font=("Times New Roman", 8))
        text.grid(row=5, column=1, sticky='w')
        ttk.Button(self.__frame, text="Previous", command=lambda p=State.Inbox: self.__goto_state(p)).grid(row=4, column=0, sticky='w')
        ttk.Button(self.__frame, text="Attach", command=lambda :open_file(text)).grid(row=4, column=1, sticky='w')
        ttk.Button(self.__frame, text="Send", command=lambda :next()).grid(row=4, column=2, sticky='e')
    
    def __process(self):
        self.__show_console(True)
        sock=self.__login()

        for i in range(1,4):
            if sock==False:
                logging.error("Connection Failed")
                logging.info(f"Retry Attempt {i}")
                ret=self.__login()

        if sock==False:
            logging.error("Connection Failed")
            logging.warning("Please Check Your Internet Connection And Your Account")
            # self.__goto_state(State.Choose_SMTP_Server)
        
        From_mail=self.__srcaddr.get()
        To_mail=self.__dstaddr.get()
        Cc_mail_list=[]
        for i in self.__ccaddr.get().strip().split(','):
            if(i.strip()!=''):
                Cc_mail_list.append(i.strip())
        Date=datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
        Data=MIMEMultipart()
        # Data=MIMEText(self.__content.get(), 'plain', 'utf-8')
        Data['Subject']=header.Header(self.__subject.get(), 'utf-8')
        Data['From']=header.Header(From_mail, 'utf-8')
        Data['To']=header.Header(To_mail, 'utf-8')
        Data['Cc']=header.Header(','.join(Cc_mail_list), 'utf-8')
        Data['Date']=header.Header(Date,'utf-8')
        Data.attach(MIMEText(self.__content.get(), 'plain', 'utf-8'))
        for file in self.__file_list:
            att = MIMEText(open(file, 'rb').read(), 'base64', 'utf-8')
            att["Content-Type"] = 'application/octet-stream'
            att["Content-Disposition"] = 'attachment; filename='+file.split('/')[-1]
            Data.attach(att)
        
        command = "MAIL FROM: <"+From_mail+">\r\n"
        sock.send(command.encode()) 
        logging.info("CLIENT: \n"+command)
        recv = sock.recv(1024).decode()
        logging.info("SERVER: \n"+recv)
        if '250' != recv[:3]:
            logging.error('250 reply not received from server.')
            return self.__goto_state(State.Process_Done)
        logging.debug("MAIL FROM Success\n")
        
        command = "RCPT TO: <"+To_mail+">\r\n"
        sock.send(command.encode()) 
        logging.info("CLIENT: \n"+command)
        recv = sock.recv(1024).decode()
        logging.info("SERVER: \n"+recv)
        if '250' != recv[:3]:
            logging.error('250 reply not received from server.')
            return self.__goto_state(State.Process_Done)
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
                return self.__goto_state(State.Process_Done)
            logging.debug("RCPT TO Success\n")
        
        command="DATA\r\n"
        sock.send(command.encode())
        logging.info("CLIENT: \n"+command)
        recv = sock.recv(1024).decode()
        logging.info("SERVER: \n"+recv)
        if '354' != recv[:3]:
            logging.error('354 reply not received from server.')
            return self.__goto_state(State.Process_Done)
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
            return self.__goto_state(State.Process_Done)
        logging.debug("Data End Success\n")
        
        command="QUIT\r\n"
        sock.send(command.encode()) 
        logging.info("CLIENT: \n"+command)
        recv = sock.recv(1024).decode()
        logging.info("SERVER: \n"+recv)
        if '221' != recv[:3]:
            logging.error('221 reply not received from server.')
            return self.__goto_state(State.Process_Done)
        logging.debug("Quit Success\n")
        return self.__goto_state(State.Process_Done)
    def __process_done(self):
        self.__show_console(True)
        ttk.Button(self.__frame, text="Back", command=lambda: self.__goto_state(State.Inbox)).grid(row=4, column=0, sticky='w')
        ttk.Button(self.__frame, text="Send Another Mail", command=lambda: self.__goto_state(State.Input_Dst)).grid(row=4, column=1, sticky='e')
    
    
    def __imap(self):
        mail_list=[]
        print("imap."+self.__mail_server.get())
        imap = imaplib.IMAP4_SSL("imap."+self.__mail_server.get())
        
        # login to server
        imap.login(self.__srcaddr.get(), self.__password.get())

        imap.select('Inbox')

        typ, data = imap.search(None, 'ALL')
        if typ == 'OK':
            for num in data[0].split():
                tmp, data = imap.fetch(num, '(RFC822)')
                if tmp == 'OK':
                    mail={}
                    # print('**********************************begin******************************************')
                    try:
                        msg = message_from_string(data[0][1].decode("utf-8"))
                        msgCharset = header.decode_header(msg.get('Subject'))[0][1]
                    except:
                        print("decode error")
                    # print(msg)
                    recv_date = header.decode_header(msg.get('Date'))[0][0]
                    mail_from = header.decode_header(msg.get('From'))[0][0]
                    mail_to = header.decode_header(msg.get('To'))[0][0]
                    subject = header.decode_header(msg.get('Subject'))[0][0]
                    if type(mail_from) == bytes:
                        mail_from = mail_from.decode(msgCharset)
                    if type(mail_to) == bytes:
                        mail_to = mail_to.decode(msgCharset)
                    if type(subject) == bytes:
                        subject = subject.decode(msgCharset)
                    # print("Message %s\n\n%s\n" % (num, subject))
                    # print('From:' + mail_from + '\nTo:' + mail_to + ' \nDate:' + recv_date)
                    mail["From"]=mail_from
                    mail["To"]=mail_to
                    mail["Date"]=recv_date
                    mail["Subject"]=subject

                    transfer_encoding = utils.parseaddr(
                        msg.get('Content-Transfer-Encoding'))[1]
                    for part in msg.walk():
                        if not part.is_multipart():
                            name = part.get_param("name")
                            if not name:  # 如果邮件内容不是附件可以打印输出
                                    if transfer_encoding == '8bit':
                                        content = part.get_payload(decode=False)
                                    else:
                                        try:
                                            content = part.get_payload(decode=True).decode(msgCharset)
                                        except:
                                            content = part.get_payload(decode=True).decode('utf8')
                    # print(content)
                    mail["Content"]=content
                    mail_list.append(mail)
                
        imap.close()
        imap.logout()
        return mail_list

    def __inbox(self):
        ttk.Button(self.__frame, text="Refresh", command=self.__inbox).grid(row=0, column=0, sticky='w')
        ttk.Button(self.__frame, text="Send Mail", command=lambda: self.__goto_state(State.Input_Dst)).grid(row=1, column=0, sticky='e')
        self.__mail_list=self.__imap()
        i=1
        for mail in self.__mail_list:
            ttk.Button(self.__frame, text=mail["Subject"], command=lambda p=i-1: self.__show_email_content(p),width=20).grid(row=i, column=2, sticky='w')
            i+=1
        ttk.Button(self.__frame, text="Previous", command=lambda: self.__goto_state(State.Choose_User)).grid(row=i, column=0, sticky='w')

    def __show_email_content(self,num):
        mail=self.__mail_list[num]
        content = mail["Content"]
        self.__save_data(content)
        abs_path =  os.path.abspath("content.html")
        
        self.__webview.load_file("file://"+abs_path,force=True,decode="utf-8")

        self.__webview.pack(fill='both', expand=True)

    def __save_data(self,content):
            with open('content.html', 'w', encoding='utf-8') as f:
                f.write(content)
    def launch(self):
        self.__goto_state(State.Choose_User)
        self.mainloop()






def main():
    app=App()
    app.launch()



if __name__ == "__main__":
    main()
