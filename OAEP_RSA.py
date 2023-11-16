from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

import os
import time
import queue
import threading

from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox



def key_gen():
    """
    Generate the pair of public key and private key

    Return
        public_key, private_key
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    return private_key



def key_load(file_dir, password=None):
    """
    Load key from file into module type
    Decrypt with password is provided

    parameter:
        file_dir: Inputed key file path
        password: Inputed password

    return:
        private_key: module type key instance
    """

    if password is not None:
        password = password.encode()

    with open(file_dir, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password,
            backend=default_backend()
        )

    return private_key



def key_serialization(private_key, password=None):
    """
    Serialize private key from module type,
    Encrypt with password if provided

    parameter:
        private_key: Inputed key
        password: Inputed password

    return:
        pem: bytes type key / encrypted key
    """

    if password is None:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

    return pem




def encrypt(data, public_key, result, queue=None):
    """
    Encrypt the data with the provided public key

    parameter:
        data: Inputed data
        public_key: Inputed key

    return:
        ciphertext: Encrypted data
    """

    ciphertext = b''

    for i in range(0, len(data), 214):
        ciphertext += public_key.encrypt(
            data[i:i+214],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        if queue.empty():
            queue.put(int(i/len(data)*10000)/100)

        if i%1500 > 214*5:
            result.append(ciphertext)
            ciphertext = b''

    queue.put(100)
    result.append(ciphertext)


def decrypt(data, private_key, result, queue=None):
    """
    Decrypt the data with the provided private key

    parameter:
        data: Inputed encrypted data
        private_key: Inputed key

    return:
        plaintext: Decrypted data
    """

    plaintext = b''

    for i in range(0, len(data), 256):
        plaintext += private_key.decrypt(
            data[i:i+256],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        if queue.empty():
            queue.put(int(i/len(data)*10000)/100)

        if i%3000 > 256*8:
            result.append(plaintext)
            plaintext = b''

    queue.put(100)
    result.append(plaintext)





root = Tk()
root.title("OAEP RSA")
root.resizable(False, False)

input_dir = StringVar()
output_dir = StringVar()
key_dir = StringVar()
status = StringVar()
password = StringVar()
prog = IntVar()


class RSA_GUI:
    def __init__(self, root):
        """
        GUI setup
        """
        self.root = root
        self.running = False
        self.thread_queue = queue.Queue()
        self.mainframe = ttk.Frame(root, padding='10 10 10 10')
        self.mainframe.grid(column=0, row=0, sticky=(N, W, E, S))

        ttk.Label(self.mainframe, text='Step 1: Choose the file to encrypt/decrypt')\
        .grid(column=1, row=0, pady=10)
        ttk.Label(self.mainframe, text='Input File').grid(column=0, row=1)
        ttk.Entry(self.mainframe, width=80, textvariable=input_dir)\
        .grid(column=1, row=1)
        ttk.Button(self.mainframe, text='Browse', command=lambda: self.button_browse(1))\
        .grid(column=2, row=1, padx=5)
        ttk.Separator(self.mainframe).grid(column=0, row=2, sticky=(W, E), columnspan=3, pady=20)


        ttk.Label(self.mainframe, text='Step 2: Choose the output folder')\
        .grid(column=1, row=3, pady=10)
        ttk.Label(self.mainframe, text='Output Folder').grid(column=0, row=4)
        ttk.Entry(self.mainframe, width=80, textvariable=output_dir)\
        .grid(column=1, row=4)
        ttk.Button(self.mainframe, text='Browse', command=lambda: self.button_browse(2))\
        .grid(column=2, row=4, padx=5)
        ttk.Separator(self.mainframe).grid(column=0, row=5, sticky=(W, E), columnspan=3, pady=20)


        ttk.Label(self.mainframe, justify=CENTER, text='Step 3: Choose the PEM file containing private key\n\
        (A new key will be generated and saved when encrypt if no file is provided)')\
        .grid(column=1, row=6, pady=10)
        ttk.Label(self.mainframe, text='Key File').grid(column=0, row=7)
        ttk.Entry(self.mainframe, width=80, textvariable=key_dir)\
        .grid(column=1, row=7)
        ttk.Button(self.mainframe, text='Browse', command=lambda: self.button_browse(3))\
        .grid(column=2, row=7, padx=5)
        ttk.Label(self.mainframe, text='Password  :')\
        .grid(column=0, row=8, sticky='w', columnspan=2, padx=180)
        ttk.Entry(self.mainframe, width=40, show='*', textvariable=password)\
        .grid(column=1, row=8, sticky='e', columnspan=2, padx=160)
        ttk.Separator(self.mainframe).grid(column=0, row=9, sticky=(W, E), columnspan=3, pady=20)


        ttk.Label(self.mainframe, text='Step 4: Start encryption/decryption')\
        .grid(column=1, row=10, pady=15)
        ttk.Label(self.mainframe, text='', textvariable=status, justify=CENTER).grid(column=1, row=11)
        ttk.Progressbar(self.mainframe, orient=HORIZONTAL, length=500, mode='determinate', variable=prog)\
        .grid(column=1, row=12, pady=15)
        self.button1 = ttk.Button(self.mainframe, text='Encrypt', command=self.button_encrypt)
        self.button1.grid(column=0, row=13, columnspan=2, padx=120, sticky='w')
        self.button2 = ttk.Button(self.mainframe, text='Decrypt', command=self.button_decrypt)
        self.button2.grid(column=1, row=13, pady=30)
        self.button3 = ttk.Button(self.mainframe, text='Output Folder', command=self.button_open)
        self.button3.grid(column=1, row=13, columnspan=2, padx=120, sticky='e')


    def process_queue(self, mode):
        """
        Queue processor when thread worker is working
        Check for the update in the queue
        Update the progress percentage
        """
        progress = 0
        while self.thread_queue.qsize():
            try:
                progress = self.thread_queue.get()
            except:
                pass

        if progress == 100:
            prog.set(progress)
            status.set(mode + '... ' + str(progress) + '%')
            self.running = False
        elif progress > 0 and progress < 100:
            prog.set(progress)
            status.set(mode + '... ' + str(progress) + '%')
        else:
            pass

        if self.running:
            self.root.after(500, lambda: self.process_queue(mode))

        return


    def message_dialog(self, dtype, dtitle, dmessage):
        """
        Popup message function for thread worker
        Show correspond message and reset button and status
        """
        if dtype == 'error':
            messagebox.showerror(title=dtitle, message=dmessage)
        elif dtype == 'info':
            messagebox.showinfo(title=dtitle, message=dmessage)

        self.button1.config(state=NORMAL)
        self.button2.config(state=NORMAL)
        status.set('Ready')




    def button_browse(self, step):
        """
        Function for browse button
        Prompt user to choose folder/file
        """
        if step == 1 or step == 3:
            directory = filedialog.askopenfilename()
            if step == 1:
                input_dir.set(directory)
            else:
                key_dir.set(directory)

        else:
            directory = filedialog.askdirectory()
            output_dir.set(directory)


    def button_encrypt(self):
        """
        Function for encrypt button
        Disable buttons and set up thread for worker
        """
        self.running = True
        self.button1.config(state=DISABLED)
        self.button2.config(state=DISABLED)
        threading.Thread(target=self.thread_encrypt).start()
        self.process_queue('Encrypting')


    def button_decrypt(self):
        """
        Function for decrypt button
        Disable buttons and set up thread for worker
        """
        self.running = True
        self.button1.config(state=DISABLED)
        self.button2.config(state=DISABLED)
        threading.Thread(target=self.thread_decrypt).start()
        self.process_queue('Decrypting')


    def thread_encrypt(self):
        """
        Thread worker to process encryption
            Check all files and path if they are valid
            Try to encrypt file
            Output result
        """
        status.set('Encrypting...')
        in_dir = input_dir.get()
        out_dir = output_dir.get()
        k_dir = key_dir.get()
        pw = password.get()
        if pw == '':
            pw = None

        if self.file_check(in_dir) and self.dir_check(out_dir):
            if k_dir != '':
                if self.file_check(k_dir):
                    try:
                        private_key = key_load(k_dir, pw)
                    except:
                        self.message_dialog('error', 'Load Key Failed',\
                        'Please check your key file (and password)')
                        return
                else:
                    self.message_dialog('error', 'Invalid Path',\
                    'Unable to locate the key file')
                    return
            else:
                private_key = key_gen()
        else:
            self.message_dialog('error', 'Invalid Path',\
            'Unable to locate the input/output path')
            return

        with open(in_dir, 'rb') as f:
            data = f.read()

        public_key = private_key.public_key()
        result = list()
        self.thread_queue = queue.Queue()
        try:
            encrypt(data, public_key, result, self.thread_queue)
        except:
            self.message_dialog('error', 'Encryption Failed',\
            'Something went wrong when encrpting, please try again')
            prog.set(0)
            return

        filename = os.path.basename(in_dir) + '-Encrypted'
        out = os.path.join(out_dir, filename)
        with open(out, 'wb+') as f:
            f.write(b''.join(result))

        if k_dir == '':
            filename = os.path.basename(in_dir) + '-Key'
            out = os.path.join(out_dir, filename)
            with open(out, 'wb+') as f:
                f.write(key_serialization(private_key, pw))

        self.message_dialog('info', 'Finished',\
        'Encryption completed successfully')
        prog.set(0)
        return



    def thread_decrypt(self):
        """
        Thread worker to process decryption
            Check all files and path if they are valid
            Try to decrypt file
            Output result
        """
        status.set('Decrypting...')
        in_dir = input_dir.get()
        out_dir = output_dir.get()
        k_dir = key_dir.get()
        pw = password.get()
        if pw == '':
            pw = None

        if self.file_check(in_dir) and self.dir_check(out_dir):
            if k_dir != '':
                if self.file_check(k_dir):
                    try:
                        private_key = key_load(k_dir, pw)
                    except:
                        self.message_dialog('error', 'Load Key Failed',\
                        'Please check your key file (and password)')
                        return
                else:
                    self.message_dialog('error', 'Invalid Path',\
                    'Unable to locate the key file')
                    return
            else:
                self.message_dialog('error', 'Invalid Path',\
                'Please choose the key file')
                return
        else:
            self.message_dialog('error', 'Invalid Path',\
            'Unable to locate the input/output path')
            return

        with open(in_dir, 'rb') as f:
            data = f.read()

        result = list()
        self.thread_queue = queue.Queue()

        try:
            decrypt(data, private_key, result, self.thread_queue)
        except:
            self.message_dialog('error', 'Decryption Failed',\
            'Something went wrong when decrpting, please try again')
            return

        filename = os.path.basename(in_dir) + '-Decrypted'
        out_dir = os.path.join(out_dir, filename)
        with open(out_dir, 'wb+') as f:
            f.write(b''.join(result))

        self.message_dialog('info', 'Finished',\
        'Decryption completed successfully')
        prog.set(0)
        return


    def button_open(self):
        """
        Function for the button to open the output folder
        Show error popup message if path is not valid
        """
        dir = output_dir.get()
        if self.dir_check(dir):
            os.startfile(dir)
        else:
            messagebox.showerror(title='Invalid Path',\
            message='Folder Not Found')


    def file_check(self, dir):
        """
        Check if file exsits
        """
        if os.path.exists(dir) and os.path.isfile(dir):
            return True
        else:
            return False

    def dir_check(self, dir):
        """
        Check if path is valid
        """
        if os.path.exists(dir) and not os.path.isfile(dir):
            return True
        else:
            return False



gui = RSA_GUI(root)
status.set('Ready')
root.mainloop()
