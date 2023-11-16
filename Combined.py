import subprocess
from tkinter import Tk, Label, Button, StringVar, OptionMenu, CENTER

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("FileEncrypt")
        self.root.geometry("400x200")

        self.label_title = Label(root, text="FileEncrypt", font=("Helvetica", 16, "bold"))
        self.label_title.grid(row=0, column=0, columnspan=3, pady=20)

        self.label_operation = Label(root, text="Select Operation:")
        self.label_operation.grid(row=1, column=0, sticky="e", pady=10)

        self.operation_var = StringVar(root)
        self.operation_var.set("Select")  # default value

        operations = ["Select", "Compression", "Encryption", "Steganography"]
        operation_menu = OptionMenu(root, self.operation_var, *operations)
        operation_menu.grid(row=1, column=1, columnspan=2, pady=10, sticky="w")

        execute_button = Button(root, text="Execute", command=self.execute_operation)
        execute_button.grid(row=2, column=0, columnspan=3, pady=20)

    def execute_operation(self):
        selected_operation = self.operation_var.get()

        if selected_operation == "Select":
            return

        script_paths = {
            "Compression": r"C:\Users\shank\OneDrive\Desktop\cpp project\compression.py",
            "Encryption": r"C:\Users\shank\OneDrive\Desktop\cpp project\OAEP_RSA.py",
            "Steganography": r"C:\Users\shank\OneDrive\Desktop\cpp project\stenography.py",
        }

        script_path = script_paths.get(selected_operation)
        if script_path:
            subprocess.Popen(["python", script_path])
        else:
            print("Invalid selection.")

if __name__ == "__main__":
    root = Tk()
    app = App(root)
    
    # Center-align the GUI on the screen
    window_width = root.winfo_reqwidth()
    window_height = root.winfo_reqheight()
    position_right = int(root.winfo_screenwidth()/2 - window_width/2)
    position_down = int(root.winfo_screenheight()/2 - window_height/2)
    root.geometry("+{}+{}".format(position_right, position_down))
    
    root.mainloop()
