from PIL import Image
from tkinter import Tk, Label, Entry, StringVar, filedialog, messagebox, simpledialog, Button, OptionMenu

class ImageSteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography")
        self.root.geometry("400x300")

        self.label_title = Label(root, text="Image Steganography", font=("Helvetica", 20))
        self.label_title.grid(row=0, column=0, columnspan=3, pady=20)

        self.label_input_file = Label(root, text="Input File:", font=("Helvetica", 16))
        self.label_input_file.grid(row=1, column=0, sticky="e", pady=10)

        self.input_file_var = StringVar(root)
        self.input_file_entry = Entry(root, textvariable=self.input_file_var, state="readonly", width=20)
        self.input_file_entry.grid(row=1, column=1, padx=5)

        browse_button = Button(root, text="Browse", command=self.browse_input_file)
        browse_button.grid(row=1, column=2, padx=5)

        self.label_operation = Label(root, text="Select Operation:", font=("Helvetica", 16))
        self.label_operation.grid(row=2, column=0, sticky="e", pady=10)

        self.operation_var = StringVar(root)
        self.operation_var.set("Select")  # default value

        operations = ["Select", "Encrypt", "Decrypt"]
        operation_menu = OptionMenu(root, self.operation_var, *operations)
        operation_menu.grid(row=2, column=1, columnspan=2, pady=10, sticky="w")

        self.label_method = Label(root, text="Select Method:", font=("Helvetica", 16))
        self.label_method.grid(row=3, column=0, sticky="e", pady=10)

        self.method_var = StringVar(root)
        self.method_var.set("Select")  # default value

        methods = ["Select", "LSB", "LSB Matching"]
        method_menu = OptionMenu(root, self.method_var, *methods)
        method_menu.grid(row=3, column=1, columnspan=2, pady=10, sticky="w")

        execute_button = Button(root, text="Execute", command=self.execute_operation, font=("Helvetica", 14))
        execute_button.grid(row=4, column=0, columnspan=3, pady=20)

    def execute_operation(self):
        selected_operation = self.operation_var.get()
        selected_method = self.method_var.get()

        if self.input_file_var.get() == "":
            messagebox.showerror("Error", "Please select an input file.")
            return

        if selected_operation == "Select" or selected_method == "Select":
            messagebox.showerror("Error", "Please select both operation and method.")
            return

        if selected_operation == "Encrypt":
            self.handle_encryption(selected_method)
        elif selected_operation == "Decrypt":
            self.handle_decryption(selected_method)

    def browse_input_file(self):
        file_path = filedialog.askopenfilename(title="Select an image file (PNG or JPG)", filetypes=[("Image files", "*.png *.jpg")])
        if file_path:
            self.input_file_var.set(file_path)

    def handle_encryption(self, selected_method):
        input_image_path = self.input_file_var.get()

        text_option = simpledialog.askstring("Text Input Method", "Enter '1' for direct input or '2' to upload a text file:", parent=self.root)

        if text_option == '1':
            text_to_hide = simpledialog.askstring("Enter Text", "Enter the text you want to encrypt:", parent=self.root)
        elif text_option == '2':
            file_path = self.open_file_dialog("Select a text file", [("Text files", "*.txt")])
            text_to_hide = self.get_text_from_file(file_path)
        else:
            messagebox.showerror("Invalid Option", "Please choose '1' or '2'.")
            return

        if text_to_hide is not None:
            output_image_path = self.save_file_dialog("Save the encrypted image as", [("Image files", "*.png *.jpg")], ".png")

            if selected_method == "LSB":
                self.encode_image_lsb(input_image_path, text_to_hide, output_image_path)
            elif selected_method == "LSB Matching":
                # Placeholder implementation for LSB Matching encoding
                # Replace this with your actual LSB Matching encoding implementation
                pass

            messagebox.showinfo("Encryption Complete", f"Text has been encrypted using {selected_method} and saved as:\n{output_image_path}")

    def handle_decryption(self, selected_method):
        input_image_path = self.input_file_var.get()

        if selected_method == "LSB":
            decoded_text = self.decode_image_lsb(input_image_path)
        elif selected_method == "LSB Matching":
            # Placeholder implementation for LSB Matching decoding
            # Replace this with your actual LSB Matching decoding implementation
            decoded_text = "Decoded text (LSB Matching)"

        messagebox.showinfo("Decryption Complete", f"Decoded Text ({selected_method}):\n{decoded_text}")

    def browse_input_file(self):
        file_path = filedialog.askopenfilename(title="Select an image file (PNG or JPG)", filetypes=[("Image files", "*.png *.jpg")])
        if file_path:
            self.input_file_var.set(file_path)

    def open_file_dialog(self, title, filetypes):
        file_path = filedialog.askopenfilename(title=title, filetypes=filetypes)
        return file_path

    def save_file_dialog(self, title, filetypes, defaultextension):
        file_path = filedialog.asksaveasfilename(title=title, filetypes=filetypes, defaultextension=defaultextension)
        return file_path

    def get_text_from_file(self, file_path):
        with open(file_path, 'r') as file:
            return file.read()

    def encode_image_lsb(self, input_image_path, text_to_hide, output_image_path):
        image = Image.open(input_image_path)
        binary_text = ''.join(format(ord(char), '08b') for char in text_to_hide)

        width, height = image.size
        binary_index = 0

        for y in range(height):
            for x in range(width):
                pixel = list(image.getpixel((x, y)))

                # Modify the least significant bit of each color channel
                for channel in range(3):
                    if binary_index < len(binary_text):
                        pixel[channel] = int(bin(pixel[channel])[2:-1] + binary_text[binary_index], 2)
                        binary_index += 1

                image.putpixel((x, y), tuple(pixel))

        image.save(output_image_path)

    def decode_image_lsb(self, input_image_path):
        image = Image.open(input_image_path)

        binary_text = ""
        width, height = image.size

        for y in range(height):
            for x in range(width):
                pixel = image.getpixel((x, y))

                # Extract the least significant bit of each color channel
                for channel in range(3):
                    binary_text += bin(pixel[channel])[-1]

        # Convert binary text to ASCII
        decoded_text = "".join([chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8)])

        return decoded_text

if __name__ == "__main__":
    root = Tk()
    app = ImageSteganographyApp(root)
    root.mainloop()
