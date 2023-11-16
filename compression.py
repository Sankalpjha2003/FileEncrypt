import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import heapq
import pickle
import threading

# Import ttkthemes for themed styling
from ttkthemes import ThemedStyle

class HuffmanNode:
    def __init__(self, char, freq):
        self.char = char
        self.freq = freq
        self.left = None
        self.right = None

    def __lt__(self, other):
        return self.freq < other.freq

def build_huffman_tree(data):
    frequency = {}
    for char in data:
        frequency[char] = frequency.get(char, 0) + 1

    priority_queue = [HuffmanNode(char, freq) for char, freq in frequency.items()]
    heapq.heapify(priority_queue)

    while len(priority_queue) > 1:
        left = heapq.heappop(priority_queue)
        right = heapq.heappop(priority_queue)

        internal_node = HuffmanNode(None, left.freq + right.freq)
        internal_node.left = left
        internal_node.right = right

        heapq.heappush(priority_queue, internal_node)

    return priority_queue[0]

def build_huffman_codes(node, code="", mapping=None):
    if mapping is None:
        mapping = {}
    if node is not None:
        if node.char is not None:
            mapping[node.char] = code
        build_huffman_codes(node.left, code + "0", mapping)
        build_huffman_codes(node.right, code + "1", mapping)
    return mapping

def compress(file_path, save_path, progress_var, progress_label):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = file.read()

        root = build_huffman_tree(data)
        codes = build_huffman_codes(root)

        compressed_data = ''.join(codes[char] for char in data)
        padding = 8 - len(compressed_data) % 8
        compressed_data += '0' * padding

        binary_str = ""
        for i in range(0, len(compressed_data), 8):
            byte = compressed_data[i:i+8]
            binary_str += chr(int(byte, 2))

        save_path += '.huf'
        with open(save_path, 'wb') as file:
            pickle.dump((codes, binary_str), file)

        progress_var.set(100)
        progress_label.config(text="File compressed and saved at:\n{}".format(save_path))
        messagebox.showinfo("Success", "File compressed successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decompress(file_path, save_path, progress_var, progress_label):
    try:
        with open(file_path, 'rb') as file:
            codes, binary_str = pickle.load(file)

        reverse_codes = {v: k for k, v in codes.items()}

        compressed_data = ''.join(format(ord(char), '08b') for char in binary_str)
        compressed_data = compressed_data.rstrip('0')

        current_code = ""
        decompressed_data = ""
        for bit in compressed_data:
            current_code += bit
            if current_code in reverse_codes:
                decompressed_data += reverse_codes[current_code]
                current_code = ""

        with open(save_path, 'w', encoding='utf-8') as file:
            file.write(decompressed_data)

        progress_var.set(100)
        progress_label.config(text="File decompressed and saved at:\n{}".format(save_path))
        messagebox.showinfo("Success", "File decompressed successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def browse_file(entry_widget):
    file_path = filedialog.askopenfilename()
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, file_path)

def browse_save_location(entry_widget):
    save_path = filedialog.asksaveasfilename()
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, save_path)

def start_compression(input_entry, save_entry, progress_var, progress_label):
    input_file = input_entry.get()
    save_location = save_entry.get()

    if not input_file or not save_location:
        messagebox.showerror("Error", "Please select input file and save location.")
        return

    progress_var.set(0)
    progress_label.config(text="File compressing...")

    progress_thread = threading.Thread(target=compress, args=(input_file, save_location, progress_var, progress_label))
    progress_thread.start()

def start_decompression(input_entry, save_entry, progress_var, progress_label):
    input_file = input_entry.get()
    save_location = save_entry.get()

    if not input_file or not save_location:
        messagebox.showerror("Error", "Please select input file and save location.")
        return

    if not input_file.endswith('.huf'):
        messagebox.showerror("Error", "Invalid file format. Please select a compressed file.")
        return

    progress_var.set(0)
    progress_label.config(text="File decompressing...")

    progress_thread = threading.Thread(target=decompress, args=(input_file, save_location, progress_var, progress_label))
    progress_thread.start()

def create_gui():
    root = tk.Tk()
    root.title("Huffman Compression")

    # Use ThemedStyle for themed styling
    style = ThemedStyle(root)
    style.set_theme("plastik")  # You can choose a different theme

    step1_label = ttk.Label(root, text="Step 1: Select the file")
    step1_label.grid(row=0, column=0, columnspan=3, padx=10, pady=5)

    input_label = ttk.Label(root, text="File Path:")
    input_label.grid(row=1, column=0, padx=10, pady=5)

    input_entry = ttk.Entry(root, width=40)
    input_entry.grid(row=1, column=1, padx=10, pady=5)

    input_browse_button = ttk.Button(root, text="Browse", command=lambda: browse_file(input_entry))
    input_browse_button.grid(row=1, column=2, padx=10, pady=5)

    step2_label = ttk.Label(root, text="Step 2: Select output folder")
    step2_label.grid(row=2, column=0, columnspan=3, padx=10, pady=5)

    save_label = ttk.Label(root, text="Save Location:")
    save_label.grid(row=3, column=0, padx=10, pady=5)

    save_entry = ttk.Entry(root, width=40)
    save_entry.grid(row=3, column=1, padx=10, pady=5)

    save_browse_button = ttk.Button(root, text="Browse", command=lambda: browse_save_location(save_entry))
    save_browse_button.grid(row=3, column=2, padx=10, pady=5)

    step3_label = ttk.Label(root, text="Step 3: Select one - Compress or Decompress")
    step3_label.grid(row=4, column=0, columnspan=3, padx=10, pady=5)

    compress_button = ttk.Button(root, text="Compress", command=lambda: start_compression(input_entry, save_entry, progress_var, progress_label))
    compress_button.grid(row=5, column=0, columnspan=3, pady=10)

    decompress_button = ttk.Button(root, text="Decompress", command=lambda: start_decompression(input_entry, save_entry, progress_var, progress_label))
    decompress_button.grid(row=6, column=0, columnspan=3, pady=10)

    progress_var = tk.DoubleVar()
    progress_label = ttk.Label(root, text="")
    progress_label.grid(row=7, column=0, columnspan=3, pady=10)

    progress_bar = ttk.Progressbar(root, orient="horizontal", length=200, mode="determinate", variable=progress_var)
    progress_bar.grid(row=8, column=0, columnspan=3, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
