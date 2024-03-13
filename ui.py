import tkinter as tk
from tkinter import filedialog, ttk
import pandas as pd
import pefile
import os
import threading

def load_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)
        return pe
    except pefile.PEFormatError:
        print("File tidak valid atau bukan file PE.")
        return None

def jaccard_similarity(set1, set2):
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    return intersection / union if union != 0 else 0

def calculate_similarity(database_entry, size_of_code, address_of_entry, size_of_image):
    set1 = {size_of_code, address_of_entry, size_of_image}
    set2 = {database_entry['SizeOfCode'], database_entry['AddressOfEntryPoint'], database_entry['SizeOfImage']}
    return jaccard_similarity(set1, set2)

def find_most_similar_entry(size_of_code, address_of_entry, size_of_image, database, progressbar):
    max_similarity = 0
    most_similar_entry = None
    total_rows = len(database)
    for index, row in database.iterrows():
        similarity = calculate_similarity(row, size_of_code, address_of_entry, size_of_image)
        if similarity > max_similarity:
            max_similarity = similarity
            most_similar_entry = row.tolist()
        progress = (index + 1) / total_rows * 100
        progressbar['value'] = progress
        root.update_idletasks()  # Update UI
    return most_similar_entry, max_similarity

def scan_file(file_path, progressbar=None):
    pe = load_pe_file(file_path)
    if pe:
        machine = pe.FILE_HEADER.Machine
        size_of_code = pe.OPTIONAL_HEADER.SizeOfCode
        address_of_entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        number_of_sections = pe.FILE_HEADER.NumberOfSections
        size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        database_entry, similarity = find_most_similar_entry(size_of_code, address_of_entry, size_of_image, df, progressbar)
        if database_entry:
            if similarity <= 0.8:
                result = f"File {file_path} bukan virus (Similarity: {similarity})"
            else:
                result = f"File {file_path} terdeteksi sebagai virus (Similarity: {similarity})"
        else:
            result = f"File {file_path} tidak cocok dalam database."
    else:
        result = f"File {file_path} tidak valid atau bukan file PE."

    if progressbar:
        progressbar.stop()
    return result

def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("Executable files", "*.exe")])
    if file_path:
        progressbar.start()
        threading.Thread(target=lambda: update_result_label(scan_file(file_path, progressbar=progressbar))).start()

def browse_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        progressbar.start()
        for file in os.listdir(folder_path):
            if file.endswith(".exe"):
                file_path = os.path.join(folder_path, file)
                threading.Thread(target=lambda: update_result_label(scan_file(file_path, progressbar=progressbar))).start()

# Load dataset
path_to_dataset = "virus.csv"
df = pd.read_csv(path_to_dataset, sep='|')

# Buat UI
root = tk.Tk()
root.title("Aplikasi Antivirus")
root.iconbitmap('icon.ico')
window_width = 800
window_height = 300
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
center_x = int(screen_width/2 - window_width / 2)
center_y = int(screen_height/2 - window_height / 2)
root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

browse_file_button = tk.Button(root, text="Pilih File", command=browse_file)
browse_file_button.pack(pady=10)

browse_folder_button = tk.Button(root, text="Pilih Folder", command=browse_folder)
browse_folder_button.pack(pady=10)

progressbar = ttk.Progressbar(root, orient="horizontal", mode="determinate", maximum=100)
progressbar.pack(pady=10)

result_label = tk.Label(root, text="", wraplength=700)
result_label.pack(pady=10)

def update_result_label(result):
    result_label.config(text=result)
    progressbar.stop()

root.mainloop()
