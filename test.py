import pandas as pd
import pefile

path_to_dataset = "virus.csv"
df = pd.read_csv(path_to_dataset, sep = '|')

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

def find_most_similar_entry(size_of_code, address_of_entry, size_of_image, database):
    max_similarity = 0
    most_similar_entry = None

    for index, row in database.iterrows():
        similarity = calculate_similarity(row, size_of_code, address_of_entry, size_of_image)
        if similarity > max_similarity:
            max_similarity = similarity
            most_similar_entry = row.tolist()

    return most_similar_entry, max_similarity

file_path = "install.exe"
pe = load_pe_file(file_path)
if pe:
    machine = pe.FILE_HEADER.Machine
    size_of_code = pe.OPTIONAL_HEADER.SizeOfCode
    address_of_entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    number_of_sections = pe.FILE_HEADER.NumberOfSections
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    subsystem = pe.OPTIONAL_HEADER.Subsystem
database_entry, similarity = find_most_similar_entry(size_of_code, address_of_entry, size_of_image, df)

if database_entry:
    print("================================================")
    print("=============Hasil Analisis File================")
    print("================================================")
    print("File Name:", file_path)
    print("Similarity:", similarity)
    print("Most similar entry:", database_entry)
    print("Size Of Entry Point:", address_of_entry)
    print("Size Of Code:", size_of_code)
    print("Machine:", machine)
    print("Number of Sections:", number_of_sections)
    print("Size of Image:", size_of_image)
    print("Subsystem:", subsystem)
    if similarity <= 0.8 :
        print("File bukan Virus")
    else :
        print("Terdeteksi Virus")
else:
    print("Tidak ada entri yang cocok dalam database.")
