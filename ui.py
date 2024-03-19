import os
import streamlit as st
import pandas as pd
import pefile

def load_pe_file(file):
    try:
        pe = pefile.PE(data=file.read())
        return pe
    except pefile.PEFormatError:
        st.error("File tidak valid atau bukan file PE.")
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

def scan_directory_for_exe(directory):
    exe_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".exe"):
                exe_files.append(os.path.join(root, file))
    return exe_files

def main():
    st.set_page_config(page_title="Anti Virus App", page_icon="🛡️")
    st.title("Anti Virus ni Bro 🛡️😎")
    st.markdown("---")

    path_to_dataset = "virus.csv"
    df = pd.read_csv(path_to_dataset, sep='|')

    option = st.radio("Pilih metode pemindaian:", ("Upload File PE", "Scan Directory"))
    st.markdown("---")

    if option == "Upload File PE":
        file_path = st.file_uploader("Upload File PE", type=["exe"])
        if file_path is not None:
            pe = load_pe_file(file_path)
            if pe:
                machine = pe.FILE_HEADER.Machine
                size_of_code = pe.OPTIONAL_HEADER.SizeOfCode
                address_of_entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                number_of_sections = pe.FILE_HEADER.NumberOfSections
                size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
                subsystem = pe.OPTIONAL_HEADER.Subsystem
                database_entry, similarity = find_most_similar_entry(size_of_code, address_of_entry, size_of_image, df)

                st.markdown("---")
                if database_entry:
                    st.write(f"**File Name:** {file_path.name}")
                    st.write(f"**Similarity:** {similarity}")
                    st.write(f"**Size Of Entry Point:** {address_of_entry}")
                    st.write(f"**Size Of Code:** {size_of_code}")
                    if similarity <= 0.8:
                        st.success("File tidak terdeteksi sebagai virus.")
                    else:
                        st.error("File terdeteksi sebagai virus.")
                else:
                    st.warning("Tidak ada entri yang cocok dalam database.")
    else:
        directory_path = st.text_input("Masukkan path direktori:")
        if st.button("Scan"):
            if os.path.isdir(directory_path):
                st.write("Mengakses direktori...")
                exe_files = scan_directory_for_exe(directory_path)
                if exe_files:
                    st.write("Hasil Pemindaian:")
                    for i, file_path in enumerate(exe_files):
                        pe = load_pe_file(open(file_path, "rb"))
                        if pe:
                            machine = pe.FILE_HEADER.Machine
                            size_of_code = pe.OPTIONAL_HEADER.SizeOfCode
                            address_of_entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                            number_of_sections = pe.FILE_HEADER.NumberOfSections
                            size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
                            subsystem = pe.OPTIONAL_HEADER.Subsystem
                            database_entry, similarity = find_most_similar_entry(size_of_code, address_of_entry, size_of_image, df)

                            if database_entry:
                                st.write(f"**File {i+1}:** {os.path.basename(file_path)}")
                                if similarity <= 0.8:
                                    st.success("File tidak terdeteksi sebagai virus.")
                                else:
                                    st.error("File terdeteksi sebagai virus.")
                            else:
                                st.write(f"**File {i+1}:** {os.path.basename(file_path)} - Tidak ada entri yang cocok dalam database.")
                else:
                    st.warning("Tidak ditemukan file .exe dalam direktori.")
            else:
                st.error("Direktori tidak valid.")
                
if __name__ == "__main__":
    main()
