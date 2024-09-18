# -*- coding: utf-8 -*-
"""
Created on Fri Dec  8 00:40:47 2023

@author: ASUS
"""

import tkinter as tk
from tkinter import messagebox,ttk
import numpy as np
import pyperclip
import textwrap

binary_mapping = {
    ' ': '00000',
    'A': '00001',
    'B': '00010',
    'C': '00011',
    'D': '00100',
    'E': '00101',
    'F': '00110',
    'G': '00111',
    'H': '01000',
    'I': '01001',
    'J': '01010',
    'K': '01011',
    'L': '01100',
    'M': '01101',
    'N': '01110',
    'O': '01111',
    'P': '10000',
    'Q': '10001',
    'R': '10010',
    'S': '10011',
    'T': '10100',
    'U': '10101',
    'V': '10110',
    'W': '10111',
    'X': '11000',
    'Y': '11001',
    'Z': '11010'
}

inv_map = {v: k for k, v in binary_mapping.items()}

# Assume this is your pre-written function with length as a parameter
def len_check(key,binary_msg):

    if len(key) == len(binary_msg):
        return key

    while len(key) < len(binary_msg):
        key = key + key

    if len(key) > len(binary_msg):
        return key[:len(binary_msg)]

def generate_key(length):
    key = ''
    for _ in range(int(length)*5):
        key = key + str(np.random.randint(0,2))
    return str(key)

def encrypt(message, key):
    binary_msg = ''


    for element in message:
        letter_to_binary = binary_mapping[element]
        binary_msg = binary_msg + letter_to_binary
    
    key = len_check(key,binary_msg)
    
    encode = int(key) + int(binary_msg)
    encode = str(encode)
    encode = encode.zfill(len(binary_msg))
    encode = encode.replace('2','0')
    return str(encode)

def decrypt(message, key):
    try:
        key = len_check(key,message)
        
        encode = int(key) + int(message)
        encode = str(encode)
        encode = encode.zfill(len(message))
        encode = encode.replace('2','0')
        
        returned_msg = ''
    
        blocks = textwrap.wrap(encode,5)
        
        for element in blocks:
    
            try:
                binary_to_letter = inv_map[element]
            except KeyError:
                binary_to_letter = '?'
    
            returned_msg = returned_msg + binary_to_letter
    except:
        return 'ERROR!'

    return returned_msg

# Functions to handle button clicks
def on_generate_key():
    try:
        length = int(key_length_entry.get())
        key = generate_key(length)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, key)
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid integer for key length.")

def on_encrypt():
    try:
        message = message_entry.get().upper()
        key = key_entry.get()
        encrypted_message = encrypt(message, key)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, encrypted_message)
    except:
        messagebox.showerror("Error")

def on_decrypt():
    try:
        message = message_entry.get()
        key = key_entry.get()
        decrypted_message = decrypt(message, key)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, decrypted_message)
    except:
        messagebox.showerror("Error")

# Copy to clipboard function
def copy_to_clipboard():
    text = output_text.get("1.0", "end-1c")
    pyperclip.copy(text)
    messagebox.showinfo("Copied", "Text copied to clipboard")

# Main window
root = tk.Tk()
root.title("Cryptography Tool")
root.geometry("400x500")  # Adjust the size as needed

# Styling
style = ttk.Style()
style.configure('TButton', font=('Arial', 10), borderwidth='4')
style.configure('TEntry', font=('Arial', 12), padding=10)
style.configure('TLabel', font=('Arial', 12), padding=5)

# Frame for Encryption/Decryption
crypto_frame = ttk.LabelFrame(root, text=" Encryption / Decryption ")
crypto_frame.pack(padx=10, pady=10, fill="both", expand=True)

# Message Entry
message_label = ttk.Label(crypto_frame, text="Message:")
message_label.pack()
message_entry = ttk.Entry(crypto_frame, width=40)
message_entry.pack()

# Key Entry
key_label = ttk.Label(crypto_frame, text="Key:")
key_label.pack()
key_entry = ttk.Entry(crypto_frame, width=40)
key_entry.pack()

# Encrypt and Decrypt Buttons
encrypt_button = ttk.Button(crypto_frame, text="Encrypt", command=on_encrypt)
encrypt_button.pack(pady=5)
decrypt_button = ttk.Button(crypto_frame, text="Decrypt", command=on_decrypt)
decrypt_button.pack(pady=5)

# Frame for Key Generation
keygen_frame = ttk.LabelFrame(root, text=" Key Generation ")
keygen_frame.pack(padx=10, pady=10, fill="both", expand=True)

# Key Length Entry
key_length_label = ttk.Label(keygen_frame, text="Key Length:")
key_length_label.pack()
key_length_entry = ttk.Entry(keygen_frame, width=40)
key_length_entry.pack()

# Generate Key Button
generate_key_button = ttk.Button(keygen_frame, text="Generate Key", command=on_generate_key)
generate_key_button.pack(pady=5)

# Output Text Field and Copy Button
output_frame = ttk.Frame(root)
output_frame.pack(padx=10, pady=10, fill="both", expand=True)

output_text = tk.Text(output_frame, height=5, width=40)
output_text.pack()
copy_button = ttk.Button(output_frame, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.pack(pady=5)

# Run the application
root.mainloop()
