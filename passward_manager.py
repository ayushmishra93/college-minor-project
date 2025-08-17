import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import hashlib
import secrets
import string
import json
from cryptography.fernet import Fernet
import base64
import os
from datetime import datetime

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        self.encryption_key = self.get_or_create_key()
        self.cipher = Fernet(self.encryption_key)
        
        self.init_database()
        
        self.create_gui()
        
        self.load_passwords()

    def get_or_create_key(self):
        """Get existing encryption key or create a new one"""
        key_file = "encryption_key.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
            return key

    def init_database(self):
        """Initialize SQLite database"""
        self.conn = sqlite3.connect('passwords.db')
        self.cursor = self.conn.cursor()
        

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                notes TEXT,
                created_date TEXT,
                updated_date TEXT
            )
        ''')
        self.conn.commit()

    def create_gui(self):
        """Create the main GUI"""

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        title_label = ttk.Label(main_frame, text="Secure Password Manager", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        

        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=1, column=0, sticky=(tk.W, tk.N), padx=(0, 10))
        
        
        ttk.Button(buttons_frame, text="Add Password", 
                  command=self.add_password_dialog).grid(row=0, column=0, pady=5, sticky=(tk.W, tk.E))
        ttk.Button(buttons_frame, text="Generate Password", 
                  command=self.generate_password_dialog).grid(row=1, column=0, pady=5, sticky=(tk.W, tk.E))
        ttk.Button(buttons_frame, text="Edit Password", 
                  command=self.edit_password).grid(row=2, column=0, pady=5, sticky=(tk.W, tk.E))
        ttk.Button(buttons_frame, text="Delete Password", 
                  command=self.delete_password).grid(row=3, column=0, pady=5, sticky=(tk.W, tk.E))
        ttk.Button(buttons_frame, text="Search", 
                  command=self.search_passwords).grid(row=4, column=0, pady=5, sticky=(tk.W, tk.E))
        ttk.Button(buttons_frame, text="Export Data", 
                  command=self.export_data).grid(row=5, column=0, pady=5, sticky=(tk.W, tk.E))
        
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(buttons_frame, textvariable=self.search_var)
        search_entry.grid(row=6, column=0, pady=5, sticky=(tk.W, tk.E))
        search_entry.bind('<KeyRelease>', self.on_search)
        

        tree_frame = ttk.Frame(main_frame)
        tree_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        

        columns = ('Website', 'Username', 'Password', 'Notes', 'Updated')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=20)
        

        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(c))
            self.tree.column(col, width=120, minwidth=100)
        

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        
        self.tree.bind('<Double-1>', self.on_double_click)

    def encrypt_password(self, password):
        """Encrypt password using Fernet"""
        return self.cipher.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        """Decrypt password using Fernet"""
        return self.cipher.decrypt(encrypted_password.encode()).decode()

    def add_password_dialog(self):
        """Dialog to add a new password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Password")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        

        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        

        ttk.Label(dialog, text="Website:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        website_entry = ttk.Entry(dialog, width=30)
        website_entry.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Label(dialog, text="Username:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        username_entry = ttk.Entry(dialog, width=30)
        username_entry.grid(row=1, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Label(dialog, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        password_entry = ttk.Entry(dialog, width=30, show="*")
        password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        
        show_var = tk.BooleanVar()
        show_check = ttk.Checkbutton(dialog, text="Show Password", variable=show_var,
                                    command=lambda: self.toggle_password_visibility(password_entry, show_var))
        show_check.grid(row=2, column=2, padx=5, pady=5)
        
        ttk.Label(dialog, text="Notes:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        notes_text = tk.Text(dialog, height=4, width=30)
        notes_text.grid(row=3, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        

        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=4, column=0, columnspan=3, pady=20)
        
        ttk.Button(button_frame, text="Generate Password", 
                  command=lambda: self.generate_and_fill_password(password_entry)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save", 
                  command=lambda: self.save_password(dialog, website_entry, username_entry, 
                                                   password_entry, notes_text)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", 
                  command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        

        dialog.columnconfigure(1, weight=1)

    def toggle_password_visibility(self, entry, show_var):
        """Toggle password visibility"""
        if show_var.get():
            entry.config(show="")
        else:
            entry.config(show="*")

    def generate_and_fill_password(self, password_entry):
        """Generate a password and fill it in the entry"""
        password = self.generate_secure_password()
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)

    def generate_password_dialog(self):
        """Dialog to generate a password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate Password")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        ttk.Label(dialog, text="Password Length:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        length_var = tk.IntVar(value=12)
        length_spinbox = ttk.Spinbox(dialog, from_=8, to=50, textvariable=length_var, width=10)
        length_spinbox.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        

        use_uppercase = tk.BooleanVar(value=True)
        use_lowercase = tk.BooleanVar(value=True)
        use_digits = tk.BooleanVar(value=True)
        use_symbols = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(dialog, text="Uppercase letters (A-Z)", variable=use_uppercase).grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5)
        ttk.Checkbutton(dialog, text="Lowercase letters (a-z)", variable=use_lowercase).grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5)
        ttk.Checkbutton(dialog, text="Digits (0-9)", variable=use_digits).grid(row=3, column=0, columnspan=2, sticky=tk.W, padx=5)
        ttk.Checkbutton(dialog, text="Special symbols (!@#$%^&*)", variable=use_symbols).grid(row=4, column=0, columnspan=2, sticky=tk.W, padx=5)
        

        ttk.Label(dialog, text="Generated Password:").grid(row=5, column=0, padx=5, pady=10, sticky=tk.W)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(dialog, textvariable=password_var, width=30, font=('Courier', 10))
        password_entry.grid(row=5, column=1, padx=5, pady=10, sticky=(tk.W, tk.E))
        

        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=6, column=0, columnspan=2, pady=20)
        
        def generate():
            password = self.generate_secure_password(
                length_var.get(), use_uppercase.get(), use_lowercase.get(), 
                use_digits.get(), use_symbols.get()
            )
            password_var.set(password)
        
        ttk.Button(button_frame, text="Generate", command=generate).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copy", 
                  command=lambda: self.copy_to_clipboard(password_var.get())).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        

        generate()
        

        dialog.columnconfigure(1, weight=1)

    def generate_secure_password(self, length=12, use_uppercase=True, use_lowercase=True, 
                               use_digits=True, use_symbols=True):
        """Generate a secure password"""
        characters = ""
        
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_digits:
            characters += string.digits
        if use_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            characters = string.ascii_letters + string.digits
        
        password = ""
        if use_uppercase:
            password += secrets.choice(string.ascii_uppercase)
        if use_lowercase:
            password += secrets.choice(string.ascii_lowercase)
        if use_digits:
            password += secrets.choice(string.digits)
        if use_symbols:
            password += secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
        

        remaining_length = length - len(password)
        password += ''.join(secrets.choice(characters) for _ in range(remaining_length))
        
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        return ''.join(password_list)

    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def save_password(self, dialog, website_entry, username_entry, password_entry, notes_text):
        """Save password to database"""
        website = website_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get()
        notes = notes_text.get("1.0", tk.END).strip()
        
        if not website or not username or not password:
            messagebox.showerror("Error", "Please fill in all required fields!")
            return
        

        encrypted_password = self.encrypt_password(password)
        

        try:
            self.cursor.execute('''
                INSERT INTO passwords (website, username, password, notes, created_date, updated_date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (website, username, encrypted_password, notes, 
                  datetime.now().isoformat(), datetime.now().isoformat()))
            self.conn.commit()
            
            messagebox.showinfo("Success", "Password saved successfully!")
            dialog.destroy()
            self.load_passwords()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {str(e)}")

    def load_passwords(self):
        """Load passwords from database and display in treeview"""

        for item in self.tree.get_children():
            self.tree.delete(item)
        
        try:
            self.cursor.execute('SELECT * FROM passwords ORDER BY website')
            rows = self.cursor.fetchall()
            
            for row in rows:

                decrypted_password = self.decrypt_password(row[3])
                display_password = "*" * len(decrypted_password)
                

                updated_date = row[6][:10] if row[6] else ""
                
                self.tree.insert('', 'end', values=(
                    row[1],  
                    row[2],  
                    display_password,  
                    row[4] or "",  
                    updated_date  
                ), tags=(row[0],))  
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load passwords: {str(e)}")

    def on_double_click(self, event):
        """Handle double-click on treeview item"""
        item = self.tree.selection()[0]
        item_id = self.tree.item(item, "tags")[0]
        
        
        self.cursor.execute('SELECT * FROM passwords WHERE id = ?', (item_id,))
        row = self.cursor.fetchone()
        
        if row:
            decrypted_password = self.decrypt_password(row[3])
            
            
            self.show_password_details(row[1], row[2], decrypted_password, row[4])

    def show_password_details(self, website, username, password, notes):
        """Show password details in a dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Password Details - {website}")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        
        ttk.Label(dialog, text=f"Website: {website}", font=('Arial', 10, 'bold')).grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)
        ttk.Label(dialog, text=f"Username: {username}").grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=10, pady=5)
        
        ttk.Label(dialog, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        password_var = tk.StringVar(value=password)
        password_entry = ttk.Entry(dialog, textvariable=password_var, width=30, show="*")
        password_entry.grid(row=2, column=1, padx=10, pady=5, sticky=(tk.W, tk.E))
        

        show_var = tk.BooleanVar()
        show_check = ttk.Checkbutton(dialog, text="Show", variable=show_var,
                                    command=lambda: self.toggle_password_visibility(password_entry, show_var))
        show_check.grid(row=2, column=2, padx=5, pady=5)
        
        if notes:
            ttk.Label(dialog, text="Notes:").grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
            notes_text = tk.Text(dialog, height=4, width=30, wrap=tk.WORD)
            notes_text.insert("1.0", notes)
            notes_text.grid(row=3, column=1, columnspan=2, padx=10, pady=5, sticky=(tk.W, tk.E))
        
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=4, column=0, columnspan=3, pady=20)
        
        ttk.Button(button_frame, text="Copy Password", 
                  command=lambda: self.copy_to_clipboard(password)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copy Username", 
                  command=lambda: self.copy_to_clipboard(username)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        

        dialog.columnconfigure(1, weight=1)

    def edit_password(self):
        """Edit selected password"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to edit!")
            return
        
        item = selection[0]
        item_id = self.tree.item(item, "tags")[0]
        

        self.cursor.execute('SELECT * FROM passwords WHERE id = ?', (item_id,))
        row = self.cursor.fetchone()
        
        if row:
            self.edit_password_dialog(row[0], row[1], row[2], self.decrypt_password(row[3]), row[4])

    def edit_password_dialog(self, password_id, website, username, password, notes):
        """Dialog to edit password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Password")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        

        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        
        ttk.Label(dialog, text="Website:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        website_entry = ttk.Entry(dialog, width=30)
        website_entry.insert(0, website)
        website_entry.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Label(dialog, text="Username:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        username_entry = ttk.Entry(dialog, width=30)
        username_entry.insert(0, username)
        username_entry.grid(row=1, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Label(dialog, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        password_entry = ttk.Entry(dialog, width=30, show="*")
        password_entry.insert(0, password)
        password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        

        show_var = tk.BooleanVar()
        show_check = ttk.Checkbutton(dialog, text="Show Password", variable=show_var,
                                    command=lambda: self.toggle_password_visibility(password_entry, show_var))
        show_check.grid(row=2, column=2, padx=5, pady=5)
        
        ttk.Label(dialog, text="Notes:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        notes_text = tk.Text(dialog, height=4, width=30)
        notes_text.insert("1.0", notes or "")
        notes_text.grid(row=3, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        

        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=4, column=0, columnspan=3, pady=20)
        
        ttk.Button(button_frame, text="Generate Password", 
                  command=lambda: self.generate_and_fill_password(password_entry)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Update", 
                  command=lambda: self.update_password(dialog, password_id, website_entry, 
                                                     username_entry, password_entry, notes_text)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", 
                  command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        
        dialog.columnconfigure(1, weight=1)

    def update_password(self, dialog, password_id, website_entry, username_entry, password_entry, notes_text):
        """Update password in database"""
        website = website_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get()
        notes = notes_text.get("1.0", tk.END).strip()
        
        if not website or not username or not password:
            messagebox.showerror("Error", "Please fill in all required fields!")
            return
        
        
        encrypted_password = self.encrypt_password(password)
        
        
        try:
            self.cursor.execute('''
                UPDATE passwords 
                SET website = ?, username = ?, password = ?, notes = ?, updated_date = ?
                WHERE id = ?
            ''', (website, username, encrypted_password, notes, 
                  datetime.now().isoformat(), password_id))
            self.conn.commit()
            
            messagebox.showinfo("Success", "Password updated successfully!")
            dialog.destroy()
            self.load_passwords()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update password: {str(e)}")

    def delete_password(self):
        """Delete selected password"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to delete!")
            return
        
        item = selection[0]
        item_id = self.tree.item(item, "tags")[0]
        
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?"):
            try:
                self.cursor.execute('DELETE FROM passwords WHERE id = ?', (item_id,))
                self.conn.commit()
                messagebox.showinfo("Success", "Password deleted successfully!")
                self.load_passwords()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete password: {str(e)}")

    def search_passwords(self):
        """Search passwords"""
        search_term = self.search_var.get().strip()
        if not search_term:
            self.load_passwords()
            return
        
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        try:
            self.cursor.execute('''
                SELECT * FROM passwords 
                WHERE website LIKE ? OR username LIKE ? OR notes LIKE ?
                ORDER BY website
            ''', (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%'))
            rows = self.cursor.fetchall()
            
            for row in rows:
                
                decrypted_password = self.decrypt_password(row[3])
                display_password = "*" * len(decrypted_password)
                
                
                updated_date = row[6][:10] if row[6] else ""
                
                self.tree.insert('', 'end', values=(
                    row[1],  # website
                    row[2],  # username
                    display_password,  # password (masked)
                    row[4] or "",  # notes
                    updated_date  # updated_date
                ), tags=(row[0],))  # Store ID in tags
        except Exception as e:
            messagebox.showerror("Error", f"Failed to search passwords: {str(e)}")

    def on_search(self, event):
        """Handle search input changes"""
        self.search_passwords()

    def export_data(self):
        """Export passwords to JSON file"""
        try:
            self.cursor.execute('SELECT * FROM passwords')
            rows = self.cursor.fetchall()
            
            export_data = []
            for row in rows:
                export_data.append({
                    'website': row[1],
                    'username': row[2],
                    'password': self.decrypt_password(row[3]),
                    'notes': row[4],
                    'created_date': row[5],
                    'updated_date': row[6]
                })
            
            
            filename = f"passwords_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            messagebox.showinfo("Export Success", f"Passwords exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")

    def sort_treeview(self, col):
        """Sort treeview by column"""
        
        items = [(self.tree.set(item, col), item) for item in self.tree.get_children('')]
        
        
        items.sort()
        
        
        for index, (val, item) in enumerate(items):
            self.tree.move(item, '', index)

    def __del__(self):
        """Cleanup when object is destroyed"""
        if hasattr(self, 'conn'):
            self.conn.close()

def main():
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()

if __name__ == "__main__":
    main() 