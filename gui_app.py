import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import re
from key_manager import (
    generate_rsa_key_pair,
    get_public_key_table_data,
    get_private_key_table_data,
    delete_public_key,
    delete_private_key,
    delete_key_pair,
    export_public_key,
    export_key_pair,
    import_public_key,
    import_key_pair,
    get_current_time,
    key_exists_in_private_ring,
    check_private_key_password
)
from message_processor import process_and_send_message, receive_and_process_message, get_message_requirements


class PGPKeyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PGP Security System")
        self.root.geometry("1150x850")

        # Main structure with tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_keys = tk.Frame(self.notebook)
        self.tab_send = tk.Frame(self.notebook)
        self.tab_receive = tk.Frame(self.notebook)

        self.notebook.add(self.tab_keys, text="Key Manager")
        self.notebook.add(self.tab_send, text="Send Message")
        self.notebook.add(self.tab_receive, text="Receive Message")

        # Refresh comboboxes when tab changes
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

        # Initialize all tabs
        self.create_key_manager_layout(self.tab_keys)
        self.create_send_layout(self.tab_send)
        self.create_receive_layout(self.tab_receive)

        self.refresh_tables()

    def on_tab_changed(self, event):
        self.refresh_comboboxes()

    # ==========================================================
    # TAB 1: KEY MANAGER
    # ==========================================================
    def create_key_manager_layout(self, parent):
        title_label = tk.Label(parent, text="PGP Key Manager", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)

        self.create_generate_key_form(parent)
        self.create_key_tables(parent)

    def create_generate_key_form(self, parent):
        form_frame = tk.LabelFrame(parent, text="Generate RSA Key Pair", padx=10, pady=10)
        form_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(form_frame, text="Name:").grid(row=0, column=0, sticky="w")
        self.name_entry = tk.Entry(form_frame, width=30)
        self.name_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(form_frame, text="Email:").grid(row=0, column=2, sticky="w")
        self.email_entry = tk.Entry(form_frame, width=30)
        self.email_entry.grid(row=0, column=3, padx=10, pady=5)

        tk.Label(form_frame, text="Key Size:").grid(row=1, column=0, sticky="w")
        self.key_size_box = ttk.Combobox(form_frame, values=["1024", "2048"], width=27, state="readonly")
        self.key_size_box.grid(row=1, column=1, padx=10, pady=5)
        self.key_size_box.current(0)

        tk.Label(form_frame, text="Password:").grid(row=1, column=2, sticky="w")
        self.password_entry = tk.Entry(form_frame, width=30, show="*")
        self.password_entry.grid(row=1, column=3, padx=10, pady=5)

        generate_button = tk.Button(form_frame, text="Generate Keys", width=20,
                                    command=self.generate_key_button_clicked)
        generate_button.grid(row=2, column=0, columnspan=4, pady=10)

    def create_key_tables(self, parent):
        tables_frame = tk.Frame(parent)
        tables_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Public keys
        public_frame = tk.LabelFrame(tables_frame, text="Public Key Ring", padx=10, pady=10)
        public_frame.pack(fill="both", expand=True, pady=5)
        self.public_table = ttk.Treeview(public_frame, columns=("key_id", "name", "email", "key_size", "created_at"),
                                         show="headings", height=5)
        self.setup_table_columns(self.public_table)
        self.public_table.pack(fill="both", expand=True)

        pub_btn_frame = tk.Frame(public_frame)
        pub_btn_frame.pack(pady=5)
        tk.Button(pub_btn_frame, text="Delete Selected", width=18, command=self.delete_selected_public_key).grid(row=0,
                                                                                                                 column=0,
                                                                                                                 padx=5)
        tk.Button(pub_btn_frame, text="Export Key", width=18, command=self.export_selected_public_key).grid(row=0,
                                                                                                            column=1,
                                                                                                            padx=5)
        tk.Button(pub_btn_frame, text="Import Key", width=18, command=self.import_public_key_clicked).grid(row=0,
                                                                                                           column=2,
                                                                                                           padx=5)

        # Private keys
        private_frame = tk.LabelFrame(tables_frame, text="Private Key Ring", padx=10, pady=10)
        private_frame.pack(fill="both", expand=True, pady=5)
        self.private_table = ttk.Treeview(private_frame, columns=("key_id", "name", "email", "key_size", "created_at"),
                                          show="headings", height=5)
        self.setup_table_columns(self.private_table)
        self.private_table.pack(fill="both", expand=True)

        priv_btn_frame = tk.Frame(private_frame)
        priv_btn_frame.pack(pady=5)
        tk.Button(priv_btn_frame, text="Delete Private", width=18, command=self.delete_selected_private_key).grid(
            row=0, column=0, padx=5)
        tk.Button(priv_btn_frame, text="Delete Pair", width=18, command=self.delete_selected_key_pair).grid(row=0,
                                                                                                            column=1,
                                                                                                            padx=5)
        tk.Button(priv_btn_frame, text="Export Pair", width=18, command=self.export_selected_key_pair).grid(row=0,
                                                                                                            column=2,
                                                                                                            padx=5)
        tk.Button(priv_btn_frame, text="Import Pair", width=18, command=self.import_key_pair_clicked).grid(row=0,
                                                                                                           column=3,
                                                                                                           padx=5)

    def setup_table_columns(self, table):
        table.heading("key_id", text="Key ID")
        table.heading("name", text="Name")
        table.heading("email", text="Email")
        table.heading("key_size", text="Size")
        table.heading("created_at", text="Created")
        table.column("key_id", width=160)
        table.column("name", width=150)
        table.column("email", width=230)
        table.column("key_size", width=80)
        table.column("created_at", width=180)

    # ==========================================================
    # TAB 2: SEND MESSAGE
    # ==========================================================
    def create_send_layout(self, parent):
        tk.Label(parent, text="Message Text:", font=("Arial", 12, "bold")).pack(anchor="w", padx=20, pady=(20, 5))
        self.msg_text = tk.Text(parent, height=10)
        self.msg_text.pack(fill="both", expand=True, padx=20)

        options_frame = tk.Frame(parent)
        options_frame.pack(fill="x", padx=20, pady=10)

        # Signing
        sign_frame = tk.LabelFrame(options_frame, text="Authenticity (Sign)", padx=10, pady=10)
        sign_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

        self.var_sign = tk.BooleanVar()
        tk.Checkbutton(sign_frame, text="Sign message", variable=self.var_sign,
                       command=self.toggle_sign_options).pack(anchor="w")
        tk.Label(sign_frame, text="Private key (sender):").pack(anchor="w", pady=(5, 0))
        self.cb_sender_key = ttk.Combobox(sign_frame, state="disabled")
        self.cb_sender_key.pack(fill="x")

        # Encryption
        enc_frame = tk.LabelFrame(options_frame, text="Confidentiality (Encrypt)", padx=10, pady=10)
        enc_frame.pack(side="left", fill="both", expand=True, padx=(5, 0))

        self.var_encrypt = tk.BooleanVar()
        tk.Checkbutton(enc_frame, text="Encrypt Message", variable=self.var_encrypt,
                       command=self.toggle_encrypt_options).pack(anchor="w")
        tk.Label(enc_frame, text="Public Key (recipient):").pack(anchor="w", pady=(5, 0))
        self.cb_receiver_key = ttk.Combobox(enc_frame, state="disabled")
        self.cb_receiver_key.pack(fill="x")

        tk.Label(enc_frame, text="Symmetric algorithm:").pack(anchor="w", pady=(5, 0))
        self.cb_algo = ttk.Combobox(enc_frame, values=["AES128", "TripleDES"], state="disabled")
        self.cb_algo.pack(fill="x")

        # Extra
        extra_frame = tk.Frame(parent)
        extra_frame.pack(fill="x", padx=20, pady=5)
        self.var_compress = tk.BooleanVar()
        tk.Checkbutton(extra_frame, text="Zip compression", variable=self.var_compress).pack(side="left", padx=10)
        self.var_radix = tk.BooleanVar()
        tk.Checkbutton(extra_frame, text="Convert to Radix-64 (Base64)", variable=self.var_radix).pack(side="left",
                                                                                                       padx=10)

        tk.Button(parent, text="Generate and Save Message", font=("Arial", 12), bg="#d0e8f2",
                  command=self.send_action).pack(pady=20)

    def toggle_sign_options(self):
        if self.var_sign.get():
            self.cb_sender_key.config(state="readonly")
        else:
            self.cb_sender_key.set("")
            self.cb_sender_key.config(state="disabled")

    def toggle_encrypt_options(self):
        if self.var_encrypt.get():
            self.cb_receiver_key.config(state="readonly")
            self.cb_algo.config(state="readonly")
            self.cb_algo.current(0)
        else:
            self.cb_receiver_key.set("")
            self.cb_receiver_key.config(state="disabled")
            self.cb_algo.set("")
            self.cb_algo.config(state="disabled")

    # ==========================================================
    # TAB 3: RECEIVE MESSAGE
    # ==========================================================
    def create_receive_layout(self, parent):
        top_frame = tk.Frame(parent)
        top_frame.pack(fill="x", padx=20, pady=20)

        tk.Button(top_frame, text="Load PGP File", font=("Arial", 12), bg="#e8f2d0",
                  command=self.receive_action).pack(side="left")

        self.lbl_verification = tk.Label(top_frame, text="Verification status: Waiting for input...",
                                         font=("Arial", 11, "bold"), fg="gray")
        self.lbl_verification.pack(side="left", padx=20)

        self.lbl_msg_info = tk.Label(parent, text="", font=("Arial", 10), fg="gray")
        self.lbl_msg_info.pack(anchor="w", padx=20)

        tk.Label(parent, text="Decrypted message content:", font=("Arial", 12, "bold")).pack(anchor="w", padx=20,
                                                                                             pady=(10, 5))
        self.received_text = tk.Text(parent, height=15, state="disabled", bg="#f4f4f4")
        self.received_text.pack(fill="both", expand=True, padx=20)

        self.btn_save_received = tk.Button(parent, text="Save Original Message to File", font=("Arial", 12),
                                           state="disabled", command=self.save_received_message)
        self.btn_save_received.pack(pady=20)

    def get_private_key_choice(self):
        keys = get_private_key_table_data()
        return [f"{k['key_id']} - {k['name']}" for k in keys]

    def describe_private_key(self, key_id):
        # Umesto sirovog Key ID-a (koji izgleda kao nečitljiv heš), korisniku
        # prikazujemo ime i mejl vlasnika ključa radi lakše identifikacije,
        # uz skraćeni ID u zagradi za slucaj da ima vise kljuceva sa istim imenom.
        for record in get_private_key_table_data():
            if record["key_id"] == key_id:
                short_id = record["key_id"][-8:]
                return f"{record['name']} <{record['email']}>\n(Key ID ...{short_id})"
        return f"(Key ID {key_id})"

    # ==========================================================
    # APPLICATION LOGIC
    # ==========================================================
    def refresh_comboboxes(self):
        priv_keys = [f"{k['key_id']} - {k['name']}" for k in get_private_key_table_data()]
        pub_keys = [f"{k['key_id']} - {k['name']}" for k in get_public_key_table_data()]
        self.cb_sender_key['values'] = priv_keys
        self.cb_receiver_key['values'] = pub_keys

    def send_action(self):
        text = self.msg_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Warning", "Message cannot be empty.")
            return

        sender_val = self.cb_sender_key.get()
        receiver_val = self.cb_receiver_key.get()

        sender_key = sender_val.split(" - ")[0] if sender_val else ""
        receiver_key = receiver_val.split(" - ")[0] if receiver_val else ""
        password = None

        if self.var_sign.get():
            if not sender_key:
                messagebox.showwarning("Warning", "You must select a private key for signing.")
                return

            # Lozinka se proverava odmah, pre nego sto se uopste pita gde da se
            # sacuva paket - ako je pogresna, korisnik odmah dobija priliku da
            # je ponovo unese (isto kao na strani prijema), umesto da sazna za
            # gresku tek posle biranja destinacije za cuvanje.
            key_label = self.describe_private_key(sender_key)
            while True:
                password = simpledialog.askstring("Password", f"Enter password for key:\n{key_label}", show='*')
                if password is None:  # Korisnik kliknuo Cancel
                    return
                if check_private_key_password(sender_key, password):
                    break
                if not messagebox.askretrycancel("Error", "Incorrect password.\n\nWould you like to try again?"):
                    return

        if self.var_encrypt.get() and not receiver_key:
            messagebox.showwarning("Warning", "You must select a public key for encryption.")
            return

        out_path = filedialog.asksaveasfilename(title="Save package", defaultextension=".pgp")
        if not out_path: return

        # Naziv sadrzaja poruke (metapodatak iz PGP strukture, nezavisan od naziva
        # kontejner (.pgp) fajla) se generise automatski, na osnovu vremena slanja.
        filename = "message_" + get_current_time().replace(":", "-").replace(" ", "_") + ".txt"

        try:
            process_and_send_message(
                original_text=text, output_path=out_path,
                filename=filename,
                do_sign=self.var_sign.get(), sender_key_id=sender_key, sender_password=password,
                do_encrypt=self.var_encrypt.get(), receiver_key_id=receiver_key, sym_algo=self.cb_algo.get(),
                do_compress=self.var_compress.get(), do_radix64=self.var_radix.get()
            )
            messagebox.showinfo("Success", "Message successfully created and saved.")
            self.msg_text.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    def receive_action(self):
        in_path = filedialog.askopenfilename(title="Select PGP message")
        if not in_path: return

        # Prvo samo "pogledamo" paket bez ikakvog kljuca, da utvrdimo da li je
        # uopste enkriptovan i, ako jeste, kojim je kljucem enkriptovan. Taj ID
        # je vec upisan u samu poruku (receiver_key_id) - korisnik ga ne bira
        # rucno, isto kao sto pravi PGP klijent radi.
        try:
            requirements = get_message_requirements(in_path)
        except Exception as e:
            messagebox.showerror("Error", f"Cannot read file: {str(e)}")
            return

        if not requirements["is_encrypted"]:
            # Poruka nije enkriptovana (samo eventualno potpisana, ili obicna) -
            # nije potreban nikakav privatni kljuc niti lozinka.
            try:
                decrypted_text, verification_status, message_info = receive_and_process_message(in_path)
                self.display_received_message(decrypted_text, verification_status, message_info)
            except Exception as e:
                messagebox.showerror("Error", f"Processing failed: {str(e)}")
            return

        required_key_id = requirements["receiver_key_id"]
        if not key_exists_in_private_ring(required_key_id):
            messagebox.showerror(
                "Missing private key",
                f"This message was encrypted for private key ID {required_key_id}, "
                f"which is not in your private key ring. You cannot decrypt it on this machine."
            )
            return

        key_label = self.describe_private_key(required_key_id)

        while True:
            password = simpledialog.askstring(
                "Password", f"Enter password for key:\n{key_label}", show='*'
            )
            if password is None:  # Korisnik kliknuo Cancel
                return

            try:
                decrypted_text, verification_status, message_info = receive_and_process_message(in_path, password)
                self.display_received_message(decrypted_text, verification_status, message_info)
                break  # Izlazimo iz while petlje jer je sve uspelo
            except Exception as e:
                # Prikaz greske, ali ostajemo u petlji da bi korisnik mogao ponovo da unese lozinku
                if not messagebox.askretrycancel("Error",
                                                 f"Decryption failed: {str(e)}\n\nWould you like to try again?"):
                    return  # Korisnik odustao od ponovnog pokusaja

    def display_received_message(self, decrypted_text, verification_status, message_info):
        self.received_text.config(state="normal")
        self.received_text.delete("1.0", tk.END)
        self.received_text.insert(tk.END, decrypted_text)
        self.received_text.config(state="disabled")
        self.lbl_verification.config(text=verification_status)

        info_text = f"Filename: {message_info['filename']}  |  Created: {message_info['message_timestamp']}"
        if message_info.get("signature_timestamp"):
            info_text += f"  |  Signed: {message_info['signature_timestamp']}"
        self.lbl_msg_info.config(text=info_text)
        self.last_received_filename = message_info["filename"]

        self.btn_save_received.config(state="normal")

    def save_received_message(self):
        suggested_name = getattr(self, "last_received_filename", "message.txt")
        out_path = filedialog.asksaveasfilename(title="Save text", defaultextension=".txt",
                                                initialfile=suggested_name,
                                                filetypes=[("text file", "*.txt")])
        if not out_path: return

        text_content = self.received_text.get("1.0", tk.END).strip()
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(text_content)
            messagebox.showinfo("Success", "Message text saved.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def generate_key_button_clicked(self):
        name = self.name_entry.get()
        email = self.email_entry.get()
        if not name:
            messagebox.showwarning("Error", "Name cannot be empty.")
            return

        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            error_message = (
                "Invalid email format.\n\n"
                "Please enter a valid email address following the standard format:\n"
                "name@example.com\n\n"
                "Ensure that the address includes an '@' symbol and a valid domain."
            )
            messagebox.showwarning("Invalid Input", error_message)
            self.email_entry.focus_set()
            return

        key_size = int(self.key_size_box.get())
        password = self.password_entry.get()

        try:
            key_id = generate_rsa_key_pair(name, email, key_size, password)
            messagebox.showinfo("Success", "Key pair generated.\nKey ID: " + key_id)
            self.name_entry.delete(0, tk.END)
            self.email_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.key_size_box.current(0)
            self.refresh_tables()
        except Exception as error:
            messagebox.showerror("Error", str(error))

    def refresh_tables(self):
        for table in (self.public_table, self.private_table):
            for row in table.get_children():
                table.delete(row)

        for key in get_public_key_table_data():
            self.public_table.insert("", tk.END, values=(
                key["key_id"], key["name"], key["email"], key["key_size"], key["created_at"]))
        for key in get_private_key_table_data():
            self.private_table.insert("", tk.END, values=(
                key["key_id"], key["name"], key["email"], key["key_size"], key["created_at"]))

    def get_selected_key_id(self, table):
        selected = table.selection()
        if not selected: return None
        return table.item(selected[0], "values")[0]

    def delete_selected_public_key(self):
        key_id = self.get_selected_key_id(self.public_table)
        if key_id and messagebox.askyesno("Confirm", "Delete public key?"):
            delete_public_key(key_id)
            self.refresh_tables()

    def delete_selected_private_key(self):
        key_id = self.get_selected_key_id(self.private_table)
        if key_id and messagebox.askyesno("Confirm", "Delete private key?"):
            delete_private_key(key_id)
            self.refresh_tables()

    def delete_selected_key_pair(self):
        key_id = self.get_selected_key_id(self.private_table)
        if key_id and messagebox.askyesno("Confirm", "Delete key pair?"):
            delete_key_pair(key_id)
            self.refresh_tables()

    def export_selected_public_key(self):
        key_id = self.get_selected_key_id(self.public_table)
        if key_id:
            path = filedialog.asksaveasfilename(defaultextension=".pem")
            if path: export_public_key(key_id, path)

    def export_selected_key_pair(self):
        key_id = self.get_selected_key_id(self.private_table)
        if key_id:
            pwd = simpledialog.askstring("Password", "Enter password:", show="*")
            path = filedialog.asksaveasfilename(defaultextension=".pem")
            if path and pwd: export_key_pair(key_id, pwd, path)

    def import_public_key_clicked(self):
        path = filedialog.askopenfilename()
        if path:
            name = simpledialog.askstring("Name", "Enter name:")
            email = simpledialog.askstring("Email", "Enter email:")
            if name and email:
                import_public_key(path, name, email)
                self.refresh_tables()

    def import_key_pair_clicked(self):
        path = filedialog.askopenfilename()
        if path:
            pwd = simpledialog.askstring("Password", "Enter password:", show="*")
            if pwd:
                import_key_pair(path, pwd)
                self.refresh_tables()


def start_application():
    root = tk.Tk()
    PGPKeyApp(root)
    try:
        root.state('zoomed')
    except tk.TclError:
        root.attributes('-zoomed', True)
    root.mainloop()
