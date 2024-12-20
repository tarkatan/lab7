import tkinter as tk
from tkinter import messagebox
import binascii

# 1. Поле Галуа (GF(2^8)) Функції

def gf_mul(a, b):
    """Множення двох елементів у GF(2^8)"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1b  # Неперервний поліном
        b >>= 1
    return p

def gf_inverse(a):
    """Знаходження мультиплікативного оберненого елемента у GF(2^8)"""
    if a == 0:
        return 0
    # Розширений алгоритм Евкліда для GF(2^8)
    r0, r1 = 0x11b, a
    s0, s1 = 0, 1
    while r1 != 0:
        deg_r0 = r0.bit_length() - 1
        deg_r1 = r1.bit_length() - 1
        if deg_r0 < deg_r1:
            r0, r1 = r1, r0
            s0, s1 = s1, s0
            deg_r0, deg_r1 = deg_r1, deg_r0
        shift = deg_r0 - deg_r1
        r0 ^= r1 << shift
        s0 ^= s1 << shift
    if r0 != 1:
        return 0  # Обернений елемент не існує
    # Зменшуємо s0 до 8 біт
    while s0.bit_length() > 8:
        shift = s0.bit_length() - 9
        s0 ^= 0x11b << shift
    return s0 & 0xFF

# 2. SubBytes та InvSubBytes Функції

def affine_transform(byte):
    """Виконує аффінне перетворення для одного байта"""
    c = 0x63
    result = 0
    for i in range(8):
        bit = (
            ((byte >> i) & 1) ^
            ((byte >> ((i + 4) % 8)) & 1) ^
            ((byte >> ((i + 5) % 8)) & 1) ^
            ((byte >> ((i + 6) % 8)) & 1) ^
            ((byte >> ((i + 7) % 8)) & 1) ^
            ((c >> i) & 1)
        )
        result |= (bit << i)
    return result

def inv_affine_transform(byte):
    """Виконує зворотне аффінне перетворення для одного байта"""
    c = 0x05
    result = 0
    for i in range(8):
        bit = (
            ((byte >> ((i + 2) % 8)) & 1) ^
            ((byte >> ((i + 5) % 8)) & 1) ^
            ((byte >> ((i + 7) % 8)) & 1) ^
            ((c >> i) & 1)
        )
        result |= (bit << i)
    return result

def sub_bytes(state):
    """Виконує операцію SubBytes над станом"""
    for i in range(16):
        byte = state[i]
        inv = gf_inverse(byte)
        state[i] = affine_transform(inv)
    return state

def inv_sub_bytes(state):
    """Виконує операцію InvSubBytes над станом"""
    for i in range(16):
        byte = state[i]
        byte = inv_affine_transform(byte)
        state[i] = gf_inverse(byte)
    return state

# 3. ShiftRows та InvShiftRows Функції

def shift_rows(state):
    """Виконує операцію ShiftRows над станом"""
    new_state = state.copy()
    # Рядок 1: зсуваємо на 1 вліво
    new_state[1], new_state[5], new_state[9], new_state[13] = \
        state[5], state[9], state[13], state[1]
    # Рядок 2: зсуваємо на 2 вліво
    new_state[2], new_state[6], new_state[10], new_state[14] = \
        state[10], state[14], state[2], state[6]
    # Рядок 3: зсуваємо на 3 вліво (або на 1 вправо)
    new_state[3], new_state[7], new_state[11], new_state[15] = \
        state[15], state[3], state[7], state[11]
    return new_state

def inv_shift_rows(state):
    """Виконує операцію InvShiftRows над станом"""
    new_state = state.copy()
    # Рядок 1: зсуваємо на 1 вправо
    new_state[5], new_state[9], new_state[13], new_state[1] = \
        state[1], state[5], state[9], state[13]
    # Рядок 2: зсуваємо на 2 вправо
    new_state[10], new_state[14], new_state[2], new_state[6] = \
        state[2], state[6], state[10], state[14]
    # Рядок 3: зсуваємо на 3 вправо (або на 1 вліво)
    new_state[15], new_state[3], new_state[7], new_state[11] = \
        state[3], state[7], state[11], state[15]
    return new_state

# 4. MixColumns та InvMixColumns Функції

def mix_columns(state):
    """Виконує операцію MixColumns над станом"""
    for c in range(4):
        column = state[c*4:(c+1)*4]
        mixed = [
            gf_mul(column[0], 2) ^ gf_mul(column[1], 3) ^ column[2] ^ column[3],
            column[0] ^ gf_mul(column[1], 2) ^ gf_mul(column[2], 3) ^ column[3],
            column[0] ^ column[1] ^ gf_mul(column[2], 2) ^ gf_mul(column[3], 3),
            gf_mul(column[0], 3) ^ column[1] ^ column[2] ^ gf_mul(column[3], 2)
        ]
        state[c*4:(c+1)*4] = mixed
    return state

def inv_mix_columns(state):
    """Виконує операцію InvMixColumns над станом"""
    for c in range(4):
        column = state[c*4:(c+1)*4]
        mixed = [
            gf_mul(column[0], 14) ^ gf_mul(column[1], 11) ^ gf_mul(column[2], 13) ^ gf_mul(column[3], 9),
            gf_mul(column[0], 9) ^ gf_mul(column[1], 14) ^ gf_mul(column[2], 11) ^ gf_mul(column[3], 13),
            gf_mul(column[0], 13) ^ gf_mul(column[1], 9) ^ gf_mul(column[2], 14) ^ gf_mul(column[3], 11),
            gf_mul(column[0], 11) ^ gf_mul(column[1], 13) ^ gf_mul(column[2], 9) ^ gf_mul(column[3], 14)
        ]
        state[c*4:(c+1)*4] = mixed
    return state

# 5. AddRoundKey Функція

def add_round_key(state, round_key):
    """Виконує операцію AddRoundKey над станом"""
    return [s ^ k for s, k in zip(state, round_key)]

# 6. Key Expansion Функції

RCON = [
    0x00, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C,
    0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63,
    0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA,
    0xEF, 0xC5, 0x91
]

def rot_word(word):
    """Зсуває байти слова вліво на один"""
    return word[1:] + word[:1]

def sub_word(word):
    """Застосовує SubBytes до кожного байту слова"""
    return [affine_transform(gf_inverse(b)) for b in word]

def key_expansion(key):
    """Розгортає початковий ключ у раундові ключі"""
    Nk = 4  # Кількість слів у ключі (4 для 128-біт)
    Nr = 10  # Кількість раундів для 128-бітного ключа
    w = []
    # Ініціалізуємо перші Nk слів початковим ключем
    for i in range(Nk):
        word = key[4*i : 4*(i+1)]
        w.append(word)
    # Розгортаємо ключ
    for i in range(Nk, 4*(Nr+1)):
        temp = w[i-1].copy()
        if i % Nk == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= RCON[i//Nk]
        word = [ (w[i-Nk][j] ^ temp[j]) for j in range(4) ]
        w.append(word)
    # Конвертуємо слова у байтовий масив
    expanded_key = []
    for word in w:
        expanded_key += word
    return expanded_key

# 7. Шифрування та Дешифрування

def aes_encrypt(plaintext, key):
    """Шифрує 128-бітний plaintext з використанням 128-бітного ключа
    Повертає ciphertext та стан після першого раунду
    """
    state = plaintext.copy()
    expanded_key = key_expansion(key)
    Nr = 10  # Кількість раундів для 128-бітного ключа
    first_round_state = None

    # Початкова AddRoundKey
    round_key = expanded_key[0:16]
    state = add_round_key(state, round_key)

    # Основні раунди
    for round in range(1, Nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        round_key = expanded_key[16*round : 16*(round+1)]
        state = add_round_key(state, round_key)
        if round == 1:
            first_round_state = state.copy()

    # Останній раунд (без MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    round_key = expanded_key[16*Nr : 16*(Nr+1)]
    state = add_round_key(state, round_key)

    return state, first_round_state

def aes_decrypt(ciphertext, key):
    """Дешифрує 128-бітний ciphertext з використанням 128-бітного ключа"""
    state = ciphertext.copy()
    expanded_key = key_expansion(key)
    Nr = 10  # Кількість раундів для 128-бітного ключа

    # Початкова AddRoundKey
    round_key = expanded_key[16*Nr : 16*(Nr+1)]
    state = add_round_key(state, round_key)

    # Основні раунди
    for round in range(Nr-1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        round_key = expanded_key[16*round : 16*(round+1)]
        state = add_round_key(state, round_key)
        state = inv_mix_columns(state)

    # Останній раунд (без InvMixColumns)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    round_key = expanded_key[0:16]
    state = add_round_key(state, round_key)

    return state

# 8. Допоміжні Функції

def string_to_bytes(s):
    """Конвертує рядок в список байтів (ASCII)"""
    return [ord(c) for c in s]

def bytes_to_hex(b):
    """Конвертує список байтів в шістнадцятковий рядок"""
    return ''.join(['{:02x}'.format(byte) for byte in b])

def bytes_to_binary(b):
    """Конвертує список байтів в бітовий рядок"""
    return ' '.join(['{:08b}'.format(byte) for byte in b])

def hex_to_bytes(hex_str):
    """Конвертує шістнадцятковий рядок в список байтів"""
    hex_str = hex_str.replace(" ", "").replace("\n", "").lower()
    if len(hex_str) != 32:
        raise ValueError("Вхідний шістнадцятковий рядок повинен мати рівно 32 символи (128 біт).")
    try:
        return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]
    except:
        raise ValueError("Вхідний рядок містить некоректні шістнадцяткові символи.")

def bytes_to_string(b):
    """Конвертує список байтів в рядок (Текст)"""
    try:
        return bytes(b).decode('utf-8')
    except UnicodeDecodeError:
        return ''.join(['.' if byte < 32 or byte > 126 else chr(byte) for byte in b])

# 9. Графічний Інтерфейс (GUI) за допомогою Tkinter

class AES_GUI:
    def __init__(self, master):
        self.master = master
        master.title("AES-128 Шифрування та Дешифрування")

        # Створення фреймів
        self.input_frame = tk.Frame(master)
        self.input_frame.pack(pady=10)

        self.button_frame = tk.Frame(master)
        self.button_frame.pack(pady=10)

        self.output_frame = tk.Frame(master)
        self.output_frame.pack(pady=10)

        # Введення Plaintext
        self.plaintext_label = tk.Label(self.input_frame, text="Plaintext (32 шістнадцяткових символи):")
        self.plaintext_label.grid(row=0, column=0, sticky='e')
        self.plaintext_entry = tk.Entry(self.input_frame, width=40)
        self.plaintext_entry.grid(row=0, column=1, padx=5)
        self.plaintext_text_label = tk.Label(self.input_frame, text="Plaintext (Текст):")
        self.plaintext_text_label.grid(row=1, column=0, sticky='e')
        self.plaintext_text_display = tk.Label(self.input_frame, text="", bg="white", anchor='w', width=40, relief='sunken')
        self.plaintext_text_display.grid(row=1, column=1, padx=5)

        # Введення Key
        self.key_label = tk.Label(self.input_frame, text="Key (32 шістнадцяткових символи):")
        self.key_label.grid(row=2, column=0, sticky='e')
        self.key_entry = tk.Entry(self.input_frame, width=40)
        self.key_entry.grid(row=2, column=1, padx=5)

        # Кнопки
        self.encrypt_button = tk.Button(self.button_frame, text="Зашифрувати", command=self.encrypt)
        self.encrypt_button.grid(row=0, column=0, padx=10)

        self.decrypt_button = tk.Button(self.button_frame, text="Розшифрувати", command=self.decrypt)
        self.decrypt_button.grid(row=0, column=1, padx=10)

        self.example_button = tk.Button(self.button_frame, text="Прикладні Дані", command=self.load_example)
        self.example_button.grid(row=0, column=2, padx=10)

        # Виведення Ciphertext
        self.ciphertext_label = tk.Label(self.output_frame, text="Шифротекст (Шістнадцятковий): Відображає зашифрований текст у шістнадцятковому форматі.")
        self.ciphertext_label.grid(row=0, column=0, sticky='e')
        self.ciphertext_hex_text = tk.Text(self.output_frame, height=2, width=50, state='disabled')
        self.ciphertext_hex_text.grid(row=0, column=1, padx=5)
        self.ciphertext_binary_label = tk.Label(self.output_frame, text="Шифротекст (Бітовий): Відображає зашифрований текст у бітовому форматі.")
        self.ciphertext_binary_label.grid(row=1, column=0, sticky='e')
        self.ciphertext_binary_text = tk.Text(self.output_frame, height=2, width=50, state='disabled')
        self.ciphertext_binary_text.grid(row=1, column=1, padx=5)

        # Виведення Decrypted Text
        self.decrypted_hex_label = tk.Label(self.output_frame, text="Розшифрований Текст (Шістнадцятковий): Відображає розшифрований текст у шістнадцятковому форматі.")
        self.decrypted_hex_label.grid(row=2, column=0, sticky='e')
        self.decrypted_hex_text = tk.Text(self.output_frame, height=2, width=50, state='disabled')
        self.decrypted_hex_text.grid(row=2, column=1, padx=5)
        self.decrypted_text_label = tk.Label(self.output_frame, text="Розшифрований Текст (Текст): Відображає розшифрований текст як звичайний текстовий рядок.")
        self.decrypted_text_label.grid(row=3, column=0, sticky='e')
        self.decrypted_text_display = tk.Text(self.output_frame, height=2, width=50, state='disabled')
        self.decrypted_text_display.grid(row=3, column=1, padx=5)

        # Виведення Стану Після Першого Раунду
        self.first_round_label = tk.Label(self.output_frame, text="Стан після першого раунду (Шістнадцятковий): Відображає стан шифрування після першого раунду у шістнадцятковому форматі.")
        self.first_round_label.grid(row=4, column=0, sticky='e')
        self.first_round_text = tk.Text(self.output_frame, height=2, width=50, state='disabled')
        self.first_round_text.grid(row=4, column=1, padx=5)

        # Прив'язка подій для оновлення Plaintext (Текст) при введенні Hex
        self.plaintext_entry.bind("<KeyRelease>", self.update_plaintext_text)

    def update_plaintext_text(self, event=None):
        """Оновлює поле Plaintext (Текст) відповідно до введеного Hex"""
        plaintext_hex = self.plaintext_entry.get()
        try:
            plaintext_bytes = hex_to_bytes(plaintext_hex)
            plaintext_text = bytes_to_string(plaintext_bytes)
        except:
            plaintext_text = "Некоректний формат Hex"
        self.plaintext_text_display.config(text=plaintext_text)

    def encrypt(self):
        plaintext_hex = self.plaintext_entry.get()
        key_hex = self.key_entry.get()
        try:
            plaintext = hex_to_bytes(plaintext_hex)
            key = hex_to_bytes(key_hex)
        except ValueError as ve:
            messagebox.showerror("Помилка Введення", str(ve))
            return

        ciphertext, first_round_state = aes_encrypt(plaintext.copy(), key.copy())
        ciphertext_hex = bytes_to_hex(ciphertext)
        ciphertext_binary = bytes_to_binary(ciphertext)
        first_round_hex = bytes_to_hex(first_round_state) if first_round_state else ""

        # Відображення Шифротексту (Шістнадцятковий)
        self.ciphertext_hex_text.config(state='normal')
        self.ciphertext_hex_text.delete(1.0, tk.END)
        self.ciphertext_hex_text.insert(tk.END, ciphertext_hex)
        self.ciphertext_hex_text.config(state='disabled')

        # Відображення Шифротексту (Бітовий)
        self.ciphertext_binary_text.config(state='normal')
        self.ciphertext_binary_text.delete(1.0, tk.END)
        self.ciphertext_binary_text.insert(tk.END, ciphertext_binary)
        self.ciphertext_binary_text.config(state='disabled')

        # Відображення Стану Після Першого Раунду
        self.first_round_text.config(state='normal')
        self.first_round_text.delete(1.0, tk.END)
        self.first_round_text.insert(tk.END, first_round_hex)
        self.first_round_text.config(state='disabled')

        # Очистити поля розшифрованого тексту
        self.decrypted_hex_text.config(state='normal')
        self.decrypted_hex_text.delete(1.0, tk.END)
        self.decrypted_hex_text.config(state='disabled')

        self.decrypted_text_display.config(state='normal')
        self.decrypted_text_display.delete(1.0, tk.END)
        self.decrypted_text_display.config(state='disabled')

    def decrypt(self):
        ciphertext_hex = self.ciphertext_hex_text.get(1.0, tk.END).strip()
        key_hex = self.key_entry.get()
        try:
            ciphertext = hex_to_bytes(ciphertext_hex)
            key = hex_to_bytes(key_hex)
        except ValueError as ve:
            messagebox.showerror("Помилка Введення", str(ve))
            return

        decrypted = aes_decrypt(ciphertext.copy(), key.copy())
        decrypted_hex = bytes_to_hex(decrypted)
        decrypted_text = bytes_to_string(decrypted)

        # Відображення Розшифрованого Тексту (Шістнадцятковий)
        self.decrypted_hex_text.config(state='normal')
        self.decrypted_hex_text.delete(1.0, tk.END)
        self.decrypted_hex_text.insert(tk.END, decrypted_hex)
        self.decrypted_hex_text.config(state='disabled')

        # Відображення Розшифрованого Тексту (Текст)
        self.decrypted_text_display.config(state='normal')
        self.decrypted_text_display.delete(1.0, tk.END)
        self.decrypted_text_display.insert(tk.END, decrypted_text)
        self.decrypted_text_display.config(state='disabled')

    def load_example(self):
        """Завантажує відомий тестовий вектор для перевірки"""
        # Відомий тестовий вектор з FIPS-197
        plaintext_hex = '427269676874206e6577206964656173'
        key_hex = '000102030405060708090a0b0c0d0e0f'
        expected_ciphertext_hex = '69c4e0d86a7b0430d8cdb78070b4c55a'

        self.plaintext_entry.delete(0, tk.END)
        self.plaintext_entry.insert(0, plaintext_hex)
        self.update_plaintext_text()

        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key_hex)

        try:
            ciphertext, first_round_state = aes_encrypt(hex_to_bytes(plaintext_hex), hex_to_bytes(key_hex))
            ciphertext_hex_result = bytes_to_hex(ciphertext)
            ciphertext_binary = bytes_to_binary(ciphertext)
            first_round_hex = bytes_to_hex(first_round_state) if first_round_state else ""
        except Exception as e:
            messagebox.showerror("Помилка Шифрування", f"Сталася помилка під час шифрування: {e}")
            return

        # Відображення Шифротексту (Шістнадцятковий)
        self.ciphertext_hex_text.config(state='normal')
        self.ciphertext_hex_text.delete(1.0, tk.END)
        self.ciphertext_hex_text.insert(tk.END, ciphertext_hex_result)
        self.ciphertext_hex_text.config(state='disabled')

        # Відображення Шифротексту (Бітовий)
        self.ciphertext_binary_text.config(state='normal')
        self.ciphertext_binary_text.delete(1.0, tk.END)
        self.ciphertext_binary_text.insert(tk.END, ciphertext_binary)
        self.ciphertext_binary_text.config(state='disabled')

        # Відображення Стану Після Першого Раунду
        self.first_round_text.config(state='normal')
        self.first_round_text.delete(1.0, tk.END)
        self.first_round_text.insert(tk.END, first_round_hex)
        self.first_round_text.config(state='disabled')

        # Перевірка правильності
        correct = (ciphertext_hex_result.lower() == expected_ciphertext_hex.lower())
        if correct:
            decrypted = aes_decrypt(ciphertext.copy(), hex_to_bytes(key_hex))
            decrypted_hex = bytes_to_hex(decrypted)
            decrypted_text = bytes_to_string(decrypted)
            self.decrypted_hex_text.config(state='normal')
            self.decrypted_hex_text.delete(1.0, tk.END)
            self.decrypted_hex_text.insert(tk.END, decrypted_hex)
            self.decrypted_hex_text.config(state='disabled')

            self.decrypted_text_display.config(state='normal')
            self.decrypted_text_display.delete(1.0, tk.END)
            self.decrypted_text_display.insert(tk.END, decrypted_text)
            self.decrypted_text_display.config(state='disabled')

            messagebox.showinfo("Прикладні Дані", "Прикладний тест пройдено успішно!")
        else:
            messagebox.showerror("Прикладні Дані", "Прикладний тест не пройдено. Шифротекст не збігається з очікуваним результатом.")

# 10. Основна Функція

def main():
    root = tk.Tk()
    gui = AES_GUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
