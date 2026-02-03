import tkinter as tk
from tkinter import ttk, scrolledtext
from tkinterdnd2 import DND_FILES, TkinterDnD
import os
import re

class CATIAVersionChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("CATIA Versiyon Kontrol")
        self.root.geometry("700x500")
        self.root.configure(bg='#2b2b2b')
        
        # Başlık
        title_frame = tk.Frame(root, bg='#1e1e1e', height=60)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame, 
            text="🔍 CATIA Dosya Versiyon Kontrolü",
            font=('Segoe UI', 16, 'bold'),
            bg='#1e1e1e',
            fg='#ffffff'
        )
        title_label.pack(expand=True)
        
        # Sürükle-bırak alanı
        drop_frame = tk.Frame(root, bg='#3d3d3d', relief=tk.RIDGE, borderwidth=2)
        drop_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))
        
        self.drop_label = tk.Label(
            drop_frame,
            text="📁 CATIA dosyalarını buraya sürükleyin\n\n"
                 "Desteklenen formatlar:\n"
                 ".CATPart, .CATProduct, .CATDrawing, .CATMaterial",
            font=('Segoe UI', 11),
            bg='#3d3d3d',
            fg='#e0e0e0',
            justify=tk.CENTER
        )
        self.drop_label.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
        
        # Sürükle-bırak özelliğini etkinleştir
        self.drop_label.drop_target_register(DND_FILES)
        self.drop_label.dnd_bind('<<Drop>>', self.drop_files)
        self.drop_label.dnd_bind('<<DragEnter>>', self.drag_enter)
        self.drop_label.dnd_bind('<<DragLeave>>', self.drag_leave)
        
        # Sonuç alanı
        result_label = tk.Label(
            root,
            text="Sonuçlar:",
            font=('Segoe UI', 10, 'bold'),
            bg='#2b2b2b',
            fg='#ffffff',
            anchor='w'
        )
        result_label.pack(fill=tk.X, padx=20, pady=(5, 5))
        
        self.result_text = scrolledtext.ScrolledText(
            root,
            height=10,
            font=('Consolas', 9),
            bg='#1e1e1e',
            fg='#00ff00',
            insertbackground='white',
            wrap=tk.WORD
        )
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))
        
        # Temizle butonu
        clear_button = tk.Button(
            root,
            text="Temizle",
            command=self.clear_results,
            font=('Segoe UI', 10),
            bg='#444444',
            fg='white',
            activebackground='#555555',
            activeforeground='white',
            relief=tk.FLAT,
            cursor='hand2',
            padx=20,
            pady=5
        )
        clear_button.pack(pady=(0, 10))
        
    def drag_enter(self, event):
        self.drop_label.config(bg='#4d4d4d')
        
    def drag_leave(self, event):
        self.drop_label.config(bg='#3d3d3d')
        
    def drop_files(self, event):
        self.drop_label.config(bg='#3d3d3d')
        files = self.root.tk.splitlist(event.data)
        
        for file_path in files:
            # Windows'ta bazen path'ler {} içinde gelir, bunları temizle
            file_path = file_path.strip('{}')
            if os.path.isfile(file_path):
                self.check_file_version(file_path)
            else:
                self.result_text.insert(tk.END, f"❌ Hata: '{file_path}' dosya değil!\n\n")
        
        self.result_text.see(tk.END)
        
    def check_file_version(self, file_path):
        """CATIA dosyasının versiyonunu kontrol et"""
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_name)[1].lower()
        
        # CATIA dosya uzantılarını kontrol et
        catia_extensions = ['.catpart', '.catproduct', '.catdrawing', '.catmaterial', 
                           '.catshape', '.cgr', '.model']
        
        if file_ext not in catia_extensions:
            self.result_text.insert(tk.END, 
                f"⚠️  '{file_name}'\n"
                f"    Bu bir CATIA dosyası değil (uzantı: {file_ext})\n\n")
            return
        
        try:
            # Dosyayı binary modda aç ve header'ı oku
            with open(file_path, 'rb') as f:
                # İlk 10KB'ı oku (genelde versiyon bilgisi başta bulunur)
                header = f.read(10240)
                
            # Byte array'i string'e çevir (hatalardan kaçın)
            try:
                header_str = header.decode('utf-8', errors='ignore')
            except:
                header_str = header.decode('latin-1', errors='ignore')
            
            # CATIA versiyon bilgisini ara
            version_info = self.extract_version(header_str)
            
            if version_info:
                self.result_text.insert(tk.END, 
                    f"✅ '{file_name}'\n"
                    f"    📌 Versiyon: {version_info}\n"
                    f"    📂 Dosya boyutu: {self.get_file_size(file_path)}\n\n",
                    'success')
            else:
                self.result_text.insert(tk.END,
                    f"⚠️  '{file_name}'\n"
                    f"    Versiyon bilgisi bulunamadı\n"
                    f"    (Dosya bozuk veya desteklenmeyen format olabilir)\n\n")
                
        except Exception as e:
            self.result_text.insert(tk.END,
                f"❌ '{file_name}'\n"
                f"    Hata: {str(e)}\n\n")
    
    def extract_version(self, text):
        """String'den CATIA versiyon bilgisini çıkar"""
        
        # CATIA V5 versiyon desenleri
        patterns = [
            r'V5-6R20\d{2}',  # V5-6R2013, V5-6R2014, vb.
            r'V5R\d{1,2}',     # V5R19, V5R20, V5R21, vb.
            r'V6R20\d{2}',     # V6R2013, V6R2014, vb.
            r'CATIA V\d[\w-]+', # Genel CATIA versiyon
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                version = match.group(0)
                
                # Versiyon numarasını daha anlamlı hale getir
                readable = self.make_version_readable(version)
                return readable
        
        # Alternatif: CATIAV5 stringini bul
        if 'CATIAV5' in text:
            # CATIAV5 etrafındaki metni al
            idx = text.index('CATIAV5')
            surrounding = text[max(0, idx-10):min(len(text), idx+30)]
            
            # Bu bölgede versiyon numarası ara
            for pattern in patterns:
                match = re.search(pattern, surrounding)
                if match:
                    return self.make_version_readable(match.group(0))
            
            return "CATIA V5 (Detaylı versiyon tespit edilemedi)"
        
        return None
    
    def make_version_readable(self, version):
        """Versiyon numarasını okunabilir hale getir"""
        
        # V5-6R2013 formatını açıkla
        if 'V5-6R' in version:
            year = version.split('R')[1]
            return f"{version} (CATIA V5-6 Release {year})"
        
        # V5R21 formatını açıkla
        elif 'V5R' in version:
            release = version.replace('V5R', '')
            return f"{version} (CATIA V5 Release {release})"
        
        # V6R2013 formatını açıkla
        elif 'V6R' in version:
            year = version.split('R')[1]
            return f"{version} (CATIA V6 Release {year})"
        
        return version
    
    def get_file_size(self, file_path):
        """Dosya boyutunu okunabilir formatta döndür"""
        size = os.path.getsize(file_path)
        
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.2f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.2f} GB"
    
    def clear_results(self):
        """Sonuç alanını temizle"""
        self.result_text.delete(1.0, tk.END)

def main():
    root = TkinterDnD.Tk()
    app = CATIAVersionChecker(root)
    root.mainloop()

if __name__ == "__main__":
    main()
