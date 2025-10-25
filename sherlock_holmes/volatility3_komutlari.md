## 🛠️ Volatility Komutları

```bash
# Süreç listeleme
vol -f memory.dump windows.pslist
vol -f memory.dump windows.pstree

# Komut satırı
vol -f memory.dump windows.cmdline

# Ağ bağlantıları
vol -f memory.dump windows.netscan

# Dosya tarama
vol -f memory.dump windows.filescan
vol -f memory.dump windows.filescan | grep -i "resume"

# Malware tespiti
vol -f memory.dump windows.malfind
vol -f memory.dump windows.psxview
```