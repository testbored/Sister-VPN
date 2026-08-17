# Sister-VPN

Sister-VPN adalah aplikasi VPN Layer 3 point-to-point untuk Linux. Aplikasi
mengambil paket IP dari perangkat TUN, melindunginya, dan mengirimkannya melalui
UDP. Di sisi penerima, aplikasi memverifikasi dan membuka paket tersebut lalu
menulis paket IP asli kembali ke TUN. Karena itu, kernel penerima
memperlakukan hasilnya sebagai traffic jaringan native.

## Fitur penting

- Tunnel Layer 3 menggunakan perangkat Linux TUN dengan `IFF_NO_PI`, sehingga
  data yang diproses aplikasi adalah paket IP asli.
- Transport tunnel menggunakan UDP sesuai kebutuhan proyek.
- Forwarding dua arah: `TUN -> encrypt -> UDP` dan
  `UDP -> decrypt -> TUN`.
- Peer UDP bersifat point-to-point: alamat IP dan port peer diberikan melalui
  argumen program.
- Setiap datagram memiliki header 20 byte yang memuat magic number, versi,
  session ID, dan sequence number.
- Penerima memverifikasi header dan tag autentikasi sebelum paket ditulis ke
  TUN, sehingga payload yang diubah atau memakai key salah akan ditolak.
- Replay window 64 paket menolak paket duplikat atau paket lama dalam satu
  session.

## Algoritma kriptografi dan alasan pemilihan

Sister-VPN memakai **ChaCha20-Poly1305** dari OpenSSL. Algoritma ini adalah
AEAD (*Authenticated Encryption with Associated Data*): payload paket IP
dienkripsi untuk menjaga kerahasiaan, sekaligus diberi autentikasi untuk
menjaga integritas dan keaslian. Artinya, penerima tidak akan memasukkan paket
ke TUN jika ciphertext, header, atau tag telah dimodifikasi.

Key awal berupa *pre-shared key* 32 byte yang dimasukkan sebagai 64 karakter
hex. HMAC-SHA-256 menurunkan key kirim dan key terima yang berbeda berdasarkan
role `initiator`/`responder`. Pemisahan ini mencegah penggunaan key dan nonce
yang sama pada dua arah traffic. Nonce 96-bit dibentuk dari session ID acak dan
sequence number yang terus naik. Kombinasi ini cocok dengan kebutuhan nonce
unik ChaCha20-Poly1305. Ini tetap proyek pembelajaran, bukan pengganti VPN
produksi seperti WireGuard.

Format datagram adalah `header 20 byte | ciphertext paket IP | tag 16 byte`.

## Build

Butuh Linux, compiler C++17, header OpenSSL (`libssl-dev`), serta perangkat
`/dev/net/tun`. Proses perlu dijalankan sebagai root atau memiliki capability
`CAP_NET_ADMIN` untuk membuat TUN.

```bash
cmake -S . -B build
cmake --build build
```

Jika CMake belum tersedia, build langsung dengan `g++`:

```bash
g++ -std=c++17 -Wall -Wextra -Wpedantic -Werror -Iincludes \
  src/main.cpp src/vpn.cpp src/tun.cpp src/udp.cpp src/crypto.cpp \
  -lcrypto -o sister-vpn
```

## Cara menjalankan program

Contoh ini memakai dua mesin yang UDP-nya saling dapat dijangkau pada `192.0.2.10` dan `192.0.2.20`. Buat PSK sekali (`openssl rand -hex 32`), lalu gunakan nilai sama di kedua sisi.

```bash
# Endpoint A, sebagai root/CAP_NET_ADMIN
sudo ./build/sister-vpn --tun svpn0 --listen 6700 \
  --peer 192.0.2.20:6700 --role initiator --key <PSK_HEX_64>

# Setelah interface svpn0 dibuat oleh program, di terminal lain:
sudo ip addr add 10.8.0.1/30 dev svpn0
sudo ip link set svpn0 mtu 1364 up

# Endpoint B
sudo ./build/sister-vpn --tun svpn0 --listen 6700 \
  --peer 192.0.2.10:6700 --role responder --key <PSK_HEX_64>

# Setelah interface svpn0 dibuat oleh program, di terminal lain:
sudo ip addr add 10.8.0.2/30 dev svpn0
sudo ip link set svpn0 mtu 1364 up
```

Atur alamat interface segera setelah proses membuat TUN. Nilai MTU TUN `1364` berasal dari batas datagram default 1400 dikurangi header tunnel 20 byte dan tag 16 byte; jika memakai `--mtu` lain, gunakan MTU TUN maksimal `nilai - 36`. Jangan mengarahkan route endpoint UDP publik lewat `svpn0`, karena tunnel akan merutekan dirinya sendiri.

## Bukti pengujian yang diminta

1. Tampilkan kedua proses dan `ip addr show svpn0`.
2. Jalankan `ping 10.8.0.2` dari A dan `ping 10.8.0.1` dari B.
3. Transfer ≥2 MB, misalnya `dd if=/dev/urandom of=large.bin bs=1M count=3`, `python3 -m http.server 8080 --bind 10.8.0.1`, lalu unduh dari B dan bandingkan `sha256sum`.
4. Jalankan `tcpdump -ni <public-interface> udp port 6700` untuk menunjukkan jaringan publik hanya melihat UDP; `tcpdump -ni svpn0` memperlihatkan paket IP asli.
