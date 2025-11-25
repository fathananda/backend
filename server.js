const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'rahasia_absensi_2024';

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = './uploads/pengajuan';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|pdf/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Hanya file gambar (JPG, PNG) atau PDF yang diizinkan'));
  }
});



// Database setup
const db = new sqlite3.Database('./absensi.db', (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
    initDatabase();
  }
});

// Initialize database tables
// Initialize database tables
function initDatabase() {
  // Gunakan db.serialize() untuk memastikan query dijalankan berurutan
  db.serialize(() => {
    // 1. CREATE TABLE mahasiswa
    db.run(`CREATE TABLE IF NOT EXISTS mahasiswa (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nama TEXT NOT NULL,
      nim TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'mahasiswa',
      gaji_pokok REAL DEFAULT 5690752,
      tunjangan_hadir REAL DEFAULT 50000,
      potongan_telat_sedang REAL DEFAULT 25000,
      potongan_telat_berat REAL DEFAULT 50000,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) console.error('Error creating mahasiswa table:', err);
      else console.log('✓ Table mahasiswa ready');
    });

    // 2. CREATE TABLE absensi
    db.run(`CREATE TABLE IF NOT EXISTS absensi (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mahasiswa_id INTEGER NOT NULL,
      tanggal DATETIME NOT NULL,
      jam_seharusnya TIME NOT NULL,
      jam_masuk_aktual TIME NOT NULL,
      keterlambatan_menit INTEGER DEFAULT 0,
      kategori_keterlambatan TEXT,
      sanksi TEXT,
      latitude REAL NOT NULL,
      longitude REAL NOT NULL,
      jarak_dari_kantor REAL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (mahasiswa_id) REFERENCES mahasiswa(id)
    )`, (err) => {
      if (err) console.error('Error creating absensi table:', err);
      else console.log('✓ Table absensi ready');
    });

    // 3. CREATE TABLE kalender
    db.run(`CREATE TABLE IF NOT EXISTS kalender (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tanggal DATE NOT NULL,
      jenis TEXT NOT NULL,
      keterangan TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) console.error('Error creating kalender table:', err);
      else console.log('✓ Table kalender ready');
    });

    // 4. CREATE TABLE pengajuan
    db.run(`CREATE TABLE IF NOT EXISTS pengajuan (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mahasiswa_id INTEGER NOT NULL,
      jenis TEXT NOT NULL,
      tanggal_mulai DATE NOT NULL,
      tanggal_selesai DATE NOT NULL,
      keterangan TEXT,
      foto_bukti TEXT,
      status TEXT DEFAULT 'pending',
      alasan_ditolak TEXT,
      diproses_oleh INTEGER,
      diproses_pada DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (mahasiswa_id) REFERENCES mahasiswa(id),
      FOREIGN KEY (diproses_oleh) REFERENCES mahasiswa(id)
    )`, (err) => {
      if (err) console.error('Error creating pengajuan table:', err);
      else console.log('✓ Table pengajuan ready');
    });

    // 5. CREATE TABLE konfigurasi
    db.run(`CREATE TABLE IF NOT EXISTS konfigurasi (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nama TEXT UNIQUE NOT NULL,
      nilai TEXT NOT NULL
    )`, (err) => {
      if (err) console.error('Error creating konfigurasi table:', err);
      else console.log('✓ Table konfigurasi ready');
    });

    // 6. INSERT default konfigurasi
    const defaultConfig = [
      { nama: 'jam_masuk_default', nilai: '08:00' },
      { nama: 'kantor_latitude', nilai: '-6.360427' },
      { nama: 'kantor_longitude', nilai: '107.095709' },
      { nama: 'kantor_nama', nilai: 'SMK Al-Luthfah - Villa Mutiara Cikarang' },
      { nama: 'radius_maksimal', nilai: '1000' }
    ];

    defaultConfig.forEach(config => {
      db.get("SELECT * FROM konfigurasi WHERE nama = ?", [config.nama], (err, row) => {
        if (err) {
          console.error('Error checking konfigurasi:', err);
          return;
        }
        if (!row) {
          db.run("INSERT INTO konfigurasi (nama, nilai) VALUES (?, ?)", [config.nama, config.nilai], (err) => {
            if (err) console.error('Error inserting konfigurasi:', err);
          });
        }
      });
    });

    // 7. CREATE admin account
    db.get("SELECT * FROM mahasiswa WHERE nim = 'admin'", (err, row) => {
      if (err) {
        console.error('Error checking admin:', err);
        return;
      }
      
      if (!row) {
        bcrypt.hash('admin123', 10, (err, hash) => {
          if (err) {
            console.error('❌ Error hashing password admin:', err);
            return;
          }
          
          db.run(
            `INSERT INTO mahasiswa (nama, nim, password, role, gaji_pokok, tunjangan_hadir, potongan_telat_sedang, potongan_telat_berat) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            ['Administrator', 'admin', hash, 'admin', 0, 0, 0, 0],
            (err) => {
              if (err) {
                console.error('❌ Error creating admin:', err);
              } else {
                console.log('\n=== AKUN ADMIN BERHASIL DIBUAT ===');
                console.log('NIM: admin');
                console.log('Password: admin123');
                console.log('===================================\n');
              }
            }
          );
        });
      } else {
        console.log('✓ Akun admin sudah ada');
      }
    });

    // 8. INSERT sample kalender
    const today = new Date();
    const nextWeek = new Date(today.getTime() + 7 * 24 * 60 * 60 * 1000);
    
    db.get("SELECT COUNT(*) as count FROM kalender", (err, row) => {
      if (err) {
        console.error('Error checking kalender:', err);
        return;
      }
      
      if (row && row.count === 0) {
        const sampleEvents = [
          { tanggal: nextWeek.toISOString().split('T')[0], jenis: 'libur', keterangan: 'Libur Nasional' },
          { tanggal: new Date(today.getTime() + 14 * 24 * 60 * 60 * 1000).toISOString().split('T')[0], jenis: 'ujian', keterangan: 'Ujian Tengah Semester' }
        ];
        
        sampleEvents.forEach(event => {
          db.run("INSERT INTO kalender (tanggal, jenis, keterangan) VALUES (?, ?, ?)", 
            [event.tanggal, event.jenis, event.keterangan],
            (err) => {
              if (err) console.error('Error inserting kalender:', err);
            }
          );
        });
      }
    });
  });
}

// ===========================
// FUNGSI PERHITUNGAN JARAK (Haversine Formula)
// ===========================

/**
 * Menghitung jarak antara dua titik koordinat (dalam meter)
 * @param {number} lat1 - Latitude titik 1
 * @param {number} lon1 - Longitude titik 1
 * @param {number} lat2 - Latitude titik 2
 * @param {number} lon2 - Longitude titik 2
 * @returns {number} Jarak dalam meter
 */


function hitungJarak(lat1, lon1, lat2, lon2) {
  const R = 6371e3; // Radius bumi dalam meter
  const φ1 = lat1 * Math.PI / 180;
  const φ2 = lat2 * Math.PI / 180;
  const Δφ = (lat2 - lat1) * Math.PI / 180;
  const Δλ = (lon2 - lon1) * Math.PI / 180;

  const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
            Math.cos(φ1) * Math.cos(φ2) *
            Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c; // Jarak dalam meter
}

/**
 * Validasi apakah lokasi dalam radius yang diizinkan
 * @param {number} userLat - Latitude user
 * @param {number} userLon - Longitude user
 * @param {number} officeLat - Latitude kantor
 * @param {number} officeLon - Longitude kantor
 * @param {number} maxRadius - Radius maksimal dalam meter
 * @returns {object} { valid, jarak, pesan }
 */
function validasiLokasi(userLat, userLon, officeLat, officeLon, maxRadius) {
  const jarak = hitungJarak(userLat, userLon, officeLat, officeLon);
  const valid = jarak <= maxRadius;

  return {
    valid,
    jarak: Math.round(jarak * 10) / 10, // Bulatkan 1 desimal
    pesan: valid 
      ? `Lokasi valid (${Math.round(jarak)}m dari kantor)`
      : `Lokasi terlalu jauh! Anda berada ${Math.round(jarak)}m dari kantor (maksimal ${maxRadius}m)`
  };
}

// ===========================
// FUNGSI PERHITUNGAN KETERLAMBATAN
// ===========================

const ATURAN_KETERLAMBATAN = {
  RINGAN: { min: 0, max: 30, label: 'Telat Ringan', sanksi: 'Tidak ada sanksi' },
  SEDANG: { min: 30, max: 120, label: 'Telat Sedang', sanksi: 'Potong tunjangan makan' },
  BERAT: { min: 120, max: Infinity, label: 'Telat Berat', sanksi: 'Penundaan jenjang karir' }
};

function hitungSelisihMenit(jamSeharusnya, jamAktual) {
  const [jamS, menitS] = jamSeharusnya.split(':').map(Number);
  const [jamA, menitA] = jamAktual.split(':').map(Number);
  
  const totalMenitSeharusnya = jamS * 60 + menitS;
  const totalMenitAktual = jamA * 60 + menitA;
  
  return totalMenitAktual - totalMenitSeharusnya;
}

function tentukanKategoriDanSanksi(menitTerlambat) {
  if (menitTerlambat <= 0) {
    return {
      kategori: 'Tepat Waktu',
      sanksi: 'Tidak ada sanksi'
    };
  }

  for (const [key, aturan] of Object.entries(ATURAN_KETERLAMBATAN)) {
    if (menitTerlambat > aturan.min && menitTerlambat <= aturan.max) {
      return {
        kategori: aturan.label,
        sanksi: aturan.sanksi
      };
    }
  }

  return {
    kategori: ATURAN_KETERLAMBATAN.BERAT.label,
    sanksi: ATURAN_KETERLAMBATAN.BERAT.sanksi
  };
}

function prosesKeterlambatan(jamSeharusnya, jamAktual) {
  const selisihMenit = hitungSelisihMenit(jamSeharusnya, jamAktual);
  const menitTerlambat = Math.max(0, selisihMenit);
  const { kategori, sanksi } = tentukanKategoriDanSanksi(menitTerlambat);

  return {
    jam_seharusnya: jamSeharusnya,
    jam_masuk_aktual: jamAktual,
    keterlambatan_menit: menitTerlambat,
    kategori_keterlambatan: kategori,
    sanksi: sanksi,
    status: menitTerlambat === 0 ? 'Tepat Waktu' : 'Terlambat'
  };
}

// ===========================
// FUNGSI CEK ABSEN HARI INI
// ===========================

function cekAbsenHariIni(mahasiswaId, callback) {
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  
  db.get(
    `SELECT * FROM absensi 
     WHERE mahasiswa_id = ? 
     AND DATE(tanggal) = DATE(?)
     ORDER BY id DESC LIMIT 1`,
    [mahasiswaId, today],
    callback
  );
}

// NEW: Fungsi perhitungan tunjangan
// PERBAIKAN LENGKAP - Ganti fungsi hitungTunjanganBulanan di server.js

function hitungTunjanganBulanan(mahasiswaId, bulan, tahun, callback) {
  const startDate = `${tahun}-${String(bulan).padStart(2, '0')}-01`;
  const endDate = `${tahun}-${String(bulan).padStart(2, '0')}-31`;

  // Ambil data mahasiswa
  db.get('SELECT * FROM mahasiswa WHERE id = ?', [mahasiswaId], (err, mahasiswa) => {
    if (err || !mahasiswa) {
      return callback(err || new Error('Mahasiswa tidak ditemukan'));
    }

    // TAMBAHKAN DEFAULT VALUE JIKA NULL/UNDEFINED
    const tunjanganHadirPerHari = mahasiswa.tunjangan_hadir || 50000;
    const potonganTelatSedangPerHari = mahasiswa.potongan_telat_sedang || 25000;
    const potonganTelatBeratPerHari = mahasiswa.potongan_telat_berat || 50000;
    const gajiPokok = mahasiswa.gaji_pokok || 5690752;

    // Hitung total hari kerja (exclude weekend & libur)
    db.all(
      `SELECT tanggal, jenis FROM kalender 
       WHERE tanggal BETWEEN ? AND ?`,
      [startDate, endDate],
      (err, kalenderData) => {
        if (err) return callback(err);

        // Hitung absensi
        db.all(
          `SELECT * FROM absensi 
           WHERE mahasiswa_id = ? 
           AND DATE(tanggal) BETWEEN ? AND ?`,
          [mahasiswaId, startDate, endDate],
          (err, absensiData) => {
            if (err) return callback(err);

            // Hitung pengajuan yang disetujui
            db.all(
              `SELECT * FROM pengajuan 
               WHERE mahasiswa_id = ? 
               AND status = 'disetujui'
               AND tanggal_mulai BETWEEN ? AND ?`,
              [mahasiswaId, startDate, endDate],
              (err, pengajuanData) => {
                if (err) return callback(err);

                // Hitung hari kerja
                const totalHariKerja = 22;

                // Hitung kehadiran
                const tepatWaktu = absensiData.filter(a => a.kategori_keterlambatan === 'Tepat Waktu').length;
                const telatRingan = absensiData.filter(a => a.kategori_keterlambatan === 'Telat Ringan').length;
                const telatSedang = absensiData.filter(a => a.kategori_keterlambatan === 'Telat Sedang').length;
                const telatBerat = absensiData.filter(a => a.kategori_keterlambatan === 'Telat Berat').length;
                
                const totalHadir = absensiData.length;
                const totalIzin = pengajuanData.filter(p => p.jenis === 'izin').length;
                const totalSakit = pengajuanData.filter(p => p.jenis === 'sakit').length;
                const totalDinas = pengajuanData.filter(p => p.jenis === 'dinas').length;
                const totalAlpa = Math.max(0, totalHariKerja - totalHadir - totalIzin - totalSakit - totalDinas);

                // Hitung dengan default value yang sudah disiapkan
                const tunjanganHadir = tepatWaktu * tunjanganHadirPerHari;
                const potonganTelatSedang = telatSedang * potonganTelatSedangPerHari;
                const potonganTelatBerat = telatBerat * potonganTelatBeratPerHari;
                const potonganAlpa = totalAlpa * 100000;

                const totalTunjangan = tunjanganHadir;
                const totalPotongan = potonganTelatSedang + potonganTelatBerat + potonganAlpa;
                const gajiBersih = gajiPokok + totalTunjangan - totalPotongan;

                callback(null, {
                  periode: `${getNamaBulan(bulan)} ${tahun}`,
                  bulan,
                  tahun,
                  gaji_pokok: gajiPokok,
                  kehadiran: {
                    total_hari_kerja: totalHariKerja,
                    hadir: totalHadir,
                    tepat_waktu: tepatWaktu,
                    telat_ringan: telatRingan,
                    telat_sedang: telatSedang,
                    telat_berat: telatBerat,
                    izin: totalIzin,
                    sakit: totalSakit,
                    dinas: totalDinas,
                    alpa: totalAlpa
                  },
                  tunjangan: {
                    tunjangan_hadir: tunjanganHadir,
                    detail: `${tepatWaktu} hari x Rp ${tunjanganHadirPerHari.toLocaleString()}`
                  },
                  potongan: {
                    telat_sedang: potonganTelatSedang,
                    telat_berat: potonganTelatBerat,
                    alpa: potonganAlpa,
                    total: totalPotongan,
                    detail: [
                      telatSedang > 0 ? `Telat Sedang: ${telatSedang} x Rp ${potonganTelatSedangPerHari.toLocaleString()}` : null,
                      telatBerat > 0 ? `Telat Berat: ${telatBerat} x Rp ${potonganTelatBeratPerHari.toLocaleString()}` : null,
                      totalAlpa > 0 ? `Alpa: ${totalAlpa} x Rp 100.000` : null
                    ].filter(Boolean)
                  },
                  total_tunjangan: totalTunjangan,
                  total_potongan: totalPotongan,
                  gaji_bersih: gajiBersih
                });
              }
            );
          }
        );
      }
    );
  });
}

function getNamaBulan(bulan) {
  const namaBulan = ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 
                     'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'];
  return namaBulan[bulan - 1];
}


// ===========================
// MIDDLEWARE
// ===========================

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  
  if (!token) {
    return res.status(403).json({ message: 'Token tidak disediakan' });
  }

  jwt.verify(token.replace('Bearer ', ''), SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Token tidak valid' });
    }
    req.userId = decoded.id;
    req.userRole = decoded.role;
    console.log('User ID:', decoded.id, 'Role:', decoded.role);
    next();
  });
}

function verifyAdmin(req, res, next) {
  console.log('Checking admin access, userRole:', req.userRole);
  if (req.userRole !== 'admin') {
    return res.status(403).json({ message: 'Akses ditolak. Hanya admin.' });
  }
  next();
}

// ===========================
// ENDPOINTS
// ===========================

// POST /register
app.post('/register', async (req, res) => {
  const { nama, nim, password } = req.body;

  if (!nama || !nim || !password) {
    return res.status(400).json({ message: 'Semua field harus diisi' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(
      'INSERT INTO mahasiswa (nama, nim, password) VALUES (?, ?, ?)',
      [nama, nim, hashedPassword],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ message: 'NIM sudah terdaftar' });
          }
          return res.status(500).json({ message: 'Error saat registrasi' });
        }
        
        res.status(201).json({
          message: 'Registrasi berhasil',
          data: {
            id: this.lastID,
            nama,
            nim
          }
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'Error server' });
  }
});

// POST /login
app.post('/login', (req, res) => {
  const { nim, password } = req.body;

  if (!nim || !password) {
    return res.status(400).json({ message: 'NIM dan password harus diisi' });
  }

  db.get('SELECT * FROM mahasiswa WHERE nim = ?', [nim], async (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Error server' });
    }

    if (!user) {
      return res.status(401).json({ message: 'NIM atau password salah' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'NIM atau password salah' });
    }

    const token = jwt.sign({ id: user.id, nim: user.nim, role: user.role || 'mahasiswa' }, SECRET_KEY, {
      expiresIn: '7d'
    });

    res.json({
      message: 'Login berhasil',
      token,
      data: {
        id: user.id,
        nama: user.nama,
        nim: user.nim,
        role: user.role || 'mahasiswa'
      }
    });
  });
});

// GET /cek-absen-hari-ini/:mahasiswa_id (NEW)
app.get('/cek-absen-hari-ini/:mahasiswa_id', verifyToken, (req, res) => {
  const { mahasiswa_id } = req.params;
  
  cekAbsenHariIni(mahasiswa_id, (err, row) => {
    if (err) {
      return res.status(500).json({ message: 'Error cek absen' });
    }
    
    res.json({
      message: 'Berhasil cek absen hari ini',
      sudah_absen: !!row,
      data: row || null
    });
  });
});

app.get('/admin/dashboard', verifyToken, verifyAdmin, (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  const thisMonth = new Date().toISOString().slice(0, 7);

  db.get('SELECT COUNT(*) as total FROM mahasiswa WHERE role = "mahasiswa"', [], (err, totalGuru) => {
    if (err) return res.status(500).json({ message: 'Error' });

    db.get('SELECT COUNT(*) as total FROM absensi WHERE DATE(tanggal) = ?', [today], (err, absenHariIni) => {
      if (err) return res.status(500).json({ message: 'Error' });

      db.get('SELECT COUNT(*) as total FROM pengajuan WHERE status = "pending"', [], (err, pengajuanPending) => {
        if (err) return res.status(500).json({ message: 'Error' });

        db.get(`SELECT COUNT(*) as total FROM absensi 
                WHERE strftime('%Y-%m', tanggal) = ? 
                AND keterlambatan_menit > 0`, [thisMonth], (err, telatBulanIni) => {
          if (err) return res.status(500).json({ message: 'Error' });

          res.json({
            message: 'Dashboard admin',
            data: {
              total_guru: totalGuru.total,
              absen_hari_ini: absenHariIni.total,
              pengajuan_pending: pengajuanPending.total,
              telat_bulan_ini: telatBulanIni.total
            }
          });
        });
      });
    });
  });
});

// GET /admin/guru - Daftar semua guru
app.get('/admin/guru', verifyToken, verifyAdmin, (req, res) => {
  db.all(`SELECT id, nama, nim, role, gaji_pokok, tunjangan_hadir, 
          potongan_telat_sedang, potongan_telat_berat, created_at 
          FROM mahasiswa WHERE role = "mahasiswa" ORDER BY nama ASC`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error mengambil data guru' });
    res.json({ message: 'Daftar guru', data: rows });
  });
});

// GET /admin/guru/:id - Detail guru
app.get('/admin/guru/:id', verifyToken, verifyAdmin, (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT * FROM mahasiswa WHERE id = ?', [id], (err, guru) => {
    if (err) return res.status(500).json({ message: 'Error' });
    if (!guru) return res.status(404).json({ message: 'Guru tidak ditemukan' });
    
    res.json({ message: 'Detail guru', data: guru });
  });
});

// PUT /admin/guru/:id - Update data guru
app.put('/admin/guru/:id', verifyToken, verifyAdmin, (req, res) => {
  const { id } = req.params;
  const { nama, nim, gaji_pokok, tunjangan_hadir, potongan_telat_sedang, potongan_telat_berat } = req.body;
  
  db.run(
    `UPDATE mahasiswa SET nama = ?, nim = ?, gaji_pokok = ?, 
     tunjangan_hadir = ?, potongan_telat_sedang = ?, potongan_telat_berat = ?
     WHERE id = ?`,
    [nama, nim, gaji_pokok, tunjangan_hadir, potongan_telat_sedang, potongan_telat_berat, id],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ message: 'NIM sudah digunakan' });
        }
        return res.status(500).json({ message: 'Error update guru' });
      }
      res.json({ message: 'Data guru berhasil diupdate' });
    }
  );
});

// DELETE /admin/guru/:id - Hapus guru
app.delete('/admin/guru/:id', verifyToken, verifyAdmin, (req, res) => {
  const { id } = req.params;
  
  // Hapus data terkait dulu
  db.run('DELETE FROM absensi WHERE mahasiswa_id = ?', [id], (err) => {
    if (err) return res.status(500).json({ message: 'Error' });
    
    db.run('DELETE FROM pengajuan WHERE mahasiswa_id = ?', [id], (err) => {
      if (err) return res.status(500).json({ message: 'Error' });
      
      db.run('DELETE FROM mahasiswa WHERE id = ?', [id], function(err) {
        if (err) return res.status(500).json({ message: 'Error hapus guru' });
        res.json({ message: 'Guru berhasil dihapus' });
      });
    });
  });
});

// GET /admin/absensi - Semua absensi dengan filter
app.get('/admin/absensi', verifyToken, verifyAdmin, (req, res) => {
  const { tanggal, mahasiswa_id } = req.query;
  
  let query = `SELECT a.*, m.nama, m.nim 
               FROM absensi a 
               JOIN mahasiswa m ON a.mahasiswa_id = m.id WHERE 1=1`;
  const params = [];
  
  if (tanggal) {
    query += ' AND DATE(a.tanggal) = ?';
    params.push(tanggal);
  }
  
  if (mahasiswa_id) {
    query += ' AND a.mahasiswa_id = ?';
    params.push(mahasiswa_id);
  }
  
  query += ' ORDER BY a.tanggal DESC LIMIT 100';
  
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error' });
    res.json({ message: 'Data absensi', data: rows });
  });
});

// GET /admin/laporan/kehadiran - Laporan kehadiran per guru
app.get('/admin/laporan/kehadiran', verifyToken, verifyAdmin, (req, res) => {
  const { bulan, tahun } = req.query;
  const now = new Date();
  const targetBulan = bulan || (now.getMonth() + 1);
  const targetTahun = tahun || now.getFullYear();
  
  const startDate = `${targetTahun}-${String(targetBulan).padStart(2, '0')}-01`;
  const endDate = `${targetTahun}-${String(targetBulan).padStart(2, '0')}-31`;
  
  db.all(`SELECT 
            m.id, m.nama, m.nim,
            COUNT(a.id) as total_hadir,
            SUM(CASE WHEN a.kategori_keterlambatan = 'Tepat Waktu' THEN 1 ELSE 0 END) as tepat_waktu,
            SUM(CASE WHEN a.kategori_keterlambatan = 'Telat Ringan' THEN 1 ELSE 0 END) as telat_ringan,
            SUM(CASE WHEN a.kategori_keterlambatan = 'Telat Sedang' THEN 1 ELSE 0 END) as telat_sedang,
            SUM(CASE WHEN a.kategori_keterlambatan = 'Telat Berat' THEN 1 ELSE 0 END) as telat_berat
          FROM mahasiswa m
          LEFT JOIN absensi a ON m.id = a.mahasiswa_id 
            AND DATE(a.tanggal) BETWEEN ? AND ?
          WHERE m.role = 'mahasiswa'
          GROUP BY m.id, m.nama, m.nim
          ORDER BY m.nama`, [startDate, endDate], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error' });
    res.json({ 
      message: 'Laporan kehadiran',
      periode: `${getNamaBulan(targetBulan)} ${targetTahun}`,
      data: rows 
    });
  });
});

// GET /admin/pengajuan/pending - Pengajuan yang perlu diproses
app.get('/admin/pengajuan/pending', verifyToken, verifyAdmin, (req, res) => {
  db.all(`SELECT p.*, m.nama, m.nim 
          FROM pengajuan p 
          JOIN mahasiswa m ON p.mahasiswa_id = m.id 
          WHERE p.status = 'pending' 
          ORDER BY p.created_at ASC`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error' });
    res.json({ message: 'Pengajuan pending', data: rows });
  });
});

// POST /admin/create-guru - Buat akun guru baru (admin only)
app.post('/admin/create-guru', verifyToken, verifyAdmin, async (req, res) => {
  const { nama, nim, password, gaji_pokok, tunjangan_hadir } = req.body;
  
  if (!nama || !nim || !password) {
    return res.status(400).json({ message: 'Data tidak lengkap' });
  }
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(
      `INSERT INTO mahasiswa (nama, nim, password, role, gaji_pokok, tunjangan_hadir) 
       VALUES (?, ?, ?, 'mahasiswa', ?, ?)`,
      [nama, nim, hashedPassword, gaji_pokok || 5690752, tunjangan_hadir || 50000],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ message: 'NIM sudah terdaftar' });
          }
          return res.status(500).json({ message: 'Error membuat akun' });
        }
        
        res.status(201).json({
          message: 'Akun guru berhasil dibuat',
          data: { id: this.lastID, nama, nim }
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'Error server' });
  }
});


// POST /presensi (UPDATED dengan validasi lokasi)
app.post('/presensi', verifyToken, (req, res) => {
  const { mahasiswa_id, jam_seharusnya, jam_masuk_aktual, latitude, longitude } = req.body;

  if (!mahasiswa_id || !jam_masuk_aktual || latitude === undefined || longitude === undefined) {
    return res.status(400).json({ message: 'Data tidak lengkap' });
  }

  // Cek apakah sudah absen hari ini
  cekAbsenHariIni(mahasiswa_id, (err, existingAbsen) => {
    if (err) {
      return res.status(500).json({ message: 'Error cek absen' });
    }

    if (existingAbsen) {
      return res.status(400).json({ 
        message: 'Anda sudah melakukan presensi hari ini',
        data: existingAbsen
      });
    }

    // Ambil konfigurasi
    db.all('SELECT * FROM konfigurasi', (err, configs) => {
      if (err) {
        return res.status(500).json({ message: 'Error mengambil konfigurasi' });
      }

      const config = {};
      configs.forEach(c => {
        config[c.nama] = c.nilai;
      });

      const jamSeharusnya = jam_seharusnya || config.jam_masuk_default || '08:00';
      const officeLat = parseFloat(config.kantor_latitude || -6.360427);
      const officeLon = parseFloat(config.kantor_longitude || 107.095709);
      const maxRadius = parseFloat(config.radius_maksimal || 1000);

      // Validasi lokasi
      const lokasiCheck = validasiLokasi(latitude, longitude, officeLat, officeLon, maxRadius);

      if (!lokasiCheck.valid) {
        return res.status(400).json({
          message: lokasiCheck.pesan,
          valid: false,
          jarak: lokasiCheck.jarak,
          radius_maksimal: maxRadius,
          lokasi_kantor: config.kantor_nama
        });
      }

      // Proses presensi
      const tanggal = new Date().toISOString();
      const hasilKeterlambatan = prosesKeterlambatan(jamSeharusnya, jam_masuk_aktual);

      db.run(
        `INSERT INTO absensi (
          mahasiswa_id, tanggal, jam_seharusnya, jam_masuk_aktual, 
          keterlambatan_menit, kategori_keterlambatan, sanksi, 
          latitude, longitude, jarak_dari_kantor
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          mahasiswa_id, 
          tanggal, 
          hasilKeterlambatan.jam_seharusnya, 
          hasilKeterlambatan.jam_masuk_aktual,
          hasilKeterlambatan.keterlambatan_menit,
          hasilKeterlambatan.kategori_keterlambatan,
          hasilKeterlambatan.sanksi,
          latitude, 
          longitude,
          lokasiCheck.jarak
        ],
        function(err) {
          if (err) {
            console.error('Error insert absensi:', err);
            return res.status(500).json({ message: 'Error saat presensi' });
          }

          res.status(201).json({
            message: 'Presensi berhasil',
            data: {
              id: this.lastID,
              mahasiswa_id,
              tanggal,
              ...hasilKeterlambatan,
              latitude,
              longitude,
              jarak_dari_kantor: lokasiCheck.jarak,
              pesan_lokasi: lokasiCheck.pesan
            }
          });
        }
      );
    });
  });
});

// POST /absen (backward compatibility)
app.post('/absen', verifyToken, (req, res) => {
  const now = new Date();
  const jam_masuk_aktual = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
  
  req.body.jam_masuk_aktual = jam_masuk_aktual;
  
  app._router.handle({...req, url: '/presensi', method: 'POST'}, res);
});

// GET /riwayat/:id_mahasiswa
app.get('/riwayat/:id_mahasiswa', verifyToken, (req, res) => {
  const { id_mahasiswa } = req.params;

  db.all(
    `SELECT a.*, m.nama, m.nim 
     FROM absensi a 
     JOIN mahasiswa m ON a.mahasiswa_id = m.id 
     WHERE a.mahasiswa_id = ? 
     ORDER BY a.tanggal DESC`,
    [id_mahasiswa],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ message: 'Error mengambil riwayat' });
      }

      res.json({
        message: 'Berhasil mengambil riwayat',
        data: rows
      });
    }
  );
});

app.get('/kalender', verifyToken, verifyAdmin, (req, res) => {
  const { bulan, tahun } = req.query;
  
  let query = 'SELECT * FROM kalender';
  const params = [];
  
  if (bulan && tahun) {
    query += ' WHERE strftime("%m", tanggal) = ? AND strftime("%Y", tanggal) = ?';
    params.push(String(bulan).padStart(2, '0'), String(tahun));
  }
  
  query += ' ORDER BY tanggal ASC';
  
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error mengambil kalender' });
    res.json({ message: 'Berhasil mengambil kalender', data: rows });
  });
});

app.post('/kalender', verifyToken, verifyAdmin, (req, res) => {
  const { tanggal, jenis, keterangan } = req.body;
  
  if (!tanggal || !jenis) {
    return res.status(400).json({ message: 'Tanggal dan jenis harus diisi' });
  }
  
  db.run(
    'INSERT INTO kalender (tanggal, jenis, keterangan) VALUES (?, ?, ?)',
    [tanggal, jenis, keterangan],
    function(err) {
      if (err) return res.status(500).json({ message: 'Error menambah kalender' });
      res.status(201).json({
        message: 'Kalender berhasil ditambahkan',
        data: { id: this.lastID, tanggal, jenis, keterangan }
      });
    }
  );
});

app.delete('/kalender/:id', verifyToken, verifyAdmin, (req, res) => {
  const { id } = req.params;
  
  db.run('DELETE FROM kalender WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ message: 'Error menghapus kalender' });
    res.json({ message: 'Kalender berhasil dihapus' });
  });
});

app.post('/pengajuan', verifyToken, upload.single('foto_bukti'), (req, res) => {
  const { mahasiswa_id, jenis, tanggal_mulai, tanggal_selesai, keterangan } = req.body;
  const foto_bukti = req.file ? `/uploads/pengajuan/${req.file.filename}` : null;
  
  if (!mahasiswa_id || !jenis || !tanggal_mulai || !tanggal_selesai) {
    return res.status(400).json({ message: 'Data tidak lengkap' });
  }
  
  db.run(
    `INSERT INTO pengajuan (mahasiswa_id, jenis, tanggal_mulai, tanggal_selesai, keterangan, foto_bukti)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [mahasiswa_id, jenis, tanggal_mulai, tanggal_selesai, keterangan, foto_bukti],
    function(err) {
      if (err) return res.status(500).json({ message: 'Error mengajukan' });
      res.status(201).json({
        message: 'Pengajuan berhasil diajukan',
        data: {
          id: this.lastID,
          mahasiswa_id,
          jenis,
          tanggal_mulai,
          tanggal_selesai,
          keterangan,
          foto_bukti,
          status: 'pending'
        }
      });
    }
  );
});

app.get('/pengajuan', verifyToken, (req, res) => {
  const { mahasiswa_id, status } = req.query;
  
  let query = `SELECT p.*, m.nama, m.nim 
               FROM pengajuan p 
               JOIN mahasiswa m ON p.mahasiswa_id = m.id`;
  const params = [];
  const conditions = [];
  
  if (mahasiswa_id) {
    conditions.push('p.mahasiswa_id = ?');
    params.push(mahasiswa_id);
  }
  
  if (status) {
    conditions.push('p.status = ?');
    params.push(status);
  }
  
  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }
  
  query += ' ORDER BY p.created_at DESC';
  
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error mengambil pengajuan' });
    res.json({ message: 'Berhasil mengambil pengajuan', data: rows });
  });
});

app.put('/pengajuan/:id/proses', verifyToken, verifyAdmin, (req, res) => {
  const { id } = req.params;
  const { status, alasan_ditolak } = req.body;
  
  if (!status || !['disetujui', 'ditolak'].includes(status)) {
    return res.status(400).json({ message: 'Status harus disetujui atau ditolak' });
  }
  
  db.run(
    `UPDATE pengajuan 
     SET status = ?, alasan_ditolak = ?, diproses_oleh = ?, diproses_pada = ?
     WHERE id = ?`,
    [status, alasan_ditolak, req.userId, new Date().toISOString(), id],
    function(err) {
      if (err) return res.status(500).json({ message: 'Error memproses pengajuan' });
      res.json({ message: `Pengajuan berhasil ${status}` });
    }
  );
});

app.get('/tunjangan/:mahasiswa_id', verifyToken, (req, res) => {
  const { mahasiswa_id } = req.params;
  const { bulan, tahun } = req.query;
  
  const now = new Date();
  const targetBulan = bulan ? parseInt(bulan) : now.getMonth() + 1;
  const targetTahun = tahun ? parseInt(tahun) : now.getFullYear();
  
  hitungTunjanganBulanan(mahasiswa_id, targetBulan, targetTahun, (err, result) => {
    if (err) return res.status(500).json({ message: err.message });
    res.json({
      message: 'Berhasil menghitung tunjangan',
      data: result
    });
  });
});

app.get('/tunjangan/:mahasiswa_id/ringkasan', verifyToken, (req, res) => {
  const { mahasiswa_id } = req.params;
  const now = new Date();
  const bulanIni = now.getMonth() + 1;
  const tahunIni = now.getFullYear();
  
  // Hitung 3 bulan terakhir
  const promises = [];
  for (let i = 0; i < 3; i++) {
    let bulan = bulanIni - i;
    let tahun = tahunIni;
    
    if (bulan <= 0) {
      bulan += 12;
      tahun -= 1;
    }
    
    promises.push(
      new Promise((resolve, reject) => {
        hitungTunjanganBulanan(mahasiswa_id, bulan, tahun, (err, result) => {
          if (err) reject(err);
          else resolve(result);
        });
      })
    );
  }
  
  Promise.all(promises)
    .then(results => {
      res.json({
        message: 'Berhasil mengambil ringkasan tunjangan',
        data: results
      });
    })
    .catch(err => {
      res.status(500).json({ message: err.message });
    });
});

// GET /konfigurasi
app.get('/konfigurasi', verifyToken, (req, res) => {
  db.all('SELECT * FROM konfigurasi', (err, rows) => {
    if (err) {
      return res.status(500).json({ message: 'Error mengambil konfigurasi' });
    }

    const config = {};
    rows.forEach(row => {
      config[row.nama] = row.nilai;
    });

    res.json({
      message: 'Berhasil mengambil konfigurasi',
      data: config
    });
  });
});

// PUT /konfigurasi
app.put('/konfigurasi', verifyToken, (req, res) => {
  const updates = req.body;
  const allowedKeys = ['jam_masuk_default', 'kantor_latitude', 'kantor_longitude', 'kantor_nama', 'radius_maksimal'];
  
  const validUpdates = Object.keys(updates).filter(key => allowedKeys.includes(key));
  
  if (validUpdates.length === 0) {
    return res.status(400).json({ message: 'Tidak ada data yang valid untuk diupdate' });
  }

  let completed = 0;
  const errors = [];

  validUpdates.forEach(key => {
    db.run(
      "UPDATE konfigurasi SET nilai = ? WHERE nama = ?",
      [updates[key], key],
      (err) => {
        if (err) errors.push({ key, error: err.message });
        
        completed++;
        if (completed === validUpdates.length) {
          if (errors.length > 0) {
            return res.status(500).json({ 
              message: 'Beberapa update gagal', 
              errors 
            });
          }
          
          res.json({
            message: 'Konfigurasi berhasil diupdate',
            data: updates
          });
        }
      }
    );
  });
});

// DELETE /mahasiswa/:id  → hapus akun berdasarkan ID
app.delete('/mahasiswa/:id', verifyToken, verifyAdmin, (req, res) => {
  const { id } = req.params;

  db.run(`DELETE FROM absensi WHERE mahasiswa_id = ?`, [id], function(err) {
    if (err) {
      return res.status(500).json({ message: 'Gagal menghapus data absensi' });
    }

    db.run(`DELETE FROM pengajuan WHERE mahasiswa_id = ?`, [id], function(err) {
      if (err) {
        return res.status(500).json({ message: 'Gagal menghapus data pengajuan' });
      }

      db.run(`DELETE FROM mahasiswa WHERE id = ?`, [id], function(err) {
        if (err) {
          return res.status(500).json({ message: 'Gagal menghapus akun mahasiswa' });
        }

        if (this.changes === 0) {
          return res.status(404).json({ message: 'Akun tidak ditemukan' });
        }

        return res.json({
          message: `Akun mahasiswa dengan ID ${id} berhasil dihapus`
        });
      });
    });
  });
});


// Start server
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
    console.log('\n=== FITUR APLIKASI ===');
    console.log('✓ Presensi dengan validasi lokasi');
    console.log('✓ Perhitungan keterlambatan & sanksi');
    console.log('✓ Kalender sekolah (libur, ujian, kegiatan)');
    console.log('✓ Pengajuan izin/sakit/dinas dengan upload foto');
    console.log('✓ Perhitungan tunjangan & gaji otomatis');
    console.log('✓ Laporan bulanan kehadiran');
    console.log('\nAturan Keterlambatan:');
    console.log('- 0-30 menit: Telat Ringan (Tidak ada sanksi)');
    console.log('- 30-120 menit: Telat Sedang (Potong tunjangan makan)');
    console.log('- >120 menit: Telat Berat (Penundaan jenjang karir)');
    console.log('\nValidasi Lokasi: Maksimal 100m dari kantor');
});