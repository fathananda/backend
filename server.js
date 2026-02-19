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

// ===========================
// MIDDLEWARE
// ===========================
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// ===========================
// RATE LIMITER - Mencegah brute force attack pada endpoint login
// ===========================
const loginAttempts = new Map(); // key: IP, value: { count, blockedUntil }
const MAX_LOGIN_ATTEMPTS = 5;
const BLOCK_DURATION_MS = 15 * 60 * 1000; // 15 menit

function checkLoginRateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const record = loginAttempts.get(ip);

  if (record && record.blockedUntil && now < record.blockedUntil) {
    const sisaDetik = Math.ceil((record.blockedUntil - now) / 1000);
    return res.status(429).json({
      message: `Terlalu banyak percobaan login. Coba lagi dalam ${sisaDetik} detik.`
    });
  }

  next();
}

function recordLoginFailed(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, blockedUntil: null };

  if (record.blockedUntil && now >= record.blockedUntil) {
    record.count = 0;
    record.blockedUntil = null;
  }

  record.count += 1;
  if (record.count >= MAX_LOGIN_ATTEMPTS) {
    record.blockedUntil = now + BLOCK_DURATION_MS;
    console.log(`[SECURITY] IP ${ip} diblokir selama 15 menit karena ${record.count}x login gagal`);
  }
  loginAttempts.set(ip, record);
}

function recordLoginSuccess(ip) {
  loginAttempts.delete(ip);
}

// ===========================
// MULTER - Upload file bukti pengajuan
// ===========================
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

// ===========================
// DATABASE SETUP
// ===========================
const db = new sqlite3.Database('./absensi.db', (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
    initDatabase();
  }
});


// ===========================
// FUNGSI GENERATE NIP OTOMATIS
// Format: GTH + tahun (4 digit) + nomor urut (4 digit)
// Contoh: GTH20240001
// ===========================
function generateNIP(callback) {
  const tahun = new Date().getFullYear();
  const prefix = `${tahun}`;

  // Cari NIP terakhir dengan prefix tahun yang sama
  db.get(
    `SELECT nip FROM guru WHERE nip LIKE ? ORDER BY nip DESC LIMIT 1`,
    [`${prefix}%`],
    (err, row) => {
      if (err || !row) {
        // Belum ada NIP tahun ini, mulai dari 0001
        callback(null, `${prefix}0001`);
      } else {
        // Ambil nomor urut terakhir dan increment
        const lastNip = row.nip;
        const lastNumber = parseInt(lastNip.replace(prefix, ''), 10);
        const nextNumber = lastNumber + 1;
        const newNip = `${prefix}${String(nextNumber).padStart(4, '0')}`;
        callback(null, newNip);
      }
    }
  );
}

// ===========================
// INISIALISASI DATABASE
// ===========================
function initDatabase() {
  db.serialize(() => {

    // ------------------------------------------
    // 1. TABEL GURU
    // ------------------------------------------
    db.run(`CREATE TABLE IF NOT EXISTS guru (
      id                    INTEGER PRIMARY KEY AUTOINCREMENT,
      nama                  TEXT    NOT NULL,
      nip                   TEXT    UNIQUE,
      email                 TEXT    UNIQUE NOT NULL,
      password              TEXT    NOT NULL,
      role                  TEXT    DEFAULT 'guru',
      gaji_pokok            REAL    DEFAULT 5690752,
      tunjangan_hadir       REAL    DEFAULT 50000,
      potongan_telat_sedang REAL    DEFAULT 25000,
      potongan_telat_berat  REAL    DEFAULT 50000,
      email_verified        INTEGER DEFAULT 0,
      last_login            DATETIME,
      device_id             TEXT,
      created_at            DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) console.error('Error creating guru table:', err);
      else console.log('✓ Table guru ready');
    });

    // ------------------------------------------
    // 2. TABEL ABSENSI
    // ------------------------------------------
    db.run(`CREATE TABLE IF NOT EXISTS absensi (
      id                       INTEGER PRIMARY KEY AUTOINCREMENT,
      guru_id                  INTEGER NOT NULL,
      tanggal                  DATETIME NOT NULL,
      jam_seharusnya           TIME NOT NULL,
      jam_masuk_aktual         TIME NOT NULL,
      keterlambatan_menit      INTEGER DEFAULT 0,
      kategori_keterlambatan   TEXT,
      sanksi                   TEXT,
      latitude                 REAL NOT NULL,
      longitude                REAL NOT NULL,
      jarak_dari_kantor        REAL,
      gps_accuracy             REAL,
      is_mock_location         INTEGER DEFAULT 0,
      is_fake_gps_suspected    INTEGER DEFAULT 0,
      network_latitude         REAL,
      network_longitude        REAL,
      device_id                TEXT,
      sync_status              TEXT DEFAULT 'online',
      created_at               DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (guru_id) REFERENCES guru(id)
    )`, (err) => {
      if (err) console.error('Error creating absensi table:', err);
      else console.log('✓ Table absensi ready');
    });

    // ------------------------------------------
    // 3. TABEL KALENDER
    // ------------------------------------------
    db.run(`CREATE TABLE IF NOT EXISTS kalender (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      tanggal     DATE    NOT NULL,
      jenis       TEXT    NOT NULL,
      keterangan  TEXT,
      created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) console.error('Error creating kalender table:', err);
      else console.log('✓ Table kalender ready');
    });

    // ------------------------------------------
    // 4. TABEL PENGAJUAN (izin/sakit/dinas)
    // ------------------------------------------
    db.run(`CREATE TABLE IF NOT EXISTS pengajuan (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      guru_id          INTEGER NOT NULL,
      jenis            TEXT    NOT NULL,
      tanggal_mulai    DATE    NOT NULL,
      tanggal_selesai  DATE    NOT NULL,
      keterangan       TEXT,
      foto_bukti       TEXT,
      status           TEXT    DEFAULT 'pending',
      alasan_ditolak   TEXT,
      diproses_oleh    INTEGER,
      diproses_pada    DATETIME,
      created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (guru_id) REFERENCES guru(id),
      FOREIGN KEY (diproses_oleh) REFERENCES guru(id)
    )`, (err) => {
      if (err) console.error('Error creating pengajuan table:', err);
      else console.log('✓ Table pengajuan ready');
    });

    // ------------------------------------------
    // 5. TABEL KONFIGURASI
    // ------------------------------------------
    db.run(`CREATE TABLE IF NOT EXISTS konfigurasi (
      id    INTEGER PRIMARY KEY AUTOINCREMENT,
      nama  TEXT UNIQUE NOT NULL,
      nilai TEXT NOT NULL
    )`, (err) => {
      if (err) console.error('Error creating konfigurasi table:', err);
      else console.log('✓ Table konfigurasi ready');
    });

    // ------------------------------------------
    // 6. TABEL OFFLINE SYNC QUEUE
    // ------------------------------------------
    db.run(`CREATE TABLE IF NOT EXISTS offline_sync_queue (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      guru_id         INTEGER NOT NULL,
      payload         TEXT    NOT NULL,
      submitted_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
      synced_at       DATETIME,
      status          TEXT    DEFAULT 'pending',
      rejection_reason TEXT,
      FOREIGN KEY (guru_id) REFERENCES guru(id)
    )`, (err) => {
      if (err) console.error('Error creating offline_sync_queue table:', err);
      else console.log('✓ Table offline_sync_queue ready');
    });

    // ------------------------------------------
    // 7. TABEL SECURITY LOG
    // ------------------------------------------
    db.run(`CREATE TABLE IF NOT EXISTS security_log (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      guru_id      INTEGER,
      event_type   TEXT    NOT NULL,
      detail       TEXT,
      ip_address   TEXT,
      device_id    TEXT,
      created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) console.error('Error creating security_log table:', err);
      else console.log('✓ Table security_log ready');
    });

    // ------------------------------------------
    // 8. INSERT DEFAULT KONFIGURASI
    // ------------------------------------------
    const defaultConfig = [
      { nama: 'jam_masuk_default',  nilai: '08:00' },
      { nama: 'kantor_latitude',    nilai: '-6.360427' },
      { nama: 'kantor_longitude',   nilai: '107.095709' },
      { nama: 'kantor_nama',        nilai: 'SMK Al-Luthfah - Villa Mutiara Cikarang' },
      { nama: 'radius_maksimal',    nilai: '100' },
      { nama: 'potongan_alpa',      nilai: '100000' },
      { nama: 'max_gps_accuracy',   nilai: '50' },
      { nama: 'offline_max_delay',  nilai: '300' }
    ];

    defaultConfig.forEach(config => {
      db.get("SELECT * FROM konfigurasi WHERE nama = ?", [config.nama], (err, row) => {
        if (!err && !row) {
          db.run("INSERT INTO konfigurasi (nama, nilai) VALUES (?, ?)",
            [config.nama, config.nilai]);
        }
      });
    });

    // ------------------------------------------
    // 9. BUAT AKUN ADMIN DEFAULT
    // ------------------------------------------
    db.get("SELECT * FROM guru WHERE email = 'admin@smkalluthfah.sch.id'", (err, row) => {
      if (!err && !row) {
        bcrypt.hash('admin123', 12, (err, hash) => {
          if (err) return;
          db.run(
            `INSERT INTO guru (nama, nip, email, password, role, gaji_pokok, tunjangan_hadir,
              potongan_telat_sedang, potongan_telat_berat, email_verified)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            ['Administrator', 'admin', 'admin@smkalluthfah.sch.id', hash,
             'admin', 0, 0, 0, 0, 1],
            (err) => {
              if (!err) {
                console.log('\n=== AKUN ADMIN BERHASIL DIBUAT ===');
                console.log('Email   : admin@smkalluthfah.sch.id');
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

    // ------------------------------------------
    // 10. SAMPLE DATA KALENDER
    // ------------------------------------------
    const today = new Date();
    db.get("SELECT COUNT(*) as count FROM kalender", (err, row) => {
      if (!err && row && row.count === 0) {
        const nextWeek = new Date(today.getTime() + 7 * 24 * 60 * 60 * 1000);
        const twoWeeks = new Date(today.getTime() + 14 * 24 * 60 * 60 * 1000);
        const sampleEvents = [
          { tanggal: nextWeek.toISOString().split('T')[0], jenis: 'libur', keterangan: 'Libur Nasional' },
          { tanggal: twoWeeks.toISOString().split('T')[0], jenis: 'ujian', keterangan: 'Ujian Tengah Semester' }
        ];
        sampleEvents.forEach(event => {
          db.run("INSERT INTO kalender (tanggal, jenis, keterangan) VALUES (?, ?, ?)",
            [event.tanggal, event.jenis, event.keterangan]);
        });
      }
    });
  });
}

// ===========================
// FUNGSI UTILITY: HAVERSINE FORMULA
// ===========================
function hitungJarak(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const φ1 = lat1 * Math.PI / 180;
  const φ2 = lat2 * Math.PI / 180;
  const Δφ = (lat2 - lat1) * Math.PI / 180;
  const Δλ = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(Δφ / 2) ** 2 +
            Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function validasiLokasi(userLat, userLon, officeLat, officeLon, maxRadius) {
  const jarak = hitungJarak(userLat, userLon, officeLat, officeLon);
  const valid = jarak <= maxRadius;
  return {
    valid,
    jarak: Math.round(jarak * 10) / 10,
    pesan: valid
      ? `Lokasi valid (${Math.round(jarak)}m dari kantor)`
      : `Lokasi terlalu jauh! Anda berada ${Math.round(jarak)}m dari kantor (maksimal ${maxRadius}m)`
  };
}

// ===========================
// FUNGSI DETEKSI FAKE GPS (SERVER-SIDE)
// ===========================
function analisaFakeGPS(payload) {
  const {
    is_mock_location,
    gps_accuracy,
    network_latitude,
    network_longitude,
    latitude,
    longitude,
    previous_latitude,
    previous_longitude,
    previous_timestamp,
    developer_options_on
  } = payload;

  const warnings = [];
  let is_suspected = false;

  if (is_mock_location === true || is_mock_location === 1) {
    warnings.push('Mock location provider terdeteksi di perangkat');
    is_suspected = true;
  }

  if (developer_options_on === true || developer_options_on === 1) {
    warnings.push('Android Developer Options aktif');
    is_suspected = true;
  }

  if (gps_accuracy !== undefined && gps_accuracy !== null) {
    if (gps_accuracy < 3) {
      warnings.push(`Akurasi GPS terlalu sempurna (${gps_accuracy}m) - kemungkinan fake GPS`);
      is_suspected = true;
    }
    if (gps_accuracy > 50) {
      warnings.push(`Akurasi GPS buruk (${gps_accuracy}m) - lokasi tidak dapat dipercaya`);
      is_suspected = true;
    }
  }

  if (network_latitude && network_longitude) {
    const selisihNetwork = hitungJarak(latitude, longitude, network_latitude, network_longitude);
    if (selisihNetwork > 500) {
      warnings.push(`GPS (${latitude},${longitude}) dan Network location (${network_latitude},${network_longitude}) berbeda ${Math.round(selisihNetwork)}m`);
      is_suspected = true;
    }
  }

  if (previous_latitude && previous_longitude && previous_timestamp) {
    const jarakDariSebelumnya = hitungJarak(latitude, longitude, previous_latitude, previous_longitude);
    const selisihWaktuDetik = (Date.now() - new Date(previous_timestamp).getTime()) / 1000;
    if (selisihWaktuDetik > 0) {
      const kecepatanMperDetik = jarakDariSebelumnya / selisihWaktuDetik;
      const kecepatanKmJam = kecepatanMperDetik * 3.6;
      if (kecepatanKmJam > 30 && jarakDariSebelumnya > 100) {
        warnings.push(`Perpindahan tidak wajar: ${Math.round(jarakDariSebelumnya)}m dalam ${Math.round(selisihWaktuDetik)}s (${Math.round(kecepatanKmJam)} km/jam)`);
        is_suspected = true;
      }
    }
  }

  return { is_suspected, warnings };
}

// ===========================
// FUNGSI UTILITY: KETERLAMBATAN
// ===========================
const ATURAN_KETERLAMBATAN = {
  RINGAN: { min: 0,   max: 30,       label: 'Telat Ringan', sanksi: 'Peringatan lisan' },
  SEDANG: { min: 30,  max: 120,      label: 'Telat Sedang', sanksi: 'Potong tunjangan makan' },
  BERAT:  { min: 120, max: Infinity, label: 'Telat Berat',  sanksi: 'Penundaan jenjang karir' }
};

function hitungSelisihMenit(jamSeharusnya, jamAktual) {
  const [jamS, menitS] = jamSeharusnya.split(':').map(Number);
  const [jamA, menitA] = jamAktual.split(':').map(Number);
  return (jamA * 60 + menitA) - (jamS * 60 + menitS);
}

function tentukanKategoriDanSanksi(menitTerlambat) {
  if (menitTerlambat <= 0) return { kategori: 'Tepat Waktu', sanksi: 'Tidak ada sanksi' };
  for (const [, aturan] of Object.entries(ATURAN_KETERLAMBATAN)) {
    if (menitTerlambat > aturan.min && menitTerlambat <= aturan.max) {
      return { kategori: aturan.label, sanksi: aturan.sanksi };
    }
  }
  return { kategori: ATURAN_KETERLAMBATAN.BERAT.label, sanksi: ATURAN_KETERLAMBATAN.BERAT.sanksi };
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
    sanksi,
    status: menitTerlambat === 0 ? 'Tepat Waktu' : 'Terlambat'
  };
}

// ===========================
// FUNGSI CEK ABSEN HARI INI
// ===========================
function cekAbsenHariIni(guruId, callback) {
  const today = new Date().toISOString().split('T')[0];
  db.get(
    `SELECT * FROM absensi WHERE guru_id = ? AND DATE(tanggal) = DATE(?) ORDER BY id DESC LIMIT 1`,
    [guruId, today],
    callback
  );
}

// ===========================
// FUNGSI HITUNG TUNJANGAN BULANAN
// ===========================
function getNamaBulan(bulan) {
  return ['Januari','Februari','Maret','April','Mei','Juni',
          'Juli','Agustus','September','Oktober','November','Desember'][bulan - 1];
}

function hitungTunjanganBulanan(guruId, bulan, tahun, callback) {
  const startDate = `${tahun}-${String(bulan).padStart(2, '0')}-01`;
  const endDate   = `${tahun}-${String(bulan).padStart(2, '0')}-31`;

  db.get('SELECT * FROM guru WHERE id = ?', [guruId], (err, guru) => {
    if (err || !guru) return callback(err || new Error('Guru tidak ditemukan'));

    const tunjanganHadirPerHari      = guru.tunjangan_hadir       || 50000;
    const potonganTelatSedangPerHari = guru.potongan_telat_sedang || 25000;
    const potonganTelatBeratPerHari  = guru.potongan_telat_berat  || 50000;
    const gajiPokok                  = guru.gaji_pokok            || 5690752;

    db.get("SELECT nilai FROM konfigurasi WHERE nama = 'potongan_alpa'", (err, configAlpa) => {
      const potonganAlpaPerHari = configAlpa ? parseInt(configAlpa.nilai) : 100000;

      db.all(
        `SELECT * FROM absensi WHERE guru_id = ? AND DATE(tanggal) BETWEEN ? AND ?`,
        [guruId, startDate, endDate],
        (err, absensiData) => {
          if (err) return callback(err);

          db.all(
            `SELECT * FROM pengajuan WHERE guru_id = ? AND status = 'disetujui'
             AND tanggal_mulai BETWEEN ? AND ?`,
            [guruId, startDate, endDate],
            (err, pengajuanData) => {
              if (err) return callback(err);

              const totalHariKerja = 22;
              const tepatWaktu  = absensiData.filter(a => a.kategori_keterlambatan === 'Tepat Waktu').length;
              const telatRingan = absensiData.filter(a => a.kategori_keterlambatan === 'Telat Ringan').length;
              const telatSedang = absensiData.filter(a => a.kategori_keterlambatan === 'Telat Sedang').length;
              const telatBerat  = absensiData.filter(a => a.kategori_keterlambatan === 'Telat Berat').length;
              const totalHadir  = absensiData.length;
              const totalIzin   = pengajuanData.filter(p => p.jenis === 'izin').length;
              const totalSakit  = pengajuanData.filter(p => p.jenis === 'sakit').length;
              const totalDinas  = pengajuanData.filter(p => p.jenis === 'dinas').length;

              const totalAlpa = Math.max(0, totalHariKerja - totalHadir - totalIzin - totalSakit - totalDinas);

              const tunjanganHadir      = tepatWaktu * tunjanganHadirPerHari;
              const potonganTelatSedang = telatSedang * potonganTelatSedangPerHari;
              const potonganTelatBerat  = telatBerat  * potonganTelatBeratPerHari;
              const potonganAlpa        = totalAlpa   * potonganAlpaPerHari;

              const totalTunjangan = tunjanganHadir;
              const totalPotongan  = potonganTelatSedang + potonganTelatBerat + potonganAlpa;
              const gajiBersih     = gajiPokok + totalTunjangan - totalPotongan;

              callback(null, {
                periode: `${getNamaBulan(bulan)} ${tahun}`,
                bulan, tahun,
                gaji_pokok: gajiPokok,
                kehadiran: {
                  total_hari_kerja: totalHariKerja,
                  hadir: totalHadir,
                  tepat_waktu: tepatWaktu,
                  telat_ringan: telatRingan,
                  telat_sedang: telatSedang,
                  telat_berat:  telatBerat,
                  izin:   totalIzin,
                  sakit:  totalSakit,
                  dinas:  totalDinas,
                  alpa:   totalAlpa
                },
                tunjangan: {
                  tunjangan_hadir: tunjanganHadir,
                  detail: `${tepatWaktu} hari x Rp ${tunjanganHadirPerHari.toLocaleString('id-ID')}`
                },
                potongan: {
                  telat_sedang: potonganTelatSedang,
                  telat_berat:  potonganTelatBerat,
                  alpa:         potonganAlpa,
                  total:        totalPotongan,
                  detail: [
                    telatSedang > 0 ? `Telat Sedang : ${telatSedang} hari x Rp ${potonganTelatSedangPerHari.toLocaleString('id-ID')}` : null,
                    telatBerat  > 0 ? `Telat Berat  : ${telatBerat} hari x Rp ${potonganTelatBeratPerHari.toLocaleString('id-ID')}`  : null,
                    totalAlpa   > 0 ? `Alfa/Lupa Absen : ${totalAlpa} hari x Rp ${potonganAlpaPerHari.toLocaleString('id-ID')}`      : null
                  ].filter(Boolean)
                },
                total_tunjangan: totalTunjangan,
                total_potongan:  totalPotongan,
                gaji_bersih:     gajiBersih
              });
            }
          );
        }
      );
    });
  });
}

// ===========================
// MIDDLEWARE AUTH
// ===========================
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ message: 'Token tidak disediakan' });

  jwt.verify(token.replace('Bearer ', ''), SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Token tidak valid atau sudah expired' });
    req.userId   = decoded.id;
    req.userRole = decoded.role;
    next();
  });
}

function verifyAdmin(req, res, next) {
  if (req.userRole !== 'admin') {
    return res.status(403).json({ message: 'Akses ditolak. Hanya admin.' });
  }
  next();
}

// ===========================
// FUNGSI CATAT SECURITY LOG
// ===========================
function catatSecurityLog(guruId, eventType, detail, req) {
  const ip       = req ? (req.ip || req.connection.remoteAddress) : null;
  const deviceId = req ? req.body.device_id : null;
  db.run(
    `INSERT INTO security_log (guru_id, event_type, detail, ip_address, device_id)
     VALUES (?, ?, ?, ?, ?)`,
    [guruId, eventType, detail, ip, deviceId]
  );
}

// ============================================================
// ENDPOINTS
// ============================================================

// ------------------------------------------
// POST /register
// ------------------------------------------
app.post('/register', async (req, res) => {
  const { nama, nip, email, password } = req.body;

  if (!nama || !email || !password) {
    return res.status(400).json({ message: 'Nama, email, dan password harus diisi' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Format email tidak valid' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    db.run(
      'INSERT INTO guru (nama, nip, email, password) VALUES (?, ?, ?, ?)',
      [nama, nip || null, email, hashedPassword],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ message: 'Email sudah terdaftar' });
          }
          return res.status(500).json({ message: 'Error saat registrasi' });
        }
        res.status(201).json({
          message: 'Registrasi berhasil',
          data: { id: this.lastID, nama, email, nip }
        });
      }
    );
  } catch {
    res.status(500).json({ message: 'Error server' });
  }
});

// ------------------------------------------
// POST /login
// ------------------------------------------
app.post('/login', checkLoginRateLimit, (req, res) => {
  const { email, password, device_id } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email dan password harus diisi' });
  }

  db.get('SELECT * FROM guru WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ message: 'Error server' });

    if (!user) {
      recordLoginFailed(ip);
      return res.status(401).json({ message: 'Email atau password salah' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      recordLoginFailed(ip);
      catatSecurityLog(user.id, 'LOGIN_GAGAL', `Login gagal dari IP ${ip}`, req);
      return res.status(401).json({ message: 'Email atau password salah' });
    }

    recordLoginSuccess(ip);

    let device_warning = null;
    if (device_id && user.device_id && user.device_id !== device_id) {
      device_warning = 'Peringatan: Login dari perangkat baru terdeteksi.';
      catatSecurityLog(user.id, 'LOGIN_DEVICE_BARU',
        `Login dari device baru: ${device_id} (sebelumnya: ${user.device_id})`, req);
    }

    db.run(
      'UPDATE guru SET device_id = ?, last_login = ? WHERE id = ?',
      [device_id || user.device_id, new Date().toISOString(), user.id]
    );

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role || 'guru' },
      SECRET_KEY,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login berhasil',
      token,
      device_warning,
      data: {
        id:    user.id,
        nama:  user.nama,
        email: user.email,
        nip:   user.nip,
        role:  user.role || 'guru'
      }
    });
  });
});

// ------------------------------------------
// GET /cek-absen-hari-ini/:guru_id
// ------------------------------------------
app.get('/cek-absen-hari-ini/:guru_id', verifyToken, (req, res) => {
  cekAbsenHariIni(req.params.guru_id, (err, row) => {
    if (err) return res.status(500).json({ message: 'Error cek absen' });
    res.json({ message: 'Berhasil cek absen hari ini', sudah_absen: !!row, data: row || null });
  });
});

// ------------------------------------------
// POST /presensi
// ------------------------------------------
app.post('/presensi', verifyToken, (req, res) => {
  const {
    guru_id,
    jam_seharusnya,
    jam_masuk_aktual,
    latitude,
    longitude,
    gps_accuracy,
    is_mock_location,
    developer_options_on,
    network_latitude,
    network_longitude,
    previous_latitude,
    previous_longitude,
    previous_timestamp,
    device_id,
    sync_status
  } = req.body;

  if (!guru_id || !jam_masuk_aktual || latitude === undefined || longitude === undefined) {
    return res.status(400).json({ message: 'Data tidak lengkap' });
  }

  cekAbsenHariIni(guru_id, (err, existingAbsen) => {
    if (err) return res.status(500).json({ message: 'Error cek absen' });
    if (existingAbsen) {
      return res.status(400).json({
        message: 'Anda sudah melakukan presensi hari ini',
        data: existingAbsen
      });
    }

    db.all('SELECT * FROM konfigurasi', (err, configs) => {
      if (err) return res.status(500).json({ message: 'Error mengambil konfigurasi' });

      const config = {};
      configs.forEach(c => { config[c.nama] = c.nilai; });

      const jamSeharusnya = jam_seharusnya || config.jam_masuk_default || '08:00';
      const officeLat     = parseFloat(config.kantor_latitude  || -6.360427);
      const officeLon     = parseFloat(config.kantor_longitude || 107.095709);
      const maxRadius     = parseFloat(config.radius_maksimal  || 100);

      const fakeGpsCheck = analisaFakeGPS({
        is_mock_location, gps_accuracy, network_latitude, network_longitude,
        latitude, longitude, previous_latitude, previous_longitude,
        previous_timestamp, developer_options_on
      });

      if (fakeGpsCheck.is_suspected) {
        catatSecurityLog(
          guru_id,
          'FAKE_GPS_DETECTED',
          JSON.stringify({ warnings: fakeGpsCheck.warnings, latitude, longitude }),
          req
        );
        return res.status(400).json({
          message: 'Presensi ditolak: terdeteksi penggunaan GPS palsu.',
          warnings: fakeGpsCheck.warnings
        });
      }

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

      const tanggal = new Date().toISOString();
      const hasilKeterlambatan = prosesKeterlambatan(jamSeharusnya, jam_masuk_aktual);

      db.run(
        `INSERT INTO absensi (
          guru_id, tanggal, jam_seharusnya, jam_masuk_aktual,
          keterlambatan_menit, kategori_keterlambatan, sanksi,
          latitude, longitude, jarak_dari_kantor,
          gps_accuracy, is_mock_location, is_fake_gps_suspected,
          network_latitude, network_longitude, device_id, sync_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          guru_id, tanggal,
          hasilKeterlambatan.jam_seharusnya,
          hasilKeterlambatan.jam_masuk_aktual,
          hasilKeterlambatan.keterlambatan_menit,
          hasilKeterlambatan.kategori_keterlambatan,
          hasilKeterlambatan.sanksi,
          latitude, longitude, lokasiCheck.jarak,
          gps_accuracy  || null,
          is_mock_location     ? 1 : 0,
          fakeGpsCheck.is_suspected ? 1 : 0,
          network_latitude  || null,
          network_longitude || null,
          device_id         || null,
          sync_status       || 'online'
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
              guru_id, tanggal,
              ...hasilKeterlambatan,
              latitude, longitude,
              jarak_dari_kantor: lokasiCheck.jarak,
              pesan_lokasi: lokasiCheck.pesan
            }
          });
        }
      );
    });
  });
});

// ------------------------------------------
// POST /presensi/sync-offline
// ------------------------------------------
app.post('/presensi/sync-offline', verifyToken, (req, res) => {
  const { records } = req.body;

  if (!records || !Array.isArray(records) || records.length === 0) {
    return res.status(400).json({ message: 'Tidak ada data untuk disinkronkan' });
  }

  db.get("SELECT nilai FROM konfigurasi WHERE nama = 'offline_max_delay'", (err, configRow) => {
    const maxDelayDetik = configRow ? parseInt(configRow.nilai) : 300;

    const results = { berhasil: [], gagal: [] };
    let processed = 0;

    records.forEach((record) => {
      const {
        guru_id, jam_seharusnya, jam_masuk_aktual,
        latitude, longitude, gps_accuracy, is_mock_location,
        developer_options_on, network_latitude, network_longitude,
        device_id, local_timestamp
      } = record;

      const serverNow = Date.now();
      const localTime = new Date(local_timestamp).getTime();
      const selisihDetik = Math.abs(serverNow - localTime) / 1000;

      if (selisihDetik > maxDelayDetik) {
        results.gagal.push({
          record,
          alasan: `Timestamp offline terlalu jauh (${Math.round(selisihDetik)}s). Maks ${maxDelayDetik}s.`
        });
        processed++;
        if (processed === records.length) {
          return res.json({ message: 'Sinkronisasi selesai', results });
        }
        return;
      }

      const fakeGpsCheck = analisaFakeGPS({
        is_mock_location, gps_accuracy, network_latitude, network_longitude,
        latitude, longitude, developer_options_on
      });

      if (fakeGpsCheck.is_suspected) {
        catatSecurityLog(guru_id, 'FAKE_GPS_OFFLINE_SYNC',
          JSON.stringify({ warnings: fakeGpsCheck.warnings }), req);
        results.gagal.push({ record, alasan: 'Terdeteksi GPS palsu: ' + fakeGpsCheck.warnings.join('; ') });
        processed++;
        if (processed === records.length) {
          return res.json({ message: 'Sinkronisasi selesai', results });
        }
        return;
      }

      const tanggalRecord = new Date(local_timestamp).toISOString().split('T')[0];
      db.get(
        `SELECT id FROM absensi WHERE guru_id = ? AND DATE(tanggal) = ?`,
        [guru_id, tanggalRecord],
        (err, existing) => {
          if (existing) {
            results.gagal.push({ record, alasan: 'Data presensi untuk tanggal ini sudah ada' });
          } else {
            db.all('SELECT * FROM konfigurasi', (err, configs) => {
              const config = {};
              configs.forEach(c => { config[c.nama] = c.nilai; });

              const officeLat = parseFloat(config.kantor_latitude  || -6.360427);
              const officeLon = parseFloat(config.kantor_longitude || 107.095709);
              const maxRadius = parseFloat(config.radius_maksimal  || 100);
              const lokasiCheck = validasiLokasi(latitude, longitude, officeLat, officeLon, maxRadius);

              if (!lokasiCheck.valid) {
                results.gagal.push({ record, alasan: lokasiCheck.pesan });
              } else {
                const jamSeharusnya = jam_seharusnya || config.jam_masuk_default || '08:00';
                const hasil = prosesKeterlambatan(jamSeharusnya, jam_masuk_aktual);

                db.run(
                  `INSERT INTO absensi (
                    guru_id, tanggal, jam_seharusnya, jam_masuk_aktual,
                    keterlambatan_menit, kategori_keterlambatan, sanksi,
                    latitude, longitude, jarak_dari_kantor,
                    gps_accuracy, is_mock_location, device_id, sync_status
                  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                  [
                    guru_id, local_timestamp,
                    hasil.jam_seharusnya, hasil.jam_masuk_aktual,
                    hasil.keterlambatan_menit, hasil.kategori_keterlambatan, hasil.sanksi,
                    latitude, longitude, lokasiCheck.jarak,
                    gps_accuracy || null, is_mock_location ? 1 : 0,
                    device_id || null, 'offline_sync'
                  ],
                  function(err) {
                    if (!err) results.berhasil.push({ record, id: this.lastID });
                    else results.gagal.push({ record, alasan: 'Error database: ' + err.message });
                  }
                );
              }
            });
          }

          processed++;
          if (processed === records.length) {
            res.json({ message: 'Sinkronisasi selesai', results });
          }
        }
      );
    });
  });
});

// ------------------------------------------
// GET /riwayat/:guru_id
// ------------------------------------------
app.get('/riwayat/:guru_id', verifyToken, (req, res) => {
  db.all(
    `SELECT a.*, g.nama, g.email FROM absensi a
     JOIN guru g ON a.guru_id = g.id
     WHERE a.guru_id = ? ORDER BY a.tanggal DESC`,
    [req.params.guru_id],
    (err, rows) => {
      if (err) return res.status(500).json({ message: 'Error mengambil riwayat' });
      res.json({ message: 'Berhasil mengambil riwayat', data: rows });
    }
  );
});

// ------------------------------------------
// KALENDER
// ------------------------------------------
app.get('/kalender', verifyToken, (req, res) => {
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
  if (!tanggal || !jenis) return res.status(400).json({ message: 'Tanggal dan jenis harus diisi' });
  db.run('INSERT INTO kalender (tanggal, jenis, keterangan) VALUES (?, ?, ?)',
    [tanggal, jenis, keterangan],
    function(err) {
      if (err) return res.status(500).json({ message: 'Error menambah kalender' });
      res.status(201).json({ message: 'Kalender berhasil ditambahkan',
        data: { id: this.lastID, tanggal, jenis, keterangan } });
    }
  );
});

app.delete('/kalender/:id', verifyToken, verifyAdmin, (req, res) => {
  db.run('DELETE FROM kalender WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ message: 'Error menghapus kalender' });
    res.json({ message: 'Kalender berhasil dihapus' });
  });
});

// ------------------------------------------
// PENGAJUAN (izin/sakit/dinas)
// ------------------------------------------
app.post('/pengajuan', verifyToken, upload.single('foto_bukti'), (req, res) => {
  const { guru_id, jenis, tanggal_mulai, tanggal_selesai, keterangan } = req.body;
  const foto_bukti = req.file ? `/uploads/pengajuan/${req.file.filename}` : null;
  if (!guru_id || !jenis || !tanggal_mulai || !tanggal_selesai)
    return res.status(400).json({ message: 'Data tidak lengkap' });
  db.run(
    `INSERT INTO pengajuan (guru_id, jenis, tanggal_mulai, tanggal_selesai, keterangan, foto_bukti)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [guru_id, jenis, tanggal_mulai, tanggal_selesai, keterangan, foto_bukti],
    function(err) {
      if (err) return res.status(500).json({ message: 'Error mengajukan' });
      res.status(201).json({
        message: 'Pengajuan berhasil diajukan',
        data: { id: this.lastID, guru_id, jenis, tanggal_mulai, tanggal_selesai,
                keterangan, foto_bukti, status: 'pending' }
      });
    }
  );
});

app.get('/pengajuan', verifyToken, (req, res) => {
  const { guru_id, status } = req.query;
  let query = `SELECT p.*, g.nama, g.email FROM pengajuan p JOIN guru g ON p.guru_id = g.id`;
  const params = [];
  const conditions = [];
  if (guru_id) { conditions.push('p.guru_id = ?'); params.push(guru_id); }
  if (status)  { conditions.push('p.status = ?');  params.push(status); }
  if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
  query += ' ORDER BY p.created_at DESC';
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error mengambil pengajuan' });
    res.json({ message: 'Berhasil mengambil pengajuan', data: rows });
  });
});

app.put('/pengajuan/:id/proses', verifyToken, verifyAdmin, (req, res) => {
  const { status, alasan_ditolak } = req.body;
  if (!status || !['disetujui', 'ditolak'].includes(status))
    return res.status(400).json({ message: 'Status harus disetujui atau ditolak' });
  db.run(
    `UPDATE pengajuan SET status = ?, alasan_ditolak = ?, diproses_oleh = ?, diproses_pada = ? WHERE id = ?`,
    [status, alasan_ditolak, req.userId, new Date().toISOString(), req.params.id],
    function(err) {
      if (err) return res.status(500).json({ message: 'Error memproses pengajuan' });
      res.json({ message: `Pengajuan berhasil ${status}` });
    }
  );
});

// ------------------------------------------
// TUNJANGAN
// ------------------------------------------
app.get('/tunjangan/:guru_id', verifyToken, (req, res) => {
  const now = new Date();
  const targetBulan = req.query.bulan ? parseInt(req.query.bulan) : now.getMonth() + 1;
  const targetTahun = req.query.tahun ? parseInt(req.query.tahun) : now.getFullYear();
  hitungTunjanganBulanan(req.params.guru_id, targetBulan, targetTahun, (err, result) => {
    if (err) return res.status(500).json({ message: err.message });
    res.json({ message: 'Berhasil menghitung tunjangan', data: result });
  });
});

app.get('/tunjangan/:guru_id/ringkasan', verifyToken, (req, res) => {
  const now = new Date();
  const bulanIni = now.getMonth() + 1;
  const tahunIni = now.getFullYear();
  const promises = [];
  for (let i = 0; i < 3; i++) {
    let bulan = bulanIni - i;
    let tahun = tahunIni;
    if (bulan <= 0) { bulan += 12; tahun -= 1; }
    promises.push(new Promise((resolve, reject) => {
      hitungTunjanganBulanan(req.params.guru_id, bulan, tahun, (err, result) => {
        if (err) reject(err); else resolve(result);
      });
    }));
  }
  Promise.all(promises)
    .then(results => res.json({ message: 'Berhasil mengambil ringkasan tunjangan', data: results }))
    .catch(err => res.status(500).json({ message: err.message }));
});

// ------------------------------------------
// KONFIGURASI
// ------------------------------------------
app.get('/konfigurasi', verifyToken, (req, res) => {
  db.all('SELECT * FROM konfigurasi', (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error mengambil konfigurasi' });
    const config = {};
    rows.forEach(row => { config[row.nama] = row.nilai; });
    res.json({ message: 'Berhasil mengambil konfigurasi', data: config });
  });
});

app.put('/konfigurasi', verifyToken, verifyAdmin, (req, res) => {
  const allowedKeys = [
    'jam_masuk_default', 'kantor_latitude', 'kantor_longitude',
    'kantor_nama', 'radius_maksimal',
    'potongan_alpa', 'max_gps_accuracy', 'offline_max_delay'
  ];
  const updates = req.body;
  const validUpdates = Object.keys(updates).filter(key => allowedKeys.includes(key));
  if (validUpdates.length === 0)
    return res.status(400).json({ message: 'Tidak ada data valid untuk diupdate' });

  let completed = 0;
  const errors = [];
  validUpdates.forEach(key => {
    db.run("UPDATE konfigurasi SET nilai = ? WHERE nama = ?", [updates[key], key], (err) => {
      if (err) errors.push({ key, error: err.message });
      completed++;
      if (completed === validUpdates.length) {
        if (errors.length > 0) return res.status(500).json({ message: 'Beberapa update gagal', errors });
        res.json({ message: 'Konfigurasi berhasil diupdate', data: updates });
      }
    });
  });
});

// ------------------------------------------
// ADMIN: DASHBOARD
// ------------------------------------------
app.get('/admin/dashboard', verifyToken, verifyAdmin, (req, res) => {
  const today     = new Date().toISOString().split('T')[0];
  const thisMonth = new Date().toISOString().slice(0, 7);

  db.get('SELECT COUNT(*) as total FROM guru WHERE role = "guru"', [], (err, totalGuru) => {
    if (err) return res.status(500).json({ message: 'Error' });
    db.get('SELECT COUNT(*) as total FROM absensi WHERE DATE(tanggal) = ?', [today], (err, absenHariIni) => {
      if (err) return res.status(500).json({ message: 'Error' });
      db.get('SELECT COUNT(*) as total FROM pengajuan WHERE status = "pending"', [], (err, pengajuanPending) => {
        if (err) return res.status(500).json({ message: 'Error' });
        db.get(`SELECT COUNT(*) as total FROM absensi WHERE strftime('%Y-%m', tanggal) = ? AND keterlambatan_menit > 0`,
          [thisMonth], (err, telatBulanIni) => {
            if (err) return res.status(500).json({ message: 'Error' });
            db.get('SELECT COUNT(*) as total FROM security_log WHERE DATE(created_at) = ? AND event_type LIKE "FAKE_GPS%"',
              [today], (err, suspiciousToday) => {
                res.json({
                  message: 'Dashboard admin',
                  data: {
                    total_guru:         totalGuru.total,
                    absen_hari_ini:     absenHariIni.total,
                    pengajuan_pending:  pengajuanPending.total,
                    telat_bulan_ini:    telatBulanIni.total,
                    suspicious_gps_hari_ini: suspiciousToday ? suspiciousToday.total : 0
                  }
                });
              });
          });
      });
    });
  });
});

// ------------------------------------------
// ADMIN: DATA GURU
// ------------------------------------------
app.get('/admin/guru', verifyToken, verifyAdmin, (req, res) => {
  db.all(`SELECT id, nama, nip, email, role, gaji_pokok, tunjangan_hadir,
          potongan_telat_sedang, potongan_telat_berat, last_login, created_at
          FROM guru WHERE role = "guru" ORDER BY nama ASC`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error mengambil data guru' });
    res.json({ message: 'Daftar guru', data: rows });
  });
});

app.get('/admin/guru/:id', verifyToken, verifyAdmin, (req, res) => {
  db.get('SELECT * FROM guru WHERE id = ?', [req.params.id], (err, guru) => {
    if (err) return res.status(500).json({ message: 'Error' });
    if (!guru) return res.status(404).json({ message: 'Guru tidak ditemukan' });
    res.json({ message: 'Detail guru', data: guru });
  });
});

app.put('/admin/guru/:id', verifyToken, verifyAdmin, (req, res) => {
  const { id } = req.params;
  const { nama, nip, email, gaji_pokok, tunjangan_hadir, potongan_telat_sedang, potongan_telat_berat } = req.body;
  db.run(
    `UPDATE guru SET nama = ?, nip = ?, email = ?, gaji_pokok = ?,
     tunjangan_hadir = ?, potongan_telat_sedang = ?, potongan_telat_berat = ? WHERE id = ?`,
    [nama, nip, email, gaji_pokok, tunjangan_hadir, potongan_telat_sedang, potongan_telat_berat, id],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed'))
          return res.status(400).json({ message: 'Email sudah digunakan' });
        return res.status(500).json({ message: 'Error update guru' });
      }
      res.json({ message: 'Data guru berhasil diupdate' });
    }
  );
});

app.delete('/admin/guru/:id', verifyToken, verifyAdmin, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM absensi WHERE guru_id = ?', [id], (err) => {
    if (err) return res.status(500).json({ message: 'Error' });
    db.run('DELETE FROM pengajuan WHERE guru_id = ?', [id], (err) => {
      if (err) return res.status(500).json({ message: 'Error' });
      db.run('DELETE FROM guru WHERE id = ?', [id], function(err) {
        if (err) return res.status(500).json({ message: 'Error hapus guru' });
        res.json({ message: 'Guru berhasil dihapus' });
      });
    });
  });
});

app.post('/admin/create-guru', verifyToken, verifyAdmin, async (req, res) => {
  const { nama, email, password, gaji_pokok, tunjangan_hadir } = req.body;
  if (!nama || !email || !password)
    return res.status(400).json({ message: 'Nama, email, dan password harus diisi' });
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email))
    return res.status(400).json({ message: 'Format email tidak valid' });
  try {
    const hashedPassword = await bcrypt.hash(password, 12);

    // Generate NIP otomatis
    generateNIP((err, nip) => {
      if (err) return res.status(500).json({ message: 'Error generate NIP' });

      db.run(
        `INSERT INTO guru (nama, nip, email, password, role, gaji_pokok, tunjangan_hadir)
         VALUES (?, ?, ?, ?, 'guru', ?, ?)`,
        [nama, nip, email, hashedPassword, gaji_pokok || 5690752, tunjangan_hadir || 50000],
        function(err) {
          if (err) {
            if (err.message.includes('UNIQUE constraint failed'))
              return res.status(400).json({ message: 'Email sudah terdaftar' });
            return res.status(500).json({ message: 'Error membuat akun' });
          }
          res.status(201).json({
            message: 'Akun guru berhasil dibuat',
            data: { id: this.lastID, nama, email, nip }
          });
        }
      );
    });
  } catch {
    res.status(500).json({ message: 'Error server' });
  }
});

// ------------------------------------------
// ADMIN: LAPORAN
// ------------------------------------------
app.get('/admin/absensi', verifyToken, verifyAdmin, (req, res) => {
  const { tanggal, guru_id } = req.query;
  let query = `SELECT a.*, g.nama, g.email FROM absensi a JOIN guru g ON a.guru_id = g.id WHERE 1=1`;
  const params = [];
  if (tanggal) { query += ' AND DATE(a.tanggal) = ?'; params.push(tanggal); }
  if (guru_id) { query += ' AND a.guru_id = ?';       params.push(guru_id); }
  query += ' ORDER BY a.tanggal DESC LIMIT 100';
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error' });
    res.json({ message: 'Data absensi', data: rows });
  });
});

app.get('/admin/laporan/kehadiran', verifyToken, verifyAdmin, (req, res) => {
  const now = new Date();
  const targetBulan = req.query.bulan || (now.getMonth() + 1);
  const targetTahun = req.query.tahun || now.getFullYear();
  const startDate = `${targetTahun}-${String(targetBulan).padStart(2, '0')}-01`;
  const endDate   = `${targetTahun}-${String(targetBulan).padStart(2, '0')}-31`;

  db.all(`SELECT g.id, g.nama, g.email, g.nip,
            COUNT(a.id) as total_hadir,
            SUM(CASE WHEN a.kategori_keterlambatan = 'Tepat Waktu' THEN 1 ELSE 0 END) as tepat_waktu,
            SUM(CASE WHEN a.kategori_keterlambatan = 'Telat Ringan' THEN 1 ELSE 0 END) as telat_ringan,
            SUM(CASE WHEN a.kategori_keterlambatan = 'Telat Sedang' THEN 1 ELSE 0 END) as telat_sedang,
            SUM(CASE WHEN a.kategori_keterlambatan = 'Telat Berat'  THEN 1 ELSE 0 END) as telat_berat
          FROM guru g
          LEFT JOIN absensi a ON g.id = a.guru_id AND DATE(a.tanggal) BETWEEN ? AND ?
          WHERE g.role = 'guru'
          GROUP BY g.id, g.nama, g.email, g.nip
          ORDER BY g.nama`, [startDate, endDate], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error' });
    res.json({ message: 'Laporan kehadiran',
      periode: `${getNamaBulan(targetBulan)} ${targetTahun}`, data: rows });
  });
});

app.get('/admin/pengajuan/pending', verifyToken, verifyAdmin, (req, res) => {
  db.all(`SELECT p.*, g.nama, g.email FROM pengajuan p
          JOIN guru g ON p.guru_id = g.id
          WHERE p.status = 'pending' ORDER BY p.created_at ASC`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error' });
    res.json({ message: 'Pengajuan pending', data: rows });
  });
});

// ------------------------------------------
// GET /admin/security-log
// ------------------------------------------
app.get('/admin/security-log', verifyToken, verifyAdmin, (req, res) => {
  const { tanggal, event_type } = req.query;
  let query = `SELECT sl.*, g.nama, g.email FROM security_log sl
               LEFT JOIN guru g ON sl.guru_id = g.id WHERE 1=1`;
  const params = [];
  if (tanggal)    { query += ' AND DATE(sl.created_at) = ?'; params.push(tanggal); }
  if (event_type) { query += ' AND sl.event_type = ?';       params.push(event_type); }
  query += ' ORDER BY sl.created_at DESC LIMIT 200';
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ message: 'Error mengambil security log' });
    res.json({ message: 'Security log', data: rows });
  });
});

// ------------------------------------------
// DELETE /guru/:id
// ------------------------------------------
app.delete('/guru/:id', verifyToken, verifyAdmin, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM absensi WHERE guru_id = ?', [id], (err) => {
    if (err) return res.status(500).json({ message: 'Gagal menghapus data absensi' });
    db.run('DELETE FROM pengajuan WHERE guru_id = ?', [id], (err) => {
      if (err) return res.status(500).json({ message: 'Gagal menghapus data pengajuan' });
      db.run('DELETE FROM guru WHERE id = ?', [id], function(err) {
        if (err) return res.status(500).json({ message: 'Gagal menghapus akun' });
        if (this.changes === 0) return res.status(404).json({ message: 'Akun tidak ditemukan' });
        res.json({ message: `Akun guru dengan ID ${id} berhasil dihapus` });
      });
    });
  });
});

// ===========================
// START SERVER
// ===========================
app.listen(PORT, () => {
  console.log(`\nServer berjalan di http://localhost:${PORT}`);
  console.log('\n=== ATURAN KETERLAMBATAN ===');
  console.log('- 0        menit : Tepat Waktu (tunjangan hadir penuh)');
  console.log('- 1-30     menit : Telat Ringan (tidak ada potongan)');
  console.log('- 31-120   menit : Telat Sedang (potong Rp 25.000)');
  console.log('- > 120    menit : Telat Berat  (potong Rp 50.000)');
  console.log('- Alfa/Lupa Absen: potong Rp 100.000 per hari');
  console.log('\n=== KEAMANAN ===');
  console.log('- Login: admin@smkalluthfah.sch.id / admin123');
  console.log('- Radius geofencing: 100 meter dari koordinat sekolah');
});